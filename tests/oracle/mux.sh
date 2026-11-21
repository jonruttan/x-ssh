#!/bin/sh
# tests/oracle/mux.sh -- connection sharing, x-ssh's and OpenSSH's.
#
# Usage: X=/path/to/x sh tests/oracle/mux.sh [SSHD] [PORT]
#
# SSHD is OpenSSH's server (/usr/sbin/sshd by default), run unprivileged
# on 127.0.0.1:PORT as tests/oracle/sshd.sh runs it.  Each end of
# OpenSSH's multiplexing protocol is checked against the other's:
#
#   master   x-ssh's ControlMaster: its socket made srw-------; OpenSSH's
#            -O check; OpenSSH's passengers, their output, error, input
#            and exit status; OpenSSH's -W through it; x-ssh's passengers
#            and -W; -O stop removing the socket; -O exit ending it
#   outlive  the master's own session ended, a passenger's goes on
#   taken    a second master at a path taken, said as OpenSSH says it
#   ask      ControlMaster ask: SSH_ASKPASS asked to confirm, a no
#            refusing the session, OpenSSH's passenger then connecting
#            itself
#   openssh  OpenSSH's ControlMaster: x-ssh's -O check, passenger, -W,
#            and -O exit
#   auto     ControlMaster auto: the first a master, the second its
#            passenger
#   none     -O with no master, or no ControlPath: OpenSSH's words
set -u
sshd=${1:-/usr/sbin/sshd}
port=${2:-22750}
X=${X:-x}
# a sockaddr_un path holds 104 bytes: the fixture's paths stay short
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-mux.XXXXXX")
kill_tree() {
	[ -n "${1:-}" ] || return 0
	for c in $(ps -axo pid,ppid | awk -v p="$1" '$2 == p { print $1 }'); do kill_tree "$c"; done
	kill "$1" 2>/dev/null
}
dpid=
cpid=
opid=
trap 'kill_tree $cpid; [ -n "$opid" ] && kill $opid 2>/dev/null; kill $dpid 2>/dev/null; rm -rf "$fx"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$fx/hostkey"
ssh-keygen -q -t ed25519 -N '' -C x-ssh-mux -f "$fx/userkey"
cp "$fx/userkey.pub" "$fx/authorized_keys"
printf 'Port %s\nListenAddress 127.0.0.1\nHostKey %s/hostkey\nAuthorizedKeysFile %s/authorized_keys\nPidFile %s/sshd.pid\nUsePAM no\nStrictModes no\n' \
	"$port" "$fx" "$fx" "$fx" > "$fx/sshd_config"
"$sshd" -D -e -f "$fx/sshd_config" > "$fx/sshd.log" 2>&1 &
dpid=$!
sleep 1
user=$(id -un)
home="$fx/home"
mkdir -p "$home"
opts="-F none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $port -i $fx/userkey -l $user"
xssh() { HOME="$home" "$X" -l ssh -- ssh $opts "$@"; }
ossh() { ssh $opts -o LogLevel=INFO "$@"; }
# what a client said, without the host key added to /dev/null, the
# launcher's note of a state image written for the fixture's home,
# OpenSSH's \r, or the master's process id
said() { grep -v -e "^Warning: Permanently added" -e "^x: no current state image" | tr -d "\r" | sed -e "s/pid=[0-9]*/pid=N/" -e "s|$fx|FX|g"; }
failed=0

fail() {
	echo "FAIL: $1" >&2
	cat "$fx/client.err" >&2
	tail -5 "$fx/sshd.log" >&2
	failed=1
}

check() { if [ "$2" = "$3" ]; then echo "ok: $1"; else printf '%s\n' "$2" > "$fx/client.err"; fail "$1 -- said the above, wanted '$3'"; fi; }
waitsock() { i=0; while ! [ -S "$1" ] && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done; }
gone() { i=0; while [ -e "$1" ] && [ $i -lt 10 ]; do i=$((i + 1)); sleep 1; done; [ -e "$1" ] && echo there || echo gone; }
mode() { ls -l "$1" 2>/dev/null | cut -c1-10; }
# a master killed leaves its socket: x-ssh has no signal handler to remove it
done_with() { kill_tree $cpid; cpid=; rm -f "$cm"; }
status() { "$@"; echo "status $?"; }

# master: x-ssh's, its passengers OpenSSH's and its own
cm="$fx/cm"
xssh -M -S "$cm" -N 127.0.0.1 < /dev/null 2> "$fx/master.err" &
cpid=$!
waitsock "$cm"
check "master -- the socket made srw-------" "$(mode "$cm")" "srw-------"
check "master -- OpenSSH's -O check" "$(ossh -S "$cm" -O check 127.0.0.1 2>&1 | said)" "Master running (pid=N)"
check "master -- an OpenSSH passenger's output, error and status" \
	"$(status ossh -S "$cm" 127.0.0.1 'echo out; echo err >&2; exit 7' < /dev/null 2>&1 | said)" "$(printf 'out\nerr\nstatus 7')"
check "master -- an OpenSSH passenger's input" "$(echo in | ossh -S "$cm" 127.0.0.1 cat 2>&1 | said)" "in"
check "master -- OpenSSH's -W through it" "$(ossh -S "$cm" -W "127.0.0.1:$port" 127.0.0.1 < /dev/null 2>/dev/null | head -c 16)" "SSH-2.0-OpenSSH_"
check "master -- x-ssh's -O check" "$(xssh -S "$cm" -O check 127.0.0.1 2>&1 | said)" "Master running (pid=N)"
check "master -- an x-ssh passenger's output and status" \
	"$(status xssh -S "$cm" 127.0.0.1 'echo out; exit 5' < /dev/null 2>&1 | said)" "$(printf 'out\nstatus 5')"
check "master -- x-ssh's -W through it" "$(xssh -S "$cm" -W "127.0.0.1:$port" 127.0.0.1 < /dev/null 2>/dev/null | head -c 16)" "SSH-2.0-OpenSSH_"
check "master -- OpenSSH's -O stop" "$(ossh -S "$cm" -O stop 127.0.0.1 2>&1 | said) $(gone "$cm")" "Stop listening request sent. gone"
done_with
xssh -M -S "$cm" -N 127.0.0.1 < /dev/null 2> "$fx/master.err" &
cpid=$!
waitsock "$cm"
check "master -- OpenSSH's -O exit" "$(ossh -S "$cm" -O exit 127.0.0.1 2>&1 | said) $(gone "$cm")" "Exit request sent. gone"
sleep 1
check "master -- ended by -O exit" "$(kill -0 $cpid 2>/dev/null && echo running || echo ended)" "ended"
done_with

# outlive: the master's session ends first
xssh -M -S "$cm" 127.0.0.1 'sleep 2' < /dev/null 2> "$fx/master.err" &
cpid=$!
waitsock "$cm"
check "outlive -- a passenger outlasts the master's session" \
	"$(status ossh -S "$cm" 127.0.0.1 'sleep 4; echo late' < /dev/null 2>&1 | said)" "$(printf 'late\nstatus 0')"
wait $cpid
check "outlive -- the master gone with it" "$(gone "$cm")" "gone"
cpid=

# taken: a second master at the same path
xssh -M -S "$cm" -N 127.0.0.1 < /dev/null 2> "$fx/master.err" &
cpid=$!
waitsock "$cm"
ours=$(xssh -M -S "$cm" 127.0.0.1 'echo ran' < /dev/null 2>&1 | said)
theirs=$(ossh -M -S "$cm" 127.0.0.1 'echo ran' < /dev/null 2>&1 | said)
check "taken -- a path taken said as OpenSSH says it" "$ours" "$theirs"
done_with

# ask: SSH_ASKPASS says no
printf '#!/bin/sh\nprintf "%%s|%%s\\n" "$SSH_ASKPASS_PROMPT" "$1" >> %s/asked\necho no\n' "$fx" > "$fx/askpass"
chmod +x "$fx/askpass"
DISPLAY=:0 SSH_ASKPASS="$fx/askpass" xssh -o ControlMaster=ask -S "$cm" -N 127.0.0.1 < /dev/null 2> "$fx/master.err" &
cpid=$!
waitsock "$cm"
check "ask -- refused, the passenger connects itself" \
	"$(ossh -S "$cm" 127.0.0.1 'echo itself' < /dev/null 2>&1 | said)" "$(printf 'Master refused session request: Permission denied\nitself')"
check "ask -- SSH_ASKPASS asked to confirm" "$(cat "$fx/asked" 2>/dev/null)" "confirm|Allow shared connection to 127.0.0.1? "
done_with

# openssh: OpenSSH's master, x-ssh's passengers
om="$fx/om"
ossh -M -S "$om" -N 127.0.0.1 < /dev/null 2> "$fx/omaster.err" &
opid=$!
waitsock "$om"
check "openssh -- x-ssh's -O check" "$(xssh -S "$om" -O check 127.0.0.1 2>&1 | said)" "Master running (pid=N)"
check "openssh -- an x-ssh passenger's output and status" \
	"$(status xssh -S "$om" 127.0.0.1 'echo out; exit 3' < /dev/null 2>&1 | said)" "$(printf 'out\nstatus 3')"
echo in > "$fx/in"
check "openssh -- an x-ssh passenger's input" "$(xssh -S "$om" 127.0.0.1 cat < "$fx/in" 2>&1 | said)" "in"
check "openssh -- x-ssh's -W through it" "$(xssh -S "$om" -W "127.0.0.1:$port" 127.0.0.1 < /dev/null 2>/dev/null | head -c 16)" "SSH-2.0-OpenSSH_"
check "openssh -- x-ssh's -O exit" "$(xssh -S "$om" -O exit 127.0.0.1 2>&1 | said) $(gone "$om")" "Exit request sent. gone"
wait $opid 2>/dev/null
opid=

# auto: a master, then its passenger
am="$fx/am"
xssh -o ControlMaster=auto -S "$am" 127.0.0.1 'sleep 3; echo first' < /dev/null > "$fx/first" 2> "$fx/master.err" &
cpid=$!
waitsock "$am"
check "auto -- the second a passenger" \
	"$(status xssh -o ControlMaster=auto -S "$am" -O check 127.0.0.1 2>&1 | said; status xssh -o ControlMaster=auto -S "$am" 127.0.0.1 'echo second; exit 4' < /dev/null 2>&1 | said)" \
	"$(printf 'Master running (pid=N)\nstatus 0\nsecond\nstatus 4')"
wait $cpid
cpid=
check "auto -- the first its master" "$(cat "$fx/first") $(gone "$am")" "first gone"

# none: no master, no ControlPath
for args in "-S $fx/none -O check" "-O check" "-S $fx/none -O exit"; do
	ours=$(status xssh $args 127.0.0.1 2>&1 | said)
	theirs=$(status ossh $args 127.0.0.1 2>&1 | said)
	check "none -- ssh $args said as OpenSSH says it" "$ours" "$theirs"
done

exit $failed
