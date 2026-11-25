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
#            and -W; -O conninfo and channels, from OpenSSH's client and
#            x-ssh's alike; -O stop removing the socket and, with no
#            session, ending the master; -O exit ending it
#   outlive  the master's own session ended, a passenger's goes on
#   taken    a second master at a path taken, said as OpenSSH says it
#   ask      ControlMaster ask: SSH_ASKPASS asked to confirm, a no
#            refusing the session, OpenSSH's passenger then connecting
#            itself; -O proxy refused as OpenSSH's master refuses it
#   forward  -O forward and cancel, from OpenSSH's client and x-ssh's:
#            -L listened for and closed, -R 0's port printed, a refused -R
#            leaving the one beside it, a refusal
#            said as OpenSSH says it; a passenger's -L, under -N too
#   proxy    -O proxy, from OpenSSH's client and x-ssh's: a session, its
#            input, output, error and status; -L and -R through it; two
#            at once, beside a passenger
#   persist  ControlPersist: the session the master's own, the master
#            then in the background serving passengers, and gone once
#            idle; under -N the shell given back at once, -O stop ending it
#   openssh  OpenSSH's ControlMaster: x-ssh's -O check, passenger, -W,
#            -O proxy and its -R, -O forward and cancel, -O conninfo and
#            channels as OpenSSH's client says them, and -O exit
#   auto     ControlMaster auto: the first a master, the second its
#            passenger
#   none     -O with no master, no ControlPath, or a command not one of
#            OpenSSH's: OpenSSH's words
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
# OpenSSH's \r and its TCP_NODELAY warning on a control socket in
# proxy mode, or the master's process id
said() { grep -v -e "^Warning: Permanently added" -e "^x: no current state image" -e "^setsockopt TCP_NODELAY" | tr -d "\r" | sed -e "s/pid=[0-9]*/pid=N/" -e "s|$fx|FX|g"; }
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
# -O conninfo and channels with what changes from ask to ask said
# alike: the machine and process, the ports, how long, the counts, the
# channels' numbers and states
info() {
	sed -e "s/^Connection information for .* pid [0-9]*$/Connection information for H pid N/" \
		-e "s/-> OpenSSH_.*/-> OpenSSH_V/" -e "s/^  tcp 127.0.0.1:[0-9]* /  tcp 127.0.0.1:P /" \
		-e "s/duration [0-9:dwhm]*$/duration T/" -e "s/[0-9]* pkts [0-9]* blks [0-9.]*[BKMGTPE]B/N pkts N blks NB/g" \
		-e "s/^  #[0-9]* /  #N /" -e "s/ (\([^ ]*\) .*)$/ (\1 ...)/"
}
# the first bytes through a forward listening on port, or none
banner() { nc -w 2 127.0.0.1 "$1" < /dev/null 2>/dev/null | head -c 8; }

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
theirs=$(status ossh -S "$cm" -O conninfo 127.0.0.1 2>&1 | said | info)
check "master -- OpenSSH's -O conninfo" "$theirs" "$(printf '%s\n' "Connection information for H pid N" \
	"  versions x-ssh_0.1.0 -> OpenSSH_V" "  tcp 127.0.0.1:P -> 127.0.0.1:$port" "  duration T" \
	"  kexalgorithm curve25519-sha256" "  hostkeyalgorithm ssh-ed25519" "  cipher chacha20-poly1305@openssh.com" \
	"  mac <implicit>" "  compression none" "  rekey limit none interval none" \
	"  traffic N pkts N blks NB in, N pkts N blks NB out" "status 0")"
check "master -- x-ssh's -O conninfo, as OpenSSH's" "$(status xssh -S "$cm" -O conninfo 127.0.0.1 2>&1 | said | info)" "$theirs"
ossh -S "$cm" 127.0.0.1 'sleep 4' < /dev/null > /dev/null 2>&1 &
held=$!
sleep 2
theirs=$(status ossh -S "$cm" -O channels 127.0.0.1 2>&1 | said | info)
check "master -- OpenSSH's -O channels, a passenger's session open" "$theirs" \
	"$(printf '%s\n' "The following connections are open:" "  #N client-session ([session] ...)" "status 0")"
check "master -- x-ssh's -O channels, as OpenSSH's" "$(status xssh -S "$cm" -O channels 127.0.0.1 2>&1 | said | info)" "$theirs"
wait $held
check "master -- OpenSSH's -O stop" "$(ossh -S "$cm" -O stop 127.0.0.1 2>&1 | said) $(gone "$cm")" "Stop listening request sent. gone"
sleep 1
check "master -- with no session, ended by -O stop" "$(kill -0 $cpid 2>/dev/null && echo running || echo ended)" "ended"
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
rm -f "$fx/asked"
ours=$(status xssh -S "$cm" -O proxy 127.0.0.1 'echo ran' < /dev/null 2>&1 | said)
theirs=$(status ossh -S "$cm" -O proxy 127.0.0.1 'echo ran' < /dev/null 2>&1 | said)
check "ask -- -O proxy refused, said as OpenSSH says it" "$ours" "$theirs"
check "ask -- -O proxy asked about" "$(sort -u "$fx/asked" 2>/dev/null)" "confirm|Allow multiplex proxy connection?"
done_with

# forward: -O forward and cancel asked of x-ssh's master, by both clients;
# passengers' own forwards, under -N too
p1=$((port + 1)); p2=$((port + 2)); p3=$((port + 3)); p4=$((port + 4)); p5=$((port + 5))
xssh -M -S "$cm" -N 127.0.0.1 < /dev/null 2> "$fx/master.err" &
cpid=$!
waitsock "$cm"
check "forward -- OpenSSH's -O forward -L, then through it" \
	"$(status ossh -S "$cm" -O forward -L "$p1:127.0.0.1:$port" 127.0.0.1 2>&1 | said) $(banner $p1)" "status 0 SSH-2.0-"
check "forward -- the same again, OK" "$(status ossh -S "$cm" -O forward -L "$p1:127.0.0.1:$port" 127.0.0.1 2>&1 | said)" "status 0"
check "forward -- x-ssh's -O forward -L, then through it" \
	"$(status xssh -S "$cm" -O forward -L "$p2:127.0.0.1:$port" 127.0.0.1 2>&1 | said) $(banner $p2)" "status 0 SSH-2.0-"
check "forward -- -O forward -R 0 prints the port allocated" \
	"$(xssh -S "$cm" -O forward -R "0:127.0.0.1:$port" 127.0.0.1 2>/dev/null | grep -c '^[0-9][0-9]*$')" "1"
for who in ossh xssh; do
	check "forward -- $who's -O forward of a port taken, said as OpenSSH says it" \
		"$(status $who -S "$cm" -O forward -L "$port:127.0.0.1:$port" 127.0.0.1 2>&1 | said)" \
		"$(printf 'mux_client_forward: forwarding request failed: Port forwarding failed\nmuxclient: master forward request failed\nstatus 255')"
done
check "forward -- OpenSSH's -O cancel, the listener closed" \
	"$(status ossh -S "$cm" -O cancel -L "$p1:127.0.0.1:$port" 127.0.0.1 2>&1 | said) $(banner $p1)" "status 0 "
for who in ossh xssh; do
	check "forward -- $who's -O cancel of a forward not asked for, said as OpenSSH says it" \
		"$(status $who -S "$cm" -O cancel -L "$p1:127.0.0.1:$port" 127.0.0.1 2>&1 | said)" \
		"$(printf 'mux_client_forward: forwarding request failed: port not forwarded\nmuxclient: master cancel forward request failed\nstatus 0')"
done
check "forward -- x-ssh's -O forward -R, then -O cancel" \
	"$(status xssh -S "$cm" -O forward -R "$p3:127.0.0.1:$port" 127.0.0.1 2>&1 | said) $(status xssh -S "$cm" -O cancel -R "$p3:127.0.0.1:$port" 127.0.0.1 2>&1 | said)" \
	"status 0 status 0"
# two remote forwards with no address given: the server refusing the
# second, the first still the master's
xssh -S "$cm" -O forward -R "$p3:127.0.0.1:$port" 127.0.0.1 > /dev/null 2>&1
check "forward -- a remote forward refused, said as OpenSSH says it" \
	"$(status xssh -S "$cm" -O forward -R "1:127.0.0.1:$port" 127.0.0.1 2>&1 | said)" \
	"$(printf 'mux_client_forward: forwarding request failed: remote port forwarding failed for listen port 1\nmuxclient: master forward request failed\nstatus 255')"
check "forward -- the one beside it still served, from the server's end, then cancelled" \
	"$(ossh -S "$cm" 127.0.0.1 "nc -w 2 127.0.0.1 $p3 < /dev/null | head -c 8" < /dev/null 2>&1 | said) $(status xssh -S "$cm" -O cancel -R "$p3:127.0.0.1:$port" 127.0.0.1 2>&1 | said)" \
	"SSH-2.0- status 0"
check "forward -- an x-ssh passenger's -L beside its command" \
	"$(xssh -S "$cm" -L "$p4:127.0.0.1:$port" 127.0.0.1 'echo ran' < /dev/null 2>&1 | said) $(banner $p4)" "ran SSH-2.0-"
check "forward -- an x-ssh passenger under -N, its -L the master's" \
	"$(status xssh -S "$cm" -N -L "$p5:127.0.0.1:$port" 127.0.0.1 < /dev/null 2>&1 | said) $(banner $p5)" "status 0 SSH-2.0-"
done_with

# proxy: -O proxy, the control connection carrying the connection
# protocol, from OpenSSH's client and x-ssh's; forwards through it, the
# server's end reaching back through -L and -R; two at once
xssh -M -S "$cm" -N 127.0.0.1 < /dev/null 2> "$fx/master.err" &
cpid=$!
waitsock "$cm"
for who in ossh xssh; do
	check "proxy -- $who's output, error and status" \
		"$(status $who -S "$cm" -O proxy 127.0.0.1 'echo out; echo err >&2; exit 7' < /dev/null 2>&1 | said)" "$(printf 'out\nerr\nstatus 7')"
	check "proxy -- $who's input" "$(echo in | $who -S "$cm" -O proxy 127.0.0.1 cat 2>&1 | said)" "in"
done
check "proxy -- OpenSSH's -L, the server's end through it" \
	"$(ossh -S "$cm" -O proxy -L "$p1:127.0.0.1:$port" 127.0.0.1 "nc -w 2 127.0.0.1 $p1 < /dev/null | head -c 8" < /dev/null 2>&1 | said)" "SSH-2.0-"
check "proxy -- x-ssh's -L, the server's end through it" \
	"$(xssh -S "$cm" -O proxy -L "$p2:127.0.0.1:$port" 127.0.0.1 "nc -w 2 127.0.0.1 $p2 < /dev/null | head -c 8" < /dev/null 2>&1 | said)" "SSH-2.0-"
check "proxy -- OpenSSH's -R, the server's end through it" \
	"$(ossh -S "$cm" -O proxy -R "$p3:127.0.0.1:$port" 127.0.0.1 "nc -w 2 127.0.0.1 $p3 < /dev/null | head -c 8" < /dev/null 2>&1 | said)" "SSH-2.0-"
check "proxy -- x-ssh's -R, the server's end through it" \
	"$(xssh -S "$cm" -O proxy -R "$p4:127.0.0.1:$port" 127.0.0.1 "nc -w 2 127.0.0.1 $p4 < /dev/null | head -c 8" < /dev/null 2>&1 | said)" "SSH-2.0-"
ossh -S "$cm" -O proxy 127.0.0.1 'sleep 2; echo first' < /dev/null > "$fx/first" 2>&1 &
fpid=$!
sleep 1
second=$(xssh -S "$cm" -O proxy 127.0.0.1 'echo second' < /dev/null 2>&1 | said)
wait $fpid
check "proxy -- two at once, each its own channel" "$second $(said < "$fx/first")" "second first"
check "proxy -- the master's own passengers beside them" \
	"$(status ossh -S "$cm" 127.0.0.1 'echo shared' < /dev/null 2>&1 | said)" "$(printf 'shared\nstatus 0')"
done_with

# persist: ControlPersist, the master going on without its session
pm="$fx/pm"
check "persist -- the session's output and status, the master's own" \
	"$(status xssh -o ControlPersist=3 -M -S "$pm" 127.0.0.1 'echo own; exit 3' < /dev/null 2>&1 | said)" "$(printf 'own\nstatus 3')"
check "persist -- the master gone on in the background" "$(ossh -S "$pm" -O check 127.0.0.1 2>&1 | said)" "Master running (pid=N)"
check "persist -- a passenger of it" "$(status ossh -S "$pm" 127.0.0.1 'echo again' < /dev/null 2>&1 | said)" "$(printf 'again\nstatus 0')"
sleep 5
check "persist -- ended once idle past ControlPersist" "$(gone "$pm")" "gone"
qm="$fx/qm"
check "persist -- under -N, the shell given back at once" \
	"$(status xssh -o ControlPersist=yes -M -S "$qm" -N 127.0.0.1 < /dev/null 2>&1 | said)" "status 0"
qpid=$(ossh -S "$qm" -O check 127.0.0.1 2>&1 | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
check "persist -- -O stop ends a master with no session" \
	"$(ossh -S "$qm" -O stop 127.0.0.1 2>&1 | said) $(gone "$qm") $(sleep 1; kill -0 "$qpid" 2>/dev/null && echo running || echo ended)" \
	"Stop listening request sent. gone ended"
[ -n "$qpid" ] && kill "$qpid" 2>/dev/null

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
check "openssh -- x-ssh's -O proxy, its output, error and status" \
	"$(status xssh -S "$om" -O proxy 127.0.0.1 'echo out; echo err >&2; exit 6' < /dev/null 2>&1 | said)" "$(printf 'out\nerr\nstatus 6')"
check "openssh -- x-ssh's -O proxy, its input" "$(xssh -S "$om" -O proxy 127.0.0.1 cat < "$fx/in" 2>&1 | said)" "in"
check "openssh -- x-ssh's -O proxy -R, the server's end through it" \
	"$(xssh -S "$om" -O proxy -R "$p2:127.0.0.1:$port" 127.0.0.1 "nc -w 2 127.0.0.1 $p2 < /dev/null | head -c 8" < /dev/null 2>&1 | said)" "SSH-2.0-"
check "openssh -- x-ssh's -O forward -L, through it, then -O cancel" \
	"$(status xssh -S "$om" -O forward -L "$p1:127.0.0.1:$port" 127.0.0.1 2>&1 | said) $(banner $p1) $(status xssh -S "$om" -O cancel -L "$p1:127.0.0.1:$port" 127.0.0.1 2>&1 | said) $(banner $p1)" \
	"status 0 SSH-2.0- status 0 "
for c in conninfo channels; do
	check "openssh -- x-ssh's -O $c, as OpenSSH's client says it" \
		"$(status xssh -S "$om" -O $c 127.0.0.1 2>&1 | said | info)" "$(status ossh -S "$om" -O $c 127.0.0.1 2>&1 | said | info)"
done
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
for args in "-S $fx/none -O check" "-O check" "-S $fx/none -O exit" "-S $fx/none -O bogus"; do
	ours=$(status xssh $args 127.0.0.1 2>&1 | said)
	theirs=$(status ossh $args 127.0.0.1 2>&1 | said)
	check "none -- ssh $args said as OpenSSH says it" "$ours" "$theirs"
done

exit $failed
