#!/bin/sh
# tests/oracle/agent.sh -- x-ssh's ssh-agent and ssh-add against OpenSSH's.
#
# Usage: X=/path/to/x sh tests/oracle/agent.sh DROPBEAR_DIR [PORT]
#
# DROPBEAR_DIR holds a built Dropbear (dropbear, dropbearkey).  Keys are
# an Ed25519, an ECDSA and a sealed RSA key.
#
#   add      the same ssh-add session -- adds, -l, -L, -d, -x, -X, -t, -D,
#            a missing file, -q -- with each pairing of x-ssh's and
#            OpenSSH's ssh-add and agent, its words and statuses OpenSSH's
#   agent    -s, -c, -k and command mode as OpenSSH's ssh-agent prints and
#            runs them, and its refusals
#   login    x-ssh's client and OpenSSH's logging in to a Dropbear with
#            no key file, the key in x-ssh's agent; x-ssh's client with
#            OpenSSH's agent
#   forward  -A: x-ssh's client to a Dropbear and to x-ssh's server, OpenSSH's
#            to x-ssh's, OpenSSH's ssh-add there finding the key; -a, and
#            AllowAgentForwarding no, give the session no agent; the
#            server's socket gone with the session
set -u
db=${1:?a built Dropbear directory}
port=${2:-22432}
X=${X:-x}
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-agent.XXXXXX")
# The launcher pipes the program into the engine, a child of its own,
# so an agent's pid is a shell's: the whole tree under it goes.
kill_tree() {
	[ -n "${1:-}" ] || return 0
	for c in $(ps -axo pid,ppid | awk -v p="$1" '$2 == p { print $1 }'); do kill_tree "$c"; done
	kill "$1" 2>/dev/null
}
dbpid=
xpid=
opid=
xdpid=
ndpid=
trap 'kill $dbpid $opid 2>/dev/null; kill_tree $xpid; kill_tree $xdpid; kill_tree $ndpid; rm -rf "$fx"' EXIT
mkdir -p "$fx/home/.ssh" "$fx/bin"
# socket paths relative to $fx: a temporary directory's absolute one can
# pass the 104 bytes a unix-domain socket's path holds
cd "$fx" || exit 1
ssh-keygen -q -t ed25519 -N '' -C first-key -f k1
ssh-keygen -q -t ecdsa -N '' -C second-key -f k2
ssh-keygen -q -t rsa -b 2048 -N pw -C sealed-key -f k3
printf '#!/bin/sh\necho pw\n' > askpass
printf '#!/bin/sh\nexec "%s" -l ssh -- ssh-add "$@"\n' "$X" > bin/xadd
printf '#!/bin/sh\nexec "%s" -l ssh -- ssh-agent "$@"\n' "$X" > bin/xagent
chmod +x askpass bin/xadd bin/xagent
failed=0

fail() {
	echo "FAIL: $1" >&2
	[ -f err ] && cat err >&2
	failed=1
}

# --- add -----------------------------------------------------------------------

# The session, as ssh-add ($1) says it to the agent at SSH_AUTH_SOCK.
session() {
	A=$1
	p() { echo "== $*" | sed "s|$fx|FX|g; s|$A|ssh-add|"; "$@" 2>&1; echo "status $?"; }
	ask="env SSH_ASKPASS=$fx/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=x"
	p $A k1
	p $A k2
	p $A -l
	p $A -L
	p $ask $A k3
	p $A -l
	p $A -d k2
	p $A -d k2
	p $A -l
	p $ask $A -x
	p $A -l
	p $A k1
	p $ask $A -X
	p $A -l
	p $A -t 3 k2
	p $A -l
	sleep 4
	p $A -l
	p $A -D
	p $A -l
	p $A nosuchfile
	p $A -q k1
	p $A -L
}

# An agent ($1, its name $2) on the socket $3, in the foreground.
start_agent() {
	rm -f "$3"
	"$1" -D -a "$3" > "$2.agent.out" 2> "$2.agent.err" &
	echo $!
	i=0
	while [ ! -S "$3" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
}

opid=$(start_agent ssh-agent o o.sock)
xpid=$(start_agent bin/xagent x x.sock)
for pairing in "ssh-add o" "ssh-add x" "bin/xadd o" "bin/xadd x"; do
	set -- $pairing
	SSH_AUTH_SOCK=$2.sock session "$1" > "add.$(basename "$1").$2" 2>&1
done
for f in add.ssh-add.x add.xadd.o add.xadd.x; do
	cmp -s add.ssh-add.o "$f" || { diff add.ssh-add.o "$f" > err; fail "add: $f differs from OpenSSH's"; }
done
[ $failed = 0 ] && echo "ok: add"

# --- agent ---------------------------------------------------------------------

# The lines -s prints, the pid and socket made general.
general() { sed -E 's|s\.[A-Za-z0-9]{10}\.agent\.[A-Za-z0-9]{10}|SOCK|; s/[0-9]+/N/g'; }
for flags in "-s" "-c"; do
	HOME=. bin/xagent $flags > out 2> err
	s=$?
	pid=$(sed -n 's/^echo Agent pid \([0-9]*\);$/\1/p' out)
	[ $s = 0 ] && [ -n "$pid" ] || fail "agent $flags: status $s"
	general < out > got
	if [ "$flags" = -s ]; then
		printf 'SSH_AUTH_SOCK=./.ssh/agent/SOCK; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=N; export SSH_AGENT_PID;\necho Agent pid N;\n' > want
	else
		printf 'setenv SSH_AUTH_SOCK ./.ssh/agent/SOCK;\nsetenv SSH_AGENT_PID N;\necho Agent pid N;\n' > want
	fi
	cmp -s want got || { diff want got > err; fail "agent $flags: its lines"; }
	sock=$(sed -n 's/^SSH_AUTH_SOCK=\([^;]*\);.*/\1/p; s/^setenv SSH_AUTH_SOCK \([^;]*\);/\1/p' out)
	SSH_AUTH_SOCK=$sock ssh-add -l > /dev/null 2> err
	[ $? = 1 ] || fail "agent $flags: OpenSSH's ssh-add -l of it"
	SSH_AGENT_PID=$pid bin/xagent -s -k > out 2> err
	printf 'unset SSH_AUTH_SOCK;\nunset SSH_AGENT_PID;\necho Agent pid %s killed;\n' "$pid" > want
	cmp -s want out || { diff want out > err; fail "agent $flags: -k"; }
	i=0
	while [ -S "$sock" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
	[ -S "$sock" ] && fail "agent $flags: the socket left after -k"
done

# command mode: the command runs with the variables set, the agent ends with it
bin/xagent -a cmd.sock sh -c 'echo "$SSH_AUTH_SOCK"; ssh-add k1 2>&1; ssh-add -l | cut -d" " -f3-' > out 2> err
printf 'cmd.sock\nIdentity added: k1 (first-key)\nfirst-key (ED25519)\n' > want
cmp -s want out || { diff want out > err; fail "agent: command mode"; }
i=0
while [ -S cmd.sock ] && [ $i -lt 150 ]; do sleep 0.1; i=$((i + 1)); done
[ -S cmd.sock ] && fail "agent: command mode left its socket"

# refusals, word for word with OpenSSH's
for args in "-k" "-a o.sock" "-c -s"; do
	unset SSH_AGENT_PID
	ssh-agent $args > want.out 2> want.err; ws=$?
	bin/xagent $args > got.out 2> got.err; gs=$?
	[ "$ws" = "$gs" ] || fail "agent $args: status $gs, OpenSSH's $ws"
	case $args in
	"-c -s") ;; # the usage text is each one's own
	*) cmp -s want.err got.err || { diff want.err got.err > err; fail "agent $args: its words"; } ;;
	esac
done
SSH_AGENT_PID=abc ssh-agent -k > /dev/null 2> want.err
SSH_AGENT_PID=abc bin/xagent -k > /dev/null 2> got.err
cmp -s want.err got.err || { diff want.err got.err > err; fail "agent -k: a bad SSH_AGENT_PID"; }
[ $failed = 0 ] && echo "ok: agent"

# --- login ---------------------------------------------------------------------

"$db/dropbearkey" -t ed25519 -f hostkey > /dev/null 2>&1
cat k1.pub > authorized_keys
"$db/dropbear" -D "$fx" -p "127.0.0.1:$port" -r hostkey -F -s > dropbear.log 2>&1 &
dbpid=$!
sleep 1
user=$(id -un)
SSH_AUTH_SOCK=x.sock ssh-add -q k1
SSH_AUTH_SOCK=o.sock ssh-add -q k1
xssh() { HOME=$fx/home "$X" -l ssh -- ssh -F none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o IdentityFile=none -o PasswordAuthentication=no -o LogLevel=ERROR "$@"; }
ossh() { HOME=$fx/home ssh -F none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o IdentityFile=none -o PasswordAuthentication=no -o LogLevel=ERROR "$@"; }
for who in "xssh x" "xssh o" "ossh x"; do
	set -- $who
	out=$(SSH_AUTH_SOCK=$2.sock $1 -p "$port" "$user@127.0.0.1" echo in 2> err)
	[ "$out" = in ] || fail "login: $1 with the $2 agent"
done
# no agent: the key is not there to offer
out=$(env -u SSH_AUTH_SOCK sh -c "HOME=$fx/home \"$X\" -l ssh -- ssh -F none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=none -o PasswordAuthentication=no -o BatchMode=yes -p $port $user@127.0.0.1 echo in" 2> err)
[ -z "$out" ] || fail "login: in with no agent"
[ $failed = 0 ] && echo "ok: login"


# --- forward -------------------------------------------------------------------

# x-ssh's server, its agent forwarding on and off
xport=$((port + 1))
nport=$((port + 2))
env -u SSH_AUTH_SOCK "$X" -l ssh -- sshd -D -e -f /dev/null -h hostkey -o ListenAddress=127.0.0.1 -p "$xport" \
	-o AuthorizedKeysFile="$fx/authorized_keys" -o PidFile=none > xserver.log 2>&1 &
xdpid=$!
env -u SSH_AUTH_SOCK "$X" -l ssh -- sshd -D -e -f /dev/null -h hostkey -o ListenAddress=127.0.0.1 -p "$nport" \
	-o AuthorizedKeysFile="$fx/authorized_keys" -o PidFile=none -o AllowAgentForwarding=no > nserver.log 2>&1 &
ndpid=$!
i=0
while ! nc -z 127.0.0.1 "$nport" 2> /dev/null && [ $i -lt 300 ]; do sleep 0.2; i=$((i + 1)); done
# the remote end: the socket it was given, and what OpenSSH's ssh-add finds there
remote='printf "%s\n" "${SSH_AUTH_SOCK:-none}"; ssh-add -l 2>&1 | cut -d" " -f3-'
for case in "xssh x $port -A" "xssh o $xport -A" "ossh x $xport -A" "xssh x $xport -a" "xssh x $nport -A"; do
	set -- $case
	out=$(SSH_AUTH_SOCK=$2.sock $1 -p "$3" $4 "$user@127.0.0.1" "$remote" 2> err)
	sock=$(echo "$out" | sed -n 1p)
	keys=$(echo "$out" | sed -n 2p)
	case "$4:$3" in
	-a:*|*:$nport) [ "$sock" = none ] || fail "forward: $case gave the agent" ;;
	*)	[ "$keys" = "first-key (ED25519)" ] || fail "forward: $case: $out"
		i=0
		while [ "$3" != "$port" ] && [ -e "$sock" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
		[ "$3" = "$port" ] || [ ! -e "$sock" ] || fail "forward: $case left $sock" ;;
	esac
done
kill_tree $xdpid
kill_tree $ndpid
[ $failed = 0 ] && echo "ok: forward"

exit $failed
