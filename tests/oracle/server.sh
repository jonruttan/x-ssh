#!/bin/sh
# tests/oracle/server.sh -- x-ssh's sshd, driven by Dropbear's client and
# OpenSSH's.
#
# Usage: X=/path/to/x sh tests/oracle/server.sh DROPBEAR_DIR [PORT]
#
# DROPBEAR_DIR holds a built Dropbear (dbclient, dropbearkey).  A fixture
# is made in a scratch directory: a host key and a Dropbear user key from
# dropbearkey, an OpenSSH user key from ssh-keygen, and both users' public
# lines as the AuthorizedKeysFile the server is given.  The x-ssh server
# is started on 127.0.0.1:PORT, in the foreground with its log on
# standard error, and through it:
#
#   dbclient  `echo hi from the x-ssh server; exit 3`: output and status
#   ssh       the same through OpenSSH's client, which asks whether a
#             key would do before it signs, and sends requests the
#             server declines; the log says so in OpenSSH's words
#   x-ssh     x-ssh's own client, with the Dropbear-format key
#   refused   a key not in authorized_keys is refused
#   input     200000 random bytes through `cksum` on the server's side
#   terminal  OpenSSH's -tt and x-ssh's RequestTTY force get a terminal, its
#             window and TERM; x-ssh at a terminal under expect (shell.exp):
#             a shell, a resize, its exit status, and the ~. escape
#   env       OpenSSH's SetEnv and x-ssh's SendEnv reach the command for
#             a variable AcceptEnv takes, and not for one it does not
#   git       `git clone` over OpenSSH's client from the server's
#             git-upload-pack: the clone's HEAD and its fsck
#   forward   a client's -L served as direct-tcpip channels to the server's
#             own ssh port: x-ssh's client (two connections) and OpenSSH's
#   remote    a client's -R listened for by the server, its connections opened
#             to the client and carried to the server's own ssh port: x-ssh's
#             client (two connections) and OpenSSH's
#   stdio     x-ssh's client's -W through the server to its own ssh port
#   clocks    a client asking a keepalive each second the server answers, a
#             client ending on its own ChannelTimeout, and a server with a
#             ChannelTimeout closing an idle client
#   test      -t passes a sound configuration and refuses AllowUsers
#   sealed    a host key under a passphrase refused as OpenSSH's sshd refuses
#             it (sshd -t, beside the system's /usr/sbin/sshd)
#   background  ssh-keygen -A makes the host key; a server started without
#             -D returns at once, writes its PidFile and serves dbclient
#
# The clients, git and the system's sshd are the oracles.
set -u
db=${1:?a built Dropbear directory}
port=${2:-22322}
X=${X:-x}
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-server.XXXXXX")
# The launcher pipes the program into the engine, a child of its own,
# so the server's pid is a shell's: the whole tree under it goes.
kill_tree() {
	[ -n "${1:-}" ] || return 0
	for c in $(ps -axo pid,ppid | awk -v p="$1" '$2 == p { print $1 }'); do kill_tree "$c"; done
	kill "$1" 2>/dev/null
}
srvpid=
bgpid=
fwdpid=
trap 'kill_tree $srvpid; kill_tree $fwdpid; kill $bgpid 2>/dev/null; rm -rf "$fx"' EXIT
"$db/dropbearkey" -t ed25519 -f "$fx/hostkey" > /dev/null 2>&1
"$db/dropbearkey" -t ed25519 -f "$fx/dbkey" > /dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -C x-ssh-server -f "$fx/osshkey"
ssh-keygen -q -t ed25519 -N '' -C stranger -f "$fx/stranger"
"$db/dropbearkey" -y -f "$fx/dbkey" 2>/dev/null | grep '^ssh-ed25519 ' > "$fx/authorized_keys"
cat "$fx/osshkey.pub" >> "$fx/authorized_keys"
user=$(id -un)
# the server's options: its own configuration, none of the system's
sshd() {
	"$X" -l ssh -- sshd -f /dev/null -h "$fx/hostkey" -o ListenAddress=127.0.0.1 \
		-o AuthorizedKeysFile="$fx/authorized_keys" -o PidFile=none -o PasswordAuthentication=no "$@"
}
started() {
	i=0
	while ! grep -q "Server listening on 127.0.0.1 port $2." "$1" 2>/dev/null; do
		i=$((i + 1))
		[ $i -lt 600 ] || { echo "FAIL: the server did not start" >&2; cat "$1" >&2; exit 1; }
		sleep 1
	done
}
SHELL=/bin/sh sshd -D -e -p "$port" -o LogLevel=DEBUG1 -o AcceptEnv='XSSH_*' > "$fx/server.log" 2>&1 &
srvpid=$!
# the listener builds the curves' engines before it listens
started "$fx/server.log" "$port"
# x-ssh's client's home, for its known_hosts
mkdir -p "$fx/home"
ossh="ssh -q -F none -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $port"
xssh() { HOME="$fx/home" "$X" -l ssh -- ssh -F none -o StrictHostKeyChecking=accept-new -q -p "$port" -i "$fx/dbkey" -l "$user" "$@"; }
failed=0

fail() {
	echo "FAIL: $1" >&2
	cat "$fx/client.err" >&2
	tail -8 "$fx/server.log" >&2
	failed=1
}

# dbclient
out=$("$db/dbclient" -y -y -p "$port" -i "$fx/dbkey" "$user@127.0.0.1" 'echo hi from the x-ssh server; exit 3' < /dev/null 2> "$fx/client.err")
status=$?
if [ "$out" = "hi from the x-ssh server" ] && [ "$status" = 3 ]; then
	echo "ok: dbclient -- output and exit status from the x-ssh server"
else
	fail "dbclient: output '$out' status $status"
fi

# ssh
out=$($ossh -i "$fx/osshkey" "$user@127.0.0.1" 'echo hi from the x-ssh server; exit 3' < /dev/null 2> "$fx/client.err")
status=$?
fp=$(ssh-keygen -l -f "$fx/osshkey" | cut -d' ' -f2)
if [ "$out" = "hi from the x-ssh server" ] && [ "$status" = 3 ] \
	&& grep -q "Accepted publickey for $user from 127.0.0.1 port [0-9]* ssh2: ED25519 $fp" "$fx/server.log"; then
	echo "ok: ssh -- OpenSSH's client too, and the log says so as OpenSSH's sshd would"
else
	fail "ssh: output '$out' status $status"
fi

# x-ssh, both ends: x-ssh's own client against its own server
out=$(xssh 127.0.0.1 'echo both ends in x; exit 4' < /dev/null 2> "$fx/client.err")
status=$?
if [ "$out" = "both ends in x" ] && [ "$status" = 4 ]; then
	echo "ok: x-ssh -- its own client against its own server"
else
	fail "x-ssh: output '$out' status $status"
fi

# refused
$ossh -i "$fx/stranger" "$user@127.0.0.1" true < /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ]; then
	echo "ok: refused -- a key not in authorized_keys is turned away"
else
	fail "refused: a stranger's key gave status $status"
fi

# input
head -c 200000 /dev/urandom > "$fx/input"
want=$(cksum < "$fx/input")
got=$("$db/dbclient" -y -y -p "$port" -i "$fx/dbkey" "$user@127.0.0.1" cksum < "$fx/input" 2> "$fx/client.err")
if [ "$got" = "$want" ]; then
	echo "ok: input -- 200000 bytes reach the command whole ($want)"
else
	fail "input: the server side's cksum '$got', the client side's '$want'"
fi

# env: AcceptEnv XSSH_* takes OpenSSH's SetEnv and x-ssh's SendEnv, and
# leaves a variable it does not name behind
out=$($ossh -i "$fx/osshkey" -o SetEnv="XSSH_ONE=from-openssh OTHER_ONE=kept-out" "$user@127.0.0.1" 'echo "$XSSH_ONE/${OTHER_ONE:-none}"' < /dev/null 2> "$fx/client.err")
out2=$(XSSH_TWO=from-x-ssh xssh -o SendEnv=XSSH_TWO 127.0.0.1 'echo "$XSSH_TWO"' < /dev/null 2> "$fx/client.err")
if [ "$out" = "from-openssh/none" ] && [ "$out2" = "from-x-ssh" ]; then
	echo "ok: env -- AcceptEnv takes what it names from either client, and nothing else"
else
	fail "env: OpenSSH's '$out', x-ssh's '$out2'"
fi

# terminal: OpenSSH's -tt gets a terminal on the server, TERM carried;
# x-ssh's RequestTTY force sends its window, from COLUMNS and LINES where
# standard input is no terminal; and x-ssh at a terminal (expect): a
# shell, its window and a resize, its exit status, and ~.
out=$(TERM=xterm-x-ssh $ossh -tt -i "$fx/osshkey" "$user@127.0.0.1" 'tty; echo "term=$TERM"' < /dev/null 2> "$fx/client.err" | tr -d '\r')
out2=$(env COLUMNS=101 LINES=33 TERM=xterm-x-ssh HOME="$fx/home" "$X" -l ssh -- ssh -F none -o StrictHostKeyChecking=accept-new -q -p "$port" -i "$fx/dbkey" -l "$user" \
	-o RequestTTY=force 127.0.0.1 'stty size; echo "term=$TERM"' < /dev/null 2> "$fx/client.err" | tr -d '\r')
if printf '%s\n' "$out" | grep -q '^/dev/' && printf '%s\n' "$out" | grep -qx 'term=xterm-x-ssh' \
	&& printf '%s\n' "$out2" | grep -qx '33 101' && printf '%s\n' "$out2" | grep -qx 'term=xterm-x-ssh'; then
	echo "ok: terminal -- OpenSSH's -tt and x-ssh's RequestTTY force get a terminal, window and TERM"
else
	fail "terminal: OpenSSH's '$out', x-ssh's '$out2'"
fi
if expect "$(dirname "$0")/shell.exp" "$port" "$fx/dbkey" "$user" "$fx/home" > "$fx/shell.out" 2>&1 && grep -qx ok "$fx/shell.out"; then
	echo "ok: shell -- x-ssh at a terminal: a shell, its window and a resize, its exit status, and ~."
else
	fail "shell: $(cat "$fx/shell.out")"
fi

# git
src="$fx/src.git"
git init -q --bare "$src"
git init -q "$fx/work"
( cd "$fx/work" && printf 'one\n' > a && git add a \
	&& git -c user.name=o -c user.email=o@o commit -q -m first \
	&& printf 'two\n' >> a && git -c user.name=o -c user.email=o@o commit -q -am second \
	&& git push -q "$src" HEAD:refs/heads/main )
GIT_SSH_COMMAND="$ossh -i $fx/osshkey" git clone -q -b main "ssh://$user@127.0.0.1$src" "$fx/dst" 2> "$fx/client.err"
want=$(git -C "$src" rev-parse main)
got=$(git -C "$fx/dst" rev-parse HEAD 2>/dev/null)
if [ "$got" = "$want" ] && git -C "$fx/dst" fsck --no-progress > /dev/null 2>> "$fx/client.err"; then
	echo "ok: git -- a clone from the x-ssh server has $want and checks clean"
else
	fail "git: the clone's HEAD '$got', the repository's '$want'"
fi

# forward: a client's -L served as direct-tcpip channels, to the server's
# own ssh port: x-ssh's client, then OpenSSH's, two connections each
fport=$((port + 10))
xssh -N -L "$fport:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" &
fwdpid=$!
i=0
while ! nc -z 127.0.0.1 "$fport" 2>/dev/null && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done
one=$(nc -w 15 127.0.0.1 "$fport" < /dev/null 2>/dev/null | head -c 13)
two=$(nc -w 15 127.0.0.1 "$fport" < /dev/null 2>/dev/null | head -c 13)
kill_tree $fwdpid
fwdpid=
if [ "$one" = "SSH-2.0-x-ssh" ] && [ "$two" = "SSH-2.0-x-ssh" ]; then
	echo "ok: forward -- x-ssh's -L is served through the x-ssh server, two connections in turn"
else
	fail "forward: x-ssh's client read '$one' then '$two'"; cat "$fx/fwd.err" >&2
fi
oport=$((port + 11))
$ossh -i "$fx/osshkey" -N -L "$oport:127.0.0.1:$port" "$user@127.0.0.1" < /dev/null 2> "$fx/fwd.err" &
fwdpid=$!
i=0
while ! nc -z 127.0.0.1 "$oport" 2>/dev/null && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done
one=$(nc -w 15 127.0.0.1 "$oport" < /dev/null 2>/dev/null | head -c 13)
kill $fwdpid 2>/dev/null
fwdpid=
if [ "$one" = "SSH-2.0-x-ssh" ]; then
	echo "ok: forward -- OpenSSH's -L is served through the x-ssh server"
else
	fail "forward: OpenSSH's client read '$one'"; cat "$fx/fwd.err" >&2
fi

# remote: a client's -R listened for by the x-ssh server, its connections
# opened to the client and carried to the server's own ssh port: x-ssh's
# client, then OpenSSH's
rport=$((port + 20))
xssh -N -R "$rport:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" &
fwdpid=$!
i=0
while [ "$(grep -c "remote forward on" "$fx/server.log")" -lt 1 ] && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done
one=$(nc -w 15 127.0.0.1 "$rport" < /dev/null 2>/dev/null | head -c 13)
two=$(nc -w 15 127.0.0.1 "$rport" < /dev/null 2>/dev/null | head -c 13)
kill_tree $fwdpid
fwdpid=
if [ "$one" = "SSH-2.0-x-ssh" ] && [ "$two" = "SSH-2.0-x-ssh" ]; then
	echo "ok: remote -- x-ssh's -R is listened for by the x-ssh server, two connections in turn"
else
	fail "remote: x-ssh's client read '$one' then '$two'"; cat "$fx/fwd.err" >&2; tail -5 "$fx/server.log" >&2
fi
oport=$((port + 21))
$ossh -i "$fx/osshkey" -N -R "$oport:127.0.0.1:$port" "$user@127.0.0.1" < /dev/null 2> "$fx/fwd.err" &
fwdpid=$!
i=0
while [ "$(grep -c "remote forward on" "$fx/server.log")" -lt 2 ] && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done
one=$(nc -w 15 127.0.0.1 "$oport" < /dev/null 2>/dev/null | head -c 13)
kill $fwdpid 2>/dev/null
fwdpid=
if [ "$one" = "SSH-2.0-x-ssh" ]; then
	echo "ok: remote -- OpenSSH's -R is listened for by the x-ssh server"
else
	fail "remote: OpenSSH's client read '$one'"; cat "$fx/fwd.err" >&2; tail -5 "$fx/server.log" >&2
fi

# stdio: x-ssh's client's -W through the x-ssh server to its own ssh port
out=$(xssh -W "127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" | head -c 13)
if [ "$out" = "SSH-2.0-x-ssh" ]; then
	echo "ok: stdio -- -W through the x-ssh server carries its own version line"
else
	fail "stdio: read '$out'"
	cat "$fx/fwd.err" >&2; tail -5 "$fx/server.log" >&2
fi

# clocks: x-ssh's client kept alive by keepalives the x-ssh server
# answers, then ending on its own ChannelTimeout; and a server with a
# ChannelTimeout closing an idle Dropbear client
xssh -N -o ServerAliveInterval=1 127.0.0.1 < /dev/null > /dev/null 2> "$fx/fwd.err" &
fwdpid=$!
sleep 12
if kill -0 $fwdpid 2>/dev/null; then
	echo "ok: clocks -- a client asking a keepalive each second is still up after 12s"
else
	fail "clocks: the ServerAliveInterval 1 client is gone"; cat "$fx/fwd.err" >&2
fi
kill_tree $fwdpid
fwdpid=
start=$(date +%s)
xssh -N -o ChannelTimeout=global=2 127.0.0.1 < /dev/null > /dev/null 2> "$fx/fwd.err"
status=$?
took=$(( $(date +%s) - start ))
if [ "$status" = 255 ] && [ $took -lt 40 ] && grep -q 'ChannelTimeout' "$fx/fwd.err"; then
	echo "ok: clocks -- ChannelTimeout ends the connection on the client's clock (${took}s)"
else
	fail "clocks: ChannelTimeout client status $status after ${took}s"; cat "$fx/fwd.err" >&2
fi
iport=$((port + 30))
sshd -D -e -p "$iport" -o ChannelTimeout=global=2 > "$fx/idle.log" 2>&1 &
idlepid=$!
started "$fx/idle.log" "$iport"
start=$(date +%s)
"$db/dbclient" -y -y -p "$iport" -i "$fx/dbkey" -N "$user@127.0.0.1" < /dev/null > /dev/null 2> "$fx/client.err"
took=$(( $(date +%s) - start ))
kill_tree $idlepid
if [ $took -lt 40 ] && grep -q 'idle past ChannelTimeout' "$fx/idle.log"; then
	echo "ok: clocks -- a server with a ChannelTimeout closes an idle client (${took}s)"
else
	fail "clocks: the ChannelTimeout server kept the client ${took}s"; cat "$fx/idle.log" >&2
fi

# test: -t passes this configuration, and refuses one with AllowUsers
sshd -t > "$fx/test.out" 2>&1
good=$?
sshd -t -o AllowUsers="$user" > "$fx/test.bad" 2>&1
bad=$?
if [ "$good" = 0 ] && [ "$bad" = 255 ] && grep -q 'allowusers is not served' "$fx/test.bad"; then
	echo "ok: test -- -t passes a sound configuration and refuses AllowUsers"
else
	fail "test: -t gave $good, with AllowUsers $bad"; cat "$fx/test.out" "$fx/test.bad" >&2
fi

# sealed: a host key under a passphrase refused as OpenSSH's sshd refuses
# it, in its words and with its status (its log ends a line CR LF on
# standard error, x-ssh's LF)
ssh-keygen -q -t ed25519 -N 'host sealed' -f "$fx/sealedhost"
"$X" -l ssh -- sshd -t -f /dev/null -h "$fx/sealedhost" > "$fx/sealed.ours" 2>&1; s=$?
ours="$(tr -d '\r' < "$fx/sealed.ours") status $s"
/usr/sbin/sshd -t -f /dev/null -h "$fx/sealedhost" > "$fx/sealed.theirs" 2>&1; s=$?
theirs="$(tr -d '\r' < "$fx/sealed.theirs") status $s"
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: sealed -- a host key under a passphrase is refused as OpenSSH's sshd refuses it"
else
	fail "sealed: x-ssh said '$ours', OpenSSH '$theirs'"
fi

# background: ssh-keygen -A making the host key under a prefix, a server
# without -D returning at once with its PidFile written, serving dbclient
bport=$((port + 1))
mkdir -p "$fx/root/etc/ssh"
"$X" -l ssh -- ssh-keygen -A -f "$fx/root" > "$fx/keygen.out" 2>&1
"$X" -l ssh -- sshd -f /dev/null -h "$fx/root/etc/ssh/ssh_host_ed25519_key" -o ListenAddress=127.0.0.1 -p "$bport" \
	-o AuthorizedKeysFile="$fx/authorized_keys" -o PidFile="$fx/pid" > "$fx/bg.log" 2>&1
status=$?
i=0
while [ ! -s "$fx/pid" ] && [ $i -lt 600 ]; do i=$((i + 1)); sleep 1; done
bgpid=$(cat "$fx/pid" 2>/dev/null)
out=$("$db/dbclient" -y -y -p "$bport" -i "$fx/dbkey" "$user@127.0.0.1" 'echo from the background; exit 5' < /dev/null 2> "$fx/client.err")
bstatus=$?
if [ "$status" = 0 ] && [ -n "$bgpid" ] && [ "$out" = "from the background" ] && [ "$bstatus" = 5 ] \
	&& grep -q 'ssh-keygen: generating new host keys: ED25519' "$fx/keygen.out" \
	&& ssh-keygen -l -f "$fx/root/etc/ssh/ssh_host_ed25519_key" > /dev/null 2>&1; then
	echo "ok: background -- ssh-keygen -A made the key; the server returned at once, wrote its pid and served"
else
	fail "background: status $status, pid '$bgpid', output '$out' status $bstatus"
	cat "$fx/keygen.out" "$fx/bg.log" >&2
fi
kill $bgpid 2>/dev/null

echo "--- the server's log"
cat "$fx/server.log"
exit $failed
