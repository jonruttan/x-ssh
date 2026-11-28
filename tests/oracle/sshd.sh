#!/bin/sh
# tests/oracle/sshd.sh -- x-ssh's client against OpenSSH's server.
#
# Usage: X=/path/to/x sh tests/oracle/sshd.sh [SSHD] [PORT]
#
# SSHD is OpenSSH's server (/usr/sbin/sshd by default), run unprivileged
# on 127.0.0.1:PORT with a configuration of its own: a fresh ssh-ed25519
# host key and user key, the user's public half its authorized_keys.
# Through it, each checked against what OpenSSH says or reads:
#
#   forward  -N -L, a local port carried to the server's own ssh port,
#            read once the server has sent its EXT_INFO and host keys
#            and nothing more
#   sockets  Unix-socket forwards, OpenSSH's streamlocal, each way:
#            -L from a socket here to the server's port, made mode
#            srw------- under StreamLocalBindMask's default; -L from a
#            port here to a socket there; -R from a socket there to the
#            server's port; -R from a port there to a socket here; and
#            -L socket to socket under StreamLocalBindMask 0077, made
#            srwx------
#   taken    a file in a local socket's place: OpenSSH's client's words,
#            the command run all the same; under StreamLocalBindUnlink
#            yes the file removed and the socket made
#   refused  the server refusing a remote socket in a file's place:
#            OpenSSH's client's warning
#   compression  -C: 120000-odd bytes of text and random bytes through
#            cat both ways under zlib@openssh.com, the trace saying so;
#            Compression no leaving it off
#
# A socket stand-in, nc -lU, serves one connection: each is started
# after its listener is found, so the probe does not take it.
set -u
sshd=${1:-/usr/sbin/sshd}
port=${2:-22740}
X=${X:-x}
# a sockaddr_un path holds 104 bytes: the fixture's paths stay short
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-sshd.XXXXXX")
kill_tree() {
	[ -n "${1:-}" ] || return 0
	for c in $(ps -axo pid,ppid | awk -v p="$1" '$2 == p { print $1 }'); do kill_tree "$c"; done
	kill "$1" 2>/dev/null
}
dpid=
cpid=
spid=
trap 'kill $dpid 2>/dev/null; kill_tree $cpid; kill_tree $spid; rm -rf "$fx"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$fx/hostkey"
ssh-keygen -q -t ed25519 -N '' -C x-ssh-sshd -f "$fx/userkey"
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
# launcher's note of a state image written for the fixture's home, or
# OpenSSH's \r: x-ssh ends a line on standard error with \n alone
said() { grep -v -e "^Warning: Permanently added" -e "^x: no current state image" | tr -d "\r"; }
failed=0

fail() {
	echo "FAIL: $1" >&2
	cat "$fx/client.err" >&2
	tail -5 "$fx/sshd.log" >&2
	failed=1
}

waitsock() { i=0; while ! [ -S "$1" ] && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done; }
waitport() { i=0; while ! nc -z 127.0.0.1 "$1" 2>/dev/null && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done; }
# a socket that says hello-unix to the one connection it takes
standin() { rm -f "$1"; ( (printf 'hello-unix\n'; sleep 15) | nc -lU "$1" > /dev/null) & spid=$!; sleep 1; }
# up to 16 bytes from a port or (-U) a socket, the writing side left open
readport() { (sleep 6) | nc -w 4 127.0.0.1 "$1" 2>/dev/null | head -c 16; }
readsock() { (sleep 6) | nc -w 4 -U "$1" 2>/dev/null | head -c 16; }
mode() { ls -l "$1" 2>/dev/null | cut -c1-10; }
done_with() { kill_tree $cpid; cpid=; kill_tree $spid; spid=; }

# forward: -N -L to the server's own port
xssh -N -L "$((port + 1)):127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/client.err" &
cpid=$!
waitport $((port + 1))
got=$(readport $((port + 1)))
done_with
if [ "$got" = "SSH-2.0-OpenSSH_" ]; then
	echo "ok: forward -- -N -L carried to the server's own port"
else
	fail "forward: read '$got'"
fi

# sockets: -L from a socket here
xssh -N -L "$fx/l.sock:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/client.err" &
cpid=$!
waitsock "$fx/l.sock"
got=$(readsock "$fx/l.sock")
m=$(mode "$fx/l.sock")
done_with
if [ "$got" = "SSH-2.0-OpenSSH_" ] && [ "$m" = "srw-------" ]; then
	echo "ok: sockets -- -L from a socket here, made $m"
else
	fail "sockets: -L from a socket read '$got', mode '$m'"
fi

# sockets: -L to a socket there
xssh -N -L "$((port + 2)):$fx/there.sock" 127.0.0.1 < /dev/null 2> "$fx/client.err" &
cpid=$!
waitport $((port + 2))
standin "$fx/there.sock"
got=$(readport $((port + 2)))
done_with
if [ "$got" = "hello-unix" ]; then
	echo "ok: sockets -- -L to a socket there"
else
	fail "sockets: -L to a socket read '$got'"
fi

# sockets: -R from a socket there
xssh -N -R "$fx/r.sock:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/client.err" &
cpid=$!
waitsock "$fx/r.sock"
got=$(readsock "$fx/r.sock")
done_with
if [ "$got" = "SSH-2.0-OpenSSH_" ]; then
	echo "ok: sockets -- -R from a socket there"
else
	fail "sockets: -R from a socket read '$got'"
fi

# sockets: -R to a socket here
xssh -N -R "$((port + 3)):$fx/here.sock" 127.0.0.1 < /dev/null 2> "$fx/client.err" &
cpid=$!
waitport $((port + 3))
standin "$fx/here.sock"
got=$(readport $((port + 3)))
done_with
if [ "$got" = "hello-unix" ]; then
	echo "ok: sockets -- -R to a socket here"
else
	fail "sockets: -R to a socket read '$got'"
fi

# sockets: socket to socket under a mask of 0077
xssh -o StreamLocalBindMask=0077 -N -L "$fx/m.sock:$fx/far.sock" 127.0.0.1 < /dev/null 2> "$fx/client.err" &
cpid=$!
waitsock "$fx/m.sock"
standin "$fx/far.sock"
got=$(readsock "$fx/m.sock")
m=$(mode "$fx/m.sock")
done_with
if [ "$got" = "hello-unix" ] && [ "$m" = "srwx------" ]; then
	echo "ok: sockets -- -L socket to socket, made $m under StreamLocalBindMask 0077"
else
	fail "sockets: socket to socket read '$got', mode '$m'"
fi

# taken: a file in the local socket's place
touch "$fx/taken.sock"
ours=$(xssh -L "$fx/taken.sock:127.0.0.1:$port" 127.0.0.1 'echo ran' < /dev/null 2>&1 | said)
theirs=$(ossh -L "$fx/taken.sock:127.0.0.1:$port" 127.0.0.1 'echo ran' < /dev/null 2>&1 | said)
if [ "$ours" = "$theirs" ] && [ -n "$ours" ]; then
	echo "ok: taken -- a file in the socket's place said as OpenSSH says it"
else
	echo "$ours" > "$fx/client.err"
	fail "taken: x-ssh said the above, OpenSSH '$theirs'"
fi
xssh -o StreamLocalBindUnlink=yes -N -L "$fx/taken.sock:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/client.err" &
cpid=$!
waitsock "$fx/taken.sock"
got=$(readsock "$fx/taken.sock")
done_with
if [ "$got" = "SSH-2.0-OpenSSH_" ]; then
	echo "ok: taken -- StreamLocalBindUnlink yes removes the file and listens"
else
	fail "taken: under StreamLocalBindUnlink read '$got'"
fi

# refused: the server refusing a remote socket
touch "$fx/rtaken.sock"
ours=$(xssh -R "$fx/rtaken.sock:127.0.0.1:$port" 127.0.0.1 'sleep 1; echo ran' < /dev/null 2>&1 | said)
theirs=$(ossh -R "$fx/rtaken.sock:127.0.0.1:$port" 127.0.0.1 'sleep 1; echo ran' < /dev/null 2>&1 | said)
if [ "$ours" = "$theirs" ] && [ -n "$ours" ]; then
	echo "ok: refused -- a remote socket refused said as OpenSSH says it"
else
	echo "$ours" > "$fx/client.err"
	fail "refused: x-ssh said the above, OpenSSH '$theirs'"
fi

# compression: -C against OpenSSH's server, text and random bytes each way
awk 'BEGIN { for (i = 0; i < 20000; i++) printf "line %d of the compressed text\n", i }' > "$fx/z.in"
head -c 100000 /dev/urandom >> "$fx/z.in"
want=$(cksum < "$fx/z.in")
got=$(xssh -v -C 127.0.0.1 cat < "$fx/z.in" 2> "$fx/client.err" | cksum)
if [ "$got" = "$want" ] && grep -q "compression zlib@openssh.com in, zlib@openssh.com out" "$fx/client.err"; then
	echo "ok: compression -- -C carries $(wc -c < "$fx/z.in" | tr -d ' ') bytes both ways under zlib@openssh.com"
else
	fail "compression: cksum '$got', wanted '$want'"
fi
got=$(xssh -o Compression=no -v 127.0.0.1 echo plain < /dev/null 2> "$fx/client.err")
if [ "$got" = "plain" ] && ! grep -q "compression zlib" "$fx/client.err"; then
	echo "ok: compression -- Compression no leaves it off"
else
	fail "compression: Compression no read '$got'"
fi

exit $failed
