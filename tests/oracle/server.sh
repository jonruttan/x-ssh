#!/bin/sh
# tests/oracle/server.sh -- x-ssh's server, driven by Dropbear's client
# and OpenSSH's.
#
# Usage: X=/path/to/x sh tests/oracle/server.sh DROPBEAR_DIR [PORT]
#
# DROPBEAR_DIR holds a built Dropbear (dbclient, dropbearkey).  A fixture
# is made in a scratch directory: a host key and a Dropbear user key from
# dropbearkey, an OpenSSH user key from ssh-keygen, and both users' public
# lines as the authorized_keys the server is pointed at with -D.  The
# x-ssh server is started on 127.0.0.1:PORT, and through it:
#
#   dbclient  `echo hi from the x-ssh server; exit 3`: output and status
#   ssh       the same through OpenSSH's client, which asks whether a
#             key would do before it signs, and sends requests the
#             server declines
#   x-ssh     x-ssh's own client, with the Dropbear-format key
#   refused   a key not in authorized_keys is refused
#   input     200000 random bytes through `cksum` on the server's side
#   git       `git clone` over OpenSSH's client from the server's
#             git-upload-pack: the clone's HEAD and its fsck
#
# The clients and git are the oracles.
set -u
db=${1:?a built Dropbear directory}
port=${2:-22322}
X=${X:-x}
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-server.XXXXXX")
srvpid=
trap 'kill $srvpid 2>/dev/null; rm -rf "$fx"' EXIT
"$db/dropbearkey" -t ed25519 -f "$fx/hostkey" > /dev/null 2>&1
"$db/dropbearkey" -t ed25519 -f "$fx/dbkey" > /dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -C x-ssh-server -f "$fx/osshkey"
ssh-keygen -q -t ed25519 -N '' -C stranger -f "$fx/stranger"
"$db/dropbearkey" -y -f "$fx/dbkey" 2>/dev/null | grep '^ssh-ed25519 ' > "$fx/authorized_keys"
cat "$fx/osshkey.pub" >> "$fx/authorized_keys"
"$X" -l ssh -- dropbear -F -E -r "$fx/hostkey" -p "127.0.0.1:$port" -D "$fx" > "$fx/server.log" 2>&1 &
srvpid=$!
# the listener builds the curves' engines before it listens
i=0
while ! grep -q 'Not backgrounding' "$fx/server.log" 2>/dev/null; do
	i=$((i + 1))
	[ $i -lt 600 ] || { echo "FAIL: the server did not start" >&2; cat "$fx/server.log" >&2; exit 1; }
	sleep 1
done
user=$(id -un)
# x-ssh's client's home, for its known_hosts
mkdir -p "$fx/home"
mkdir -p "$fx/home"
ossh="ssh -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $port"
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
if [ "$out" = "hi from the x-ssh server" ] && [ "$status" = 3 ]; then
	echo "ok: ssh -- OpenSSH's client too"
else
	fail "ssh: output '$out' status $status"
fi

# x-ssh, both ends: x-ssh's own client against its own server
out=$(HOME="$fx/home" "$X" -l ssh -- dbclient -y -p "$port" -i "$fx/dbkey" -l "$user" 127.0.0.1 'echo both ends in x; exit 4' < /dev/null 2> "$fx/client.err")
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

echo "--- the server's log"
cat "$fx/server.log"
exit $failed
