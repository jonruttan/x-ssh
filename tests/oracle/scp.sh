#!/bin/sh
# tests/oracle/scp.sh -- x-ssh's scp, both ends, against the system's.
#
# Usage: X=/path/to/x sh tests/oracle/scp.sh DROPBEAR_DIR [PORT]
#
# DROPBEAR_DIR holds a built Dropbear (dropbear, dropbearkey).  Files are
# 300000 random bytes, NULs and all, past every channel window, and each
# copy is checked with cmp.
#
#   up, down   x-ssh's scp to and from a Dropbear, whose remote end is the
#              system's `scp -t` and `scp -f`
#   many       two files into a directory, the remote end told -d
#   times      -p carries the modification time
#   ends       OpenSSH's `scp -O` to and from x-ssh's server, whose PATH
#              finds x-ssh's scp: x-ssh's remote ends, -t and -f, -p keeping
#              the time at the sink
set -u
db=${1:?a built Dropbear directory}
port=${2:-22422}
xport=$((port + 1))
X=${X:-x}
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-scp.XXXXXX")
# The launcher pipes the program into the engine, a child of its own,
# so the server's pid is a shell's: the whole tree under it goes.
kill_tree() {
	for c in $(ps -axo pid,ppid | awk -v p="$1" '$2 == p { print $1 }'); do kill_tree "$c"; done
	kill "$1" 2>/dev/null
}
dbpid=
xpid=
trap 'kill $dbpid 2>/dev/null; kill_tree $xpid; rm -rf "$fx"' EXIT
user=$(id -un)
mkdir -p "$fx/home" "$fx/bin" "$fx/remote" "$fx/local"
"$db/dropbearkey" -t ed25519 -f "$fx/hostkey" > /dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -C x-ssh-scp -f "$fx/userkey"
cp "$fx/userkey.pub" "$fx/authorized_keys"
"$db/dropbear" -D "$fx" -p "127.0.0.1:$port" -r "$fx/hostkey" -F -s > "$fx/dropbear.log" 2>&1 &
dbpid=$!
# the ssh program x-ssh's scp spawns: x-ssh's client, the host accepted
printf '#!/bin/sh\nHOME="%s" exec "%s" -l ssh -- dbclient -y "$@"\n' "$fx/home" "$X" > "$fx/bin/xssh"
# the scp x-ssh's server finds on its PATH
printf '#!/bin/sh\nexec "%s" -l ssh -- scp "$@"\n' "$X" > "$fx/bin/scp"
chmod +x "$fx/bin/xssh" "$fx/bin/scp"
head -c 300000 /dev/urandom > "$fx/a"
head -c 300000 /dev/urandom > "$fx/b"
touch -t 202001020304.05 "$fx/a"
sleep 1
failed=0

fail() {
	echo "FAIL: $1" >&2
	cat "$fx/err" >&2
	failed=1
}

xscp() { "$X" -l ssh -- scp -S "$fx/bin/xssh" -P "$port" -i "$fx/userkey" "$@" < /dev/null 2> "$fx/err"; }

# up
if xscp "$fx/a" "$user@127.0.0.1:$fx/remote/a" && cmp -s "$fx/a" "$fx/remote/a"; then
	echo "ok: up -- a file to a Dropbear arrives whole"
else
	fail "up"
fi

# down
if xscp "$user@127.0.0.1:$fx/remote/a" "$fx/local/a" && cmp -s "$fx/a" "$fx/local/a"; then
	echo "ok: down -- a file from a Dropbear arrives whole"
else
	fail "down"
fi

# many
mkdir -p "$fx/remote/many"
if xscp "$fx/a" "$fx/b" "$user@127.0.0.1:$fx/remote/many" && cmp -s "$fx/a" "$fx/remote/many/a" && cmp -s "$fx/b" "$fx/remote/many/b"; then
	echo "ok: many -- two files into a directory"
else
	fail "many"
fi

# times
if xscp -p "$fx/a" "$user@127.0.0.1:$fx/remote/timed" \
	&& [ "$(stat -f %m "$fx/a" 2>/dev/null || stat -c %Y "$fx/a")" = "$(stat -f %m "$fx/remote/timed" 2>/dev/null || stat -c %Y "$fx/remote/timed")" ]; then
	echo "ok: times -- -p carries the modification time"
else
	fail "times"
fi

# tree: a directory under -r, both ways; without -r it is refused
mkdir -p "$fx/tree/sub/deep"
head -c 50000 /dev/urandom > "$fx/tree/one"
head -c 50000 /dev/urandom > "$fx/tree/sub/two"
head -c 50000 /dev/urandom > "$fx/tree/sub/deep/three"
if xscp -r "$fx/tree" "$user@127.0.0.1:$fx/remote" && diff -r "$fx/tree" "$fx/remote/tree" > /dev/null; then
	echo "ok: tree -- -r sends a directory to a Dropbear whole"
else
	fail "tree up"
fi
if xscp -r "$user@127.0.0.1:$fx/remote/tree" "$fx/local/tree" && diff -r "$fx/tree" "$fx/local/tree" > /dev/null; then
	echo "ok: tree -- -r fetches a directory from a Dropbear whole"
else
	fail "tree down"
fi
if xscp "$fx/tree" "$user@127.0.0.1:$fx/remote/flat"; then
	fail "tree: a directory without -r was accepted"
else
	if grep -q 'not a regular file' "$fx/err" && [ ! -e "$fx/remote/flat" ]; then
		echo "ok: tree -- a directory without -r is refused"
	else
		fail "tree: a directory without -r"
	fi
fi

# ends: x-ssh's server, its PATH finding x-ssh's scp
PATH="$fx/bin:$PATH" "$X" -l ssh -- dropbear -F -E -r "$fx/hostkey" -p "127.0.0.1:$xport" -D "$fx" > "$fx/xserver.log" 2>&1 &
xpid=$!
i=0
while ! grep -q 'Not backgrounding' "$fx/xserver.log" 2>/dev/null; do
	i=$((i + 1)); [ $i -lt 600 ] || break; sleep 1
done
oscp="scp -O -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $xport -i $fx/userkey"
if $oscp "$fx/b" "$user@127.0.0.1:$fx/remote/b-x" 2> "$fx/err" && cmp -s "$fx/b" "$fx/remote/b-x"; then
	echo "ok: ends -- OpenSSH's scp to x-ssh's scp -t"
else
	fail "ends: to x-ssh's scp -t"; tail -5 "$fx/xserver.log" >&2
fi
if $oscp -p "$fx/a" "$user@127.0.0.1:$fx/remote/a-timed" 2> "$fx/err" \
	&& [ "$(stat -f %m "$fx/a" 2>/dev/null || stat -c %Y "$fx/a")" = "$(stat -f %m "$fx/remote/a-timed" 2>/dev/null || stat -c %Y "$fx/remote/a-timed")" ]; then
	echo "ok: ends -- OpenSSH's scp -p to x-ssh's scp -t keeps the modification time"
else
	fail "ends: -p to x-ssh's scp -t"; tail -5 "$fx/xserver.log" >&2
fi
if $oscp "$user@127.0.0.1:$fx/b" "$fx/local/b-x" 2> "$fx/err" && cmp -s "$fx/b" "$fx/local/b-x"; then
	echo "ok: ends -- OpenSSH's scp from x-ssh's scp -f"
else
	fail "ends: from x-ssh's scp -f"; tail -5 "$fx/xserver.log" >&2
fi
if $oscp -r "$fx/tree" "$user@127.0.0.1:$fx/remote/tree-x" 2> "$fx/err" && diff -r "$fx/tree" "$fx/remote/tree-x" > /dev/null; then
	echo "ok: ends -- OpenSSH's scp -r to x-ssh's scp -t"
else
	fail "ends: -r to x-ssh's scp -t"; tail -5 "$fx/xserver.log" >&2
fi
if $oscp -r "$user@127.0.0.1:$fx/tree" "$fx/local/tree-x" 2> "$fx/err" && diff -r "$fx/tree" "$fx/local/tree-x" > /dev/null; then
	echo "ok: ends -- OpenSSH's scp -r from x-ssh's scp -f"
else
	fail "ends: -r from x-ssh's scp -f"; tail -5 "$fx/xserver.log" >&2
fi

exit $failed
