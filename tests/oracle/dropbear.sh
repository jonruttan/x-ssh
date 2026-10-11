#!/bin/sh
# tests/oracle/dropbear.sh -- x-ssh's client against a Dropbear.
#
# Usage: X=/path/to/x sh tests/oracle/dropbear.sh DROPBEAR_DIR [PORT]
#
# DROPBEAR_DIR holds a built Dropbear (dropbear, dropbearkey).  A fixture
# is made in a scratch directory: an ssh-ed25519 host key, an ssh-ed25519
# user key (ssh-keygen), its public half as authorized_keys.  A non-root
# Dropbear is started on 127.0.0.1:PORT for the run, and three things are
# done through it, each checked against what the system's own tools say:
#
#   exec    `echo hi from x-ssh; exit 3` with -y: the output and the exit
#           status, and the host's key recorded in known_hosts;
#           the client's -v trace printed after (CPU milliseconds a step)
#   input   200000 random bytes on the client's standard input, past
#           Dropbear's 24 KB window, through `cksum` on the far side
#   hosts   without -y, a host not in known_hosts and a host whose key
#           has changed are refused, status 255, before authentication
#   git     `git clone` of a repository behind the Dropbear, with x-ssh
#           as git's ssh: the clone's HEAD and its fsck
#
# Dropbear and git are the oracles; this is the live test the specs
# cannot replay, since every exchange has fresh ephemeral keys.
set -u
db=${1:?a built Dropbear directory}
port=${2:-22222}
X=${X:-x}
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-oracle.XXXXXX")
dbpid=
trap 'kill $dbpid 2>/dev/null; rm -rf "$fx"' EXIT
"$db/dropbearkey" -t ed25519 -f "$fx/hostkey" > /dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -C x-ssh-oracle -f "$fx/userkey"
cp "$fx/userkey.pub" "$fx/authorized_keys"
"$db/dropbear" -D "$fx" -p "127.0.0.1:$port" -r "$fx/hostkey" -F -s > "$fx/dropbear.log" 2>&1 &
dbpid=$!
sleep 1
user=$(id -un)
# the clients' home, for known_hosts
home="$fx/home"
mkdir -p "$home"
failed=0

fail() {
	echo "FAIL: $1" >&2
	cat "$fx/client.err" >&2
	tail -5 "$fx/dropbear.log" >&2
	failed=1
}

# exec, the host unknown and accepted with -y: its key must land in
# known_hosts as Dropbear's own hostkey.pub spells it
out=$(HOME="$home" "$X" -l ssh -- dbclient -y -v -p "$port" -i "$fx/userkey" -l "$user" 127.0.0.1 'echo hi from x-ssh; exit 3' < /dev/null 2> "$fx/client.err")
status=$?
key=$(cut -d' ' -f2 "$fx/hostkey.pub")
line=$(cat "$home/.ssh/known_hosts" 2>/dev/null)
if [ "$out" = "hi from x-ssh" ] && [ "$status" = 3 ] && [ "$line" = "[127.0.0.1]:$port ssh-ed25519 $key" ]; then
	echo "ok: exec -- output and exit status through Dropbear, the host's key recorded"
	cat "$fx/client.err"
else
	fail "exec: output '$out' status $status known_hosts '$line'"
fi

# hosts: an unknown host refused without -y, then a changed key refused
HOME="$fx/nobody" "$X" -l ssh -- dbclient -p "$port" -i "$fx/userkey" -l "$user" 127.0.0.1 true < /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ] && grep -q 'not in known_hosts' "$fx/client.err"; then
	echo "ok: hosts -- an unknown host is refused without -y"
else
	fail "hosts: an unknown host gave status $status"
fi
mkdir -p "$fx/changed/.ssh"
printf '[127.0.0.1]:%s ssh-ed25519 %s\n' "$port" "$(cut -d' ' -f2 "$fx/userkey.pub")" > "$fx/changed/.ssh/known_hosts"
HOME="$fx/changed" "$X" -l ssh -- dbclient -y -p "$port" -i "$fx/userkey" -l "$user" 127.0.0.1 true < /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ] && grep -q 'differs' "$fx/client.err"; then
	echo "ok: hosts -- a changed key is refused, -y or not"
else
	fail "hosts: a changed key gave status $status"
fi

# input
head -c 200000 /dev/urandom > "$fx/input"
want=$(cksum < "$fx/input")
got=$(HOME="$home" "$X" -l ssh -- dbclient -p "$port" -i "$fx/userkey" -l "$user" 127.0.0.1 cksum < "$fx/input" 2> "$fx/client.err")
if [ "$got" = "$want" ]; then
	echo "ok: input -- 200000 bytes of standard input arrive whole ($want)"
else
	fail "input: the far side's cksum '$got', the near side's '$want'"
fi

# git
src="$fx/src.git"
git init -q --bare "$src"
git init -q "$fx/work"
( cd "$fx/work" && printf 'one\n' > a && mkdir -p d && printf 'two\n' > d/b \
	&& git add a d && git -c user.name=o -c user.email=o@o commit -q -m first \
	&& printf 'three\n' >> a && git -c user.name=o -c user.email=o@o commit -q -am second \
	&& git push -q "$src" HEAD:refs/heads/main )
printf '#!/bin/sh\nHOME="%s" exec "%s" -l ssh -- dbclient -p %s -i "%s" -l %s "$@"\n' "$home" "$X" "$port" "$fx/userkey" "$user" > "$fx/ssh"
chmod +x "$fx/ssh"
GIT_SSH="$fx/ssh" GIT_SSH_VARIANT=simple git clone -q -b main "ssh://127.0.0.1$src" "$fx/dst" 2> "$fx/client.err"
want=$(git -C "$src" rev-parse main)
got=$(git -C "$fx/dst" rev-parse HEAD 2>/dev/null)
if [ "$got" = "$want" ] && git -C "$fx/dst" fsck --no-progress > /dev/null 2>> "$fx/client.err"; then
	echo "ok: git -- a clone through x-ssh has $want and checks clean"
else
	fail "git: the clone's HEAD '$got', the repository's '$want'"
fi

exit $failed
