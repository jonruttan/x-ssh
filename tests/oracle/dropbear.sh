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
#   keys    a key x-ssh's dropbearkey makes is read by Dropbear's with
#           the same fingerprint, x-ssh shows Dropbear's key as it does,
#           and the made key, in Dropbear's format, authenticates the client
#   convert dropbearconvert each way: ssh-keygen reads the OpenSSH file
#           x-ssh wrote from Dropbear's host key, dropbearkey reads the
#           Dropbear file x-ssh wrote from ssh-keygen's user key
#   forward -N -L: a local port carried through the Dropbear to its own
#           ssh port, two connections in turn reading its version line
#   remote  -N -R: the Dropbear listens, its connections come here and
#           reach its own ssh port, two in turn reading its version line
#   netcat  -B: the Dropbear's own version line carried to standard output
#   idle    -N -I 2 ends on the client's own clock
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
# The launcher pipes the program into the engine, a child of its own,
# so a client's pid is a shell's: the whole tree under it goes.
kill_tree() {
	for c in $(ps -axo pid,ppid | awk -v p="$1" '$2 == p { print $1 }'); do kill_tree "$c"; done
	kill "$1" 2>/dev/null
}
dbpid=
fwdpid=
trap 'kill $dbpid 2>/dev/null; kill_tree $fwdpid; rm -rf "$fx"' EXIT
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

# keys: a key x-ssh makes is one Dropbear reads, with the fingerprint
# x-ssh printed; x-ssh shows Dropbear's own key as dropbearkey -y does;
# and the key it made authenticates its client, read in Dropbear's format
"$X" -l ssh -- dropbearkey -t ed25519 -f "$fx/xkey" > "$fx/xkey.out" 2> "$fx/client.err"
status=$?
ours=$(tail -1 "$fx/xkey.out")
theirs=$("$db/dropbearkey" -y -f "$fx/xkey" 2>> "$fx/client.err" | tail -1)
publine=$(cut -d' ' -f1-2 "$fx/xkey.pub" 2>/dev/null)
theirline=$("$db/dropbearkey" -y -f "$fx/xkey" 2>/dev/null | sed -n 2p | cut -d' ' -f1-2)
if [ "$status" = 0 ] && [ -n "$ours" ] && [ "$ours" = "$theirs" ] && [ "$publine" = "$theirline" ]; then
	echo "ok: keys -- dropbearkey reads the key x-ssh made: $theirs"
else
	fail "keys: status $status, x-ssh '$ours', dropbearkey '$theirs', .pub '$publine'"
fi
ours=$("$X" -l ssh -- dropbearkey -y -f "$fx/hostkey" 2> "$fx/client.err" | sed -n '2p;3p' | cut -d' ' -f1-2)
theirs=$("$db/dropbearkey" -y -f "$fx/hostkey" 2>/dev/null | sed -n '2p;3p' | cut -d' ' -f1-2)
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: keys -- x-ssh shows Dropbear's key as dropbearkey -y does"
else
	fail "keys: x-ssh shows '$ours', dropbearkey '$theirs'"
fi
cat "$fx/xkey.pub" >> "$fx/authorized_keys"
out=$(HOME="$home" "$X" -l ssh -- dbclient -p "$port" -i "$fx/xkey" -l "$user" 127.0.0.1 'echo made here' < /dev/null 2> "$fx/client.err")
if [ "$out" = "made here" ]; then
	echo "ok: keys -- the key x-ssh made authenticates it"
else
	fail "keys: a client with the key x-ssh made said '$out'"
fi

# convert: each way, the other side's tool reading what x-ssh wrote
"$X" -l ssh -- dropbearconvert dropbear openssh "$fx/hostkey" "$fx/host.ossh" > /dev/null 2> "$fx/client.err"
status=$?
ours=$(ssh-keygen -y -f "$fx/host.ossh" 2>> "$fx/client.err" | cut -d' ' -f1-2)
theirs=$("$db/dropbearkey" -y -f "$fx/hostkey" 2>/dev/null | sed -n 2p | cut -d' ' -f1-2)
if [ "$status" = 0 ] && grep -q "Wrote key to '$fx/host.ossh'" "$fx/client.err" && [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: convert -- ssh-keygen reads the OpenSSH file x-ssh wrote from Dropbear's key"
else
	fail "convert: dropbear to openssh status $status, ssh-keygen '$ours', dropbearkey '$theirs'"
fi
"$X" -l ssh -- dropbearconvert openssh dropbear "$fx/userkey" "$fx/user.db" > /dev/null 2> "$fx/client.err"
status=$?
ours=$("$db/dropbearkey" -y -f "$fx/user.db" 2>> "$fx/client.err" | sed -n 2p | cut -d' ' -f1-2)
theirs=$(ssh-keygen -y -f "$fx/userkey" 2>/dev/null | cut -d' ' -f1-2)
if [ "$status" = 0 ] && [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: convert -- dropbearkey reads the Dropbear file x-ssh wrote from ssh-keygen's key"
else
	fail "convert: openssh to dropbear status $status, dropbearkey '$ours', ssh-keygen '$theirs'"
fi

# forward: -N -L, a local port carried through the Dropbear to its own
# ssh port: each connection reads the server's version line, two in turn
fport=$((port + 10))
HOME="$home" "$X" -l ssh -- dbclient -p "$port" -i "$fx/userkey" -l "$user" -N -L "$fport:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" &
fwdpid=$!
i=0
while ! nc -z 127.0.0.1 "$fport" 2>/dev/null && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done
one=$(nc -w 3 127.0.0.1 "$fport" < /dev/null 2>/dev/null | head -c 16)
two=$(nc -w 3 127.0.0.1 "$fport" < /dev/null 2>/dev/null | head -c 16)
kill_tree $fwdpid
fwdpid=
if [ "$one" = "SSH-2.0-dropbear" ] && [ "$two" = "SSH-2.0-dropbear" ]; then
	echo "ok: forward -- -L carries two connections in turn through the Dropbear"
else
	fail "forward: read '$one' then '$two' through the forwarded port"
	cat "$fx/fwd.err" >&2
fi

# remote: -N -R, the Dropbear listening for a port whose connections come
# here and go to its own ssh port, two in turn reading its version line
rport=$((port + 20))
HOME="$home" "$X" -l ssh -- dbclient -p "$port" -i "$fx/userkey" -l "$user" -N -R "$rport:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" &
fwdpid=$!
i=0
while ! nc -z 127.0.0.1 "$rport" 2>/dev/null && [ $i -lt 60 ]; do i=$((i + 1)); sleep 1; done
one=$(nc -w 3 127.0.0.1 "$rport" < /dev/null 2>/dev/null | head -c 16)
two=$(nc -w 3 127.0.0.1 "$rport" < /dev/null 2>/dev/null | head -c 16)
kill_tree $fwdpid
fwdpid=
if [ "$one" = "SSH-2.0-dropbear" ] && [ "$two" = "SSH-2.0-dropbear" ]; then
	echo "ok: remote -- -R's connections come from the Dropbear and reach the host here, two in turn"
else
	fail "remote: read '$one' then '$two' through the remote port"
	cat "$fx/fwd.err" >&2
fi

# netcat: -B, the client's own output carried from the Dropbear's own ssh
# port through it: its version line
out=$(HOME="$home" "$X" -l ssh -- dbclient -p "$port" -i "$fx/userkey" -l "$user" -B "127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" | head -c 16)
if [ "$out" = "SSH-2.0-dropbear" ]; then
	echo "ok: netcat -- -B carries the Dropbear's own version line to standard output"
else
	fail "netcat: read '$out'"
	cat "$fx/fwd.err" >&2
fi

# idle: -N -I 2 with nothing to carry ends on the client's own clock
start=$(date +%s)
HOME="$home" "$X" -l ssh -- dbclient -p "$port" -i "$fx/userkey" -l "$user" -N -I 2 127.0.0.1 < /dev/null > /dev/null 2> "$fx/fwd.err"
status=$?
took=$(( $(date +%s) - start ))
if [ "$status" != 0 ] && [ $took -lt 40 ] && grep -q 'Idle timeout' "$fx/fwd.err"; then
	echo "ok: idle -- -I ends the connection on the client's clock (status $status after ${took}s)"
else
	fail "idle: status $status after ${took}s"
	cat "$fx/fwd.err" >&2
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
