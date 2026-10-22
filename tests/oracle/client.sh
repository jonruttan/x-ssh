#!/bin/sh
# tests/oracle/client.sh -- x-ssh's client and key tool against Dropbear's
# server and OpenSSH's tools.
#
# Usage: X=/path/to/x sh tests/oracle/client.sh DROPBEAR_DIR [PORT]
#
# DROPBEAR_DIR holds a built Dropbear (dropbear, dropbearkey).  A fixture
# is made in a scratch directory: an ssh-ed25519 host key, an ssh-ed25519
# user key (OpenSSH's ssh-keygen), its public half as authorized_keys.  A
# non-root Dropbear is started on 127.0.0.1:PORT for the run, and through
# it, each checked against what the system's own tools say:
#
#   exec     `echo hi from x-ssh; exit 3` under StrictHostKeyChecking
#            accept-new: the output and the exit status, the host's key
#            recorded in known_hosts; the -v trace printed after
#   hosts    a host not in known_hosts refused in batch mode and under
#            StrictHostKeyChecking yes, a host whose key has changed
#            refused, each status 255 before authentication
#   input    200000 random bytes on the client's standard input, past
#            Dropbear's 24 KB window, through `cksum` on the far side
#   keys     a key x-ssh's ssh-keygen makes is read by OpenSSH's with the
#            fingerprint and randomart x-ssh printed and the public line
#            it wrote; x-ssh's -l and -y say what OpenSSH's do of a key
#            OpenSSH made; the made key authenticates the client
#   sealed   a key x-ssh seals under a passphrase opens in OpenSSH's
#            ssh-keygen; x-ssh's -y, -l and -p say what OpenSSH's do of
#            a key OpenSSH sealed; a sealed key authenticates the client,
#            its passphrase by SSH_ASKPASS once the server would take it
#   host keys  a Dropbear with an RSA host key, then an ECDSA one: each
#            checked and recorded in known_hosts under its type
#   key types  ssh-keygen -l -v on RSA and ECDSA keys, as OpenSSH's
#   identities  ECDSA keys x-ssh makes, P-256 and P-384, read by OpenSSH's
#            ssh-keygen; -y, -l -v and -p of OpenSSH's RSA and ECDSA keys
#            as OpenSSH's; the client authenticated by RSA and ECDSA keys
#   rewrite  ssh-keygen -p turns Dropbear's host key into a file
#            OpenSSH's ssh-keygen reads as the key dropbearkey shows
#   known    ssh-keygen -F and -R on a known_hosts, as OpenSSH's do them
#   config   ssh -G for a Host block's Hostname, Port and User, as
#            OpenSSH's ssh -G prints them
#   forward  -N -L: a local port carried through the Dropbear to its own
#            ssh port, two connections in turn reading its version line
#   remote   -N -R: the Dropbear listens, its connections come here and
#            reach its own ssh port, two in turn reading its version line
#   stdio    -W: the Dropbear's own version line carried to standard output
#   idle     -N with ChannelTimeout global=2 ends on the client's own clock
#   git      `git clone` of a repository behind the Dropbear, with x-ssh
#            as git's ssh, given OpenSSH's options: the clone's HEAD and
#            its fsck
#
# Dropbear, OpenSSH's tools and git are the oracles; this is the live
# test the specs cannot replay, since every exchange has fresh ephemeral
# keys.
set -u
db=${1:?a built Dropbear directory}
port=${2:-22222}
X=${X:-x}
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-oracle.XXXXXX")
# The launcher pipes the program into the engine, a child of its own,
# so a client's pid is a shell's: the whole tree under it goes.
kill_tree() {
	[ -n "${1:-}" ] || return 0
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
# the clients' home, for known_hosts; no user configuration but the test's
home="$fx/home"
mkdir -p "$home"
xssh() { HOME="$home" "$X" -l ssh -- ssh -F none -p "$port" -i "$fx/userkey" -l "$user" "$@"; }
failed=0

fail() {
	echo "FAIL: $1" >&2
	cat "$fx/client.err" >&2
	tail -5 "$fx/dropbear.log" >&2
	failed=1
}

# exec, the host new and accepted: its key must land in known_hosts as
# Dropbear's own hostkey.pub spells it
out=$(xssh -o StrictHostKeyChecking=accept-new -v 127.0.0.1 'echo hi from x-ssh; exit 3' < /dev/null 2> "$fx/client.err")
status=$?
key=$(cut -d' ' -f2 "$fx/hostkey.pub")
line=$(cat "$home/.ssh/known_hosts" 2>/dev/null)
if [ "$out" = "hi from x-ssh" ] && [ "$status" = 3 ] && [ "$line" = "[127.0.0.1]:$port ssh-ed25519 $key" ] \
	&& grep -q "Warning: Permanently added '\[127.0.0.1\]:$port' (ED25519) to the list of known hosts." "$fx/client.err"; then
	echo "ok: exec -- output and exit status through Dropbear, the host's key recorded"
	cat "$fx/client.err"
else
	fail "exec: output '$out' status $status known_hosts '$line'"
fi

# hosts: an unknown host refused in batch mode and under strict checking,
# then a changed key refused
HOME="$fx/nobody" "$X" -l ssh -- ssh -F none -o BatchMode=yes -p "$port" -i "$fx/userkey" -l "$user" 127.0.0.1 true < /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ] && grep -qx 'Host key verification failed.' "$fx/client.err"; then
	echo "ok: hosts -- an unknown host is refused in batch mode"
else
	fail "hosts: an unknown host in batch mode gave status $status"
fi
HOME="$fx/nobody" "$X" -l ssh -- ssh -F none -o StrictHostKeyChecking=yes -p "$port" -i "$fx/userkey" -l "$user" 127.0.0.1 true < /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ] && grep -q "No ED25519 host key is known for \[127.0.0.1\]:$port and you have requested strict checking." "$fx/client.err"; then
	echo "ok: hosts -- an unknown host is refused under StrictHostKeyChecking yes"
else
	fail "hosts: an unknown host under strict checking gave status $status"
fi
mkdir -p "$fx/changed/.ssh"
printf '[127.0.0.1]:%s ssh-ed25519 %s\n' "$port" "$(cut -d' ' -f2 "$fx/userkey.pub")" > "$fx/changed/.ssh/known_hosts"
HOME="$fx/changed" "$X" -l ssh -- ssh -F none -o StrictHostKeyChecking=no -p "$port" -i "$fx/userkey" -l "$user" 127.0.0.1 true < /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ] && grep -q 'REMOTE HOST IDENTIFICATION HAS CHANGED' "$fx/client.err" \
	&& grep -q "Offending ED25519 key in $fx/changed/.ssh/known_hosts:1" "$fx/client.err"; then
	echo "ok: hosts -- a changed key is refused, whatever the policy"
else
	fail "hosts: a changed key gave status $status"
fi

# input
head -c 200000 /dev/urandom > "$fx/input"
want=$(cksum < "$fx/input")
got=$(xssh 127.0.0.1 cksum < "$fx/input" 2> "$fx/client.err")
if [ "$got" = "$want" ]; then
	echo "ok: input -- 200000 bytes of standard input arrive whole ($want)"
else
	fail "input: the far side's cksum '$got', the near side's '$want'"
fi

# keys: a key x-ssh makes is one OpenSSH reads, with the fingerprint and
# randomart x-ssh printed and the public line it wrote
"$X" -l ssh -- ssh-keygen -t ed25519 -N '' -C made-here -f "$fx/xkey" > "$fx/xkey.out" 2> "$fx/client.err"
status=$?
ours=$(sed -n '/^The key fingerprint is:$/,$p' "$fx/xkey.out" | grep -v '^The key')
theirs=$(ssh-keygen -l -v -f "$fx/xkey" 2>> "$fx/client.err" | sed 's/^256 \(SHA256:[^ ]* made-here\) (ED25519)$/\1/')
pub=$(cat "$fx/xkey.pub" 2>/dev/null)
theirpub=$(ssh-keygen -y -f "$fx/xkey" 2>/dev/null)
if [ "$status" = 0 ] && [ -n "$ours" ] && [ "$ours" = "$theirs" ] && [ "$pub" = "$theirpub" ]; then
	echo "ok: keys -- OpenSSH's ssh-keygen reads the key x-ssh made, its fingerprint and randomart as x-ssh printed"
else
	fail "keys: status $status, x-ssh '$ours', ssh-keygen '$theirs', .pub '$pub' vs '$theirpub'"
fi
ours=$("$X" -l ssh -- ssh-keygen -l -v -f "$fx/userkey" 2> "$fx/client.err"; "$X" -l ssh -- ssh-keygen -y -f "$fx/userkey" 2>> "$fx/client.err")
theirs=$(ssh-keygen -l -v -f "$fx/userkey"; ssh-keygen -y -f "$fx/userkey")
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: keys -- x-ssh's -l -v and -y say what OpenSSH's do of OpenSSH's key"
else
	fail "keys: x-ssh says '$ours', OpenSSH '$theirs'"
fi
cat "$fx/xkey.pub" >> "$fx/authorized_keys"
out=$(HOME="$home" "$X" -l ssh -- ssh -F none -p "$port" -i "$fx/xkey" -l "$user" 127.0.0.1 'echo made here' < /dev/null 2> "$fx/client.err")
if [ "$out" = "made here" ]; then
	echo "ok: keys -- the key x-ssh made authenticates it"
else
	fail "keys: a client with the key x-ssh made said '$out'"
fi

# sealed: a key x-ssh seals under a passphrase is one OpenSSH's
# ssh-keygen opens under it alone
"$X" -l ssh -- ssh-keygen -q -t ed25519 -N 'sealed here' -C sealed-x -f "$fx/xsealed" > /dev/null 2> "$fx/client.err"
status=$?
theirpub=$(ssh-keygen -y -P 'sealed here' -f "$fx/xsealed" 2>> "$fx/client.err")
wrong=$(ssh-keygen -y -P 'sealed hear' -f "$fx/xsealed" 2>&1)
if [ "$status" = 0 ] && [ -n "$theirpub" ] && [ "$theirpub" = "$(cat "$fx/xsealed.pub")" ] \
	&& [ "$wrong" = "$(printf 'Load key "%s": incorrect passphrase supplied to decrypt private key\r' "$fx/xsealed")" ]; then
	echo "ok: sealed -- OpenSSH's ssh-keygen opens the key x-ssh sealed, under its passphrase alone"
else
	fail "sealed: status $status, ssh-keygen -y '$theirpub', a wrong passphrase '$wrong'"
fi
# x-ssh's -y, -l (no passphrase, with FILE.pub and without) and -p say
# what OpenSSH's do of a key OpenSSH sealed
ssh-keygen -q -t ed25519 -N 'theirs sealed' -C sealed-o -f "$fx/osealed"
keygen_says() {
	k=$1
	shift
	"$@" -y -P 'theirs sealed' -f "$fx/osealed" 2>&1; echo "status $?"
	"$@" -y -P 'theirs seal' -f "$fx/osealed" 2>&1; echo "status $?"
	"$@" -l -f "$fx/osealed" 2>&1; echo "status $?"
	mv "$fx/osealed.pub" "$fx/osealed.pubx"
	"$@" -l -f "$fx/osealed" 2>&1; echo "status $?"
	mv "$fx/osealed.pubx" "$fx/osealed.pub"
	cp "$fx/osealed" "$fx/changed.$k"
	o=$("$@" -p -P 'theirs seal' -N 'changed' -f "$fx/changed.$k" 2>&1); s=$?
	echo "$o" | sed "s|$fx/changed.$k|K|"; echo "status $s"
	"$@" -p -P 'theirs sealed' -N 'changed' -f "$fx/changed.$k" 2>&1; echo "status $?"
	ssh-keygen -y -P changed -f "$fx/changed.$k" 2>&1; echo "status $?"
	"$@" -p -P 'changed' -N '' -f "$fx/changed.$k" 2>&1; echo "status $?"
	ssh-keygen -y -P '' -f "$fx/changed.$k" 2>&1; echo "status $?"
}
ours=$(keygen_says ours "$X" -l ssh -- ssh-keygen < /dev/null)
theirs=$(keygen_says theirs ssh-keygen < /dev/null)
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: sealed -- x-ssh's -y, -l and -p say what OpenSSH's do of a key OpenSSH sealed"
else
	fail "sealed: x-ssh said
$ours
OpenSSH said
$theirs"
fi
# a sealed key authenticates the client, its passphrase asked of
# SSH_ASKPASS only once the server would take it: the sealed key not in
# authorized_keys is offered first and asks nothing; in batch mode
# nothing is asked and the key is passed over
cat "$fx/xsealed.pub" >> "$fx/authorized_keys"
printf '#!/bin/sh\necho "$1" >> "%s/asked"\necho "sealed here"\n' "$fx" > "$fx/askpass"
chmod +x "$fx/askpass"
out=$(SSH_ASKPASS="$fx/askpass" SSH_ASKPASS_REQUIRE=force HOME="$home" "$X" -l ssh -- ssh -F none -p "$port" \
	-i "$fx/osealed" -i "$fx/xsealed" -l "$user" 127.0.0.1 'echo sealed key' < /dev/null 2> "$fx/client.err")
asked=$(cat "$fx/asked" 2>/dev/null)
rm -f "$fx/asked"
SSH_ASKPASS="$fx/askpass" SSH_ASKPASS_REQUIRE=force HOME="$home" "$X" -l ssh -- ssh -F none -o BatchMode=yes -p "$port" \
	-i "$fx/xsealed" -l "$user" 127.0.0.1 true < /dev/null 2>> "$fx/client.err"
bstatus=$?
if [ "$out" = "sealed key" ] && [ "$asked" = "Enter passphrase for key '$fx/xsealed': " ] && [ "$bstatus" = 255 ] \
	&& [ ! -f "$fx/asked" ]; then
	echo "ok: sealed -- a sealed key authenticates the client, asked for once the server would take it, never in batch mode"
else
	fail "sealed: the client said '$out', asked '$asked', batch status $bstatus"
fi

# host key types: a Dropbear with an RSA host key alone, then one with an
# ECDSA P-256 key alone; x-ssh's client checks each signature and records
# each key under its type, as Dropbear's own key files spell them
for t in rsa:ssh-rsa ecdsa:ecdsa-sha2-nistp256; do
	kind=${t%%:*}; type=${t##*:}
	tport=$((port + 40))
	"$db/dropbearkey" -t $kind -f "$fx/host-$kind" > /dev/null 2>&1
	mkdir -p "$fx/types-$kind"
	"$db/dropbear" -D "$fx" -p "127.0.0.1:$tport" -r "$fx/host-$kind" -F -s > "$fx/dropbear-$kind.log" 2>&1 &
	tpid=$!
	sleep 1
	out=$(HOME="$fx/types-$kind" "$X" -l ssh -- ssh -F none -o StrictHostKeyChecking=accept-new -p "$tport" -i "$fx/userkey" -l "$user" \
		127.0.0.1 "echo by $kind" < /dev/null 2> "$fx/client.err")
	status=$?
	kill $tpid 2>/dev/null; wait $tpid 2>/dev/null
	want=$("$db/dropbearkey" -y -f "$fx/host-$kind" 2>/dev/null | grep "^$type " | cut -d' ' -f1-2)
	line=$(cut -d' ' -f2-3 "$fx/types-$kind/.ssh/known_hosts" 2>/dev/null)
	if [ "$out" = "by $kind" ] && [ "$status" = 0 ] && [ -n "$want" ] && [ "$line" = "$want" ]; then
		echo "ok: host keys -- a $type host key checked and recorded"
	else
		fail "host keys: $type, output '$out' status $status, known_hosts '$line', the key '$want'"
	fi
done

# key types: x-ssh's ssh-keygen -l -v on RSA and ECDSA public keys, as
# OpenSSH's says them, randomart and all
ssh-keygen -q -t rsa -b 3072 -N '' -C rsa-key -f "$fx/rsa-key"
ssh-keygen -q -t ecdsa -b 384 -N '' -C ecdsa-key -f "$fx/ecdsa-key"
ours=$("$X" -l ssh -- ssh-keygen -l -v -f "$fx/rsa-key.pub" 2> "$fx/client.err"; "$X" -l ssh -- ssh-keygen -l -v -f "$fx/ecdsa-key.pub" 2>> "$fx/client.err")
theirs=$(ssh-keygen -l -v -f "$fx/rsa-key.pub"; ssh-keygen -l -v -f "$fx/ecdsa-key.pub")
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: key types -- ssh-keygen -l -v on RSA and ECDSA keys as OpenSSH's"
else
	fail "key types: x-ssh '$ours', OpenSSH '$theirs'"
fi

# identities: ECDSA keys x-ssh's ssh-keygen makes, on P-256 and P-384,
# read by OpenSSH's with the fingerprint and randomart x-ssh printed and
# the public line it wrote
for b in 256 384; do
	"$X" -l ssh -- ssh-keygen -t ecdsa -b $b -N '' -C made-ecdsa -f "$fx/xecdsa$b" > "$fx/xecdsa.out" 2> "$fx/client.err"
	status=$?
	ours=$(sed -n '/^The key fingerprint is:$/,$p' "$fx/xecdsa.out" | grep -v '^The key')
	theirs=$(ssh-keygen -l -v -f "$fx/xecdsa$b" 2>> "$fx/client.err" | sed "s/^$b \(SHA256:[^ ]* made-ecdsa\) (ECDSA)$/\1/")
	pub=$(cat "$fx/xecdsa$b.pub" 2>/dev/null)
	theirpub=$(ssh-keygen -y -f "$fx/xecdsa$b" 2>/dev/null)
	if [ "$status" = 0 ] && [ -n "$ours" ] && [ "$ours" = "$theirs" ] && [ "$pub" = "$theirpub" ]; then
		echo "ok: identities -- OpenSSH's ssh-keygen reads the ECDSA P-$b key x-ssh made"
	else
		fail "identities: P-$b status $status, x-ssh '$ours', ssh-keygen '$theirs', .pub '$pub' vs '$theirpub'"
	fi
done
# x-ssh's -y and -l -v of OpenSSH's RSA and ECDSA private keys, and -p
# sealing them: OpenSSH's -y opens each under the new passphrase alone
ours=$(for k in rsa-key ecdsa-key; do
	"$X" -l ssh -- ssh-keygen -y -f "$fx/$k" 2>&1; "$X" -l ssh -- ssh-keygen -l -v -f "$fx/$k" 2>&1
	cp "$fx/$k" "$fx/$k.sealed"
	"$X" -l ssh -- ssh-keygen -p -P '' -N 'now sealed' -f "$fx/$k.sealed" 2>&1 | sed "s|$fx/||"
	ssh-keygen -y -P 'now sealed' -f "$fx/$k.sealed" 2>&1
	"$X" -l ssh -- ssh-keygen -y -P 'now sealed' -f "$fx/$k.sealed" 2>&1
done < /dev/null)
theirs=$(for k in rsa-key ecdsa-key; do
	ssh-keygen -y -f "$fx/$k"; ssh-keygen -l -v -f "$fx/$k"
	printf "Key has comment '%s'\nYour identification has been saved with the new passphrase.\n" "$k"
	ssh-keygen -y -f "$fx/$k"; ssh-keygen -y -f "$fx/$k"
done)
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: identities -- x-ssh's -y, -l -v and -p of OpenSSH's RSA and ECDSA keys as OpenSSH's"
else
	fail "identities: x-ssh said
$ours
OpenSSH said
$theirs"
fi
# each authenticates the client: RSA by the rsa-sha2 Dropbear's
# server-sig-algs names, ECDSA P-384 OpenSSH's and P-256 x-ssh's
cat "$fx/rsa-key.pub" "$fx/ecdsa-key.pub" "$fx/xecdsa256.pub" >> "$fx/authorized_keys"
for k in rsa-key ecdsa-key xecdsa256; do
	out=$(HOME="$home" "$X" -l ssh -- ssh -F none -p "$port" -i "$fx/$k" -l "$user" 127.0.0.1 "echo by $k" < /dev/null 2> "$fx/client.err")
	if [ "$out" = "by $k" ]; then
		echo "ok: identities -- the client authenticated with $k"
	else
		fail "identities: a client with $k said '$out'"
	fi
done

# rewrite: -p turns Dropbear's key file into OpenSSH's
cp "$fx/hostkey" "$fx/host.rewritten"
"$X" -l ssh -- ssh-keygen -p -P '' -N '' -f "$fx/host.rewritten" > "$fx/rewrite.out" 2> "$fx/client.err"
status=$?
ours=$(ssh-keygen -y -f "$fx/host.rewritten" 2>> "$fx/client.err" | cut -d' ' -f1-2)
theirs=$("$db/dropbearkey" -y -f "$fx/hostkey" 2>/dev/null | sed -n 2p | cut -d' ' -f1-2)
if [ "$status" = 0 ] && grep -q 'Your identification has been saved with the new passphrase.' "$fx/rewrite.out" \
	&& [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: rewrite -- OpenSSH's ssh-keygen reads Dropbear's key x-ssh rewrote"
else
	fail "rewrite: status $status, ssh-keygen '$ours', dropbearkey '$theirs'"
fi

# known: -F and -R as OpenSSH's do them, each on its own copy
printf 'a.example ssh-ed25519 AAAA1\n[h]:2222,h2 ssh-ed25519 AAAA2\n# a comment\nb.example ssh-ed25519 AAAA3\n' > "$fx/kh.ours"
cp "$fx/kh.ours" "$fx/kh.theirs"
ours=$("$X" -l ssh -- ssh-keygen -F '[h]:2222' -f "$fx/kh.ours" 2> "$fx/client.err"; echo "status $?"
	"$X" -l ssh -- ssh-keygen -R h2 -f "$fx/kh.ours" 2>> "$fx/client.err" | sed "s|$fx/kh.ours|KH|g"; cat "$fx/kh.ours")
theirs=$(ssh-keygen -F '[h]:2222' -f "$fx/kh.theirs"; echo "status $?"
	ssh-keygen -R h2 -f "$fx/kh.theirs" 2>/dev/null | sed "s|$fx/kh.theirs|KH|g"; cat "$fx/kh.theirs")
if [ "$ours" = "$theirs" ]; then
	echo "ok: known -- ssh-keygen -F and -R as OpenSSH's"
else
	fail "known: x-ssh said '$ours', OpenSSH '$theirs'"
fi

# config: a Host block's settings as OpenSSH's ssh -G prints them
printf 'Host gw\n  Hostname %%h.example.org\n  Port 2200\n  User git\n' > "$fx/config"
ours=$(HOME="$home" "$X" -l ssh -- ssh -F "$fx/config" -G gw 2> "$fx/client.err" | grep -E '^(hostname|port|user) ' | sort)
theirs=$(ssh -F "$fx/config" -G gw | grep -E '^(hostname|port|user) ' | sort)
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	echo "ok: config -- ssh -G settles a Host block as OpenSSH's does"
else
	fail "config: x-ssh '$ours', OpenSSH '$theirs'"
fi

# forward: -N -L, a local port carried through the Dropbear to its own
# ssh port: each connection reads the server's version line, two in turn
fport=$((port + 10))
xssh -N -L "$fport:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" &
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
xssh -N -R "$rport:127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" &
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

# stdio: -W, the client's own output carried from the Dropbear's own ssh
# port through it: its version line
out=$(xssh -W "127.0.0.1:$port" 127.0.0.1 < /dev/null 2> "$fx/fwd.err" | head -c 16)
if [ "$out" = "SSH-2.0-dropbear" ]; then
	echo "ok: stdio -- -W carries the Dropbear's own version line to standard output"
else
	fail "stdio: read '$out'"
	cat "$fx/fwd.err" >&2
fi

# idle: -N with ChannelTimeout global=2 and nothing to carry ends on the
# client's own clock
start=$(date +%s)
xssh -N -o ChannelTimeout=global=2 127.0.0.1 < /dev/null > /dev/null 2> "$fx/fwd.err"
status=$?
took=$(( $(date +%s) - start ))
if [ "$status" = 255 ] && [ $took -lt 40 ] && grep -q 'ChannelTimeout' "$fx/fwd.err"; then
	echo "ok: idle -- ChannelTimeout ends the connection on the client's clock (${took}s)"
else
	fail "idle: status $status after ${took}s"
	cat "$fx/fwd.err" >&2
fi

# git: x-ssh's ssh as git's, a wrapper named ssh so git gives it OpenSSH's
# options -- the port by -p, and -o SendEnv=GIT_PROTOCOL
src="$fx/src.git"
git init -q --bare "$src"
git init -q "$fx/work"
( cd "$fx/work" && printf 'one\n' > a && mkdir -p d && printf 'two\n' > d/b \
	&& git add a d && git -c user.name=o -c user.email=o@o commit -q -m first \
	&& printf 'three\n' >> a && git -c user.name=o -c user.email=o@o commit -q -am second \
	&& git push -q "$src" HEAD:refs/heads/main )
mkdir -p "$fx/gitbin"
printf '#!/bin/sh\nHOME="%s" exec "%s" -l ssh -- ssh -F none -i "%s" -l %s "$@"\n' "$home" "$X" "$fx/userkey" "$user" > "$fx/gitbin/ssh"
chmod +x "$fx/gitbin/ssh"
GIT_SSH="$fx/gitbin/ssh" git clone -q -b main "ssh://127.0.0.1:$port$src" "$fx/dst" 2> "$fx/client.err"
want=$(git -C "$src" rev-parse main)
got=$(git -C "$fx/dst" rev-parse HEAD 2>/dev/null)
if [ "$got" = "$want" ] && git -C "$fx/dst" fsck --no-progress > /dev/null 2>> "$fx/client.err"; then
	echo "ok: git -- a clone through x-ssh has $want and checks clean"
else
	fail "git: the clone's HEAD '$got', the repository's '$want'"
fi

exit $failed
