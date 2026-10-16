#!/bin/sh
# # x-ssh -- SSH on x-lang, after Dropbear
#
# ## tests/linux/password.sh -- password logins, as root in the container
#
# A user is made with a known password, its SHA-512 crypt in /etc/shadow
# ("pw", x-lang's Crypt example), and the x-ssh server started as root,
# the one user a server that does not drop privileges can log in.  Through
# it:
#
#   dbclient   Dropbear's client, DROPBEAR_PASSWORD: output and status
#   ssh        OpenSSH's client, the password by SSH_ASKPASS
#   x-ssh      x-ssh's own client, DROPBEAR_PASSWORD and no key
#   wrong      a wrong password is refused, status 255, and logged
#   -s         a server started with -s offers no password
#
# The clients are the oracles.
set -u
# x finds the mounted bundle as the lang "ssh"
mkdir -p /langs && ln -sfn /x-ssh /langs/ssh
export X_LANG_DIR=/langs/
X=${X:-x}
port=
fx=$(mktemp -d)
srvpid=
trap 'rm -rf "$fx"' EXIT
hash='$6$saltsalt$pauPrmdmG4BTE9h2HPmywiw152IFch6BJCEsaY6D.PLTfpV8sqvXwWdyfsgVgozkYH9B80bAip/08R2BPH2xk/'
sed -i "s|^root:[^:]*:|root:$hash:|" /etc/shadow
dropbearkey -t ed25519 -f "$fx/hostkey" > /dev/null 2>&1 || "$X" -l ssh -- dropbearkey -t ed25519 -f "$fx/hostkey" > /dev/null 2>&1
: > "$fx/authorized_keys"
mkdir -p "$fx/home"
failed=0
fail() { echo "FAIL: $1" >&2; cat "$fx/client.err" >&2; tail -5 "$fx/server.log" >&2; failed=1; }

start() {
	port=$1; shift
	USER=root "$X" -l ssh -- dropbear -F -E "$@" -r "$fx/hostkey" -p "127.0.0.1:$port" -D "$fx" > "$fx/server.log" 2>&1 &
	srvpid=$!
	i=0
	while ! grep -q 'Not backgrounding' "$fx/server.log" 2>/dev/null; do
		i=$((i + 1)); [ $i -lt 600 ] || { echo "FAIL: the server did not start" >&2; cat "$fx/server.log" >&2; exit 1; }
		sleep 1
	done
}

start 2222

# dbclient
out=$(DROPBEAR_PASSWORD=pw dbclient -y -y -p "$port" root@127.0.0.1 'echo by password; exit 3' < /dev/null 2> "$fx/client.err")
status=$?
if [ "$out" = "by password" ] && [ "$status" = 3 ] && grep -q "Password auth succeeded for 'root'" "$fx/server.log"; then
	echo "ok: dbclient -- Dropbear's client logs in by password"
else
	fail "dbclient: output '$out' status $status"
fi

# ssh
printf '#!/bin/sh\necho pw\n' > "$fx/askpass"; chmod +x "$fx/askpass"
out=$(SSH_ASKPASS="$fx/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=: ssh -q -o StrictHostKeyChecking=no \
	-o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password \
	-p "$port" root@127.0.0.1 'echo by password; exit 3' < /dev/null 2> "$fx/client.err")
status=$?
if [ "$out" = "by password" ] && [ "$status" = 3 ]; then
	echo "ok: ssh -- OpenSSH's client too"
else
	fail "ssh: output '$out' status $status"
fi

# x-ssh
out=$(HOME="$fx/home" DROPBEAR_PASSWORD=pw "$X" -l ssh -- dbclient -y -p "$port" -l root 127.0.0.1 'echo both ends in x; exit 4' < /dev/null 2> "$fx/client.err")
status=$?
if [ "$out" = "both ends in x" ] && [ "$status" = 4 ]; then
	echo "ok: x-ssh -- its own client, by password"
else
	fail "x-ssh: output '$out' status $status"
fi

# wrong
HOME="$fx/home" DROPBEAR_PASSWORD=px "$X" -l ssh -- dbclient -y -p "$port" -l root 127.0.0.1 true < /dev/null > /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ] && grep -q "Bad password attempt for 'root'" "$fx/server.log"; then
	echo "ok: wrong -- a wrong password is refused and logged"
else
	fail "wrong: status $status"
fi

# -s
# the launcher pipes the program into the engine, a child of its own: the
# first server stays up, and the second listens on a port of its own
start 2223 -s
DROPBEAR_PASSWORD=pw dbclient -y -y -p "$port" root@127.0.0.1 true < /dev/null > /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" != 0 ] && ! grep -q 'Password auth' "$fx/server.log"; then
	echo "ok: -s -- a server started with -s offers no password"
else
	fail "-s: status $status"
fi

exit $failed
