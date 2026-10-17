#!/bin/sh
# # x-ssh -- SSH on x-lang
#
# ## tests/linux/password.sh -- password logins, as root in the container
#
# A user is made with a known password, its SHA-512 crypt in /etc/shadow
# ("pw", x-lang's Crypt example), and the x-ssh sshd started as root, the
# one user a server that does not drop privileges can log in, with
# PermitRootLogin yes.  Through it:
#
#   dbclient   Dropbear's client, DROPBEAR_PASSWORD: output and status
#   ssh        OpenSSH's client, the password by SSH_ASKPASS
#   x-ssh      x-ssh's own client, the password by SSH_ASKPASS, no key
#   wrong      a wrong password is refused, status 255, and logged
#   prompt     x-ssh's client asks at the terminal (expect): whether to
#              trust the new host, then the password, again after a wrong
#              one, echoing neither
#   syslog     a server without -e logs to busybox's syslogd, as sshd in
#              the auth facility
#   root       under PermitRootLogin's default root's password is refused,
#              logged, and MaxAuthTries ends it; under PasswordAuthentication
#              no none is asked
#
# The clients are the oracles.
set -u
# x finds the mounted bundle as the lang "ssh"
mkdir -p /langs && ln -sfn /x-ssh /langs/ssh
export X_LANG_DIR=/langs/
X=${X:-x}
port=
fx=$(mktemp -d)
trap 'rm -rf "$fx"' EXIT
hash='$6$saltsalt$pauPrmdmG4BTE9h2HPmywiw152IFch6BJCEsaY6D.PLTfpV8sqvXwWdyfsgVgozkYH9B80bAip/08R2BPH2xk/'
sed -i "s|^root:[^:]*:|root:$hash:|" /etc/shadow
"$X" -l ssh -- ssh-keygen -q -t ed25519 -N '' -f "$fx/hostkey" > /dev/null 2>&1
mkdir -p "$fx/home"
printf '#!/bin/sh\necho pw\n' > "$fx/askpass"; printf '#!/bin/sh\necho px\n' > "$fx/wrongpass"
chmod +x "$fx/askpass" "$fx/wrongpass"
failed=0
fail() { echo "FAIL: $1" >&2; cat "$fx/client.err" >&2; tail -5 "$fx/server.log" >&2; failed=1; }

# The server on a port, its options after the fixture's; the log on
# standard error unless the caller says otherwise.
start() {
	port=$1; log=$2; shift 2
	USER=root "$X" -l ssh -- sshd -D -f /dev/null -h "$fx/hostkey" -o ListenAddress=127.0.0.1 -p "$port" -o PidFile=none "$@" > "$log" 2>&1 &
}
started() {
	i=0
	while ! grep -q "Server listening on 127.0.0.1 port $2." "$1" 2>/dev/null; do
		i=$((i + 1)); [ $i -lt 600 ] || { echo "FAIL: the server did not start" >&2; cat "$1" >&2; exit 1; }
		sleep 1
	done
}
xssh() { HOME="$fx/home" "$X" -l ssh -- ssh -F none -o StrictHostKeyChecking=accept-new -q -p "$port" -l root "$@"; }

start 2222 "$fx/server.log" -e -o PermitRootLogin=yes
started "$fx/server.log" 2222

# dbclient
out=$(DROPBEAR_PASSWORD=pw dbclient -y -y -p "$port" root@127.0.0.1 'echo by password; exit 3' < /dev/null 2> "$fx/client.err")
status=$?
if [ "$out" = "by password" ] && [ "$status" = 3 ] && grep -q "Accepted password for root from 127.0.0.1 port [0-9]* ssh2" "$fx/server.log"; then
	echo "ok: dbclient -- Dropbear's client logs in by password"
else
	fail "dbclient: output '$out' status $status"
fi

# ssh
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
out=$(SSH_ASKPASS="$fx/askpass" SSH_ASKPASS_REQUIRE=force xssh 127.0.0.1 'echo both ends in x; exit 4' < /dev/null 2> "$fx/client.err")
status=$?
if [ "$out" = "both ends in x" ] && [ "$status" = 4 ]; then
	echo "ok: x-ssh -- its own client, the password by SSH_ASKPASS"
else
	fail "x-ssh: output '$out' status $status"
fi

# wrong
SSH_ASKPASS="$fx/wrongpass" SSH_ASKPASS_REQUIRE=force xssh -o NumberOfPasswordPrompts=1 127.0.0.1 true < /dev/null > /dev/null 2> "$fx/client.err"
status=$?
if [ "$status" = 255 ] && grep -q "Failed password for root from 127.0.0.1 port [0-9]* ssh2" "$fx/server.log" \
	&& grep -q 'root@127.0.0.1: Permission denied (publickey,password).' "$fx/client.err"; then
	echo "ok: wrong -- a wrong password is refused and logged"
else
	fail "wrong: status $status"
fi

# prompt
mkdir -p /tmp/prompt-home
if expect tests/linux/prompt.exp "$port" > "$fx/prompt.out" 2>&1 && grep -qx ok "$fx/prompt.out"; then
	echo "ok: prompt -- x-ssh asks whether to trust the host, then the password, again after a wrong one, echoing neither"
else
	fail "prompt: $(cat "$fx/prompt.out")"
fi

# syslog: a server without -e logs to busybox's syslogd, as sshd, auth
syslogd -O "$fx/messages"
start 2224 "$fx/quiet.log" -o PermitRootLogin=yes
i=0
while ! grep -q 'sshd\[[0-9]*\]: Server listening on 127.0.0.1 port 2224.' "$fx/messages" 2>/dev/null; do
	i=$((i + 1)); [ $i -lt 600 ] || break; sleep 1
done
out=$(DROPBEAR_PASSWORD=pw dbclient -y -y -p 2224 root@127.0.0.1 'echo by syslog' < /dev/null 2> "$fx/client.err")
if [ "$out" = "by syslog" ] && grep -q "auth.info sshd\\[[0-9]*\\]: Accepted password for root from 127.0.0.1" "$fx/messages" \
	&& ! grep -q 'Accepted password' "$fx/quiet.log"; then
	echo "ok: syslog -- without -e the server logs to syslogd as sshd, auth"
else
	fail "syslog: output '$out'"; cat "$fx/messages" >&2; cat "$fx/quiet.log" >&2
fi

# root: PermitRootLogin's default refuses root's password, and says so,
# until MaxAuthTries disconnects a client that keeps trying; Dropbear's
# client exits 0 after that disconnect, so the log is the judge.
# PasswordAuthentication no offers none.
# the launcher pipes the program into the engine, a child of its own: the
# first servers stay up, and these listen on ports of their own
start 2225 "$fx/root.log" -e
started "$fx/root.log" 2225
out=$(DROPBEAR_PASSWORD=pw dbclient -y -y -p 2225 root@127.0.0.1 'echo got-in' < /dev/null 2> "$fx/client.err")
start 2223 "$fx/nopw.log" -e -o PermitRootLogin=yes -o PasswordAuthentication=no
started "$fx/nopw.log" 2223
out2=$(DROPBEAR_PASSWORD=pw dbclient -y -y -p 2223 root@127.0.0.1 'echo got-in' < /dev/null 2> "$fx/client.err")
if [ -z "$out" ] && grep -q 'ROOT LOGIN REFUSED FROM 127.0.0.1 port' "$fx/root.log" \
	&& grep -q 'maximum authentication attempts exceeded for root' "$fx/root.log" && ! grep -q 'Accepted' "$fx/root.log" \
	&& [ -z "$out2" ] && ! grep -q 'password for root' "$fx/nopw.log"; then
	echo "ok: root -- PermitRootLogin's default refuses root's password, MaxAuthTries ends it; PasswordAuthentication no offers none"
else
	fail "root: outputs '$out' and '$out2'"; cat "$fx/root.log" "$fx/nopw.log" >&2
fi

exit $failed
