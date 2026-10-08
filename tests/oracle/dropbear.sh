#!/bin/sh
# tests/oracle/dropbear.sh -- one command through x-ssh against a Dropbear.
#
# Usage: X=/path/to/x sh tests/oracle/dropbear.sh DROPBEAR_DIR [PORT]
#
# DROPBEAR_DIR holds a built Dropbear (dropbear, dropbearkey, dbclient).
# A fixture is made in a scratch directory: an ssh-ed25519 host key, an
# ssh-ed25519 user key (ssh-keygen), its public half as authorized_keys.
# A non-root Dropbear is started on 127.0.0.1:PORT for the run, x-ssh runs
# `echo hi from x-ssh; exit 3` through it, and the output and the status
# are checked.  Dropbear is the oracle; this is the live test the specs
# cannot replay, since every exchange has fresh ephemeral keys.
set -u
db=${1:?a built Dropbear directory}
port=${2:-22222}
X=${X:-x}
here=$(cd "$(dirname "$0")/../.." && pwd)
fx=$(mktemp -d "${TMPDIR:-/tmp}/x-ssh-oracle.XXXXXX")
trap 'kill $dbpid 2>/dev/null; rm -rf "$fx"' EXIT
"$db/dropbearkey" -t ed25519 -f "$fx/hostkey" > /dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -C x-ssh-oracle -f "$fx/userkey"
cp "$fx/userkey.pub" "$fx/authorized_keys"
"$db/dropbear" -D "$fx" -p "127.0.0.1:$port" -r "$fx/hostkey" -F -s > "$fx/dropbear.log" 2>&1 &
dbpid=$!
sleep 1
out=$("$X" -l ssh -- dbclient -p "$port" -i "$fx/userkey" -l "$(id -un)" 127.0.0.1 'echo hi from x-ssh; exit 3' 2> "$fx/client.err")
status=$?
if [ "$out" = "hi from x-ssh" ] && [ "$status" = 3 ]; then
  echo "ok: output and exit status through Dropbear"
  exit 0
fi
echo "FAIL: output '$out' status $status" >&2
cat "$fx/client.err" >&2
tail -5 "$fx/dropbear.log" >&2
exit 1
