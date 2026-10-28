#!/bin/sh
# Join the tailnet with the auth key file the driver copied here, then delete
# the file whatever happened. Usage: tsup.sh <keyfile> <hostname> [socket]
# The key is passed as file:..., so it never appears on a command line.
key=$1 name=$2 sock=${3:-}
TS=tailscale
[ -n "$sock" ] && TS="tailscale --socket=$sock"
chmod 600 "$key" 2>/dev/null
timeout 60 $TS up --auth-key="file:$key" --hostname="$name" --accept-routes=false >/var/e2e/tsup.log 2>&1
rc=$?
rm -f "$key"
test -e "$key" && echo KEYFILE-STILL-PRESENT >>/var/e2e/tsup.log
ip4=$($TS ip -4 2>/dev/null | head -1)
echo "rc=$rc ip=$ip4" >/var/e2e/tsup.done
$TS status --json 2>/dev/null >/var/e2e/tsstatus.json
exit $rc
