#!/bin/sh
# Join the tailnet with the auth key file the driver copied here, then delete
# the file whatever happened. Usage: tsup.sh <keyfile> <hostname> <generation> [socket]
# The key is passed as file:..., so it never appears on a command line.
# tsup.done carries the generation (the run ID), so a marker left by an
# earlier run is never taken for this one.
key=$1 name=$2 gen=$3 sock=${4:-}
trap 'rm -f "$key"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p /var/e2e
rm -f /var/e2e/tsup.done
TS=tailscale
[ -n "$sock" ] && TS="tailscale --socket=$sock"
chmod 600 "$key" 2>/dev/null
timeout 60 $TS up --auth-key="file:$key" --hostname="$name" --accept-routes=false >/var/e2e/tsup.log 2>&1
rc=$?
rm -f "$key"
test -e "$key" && echo KEYFILE-STILL-PRESENT >>/var/e2e/tsup.log
ip4=$($TS ip -4 2>/dev/null | head -1)
echo "gen=$gen rc=$rc ip=$ip4" >/var/e2e/tsup.done.tmp && mv /var/e2e/tsup.done.tmp /var/e2e/tsup.done
$TS status --json 2>/dev/null >/var/e2e/tsstatus.json
exit $rc
