#!/bin/sh
# tswait.sh <secs> <peer...>: wait until every peer answers tailscale ping.
secs=$1; shift
end=$(( $(date +%s) + secs ))
for p in "$@"; do
	# A pong via DERP still exits non-zero ("direct connection not established").
	until timeout 8 tailscale ping -c 1 --timeout 5s "$p" 2>&1 | grep -q '^pong from'; do
		[ "$(date +%s)" -ge "$end" ] && { echo "unreachable $p"; exit 1; }
		sleep 2
	done
	echo "pong $p"
done
