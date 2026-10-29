#!/bin/sh
# Phase 6 on T1 (root): append lines to deploy2's authorized_keys while a
# rotation of that account runs, as an editor or a config tool would.
#   rot-append.sh <public-key-file> <count> <interval> <round> <start-epoch>
# It starts at <start-epoch> on T1's clock (A starts the rotation 2 s later),
# and logs "<n> <time>" after each append to /var/e2e/append-<round>.log, so
# the judge can place every write against the rotation's window.
set -u
f=/home/deploy2/.ssh/authorized_keys
log=/var/e2e/append-$4.log
rm -f /var/e2e/append-$4.done
: >"$log"
while [ "$(date +%s)" -lt "$5" ]; do sleep 0.1; done
n=0
while [ $n -lt "$2" ]; do
	n=$((n + 1))
	printf '%s %s hk-e2e-manual-%s-%d\n' "$(cut -d' ' -f1 "$1")" "$(cut -d' ' -f2 "$1")" "$4" $n >>$f
	echo "$n $(date +%s.%N)" >>"$log"
	sleep "$3"
done
echo $n >/var/e2e/append-$4.done
