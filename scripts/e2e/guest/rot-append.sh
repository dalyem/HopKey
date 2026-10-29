#!/bin/sh
# Phase 6 on T1 (root): append lines to deploy2's authorized_keys while a
# rotation of that account runs, as an editor or a config tool would.
#   rot-append.sh <public-key-file> <count> <interval> <round>
set -u
f=/home/deploy2/.ssh/authorized_keys
rm -f /var/e2e/append-$4.done
n=0
while [ $n -lt "$2" ]; do
	n=$((n + 1))
	printf '%s %s hk-e2e-manual-%s-%d\n' "$(cut -d' ' -f1 "$1")" "$(cut -d' ' -f2 "$1")" "$4" $n >>$f
	sleep "$3"
done
echo $n >/var/e2e/append-$4.done
