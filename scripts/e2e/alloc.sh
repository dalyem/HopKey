#!/usr/bin/env bash
# Machines for run.sh, recorded as they are asked for. Runs on the orchestrator.
#
#   alloc.sh <vm|sbx> <who> <record-file> <project> <ttl> [image]
#   alloc.sh resolve <vm|sbx> <op-id> <timeout>   prints "id <machine>", "ended <state>" or nothing
#
# run.sh starts the first form under setsid, in a session of its own, and it
# ignores INT, TERM and HUP (so does the kiln it runs): a signal to the
# driver's process group, a Ctrl-C or a closed terminal never stops it
# between "kiln asked for a machine" and "the ID is on disk". The driver's
# cleanup waits for "done" and releases what is recorded.
#
# Record lines, appended in this order:
#   pid <pid>         this worker
#   op <op-id>        the allocation operation, the moment kiln returns it
#   id <machine-id>   the VM lease or sandbox, once known
#   fail <reason>     no machine ID: "ended <state>" means the operation ended without one
#   done
set -u
idre() { [ "$1" = sbx ] && echo 'sbx_[a-z0-9]+' || echo 'vml_[a-z0-9]+'; }
resolve() { # kind op timeout
	kiln op status "$2" --wait --timeout "$3" --json 2>/dev/null | python3 -I -c 'import json, re, sys
try:
    o = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
r = o.get("result") or {}
v = r.get("leaseId") or r.get("sandboxId") or r.get("id") or ""
m = re.search(sys.argv[1], v if isinstance(v, str) else "") or re.search(sys.argv[1], json.dumps(r))
if m:
    print("id " + m.group(0))
elif o.get("state") in ("failed", "cancelled", "canceled", "expired"):
    print("ended " + o["state"])' "$(idre "$1")"
}
if [ "${1:-}" = resolve ]; then
	resolve "$2" "$3" "$4"
	exit 0
fi

kind=$1 who=$2 rec=$3 proj=$4 ttl=$5 image=${6:-}
trap '' INT TERM HUP
echo "pid $$" >>"$rec"
finish() { echo done >>"$rec"; exit "$1"; }
case $kind in
vm) out=$(kiln vm lease --project "$proj" --template ubuntu-24.04 --ttl "$ttl" --json --no-wait 2>>"$rec.err") ;;
sbx) out=$(kiln sandbox create --project "$proj" --image "$image" --ttl "$ttl" --json --no-wait 2>>"$rec.err") ;;
*) echo "fail unknown kind $kind" >>"$rec"; finish 2 ;;
esac
op=$(printf '%s' "$out" | grep -oE 'op_[a-z0-9]+' | head -1)
id=$(printf '%s' "$out" | grep -oE "$(idre "$kind")" | head -1)
[ -n "$op" ] && echo "op $op" >>"$rec"
[ -n "$id" ] && echo "id $id" >>"$rec"
if [ -z "$op" ] && [ -z "$id" ]; then
	echo "fail kiln returned no operation for $who: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-200)" >>"$rec"
	finish 1
fi
if [ -z "$id" ]; then
	res=$(resolve "$kind" "$op" 15m)
	case $res in
	"id "*) echo "$res" >>"$rec" ;;
	"ended "*) echo "fail $res" >>"$rec"; finish 1 ;;
	*) echo "fail operation $op still unresolved after 15m" >>"$rec"; finish 1 ;;
	esac
fi
finish 0
