#!/usr/bin/env bash
# HopKey end-to-end tests on Kiln. Runs on the orchestrator and talks to the
# test machines only through the kiln CLI; nothing from the repo runs here.
#
#   scripts/e2e/run.sh [--phases 1,2,3,4,5] [--keep] [--ttl 4h] [--run-id ID]
#                      [--reuse e2e-out/<old-run>]   (debugging: reset and reuse kept machines)
#
# Phases: 1 local only (both VMs), 2 MCP, 3 sync, 4 SSH over Tailscale,
# 5 revocation matrix. 3-5 need a Tailscale auth key in
# $HOP_E2E_TS_AUTHKEY_FILE (default ~/hopkey-test/ts-authkey); the file is only
# ever copied by path (kiln vm put/sandbox write --from-file), never read here.
#
# Output: e2e-out/<run-id>/REPORT.md and results.jsonl.
# Exit: 0 every check passed; 1 assertion failures; 2 harness failure (setup,
# collection, masking, a release); 3 missing coverage (a selected phase or step
# did not finish); 128+n interrupted by signal n.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PHASES=1,2,3,4,5
KEEP=0
TTL=4h
RUN=""
REUSE=""
UBUNTU_IMAGE=${HOP_E2E_UBUNTU_IMAGE:-docker.io/library/ubuntu@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c}
KEYFILE=${HOP_E2E_TS_AUTHKEY_FILE:-$HOME/hopkey-test/ts-authkey}
CLOCK_MAX=0.5 # largest A-B clock offset (plus its uncertainty) the timing checks accept

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
	case $1 in
	--phases) PHASES=$2; shift 2 ;;
	--keep) KEEP=1; shift ;;
	--ttl) TTL=$2; shift 2 ;;
	--run-id) RUN=$2; shift 2 ;;
	--reuse) REUSE=$2; shift 2 ;;
	-h | --help) usage 0 ;;
	*) echo "unknown argument: $1" >&2; usage 2 ;;
	esac
done
[ -n "$RUN" ] || RUN="$(date -u +%m%d%H%M)-$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')"
want() { case ",$PHASES," in *",$1,"*) return 0 ;; esac; return 1; }
NEED_TS=0
for p in 3 4 5; do want $p && NEED_TS=1; done
NEED_SBX=0
for p in 4 5; do want $p && NEED_SBX=1; done

OUT=$REPO/e2e-out/$RUN
mkdir -p "$OUT/bin" "$OUT/results" "$OUT/logs"
install -d -m 0700 "$OUT/tmp"
DLOG=$OUT/driver.log
DRES=$OUT/results/driver.jsonl
STEPS=$OUT/steps.jsonl # step and phase start/end records: report.py checks coverage with them
ALLOC=$OUT/alloc.state  # every machine this run asked for, written the moment its ID exists
: >"$DRES"; : >"$STEPS"; : >"$ALLOC"
T_START=$(date +%s)
NODE=hk-$(echo "$RUN" | tr -cd 'a-z0-9')
EMAIL="hoptest+$(echo "$RUN" | tr -cd 'a-z0-9')@example.com"
CUR_PHASE=0
CLOCK_OFF=0 # B's clock minus A's, measured once the tailnet is up

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$DLOG" >&2; }

# A check recorded by the driver (cross-machine timings, harness failures).
dcheck() { # phase id name status detail [bug]
	python3 -I -c 'import json,sys,time
p,i,n,s,d=sys.argv[1:6]; b=sys.argv[6] if len(sys.argv)>6 and sys.argv[6] else None
print(json.dumps({"run":sys.argv[7],"phase":int(p),"machine":"driver","id":"p%s.%s"%(p,i),"name":n,"status":s,"detail":d,"evidence":"","bug":b,"ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())}))' \
		"$1" "$2" "$3" "$4" "$5" "${6:-}" "$RUN" >>"$DRES"
	log "check $4 p$1.$2 $3 ${5:+| $5}"
}
die() { log "FATAL: $*"; dcheck "$CUR_PHASE" harness.fatal "the run gets through setup and every selected phase" fail "$*" harness; exit 2; }
step_rec() { # phase who step job event rc
	printf '{"phase":%s,"who":"%s","step":"%s","job":"%s","event":"%s","rc":"%s","ts":%s}\n' "$1" "$2" "$3" "$4" "$5" "$6" "$(date +%s)" >>"$STEPS"
}

if [ "$NEED_TS" = 1 ] && ! test -s "$KEYFILE"; then
	die "phases ${PHASES} need a Tailscale auth key (reusable, ephemeral, tagged tag:hoptest) in $KEYFILE; set HOP_E2E_TS_AUTHKEY_FILE, or run with --phases 1,2"
fi
command -v kiln >/dev/null || die "the kiln CLI is not on PATH"
kiln whoami >/dev/null 2>&1 || die "kiln is not logged in (kiln whoami failed)"
log "run $RUN, phases $PHASES, output $OUT"

# ------------------------------------------------------------------ machines

A="" B="" T1="" T2="" T3="" PUBLISHED=0
MACH=$OUT/machines.env
save_machines() { printf 'A=%s\nB=%s\nT1=%s\nT2=%s\nT3=%s\n' "$A" "$B" "$T1" "$T2" "$T3" >"$MACH"; }

vx() { # vm command-string: stdout of the command (kiln waits at most 8 s)
	kiln vm exec "$1" --command "$2" 2>>"$DLOG"
}
sx() { # sandbox command-string
	kiln sandbox exec "$1" --command "$2" 2>>"$DLOG"
}
q() { printf '%q ' "$@"; }
# Diagnostics from a machine, always masked there first (sandboxes hold no hop secrets; only Tailscale keys are scrubbed).
vtail() { # vm file [bytes]
	vx "$1" "if [ -f /opt/e2e/masklogs.py ]; then python3 /opt/e2e/masklogs.py tail $2 ${3:-600}; else echo '<diagnostics withheld: no masking script on the machine>'; fi" | tr '\n' ' '
}
stail() { # sandbox file [bytes]
	sx "$1" "tail -c ${3:-600} $2 2>&1" | sed -E 's/tskey-[A-Za-z0-9-]{8,}/<TS-AUTHKEY>/g' | tr '\n' ' '
}

# vjob vm phase step cmd... : start a step detached, in hke2e.slice; prints the job name.
vjob() {
	local vm=$1 phase=$2 step=$3; shift 3
	local name="${step//[^a-zA-Z0-9]/-}-$(date +%s%N | tail -c 8)$RANDOM"
	vx "$vm" "systemd-run --unit=hke2e-$name --slice=hke2e.slice --collect --quiet --setenv=E2E_PHASE=$phase --setenv=E2E_STEP=$step /bin/bash /opt/e2e/job.sh $name $(q "$@")" >/dev/null
	step_rec "$phase" "$(whois "$vm")" "$step" "$name" start ""
	echo "$name"
}
# vwait vm job timeout: prints the job's exit code, or "timeout".
vwait() {
	local vm=$1 name=$2 to=${3:-900} t0=$SECONDS rc
	while [ $((SECONDS - t0)) -lt "$to" ]; do
		rc=$(vx "$vm" "cat /var/e2e/jobs/$name.rc 2>/dev/null" | tr -d '[:space:]')
		if [ -n "$rc" ]; then echo "$rc"; return 0; fi
		sleep 3
	done
	echo timeout
}
whois() { case $1 in "$A") echo A ;; "$B") echo B ;; *) echo "$1" ;; esac; }
# vfinish vm job phase step timeout: wait for a job; a crash or timeout is a harness failure (returns 1).
vfinish() {
	local vm=$1 j=$2 phase=$3 step=$4 to=$5 who rc
	who=$(whois "$vm")
	rc=$(vwait "$vm" "$j" "$to")
	step_rec "$phase" "$who" "$step" "$j" end "$rc"
	[ "$rc" = 0 ] && return 0
	dcheck "$phase" "harness.$who.$step" "step $step on $who finished" fail "exit $rc: $(vtail "$vm" "/var/e2e/jobs/$j.out")" harness
	return 1
}
# vrun vm phase step timeout cmd... : a step, waited for.
vrun() {
	local vm=$1 phase=$2 step=$3 to=$4; shift 4
	log "[$(whois "$vm")] p$phase $step: $*"
	local j
	j=$(vjob "$vm" "$phase" "$step" "$@")
	vfinish "$vm" "$j" "$phase" "$step" "$to"
}
py() { echo python3 "/opt/e2e/$1"; } # guest script path
# vsys vm name timeout command: a root command outside hke2e.slice (reset, export); prints its exit code or "timeout".
vsys() {
	local vm=$1 name=$2 to=$3 cmd=$4 t0=$SECONDS rc
	vx "$vm" "rm -f /var/tmp/hk-$name.rc; systemd-run --unit=hksys-$name-$RANDOM --collect --quiet /bin/sh -c $(q "( $cmd ) >/var/tmp/hk-$name.out 2>&1; echo \$? >/var/tmp/hk-$name.rc.tmp && mv /var/tmp/hk-$name.rc.tmp /var/tmp/hk-$name.rc")" >/dev/null
	while [ $((SECONDS - t0)) -lt "$to" ]; do
		rc=$(vx "$vm" "cat /var/tmp/hk-$name.rc 2>/dev/null" | tr -d '[:space:]')
		if [ -n "$rc" ]; then echo "$rc"; return 0; fi
		sleep 2
	done
	echo timeout
}

boot_id() { vx "$1" "cat /proc/sys/kernel/random/boot_id" | tr -d '[:space:]'; }
REBOOT_FROM=""
reboot_start() { # vm
	REBOOT_FROM=$(boot_id "$1")
	log "rebooting $(whois "$1") (boot $REBOOT_FROM)"
	vx "$1" "nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 &" >/dev/null
}
reboot_finish() { # vm phase: wait for a new boot, tailscale (if used) and the user runtime dir
	local vm=$1 t0=$SECONDS now=""
	sleep 10
	while [ $((SECONDS - t0)) -lt 300 ]; do
		now=$(boot_id "$vm")
		[ -n "$now" ] && [ "$now" != "$REBOOT_FROM" ] && break
		sleep 5
	done
	if [ -z "$now" ] || [ "$now" = "$REBOOT_FROM" ] || [ -z "$REBOOT_FROM" ]; then
		# Every "after a reboot" check that follows would prove nothing.
		dcheck "$2" "harness.reboot-$(whois "$vm")" "$(whois "$vm") rebooted" fail "boot id before '$REBOOT_FROM', after '$now'" harness
		return 1
	fi
	if [ "$NEED_TS" = 1 ]; then
		for i in $(seq 1 30); do
			[ -n "$(vx "$vm" "tailscale ip -4 2>/dev/null | head -1")" ] && break
			sleep 3
		done
	fi
	vx "$vm" "for i in \$(seq 1 20); do [ -d /run/user/\$(id -u tester) ] && break; sleep 0.3; done; uptime" >>"$DLOG"
	log "$(whois "$vm") is back after $((SECONDS - t0))s"
}
reboot_vm() { reboot_start "$1"; reboot_finish "$1" "$2"; } # vm phase

# ------------------------------------------------------------------ allocation and cleanup

# kiln calls that allocate or release run in their own session, so a Ctrl-C
# at the terminal reaches only this script, never a half-done allocation.
op_lease() { # op timeout: the lease ID an operation produced, once it finishes
	setsid -w kiln op status "$1" --wait --timeout "$2" --json 2>>"$DLOG" | python3 -I -c 'import json,sys
try: print(json.load(sys.stdin).get("result",{}).get("leaseId",""))
except Exception: print("")'
}
alloc_vm() { # who
	local who=$1 op id
	op=$(setsid -w kiln vm lease --project "$REPO" --template ubuntu-24.04 --ttl "$TTL" --json --no-wait 2>>"$DLOG" | grep -o 'op_[a-z0-9]*' | head -1)
	[ -n "$op" ] || { log "could not start the lease for CLI-$who"; return 1; }
	echo "vmop $who $op" >>"$ALLOC"
	id=$(op_lease "$op" 15m)
	[ -n "$id" ] || { log "lease operation $op for CLI-$who gave no VM"; return 1; }
	echo "vm $who $id" >>"$ALLOC"
}
alloc_sbx() { # who
	local who=$1 id
	id=$(setsid -w kiln sandbox create --project "$REPO" --image "$UBUNTU_IMAGE" --ttl "$TTL" --json 2>>"$DLOG" | grep -o 'sbx_[a-z0-9]*' | head -1)
	[ -n "$id" ] || { log "could not create sandbox $who"; return 1; }
	echo "sbx $who $id" >>"$ALLOC"
}
read_allocs() { # set A B T1 T2 T3 from the allocation state
	local kind who id
	while read -r kind who id; do
		case $kind in vm | sbx) printf -v "$who" '%s' "$id" ;; esac
	done <"$ALLOC"
}
ALLOC_PIDS=() BG_PIDS=()
reconcile_allocs() {
	local p t0=$SECONDS kind who op
	# Allocations still under way finish first; each writes its ID to ALLOC.
	for p in "${ALLOC_PIDS[@]}"; do
		while kill -0 "$p" 2>/dev/null && [ $((SECONDS - t0)) -lt 1200 ]; do
			log "waiting for allocation job $p to finish, so its machine can be released"
			wait "$p" 2>/dev/null || sleep 1
		done
	done
	# A lease operation with no VM recorded (its job was cut short): ask the operation.
	while read -r kind who op; do
		[ "$kind" = vmop ] || continue
		grep -q "^vm $who " "$ALLOC" && continue
		log "reconciling lease operation $op for CLI-$who"
		id=$(op_lease "$op" 10m)
		if [ -n "$id" ]; then echo "vm $who $id" >>"$ALLOC"; else log "WARNING: operation $op gave no VM; check: kiln op status $op"; fi
	done < <(cat "$ALLOC")
	read_allocs
}
# Auth key copies: recorded before each copy, deleted and checked at cleanup on every machine, also with --keep.
key_copied() { echo "key $1 $2 $3" >>"$ALLOC"; } # vm|sbx id path
delete_keys() {
	local kind m path st left=0
	while read -r _ kind m path; do
		if [ "$kind" = vm ]; then
			st=$(vx "$m" "rm -f $path; test -e $path && echo present || echo gone" | tr -d '[:space:]')
		else
			st=$(sx "$m" "rm -f $path; test -e $path && echo present || echo gone" | tr -d '[:space:]')
		fi
		if [ "$st" = gone ]; then
			log "auth key gone from $m:$path"
		else
			left=1
			dcheck 0 "harness.authkey-$m" "the Tailscale auth key is deleted from $m" fail "after rm: '$st' at $path" harness
		fi
	done < <(grep '^key ' "$ALLOC")
	return $left
}
RELEASE_FAIL=0
release_all() {
	local kind who id i
	while read -r kind who id; do
		case $kind in
		vm) for i in 1 2 3; do setsid -w kiln vm release "$id" >>"$DLOG" 2>&1 && break; sleep 5; done ;;
		sbx) for i in 1 2 3; do setsid -w kiln sandbox destroy "$id" >>"$DLOG" 2>&1 && break; sleep 5; done ;;
		*) continue ;;
		esac
		log "release $kind $who $id: try $i"
	done < <(grep -E '^(vm|sbx) ' "$ALLOC" | sort -u)
}
verify_released() { # every machine of this run is gone; warns about other live ones made since the start
	local v s
	v=$(kiln vm list --json 2>>"$DLOG") || { log "WARNING: kiln vm list failed"; RELEASE_FAIL=1; return; }
	s=$(kiln sandbox list --json 2>>"$DLOG") || { log "WARNING: kiln sandbox list failed"; RELEASE_FAIL=1; return; }
	python3 -I - "$ALLOC" "$T_START" "$v" "$s" <<'EOF' | tee -a "$DLOG" >&2
import datetime, json, sys
alloc, t0 = sys.argv[1], int(sys.argv[2])
ours = {l.split()[2] for l in open(alloc) if l.split()[:1] in (['vm'], ['sbx']) and len(l.split()) > 2}
gone = ('released', 'destroyed', 'expired', 'failed')
live, ours_live, seen = [], [], set()
for kind, blob, key in (('vm', sys.argv[3], 'leases'), ('sbx', sys.argv[4], 'sandboxes')):
    try:
        items = json.loads(blob).get(key, [])
    except ValueError:
        items = []
        print('WARNING: could not parse the %s list' % kind)
    for it in items:
        st = it.get('state', '')
        seen.add(it.get('id'))
        if any(st.startswith(g) for g in gone):
            continue
        if it.get('id') in ours:
            ours_live.append('%s %s' % (it['id'], st))
        else:
            try:
                made = datetime.datetime.fromisoformat(it.get('createdAt', '').replace('Z', '+00:00')).timestamp()
            except ValueError:
                made = 0
            if made >= t0 - 60:
                live.append('%s %s' % (it.get('id'), st))
# A machine missing from the lists is not proven gone (another kiln identity, for one).
missing = sorted(ours - seen)
print('machines of this run still live: %s; not in the lists: %s' % (ours_live or 'none', missing or 'none'))
if live:
    print('WARNING: live machines created since this run started that it has no record of: %s' % live)
sys.exit(1 if ours_live or missing else 0)
EOF
	[ "${PIPESTATUS[0]}" = 0 ] || RELEASE_FAIL=1
}
stop_bg() { # stop setup jobs still running against the machines
	local p
	for p in "${BG_PIDS[@]}"; do
		kill -0 "$p" 2>/dev/null || continue
		pkill -TERM -P "$p" 2>/dev/null
		kill -TERM "$p" 2>/dev/null
	done
}

SETUP_STARTED=0
collect() { # results and masked logs from each CLI VM
	local who vm rc parts got sum n
	for who in A B; do
		vm=${!who}
		[ -n "$vm" ] || continue
		if [ "$HURRY" = 1 ]; then
			dcheck 0 "harness.collect-$who" "results and logs collected from $who" fail "skipped: interrupted during cleanup" harness
			continue
		fi
		# Stop every writer (jobs and what they started), then mask into a separate export directory.
		rc=$(vsys "$vm" "export-$RUN" 180 "systemctl stop hke2e.slice; if systemctl is-active -q hke2e.slice; then echo not-quiesced; fi; python3 /opt/e2e/masklogs.py export")
		vx "$vm" "cat /var/tmp/hk-export-$RUN.out" >"$OUT/tmp/export-$who.out"
		grep -q not-quiesced "$OUT/tmp/export-$who.out" &&
			dcheck 0 "harness.quiesce-$who" "every suite job on $who stopped before the export" fail "hke2e.slice still active" harness
		case $rc in
		0) ;;
		3) dcheck 0 "harness.mask-$who" "every log on $who masked and exported" fail "$(grep -c '^not exported' "$OUT/tmp/export-$who.out") files withheld: $(grep '^not exported' "$OUT/tmp/export-$who.out" | head -5 | tr '\n' ' ')" harness ;;
		*)
			dcheck 0 "harness.mask-$who" "every log on $who masked and exported" fail "export failed ($rc): nothing exported" harness
			continue
			;;
		esac
		parts=$(vx "$vm" "cd /var/e2e/export && tar czf /tmp/hk-logs.tgz . && sha256sum /tmp/hk-logs.tgz | cut -d' ' -f1 && base64 -w0 /tmp/hk-logs.tgz > /tmp/hk-logs.b64 && rm -rf /tmp/hk-logs.d && mkdir /tmp/hk-logs.d && split -b 200000 /tmp/hk-logs.b64 /tmp/hk-logs.d/p. && ls /tmp/hk-logs.d")
		sum=$(echo "$parts" | head -1)
		: >"$OUT/tmp/logs.b64"
		n=0
		for p in $(echo "$parts" | tail -n +2); do
			[ "$HURRY" = 1 ] && break
			kiln vm get "$vm" "/tmp/hk-logs.d/$p" --max-bytes 262144 -o "$OUT/tmp/part" 2>>"$DLOG" && cat "$OUT/tmp/part" >>"$OUT/tmp/logs.b64" && n=$((n + 1))
		done
		base64 -d "$OUT/tmp/logs.b64" >"$OUT/tmp/logs.tgz" 2>/dev/null
		got=$(sha256sum "$OUT/tmp/logs.tgz" | cut -d' ' -f1)
		if [ -z "$sum" ] || [ "$got" != "$sum" ]; then
			dcheck 0 "harness.collect-$who" "results and logs collected from $who" fail "the archive did not arrive whole ($n parts)" harness
			continue
		fi
		mkdir -p "$OUT/logs/$who"
		tar xzf "$OUT/tmp/logs.tgz" -C "$OUT/logs/$who" 2>>"$DLOG" || { dcheck 0 "harness.collect-$who" "results and logs collected from $who" fail "tar failed" harness; continue; }
		for f in "$OUT/logs/$who"/results/*.jsonl; do
			[ -e "$f" ] && cp "$f" "$OUT/results/$(basename "${f%.jsonl}")-$who.jsonl"
		done
		log "collected $who: $(head -1 "$OUT/tmp/export-$who.out")"
	done
}

CLEANED=0 HURRY=0 INTERRUPTED=0
on_signal() { INTERRUPTED=$1; log "interrupted (signal $1)"; exit $((128 + $1)); }
trap 'on_signal 2' INT
trap 'on_signal 15' TERM
trap 'on_signal 1' HUP
cleanup() {
	local rc=$? code
	[ "$CLEANED" = 1 ] && return
	CLEANED=1
	# Interrupts stay trapped until the end: another one only skips the collection, never the releases.
	trap 'HURRY=1; log "interrupt during cleanup: skipping what is left of the collection; machines are still released"' INT TERM HUP
	stop_bg
	reconcile_allocs
	save_machines
	delete_keys
	if [ "$SETUP_STARTED" = 1 ]; then
		log "collecting results"
		collect
	fi
	rm -f "$OUT/verdict"
	python3 -I "$HERE/report.py" "$OUT" "$RUN" "$PHASES" "$T_START" "$(date +%s)" "$MACH" >>"$DLOG" 2>&1 || log "report.py failed"
	code=$(cat "$OUT/verdict" 2>/dev/null || echo 2)
	if [ "$KEEP" = 1 ]; then
		log "--keep: machines left up: CLI-A $A, CLI-B $B, T1 $T1, T2 $T2, T3 $T3 (release with kiln vm release / kiln sandbox destroy)"
	else
		release_all
		verify_released
	fi
	[ "$PUBLISHED" = 1 ] && kiln unpublish --project "$REPO" >>"$DLOG" 2>&1
	rm -rf "$OUT/tmp" "$SECTMP"
	[ "$RELEASE_FAIL" = 1 ] && [ "$code" -lt 2 ] && code=2
	[ "$INTERRUPTED" != 0 ] && code=$((128 + INTERRUPTED))
	log "report: $OUT/REPORT.md ($(($(date +%s) - T_START))s), exit $code (driver exit $rc)"
	exit "$code"
}
# Secrets in transit between machines: a private directory outside e2e-out.
SECTMP=$(mktemp -d "${TMPDIR:-/tmp}/hk-e2e-sec.XXXXXX") || die "mktemp failed"
chmod 700 "$SECTMP"
trap cleanup EXIT

# ------------------------------------------------------------------ build

log "building hop and hop-server (linux-amd64) on Kiln"
COMMIT=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
git -C "$REPO" diff --quiet HEAD 2>/dev/null || COMMIT="$COMMIT+dirty"
BUILD_CMD='export PATH=$PATH:/usr/local/go/bin GOCACHE=$PWD/.check-cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64; mkdir -p /artifacts && LDF="-s -w -X github.com/dalyem/hopkey/internal/version.Version='$COMMIT'" && go build -trimpath -ldflags "$LDF" -o /artifacts/hop ./cmd/hop && go build -trimpath -ldflags "$LDF" -o /artifacts/hop-server ./cmd/hop-server && cd /artifacts && sha256sum hop hop-server > SHA256SUMS && cat SHA256SUMS'
kiln checks run --project "$REPO" --json --timeout 20m --command "$BUILD_CMD" >"$OUT/build.json" 2>>"$DLOG" || die "build failed: see $OUT/build.json"
OP=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["operation"]["id"])' "$OUT/build.json")
for f in hop hop-server SHA256SUMS; do
	kiln artifacts get "$OP" "$f" -o "$OUT/bin/$f" 2>>"$DLOG" || die "could not fetch artifact $f from $OP"
done
(cd "$OUT/bin" && sha256sum -c SHA256SUMS >>"$DLOG" 2>&1) || die "artifact checksum mismatch"
SHA_HOP=$(awk '$2=="hop"{print $1}' "$OUT/bin/SHA256SUMS")
SHA_SRV=$(awk '$2=="hop-server"{print $1}' "$OUT/bin/SHA256SUMS")
log "built $COMMIT: hop $SHA_HOP, hop-server $SHA_SRV (job $OP)"

# ------------------------------------------------------------------ provision

if [ -n "$REUSE" ]; then
	. "$REUSE/machines.env" || die "no $REUSE/machines.env"
	log "reusing CLI-A $A, CLI-B $B${T1:+, T1 $T1, T2 $T2, T3 $T3}"
	for who in A B T1 T2 T3; do
		[ -n "${!who}" ] || continue
		case $who in T*) echo "sbx $who ${!who}" ;; *) echo "vm $who ${!who}" ;; esac >>"$ALLOC"
	done
else
	log "leasing CLI-A and CLI-B$([ "$NEED_SBX" = 1 ] && echo ", creating three sandboxes")"
	alloc_vm A & ALLOC_PIDS+=($!)
	alloc_vm B & ALLOC_PIDS+=($!)
	if [ "$NEED_SBX" = 1 ]; then
		for t in T1 T2 T3; do alloc_sbx $t & ALLOC_PIDS+=($!); done
	fi
	for p in "${ALLOC_PIDS[@]}"; do wait "$p"; done
	read_allocs
fi
save_machines
log "CLI-A $A, CLI-B $B${T1:+, T1 $T1, T2 $T2, T3 $T3}"
[ -n "$A" ] && [ -n "$B" ] || die "could not lease two VMs"
if [ "$NEED_SBX" = 1 ] && { [ -z "$T1" ] || [ -z "$T2" ] || [ -z "$T3" ]; }; then die "could not create three sandboxes"; fi

# Upload a local file in <=500 KB base64 chunks of its gzip, then verify sha256 there.
upload() { # vm src dst sha mode
	local vm=$1 src=$2 dst=$3 sha=$4 mode=${5:-0755} d c n=0
	d=$OUT/tmp/up.$(basename "$src").$vm
	rm -rf "$d"; mkdir -p "$d"
	gzip -9c "$src" | base64 -w0 | split -b 500000 -a 3 - "$d/c."
	vx "$vm" "rm -rf /var/e2e/up/$(basename "$src"); mkdir -p /var/e2e/up/$(basename "$src")" >/dev/null
	for c in "$d"/c.*; do
		kiln vm put "$vm" "/var/e2e/up/$(basename "$src")/$(basename "$c")" --from-file "$c" >>"$DLOG" 2>&1 || return 1
		n=$((n + 1))
	done
	local got
	got=$(vx "$vm" "cat /var/e2e/up/$(basename "$src")/c.* | base64 -d | gunzip > $dst.new && chmod $mode $dst.new && mv $dst.new $dst && sha256sum $dst | cut -d' ' -f1")
	[ "$got" = "$sha" ] || { log "sha256 mismatch for $dst on $vm: '$got' != '$sha'"; return 1; }
	log "uploaded $(basename "$src") to $vm in $n chunks, sha256 ok"
}
tar czf "$OUT/tmp/guest.tgz" -C "$HERE/guest" .
SHA_GUEST=$(sha256sum "$OUT/tmp/guest.tgz" | cut -d' ' -f1)

setup_vm() { # who vm
	local who=$1 vm=$2 j rc
	for i in $(seq 1 40); do vx "$vm" "true" >/dev/null && break; sleep 3; done
	upload "$vm" "$OUT/tmp/guest.tgz" /var/tmp/guest.tgz "$SHA_GUEST" 0644 || return 1
	vx "$vm" "rm -rf /opt/e2e && mkdir -p /opt/e2e && tar xzf /var/tmp/guest.tgz -C /opt/e2e && chmod 755 /opt/e2e/*.sh /opt/e2e/*.py" >/dev/null
	if [ -n "$REUSE" ]; then
		rc=$(vsys "$vm" "reset-$RUN" 180 "/opt/e2e/reset-vm.sh")
		[ "$rc" = 0 ] || { log "reset-vm on $who failed ($rc): $(vtail "$vm" "/var/tmp/hk-reset-$RUN.out" 400)"; return 1; }
	fi
	upload "$vm" "$OUT/bin/hop" /usr/local/bin/hop "$SHA_HOP" || return 1
	if [ "$who" = A ] && [ "$NEED_TS" = 1 ]; then upload "$vm" "$OUT/bin/hop-server" /usr/local/bin/hop-server "$SHA_SRV" || return 1; fi
	vx "$vm" "mkdir -p /var/e2e/jobs" >/dev/null
	j=$(vjob "$vm" 0 setup /bin/bash /opt/e2e/setup-vm.sh "$who" "$RUN" "$NEED_TS")
	rc=$(vwait "$vm" "$j" 900)
	step_rec 0 "$who" setup "$j" end "$rc"
	[ "$rc" = 0 ] || { log "setup-vm on $who failed ($rc): $(vtail "$vm" "/var/e2e/jobs/$j.out" 400)"; return 1; }
	log "CLI-$who set up: $(vx "$vm" "hop --version 2>&1 | head -1; echo ntp=\$(cat /var/e2e/state/ntp)" | tr '\n' ' ')"
}
setup_sbx() { # name id
	local name=$1 id=$2
	sx "$id" "rm -f /var/e2e/setup.done /var/e2e/tsup.done" >/dev/null
	for f in setup-target.sh tsup.sh; do kiln sandbox write "$id" "/root/$f" --from-file "$HERE/guest/$f" >>"$DLOG" 2>&1 || return 1; done
	kiln sandbox exec "$id" --background --timeout-seconds 1500 --command "sh /root/setup-target.sh $name $RUN" >>"$DLOG" 2>&1 || return 1
}

log "setting up the machines"
SETUP_STARTED=1
setup_vm A "$A" >"$OUT/tmp/setupA.log" 2>&1 &
PA=$!
setup_vm B "$B" >"$OUT/tmp/setupB.log" 2>&1 &
PB=$!
BG_PIDS+=("$PA" "$PB")
if [ "$NEED_SBX" = 1 ]; then setup_sbx t1 "$T1" && setup_sbx t2 "$T2" && setup_sbx t3 "$T3" || die "sandbox setup could not start"; fi
wait $PA || die "CLI-A setup failed: $(cat "$OUT/tmp/setupA.log")"
wait $PB || die "CLI-B setup failed: $(cat "$OUT/tmp/setupB.log")"
cat "$OUT/tmp/setupA.log" "$OUT/tmp/setupB.log" >>"$DLOG"

# Public keys between machines (never private material).
kiln vm get "$A" /var/e2e/state/testkey.pub -o "$OUT/tmp/testkey.pub" 2>>"$DLOG" || die "no testkey.pub on A"
kiln vm get "$B" /var/e2e/state/bkey.pub -o "$OUT/tmp/bkey.pub" 2>>"$DLOG" || die "no bkey.pub on B"
kiln vm put "$A" /var/e2e/state/bkey.pub --from-file "$OUT/tmp/bkey.pub" >>"$DLOG" 2>&1 || die "could not copy bkey.pub to A"
kiln vm put "$B" /var/e2e/state/testkey-A.pub --from-file "$OUT/tmp/testkey.pub" >>"$DLOG" 2>&1 || die "could not copy testkey.pub to B"
# B's target accepts A's vault key: phase 4 logs in to B from A over the tailnet (and the clock probe uses it).
vx "$B" "cat /var/e2e/state/testkey-A.pub >> /home/target/.ssh/authorized_keys" >/dev/null

# ------------------------------------------------------------------ tailnet and server

envline() { echo "$1=$2"; }
if [ "$NEED_SBX" = 1 ]; then
	log "waiting for the sandbox targets"
	for s in "$T1" "$T2" "$T3"; do
		st=""
		for i in $(seq 1 120); do
			st=$(sx "$s" "cat /var/e2e/setup.done 2>/dev/null")
			case $st in *" $RUN") break ;; esac
			sleep 5
		done
		[ "$st" = "ok $RUN" ] || die "sandbox $s setup failed ($st): $(stail "$s" /var/e2e/setup.log 400)"
		kiln sandbox write "$s" /var/e2e/authorized_keys --from-file "$OUT/tmp/testkey.pub" >>"$DLOG" 2>&1 || die "could not copy testkey.pub to $s"
		sx "$s" "for u in deploy deploy2; do install -d -m 700 -o \$u -g \$u /home/\$u/.ssh; install -m 600 -o \$u -g \$u /var/e2e/authorized_keys /home/\$u/.ssh/authorized_keys; done; echo ok" >>"$DLOG"
	done
	kiln sandbox read "$T2" /var/e2e/internal-hostkey.pub -o "$OUT/tmp/t2-internal.pub" 2>>"$DLOG" || die "no internal host key on T2"
	kiln vm put "$A" /var/e2e/state/t2-internal.pub --from-file "$OUT/tmp/t2-internal.pub" >>"$DLOG" 2>&1 || die "could not copy the T2 host key to A"
fi

if [ "$NEED_TS" = 1 ]; then
	log "joining the tailnet as $NODE-*"
	declare -A TSJOB
	for who in A B; do
		vm=${!who}
		vx "$vm" "rm -f /var/e2e/tsup.done" >/dev/null
		key_copied vm "$vm" /root/e2e/ts-authkey
		kiln vm put "$vm" /root/e2e/ts-authkey --from-file "$KEYFILE" >>"$DLOG" 2>&1 || die "could not copy the auth key to $who"
		TSJOB[$who]=$(vjob "$vm" 0 tsup sh /opt/e2e/tsup.sh /root/e2e/ts-authkey "$NODE-$(echo $who | tr A-Z a-z)" "$RUN")
	done
	if [ "$NEED_SBX" = 1 ]; then
		for t in 1 2 3; do
			s=$(eval echo \$T$t)
			key_copied sbx "$s" /root/ts-authkey
			kiln sandbox write "$s" /root/ts-authkey --from-file "$KEYFILE" >>"$DLOG" 2>&1 || die "could not copy the auth key to T$t"
			kiln sandbox exec "$s" --background --timeout-seconds 120 --command "sh /root/tsup.sh /root/ts-authkey $NODE-t$t $RUN /run/tailscale/tailscaled.sock" >>"$DLOG" 2>&1 ||
				die "could not start tailscale up on T$t"
		done
	fi
	for who in A B; do
		vfinish "${!who}" "${TSJOB[$who]}" 0 tsup 120 || die "tailscale up failed on $who: $(vtail "${!who}" /var/e2e/tsup.log) $(vx "${!who}" "cat /var/e2e/tsup.done")"
		case $(vx "${!who}" "cat /var/e2e/tsup.done") in "gen=$RUN rc=0"*) ;; *) die "tailscale up on $who left no marker for this run" ;; esac
		left=$(vx "${!who}" "test -e /root/e2e/ts-authkey && echo present || echo gone")
		[ "$left" = gone ] || die "the auth key file is still on $who"
	done
	if [ "$NEED_SBX" = 1 ]; then
		for t in 1 2 3; do
			s=$(eval echo \$T$t)
			d=""
			for i in $(seq 1 30); do d=$(sx "$s" "cat /var/e2e/tsup.done 2>/dev/null"); [ -n "$d" ] && break; sleep 3; done
			case $d in "gen=$RUN rc=0"*) ;; *) die "tailscale up failed on T$t: $d $(stail "$s" /var/e2e/tsup.log)" ;; esac
			[ "$(sx "$s" "test -e /root/ts-authkey && echo present || echo gone")" = gone ] || die "the auth key file is still on T$t"
		done
	fi
	PEERS="$NODE-b"
	[ "$NEED_SBX" = 1 ] && PEERS="$PEERS $NODE-t1 $NODE-t2 $NODE-t3"
	j=$(vjob "$A" 0 tswait sh /opt/e2e/tswait.sh 180 $PEERS)
	vfinish "$A" "$j" 0 tswait 240 || die "tailnet peers are not reachable from A ($(vtail "$A" "/var/e2e/jobs/$j.out")); the ACL must allow tag:hoptest -> tag:hoptest"
	vx "$A" "python3 /opt/e2e/tsnames.py $NODE" >"$OUT/tmp/tsenv"
	grep -q '^HK_A_IP=' "$OUT/tmp/tsenv" && grep -q '^HK_B_IP=' "$OUT/tmp/tsenv" || die "could not read the tailnet names: $(cat "$OUT/tmp/tsenv")"
	SIP=$(sed -n 's/^HK_A_IP=//p' "$OUT/tmp/tsenv")
	BIP=$(sed -n 's/^HK_B_IP=//p' "$OUT/tmp/tsenv")
	{ cat "$OUT/tmp/tsenv"; envline HK_SERVER_IP "$SIP"; envline HK_SERVER_URL "https://$SIP:8443"; envline HK_EMAIL "$EMAIL"; envline HK_RUN "$RUN"; } >"$OUT/tmp/env"
	for who in A B; do kiln vm put "${!who}" /etc/hk-e2e/env --from-file "$OUT/tmp/env" >>"$DLOG" 2>&1 || die "could not copy the env file to $who"; done
	cp "$OUT/tmp/env" "$OUT/tailnet.env"
	log "tailnet: $(tr '\n' ' ' <"$OUT/tmp/env")"

	log "starting the throwaway hop-server on CLI-A at https://$SIP:8443"
	j=$(vjob "$A" 0 server bash /opt/e2e/server.sh "$SIP" "$EMAIL")
	vfinish "$A" "$j" 0 server 120 || die "hop-server did not start: $(vtail "$A" "/var/e2e/jobs/$j.out")"
	kiln vm get "$A" /var/e2e/state/ca.crt -o "$OUT/tmp/ca.crt" 2>>"$DLOG" || die "no CA certificate"
	kiln vm put "$B" /usr/local/share/ca-certificates/hk-e2e-ca.crt --from-file "$OUT/tmp/ca.crt" >>"$DLOG" 2>&1 || die "could not copy the CA to B"
	vx "$B" "update-ca-certificates >/dev/null 2>&1; curl -fsS -m 8 https://$SIP:8443/v1/healthz" >>"$DLOG" || die "CLI-B cannot reach the server over the tailnet"
fi

# Clock offset between A and B (cross-machine timings depend on it). Prints "offset rtt" or nothing.
clock_measure() { # name phase
	local j st
	j=$(vjob "$A" "$2" "$1" $(py clockoff.py) "$1" "$BIP")
	vfinish "$A" "$j" "$2" "$1" 90 || return 1
	st=$(vx "$A" "cat /var/e2e/state/$1")
	python3 -I -c 'import json,sys
try:
    v = json.loads(sys.argv[1]); print("%.4f %.4f %d" % (v["offset"], v["rtt"], v["samples"]))
except Exception:
    pass' "$st"
}
clock_check() { # name phase id label
	local m off rtt n st
	m=$(clock_measure "$1" "$2")
	if [ -z "$m" ]; then
		dcheck "$2" "$3" "$4" fail "no measurement" harness
		return 1
	fi
	read -r off rtt n <<<"$m"
	st=$(python3 -I -c 'import sys; o,r,m=map(float,sys.argv[1:4]); print("pass" if abs(o)+r/2<=m else "fail")' "$off" "$rtt" "$CLOCK_MAX")
	dcheck "$2" "$3" "$4" "$st" "B minus A: ${off}s, round trip ${rtt}s, $n samples, limit ${CLOCK_MAX}s" "$([ "$st" = pass ] || echo harness)"
	CLOCK_OFF=$off
}
if [ "$NEED_TS" = 1 ]; then
	clock_check clock-start 0 clock-start "the clocks of A and B agree within ${CLOCK_MAX}s (offset plus half the round trip)"
fi

# Secrets between machines: through a private temp directory, never on a command line.
copy_secret() { # name from-vm to-vm
	local name=$1 f rc
	f=$(mktemp "$SECTMP/sec.XXXXXX") || return 1
	(
		trap 'rm -f "$f"' EXIT
		trap 'exit 130' INT TERM
		kiln vm get "$2" "/root/e2e/sec/$name" -o "$f" 2>>"$DLOG" || exit 1
		[ -s "$f" ] || exit 1
		kiln vm put "$3" "/root/e2e/sec/.$name.part" --from-file "$f" >>"$DLOG" 2>&1 || exit 1
		r=$(vx "$3" "chmod 600 /root/e2e/sec/.$name.part && [ \$(stat -c %s /root/e2e/sec/.$name.part) = $(stat -c %s "$f") ] && mv /root/e2e/sec/.$name.part /root/e2e/sec/$name && echo moved")
		[ "$r" = moved ]
	)
	rc=$?
	rm -f "$f"
	[ "$rc" = 0 ] || dcheck "$CUR_PHASE" "harness.copy-$name" "the secret $name is copied from $(whois "$2") to $(whois "$3")" fail "transfer failed" harness
	return $rc
}
xfer() { # from-vm path to-vm path (not secret)
	local f rc
	f=$(mktemp "$SECTMP/xfer.XXXXXX") || return 1
	kiln vm get "$1" "$2" -o "$f" 2>>"$DLOG" && kiln vm put "$3" "$4" --from-file "$f" >>"$DLOG" 2>&1
	rc=$?
	rm -f "$f"
	[ "$rc" = 0 ] || dcheck "$CUR_PHASE" "harness.xfer-$(basename "$2")" "$2 is copied from $(whois "$1") to $(whois "$3")" fail "transfer failed" harness
	return $rc
}

offset() { # W C: W's clock minus C's, from the measured B-minus-A offset
	case "$1$2" in BA) echo "$CLOCK_OFF" ;; AB) python3 -I -c 'import sys; print(-float(sys.argv[1]))' "$CLOCK_OFF" ;; *) echo 0 ;; esac
}
# judge limit offset change-json watch-json...: "pass|fail|harness detail" for a change on C seen on W.
# A missing or malformed state, a watch that held before the change, or a
# negative delta is a harness failure, never a pass.
judge() {
	python3 -I - "$@" <<'EOF'
import json, sys
limit, off = float(sys.argv[1]), float(sys.argv[2])
def out(st, msg):
    print(st, msg)
    sys.exit(0)
def parse(s, what):
    if not s.strip():
        out('harness', '%s: no state written' % what)
    try:
        v = json.loads(s)
    except ValueError:
        out('harness', '%s: malformed state %r' % (what, s[:80]))
    if not isinstance(v, dict):
        out('harness', '%s: malformed state %r' % (what, s[:80]))
    return v
ch = parse(sys.argv[3], 'change')
if ch.get('ok') is False:
    out('harness', 'the change step reports it did not take effect')
if 'rc' in ch and ch['rc'] != 0:
    out('fail', 'change failed: %s' % ch.get('out', ch['rc']))
t = ch.get('done', ch.get('t'))
if not isinstance(t, (int, float)):
    out('harness', 'change: no time recorded')
seen = []
for i, w in enumerate(sys.argv[4:]):
    v = parse(w, 'watch %d' % (i + 1))
    if v.get('initially'):
        out('harness', 'watch %d: the condition held before the change' % (i + 1))
    if not isinstance(v.get('seen'), (int, float)):
        out('fail', 'not seen (watch %d: %s)' % (i + 1, 'timed out' if 'timeout' in v else 'no sighting'))
    seen.append(v['seen'])
d = max(seen) - off - t
if d < -0.25:
    out('harness', 'implausible delta %.2fs (clock offset %.3fs applied)' % (d, off))
out('pass' if d <= limit else 'fail', '%.2fs (clock offset %.3fs applied)' % (d, off))
EOF
}
jcheck() { # phase id name judge-output
	local st det
	read -r st det <<<"$4"
	case $st in
	pass | fail) dcheck "$1" "$2" "$3" "$st" "$det" ;;
	*) dcheck "$1" "$2" "$3" fail "${det:-no verdict}" harness ;;
	esac
}

# Cross-machine propagation: watcher on W, change on C, timed with the measured clock offset.
prop() { # id W C spec hop-args...
	local id=$1 W=$2 C=$3 spec=$4; shift 4
	local jw jm s m
	jw=$(vjob "${!W}" 3 "watch-$id" $(py syncops.py) watch "$id" "$spec" 120)
	for i in $(seq 1 20); do [ "$(vx "${!W}" "test -s /var/e2e/state/watch-$id && echo y")" = y ] && break; sleep 1; done
	jm=$(vjob "${!C}" 3 "mark-$id" $(py syncops.py) mark "$id" "$@")
	vfinish "${!C}" "$jm" 3 "mark-$id" 90
	vfinish "${!W}" "$jw" 3 "watch-$id" 150
	m=$(vx "${!C}" "cat /var/e2e/state/mark-$id 2>/dev/null")
	s=$(vx "${!W}" "cat /var/e2e/state/watch-$id 2>/dev/null")
	jcheck 3 "prop.$id" "propagation $id ($C to $W) with no hop sync, within 10s" "$(judge 10 "$(offset "$W" "$C")" "$m" "$s")"
}

# ------------------------------------------------------------------ phases
# A phase function returns non-zero when it stops early; report.py then counts the phase as incomplete.

phase1() {
	log "=== phase 1: local only"
	local ja jb
	ja=$(vjob "$A" 1 main $(py p1.py) main)
	jb=$(vjob "$B" 1 main $(py p1.py) main)
	vfinish "$A" "$ja" 1 main 1200
	vfinish "$B" "$jb" 1 main 1200
	vrun "$B" 1 before-reboot 120 $(py p1.py) before-reboot
	reboot_vm "$B" 1 || return 1
	vrun "$B" 1 after-reboot 300 $(py p1.py) after-reboot
	return 0
}

phase2() {
	log "=== phase 2: MCP"
	vrun "$A" 2 main 1200 $(py p2.py)
	return 0
}

ensure_signed_in() { # B's device name if it has to sign in
	vrun "$A" "$CUR_PHASE" ensure-a 300 $(py p3.py) ensure-a
	copy_secret kit "$A" "$B" && copy_secret masterpw "$A" "$B" || return 1
	vrun "$B" "$CUR_PHASE" ensure-b 300 $(py p3.py) ensure-b "$1"
}

phase3() {
	log "=== phase 3: sync"
	vrun "$A" 3 server-check 60 $(py p3.py) server-check
	vrun "$B" 3 server-check 60 $(py p3.py) server-check
	vrun "$A" 3 signup 300 $(py p3.py) signup
	xfer "$A" /var/e2e/state/hosts-A.json "$B" /var/e2e/state/hosts-A.json || return 1
	vrun "$B" 3 b-refusals 180 $(py p3.py) b-refusals

	log "login by approval"
	local jl code sas ja i
	jl=$(vjob "$B" 3 b-login-approve $(py p3.py) b-login-approve)
	for i in $(seq 1 30); do
		code=$(vx "$B" "grep -o 'hop auth approve [A-Z0-9-]*' /var/e2e/logs/pty-blogin.log 2>/dev/null | head -1 | cut -d' ' -f4")
		[ -n "$code" ] && break
		sleep 2
	done
	if [ -z "$code" ]; then
		dcheck 3 harness.approve-code "B shows an approval code" fail "no code in the pty log" harness
	else
		vrun "$A" 3 a-approve-start 90 $(py p3.py) a-approve-start "$code"
		for i in $(seq 1 30); do
			sas=$(vx "$B" "grep -oE 'Check code: +[0-9]{4} [0-9]{4}' /var/e2e/logs/pty-blogin.log | head -1 | grep -oE '[0-9]{4} [0-9]{4}' | tr -d ' '")
			[ -n "$sas" ] && break
			sleep 2
		done
		ja=$(vjob "$A" 3 a-approve-sas $(py p3.py) a-approve-sas "$code" "$sas")
		for i in $(seq 1 40); do
			[ "$(vx "$B" "grep -q 'yes or no' /var/e2e/logs/pty-blogin.log && echo y")" = y ] && break
			sleep 2
		done
		vx "$B" "echo yes > /var/e2e/state/blogin.in" >/dev/null
		vfinish "$A" "$ja" 3 a-approve-sas 180
	fi
	vfinish "$B" "$jl" 3 b-login-approve 360
	vrun "$B" 3 b-received 120 $(py p3.py) b-received

	log "propagation"
	prop a2b-add B A hosts:synca1 add synca1 --address 10.9.9.1 --user deploy --tag synctest
	prop a2b-edit B A hosts:synca1:user=deploy2 edit synca1 --user deploy2
	prop a2b-rm B A hosts:synca1:absent rm synca1 --yes
	prop b2a-add A B hosts:syncb1 add syncb1 --address 10.9.9.2 --user deploy --tag synctest
	prop b2a-edit A B hosts:syncb1:port=2200 edit syncb1 --port 2200
	prop b2a-rm A B hosts:syncb1:absent rm syncb1 --yes
	prop b2a-key A B keys:bkey key add /home/tester/bkey --name bkey
	prop a2b-snip B A snippets:syncsnip snippet add syncsnip -- uptime
	vrun "$A" 3 usebkey 120 $(py p3.py) usebkey

	log "offline outbox"
	vrun "$B" 3 offline-start 180 $(py p3.py) offline-start
	local jw1 jw2 t_un s1 s2
	jw1=$(vjob "$A" 3 watch-offb1 $(py syncops.py) watch offb1 hosts:offb1 240)
	jw2=$(vjob "$A" 3 watch-offsnip $(py syncops.py) watch offsnip snippets:offsnip 240)
	sleep 3
	vrun "$B" 3 offline-end 60 $(py p3.py) offline-end
	vfinish "$A" "$jw1" 3 watch-offb1 300
	vfinish "$A" "$jw2" 3 watch-offsnip 300
	t_un=$(vx "$B" "cat /var/e2e/state/unblocked 2>/dev/null")
	s1=$(vx "$A" "cat /var/e2e/state/watch-offb1 2>/dev/null")
	s2=$(vx "$A" "cat /var/e2e/state/watch-offsnip 2>/dev/null")
	jcheck 3 outbox-drain "the offline outbox drains on its own when the network returns, host and snippet on A within 120s (backoff up to ~60s; no hop sync)" \
		"$(judge 120 "$(offset A B)" "$t_un" "$s1" "$s2")"

	log "conflicts"
	vrun "$A" 3 cf-setup 120 $(py p3.py) cf-setup
	vrun "$B" 3 wait-host 120 $(py p3.py) wait-host cf3 90
	vrun "$B" 3 block 30 $(py p3.py) block 1
	vrun "$A" 3 cf-edit 60 $(py p3.py) cf-edit A
	vrun "$B" 3 cf-edit 60 $(py p3.py) cf-edit B
	vrun "$B" 3 block 30 $(py p3.py) block 0
	vrun "$B" 3 conflict-check 300 $(py p3.py) conflict-check
	xfer "$B" /var/e2e/state/cf-B "$A" /var/e2e/state/cf-B-from
	vrun "$A" 3 converge 120 $(py p3.py) converge

	log "daemon restart and reboots"
	vrun "$B" 3 daemon-stop 60 $(py p3.py) daemon-stop
	vrun "$A" 3 mark-rs1 60 $(py syncops.py) mark rs1 add rs1 --address 10.9.7.1 --user deploy
	vrun "$B" 3 after-restart 120 $(py p3.py) after-restart rs1
	reboot_start "$B"
	sleep 8
	vrun "$A" 3 mark-rb1 60 $(py syncops.py) mark rb1 add rb1 --address 10.9.7.2 --user deploy
	reboot_finish "$B" 3 || return 1
	vrun "$B" 3 after-reboot 240 $(py p3.py) after-reboot rb1
	vrun "$B" 3 service-setup 120 $(py p3.py) service-setup
	reboot_start "$B"
	sleep 8
	vrun "$A" 3 mark-rb2 60 $(py syncops.py) mark rb2 add rb2 --address 10.9.7.3 --user deploy --key testkey
	reboot_finish "$B" 3 || return 1
	vrun "$B" 3 after-reboot-service 400 $(py p3.py) after-reboot-service rb2

	log "devices, logout"
	local aname
	aname=$(vx "$A" "hostname" | tr -d '[:space:]')
	vrun "$A" 3 devices 60 $(py p3.py) devices cli-b
	vrun "$B" 3 devices 60 $(py p3.py) devices "$aname"
	vrun "$B" 3 logout 180 $(py p3.py) logout
	vrun "$A" 3 a-after-logout 60 $(py p3.py) a-after-logout cli-b
	copy_secret kit "$A" "$B" && copy_secret masterpw "$A" "$B" || return 1
	vrun "$B" 3 pwlogin 240 $(py p3.py) pwlogin cli-b2
	return 0
}

phase4() {
	log "=== phase 4: SSH over Tailscale"
	ensure_signed_in cli-b2 || return 1
	vrun "$A" 4 a-add 300 $(py p4.py) a-add
	vrun "$A" 4 a-jump 180 $(py p4.py) a-jump
	vrun "$A" 4 a-ts 240 $(py p4.py) a-ts
	vrun "$A" 4 a-ts-b 180 $(py p4.py) a-ts-b
	vrun "$B" 4 b-use 300 $(py p4.py) b-use
	vrun "$B" 4 b-mcp 180 $(py p4.py) b-mcp
	local e ja jb ca cb
	e=$(($(date +%s) + 15))
	ja=$(vjob "$A" 4 conc $(py p4.py) conc $e)
	jb=$(vjob "$B" 4 conc $(py p4.py) conc $e)
	vfinish "$A" "$ja" 4 conc 300
	vfinish "$B" "$jb" 4 conc 300
	ca=$(vx "$A" "cat /var/e2e/state/conc 2>/dev/null"); cb=$(vx "$B" "cat /var/e2e/state/conc 2>/dev/null")
	# The concurrency check means something only if A's and B's batches really overlapped.
	jcheck 4 conc-overlap "A's and B's parallel batches overlap in time (at least half of the shorter one)" "$(python3 -I - "$ca" "$cb" "$CLOCK_OFF" <<'EOF'
import json, sys
try:
    a, b, off = json.loads(sys.argv[1]), json.loads(sys.argv[2]), float(sys.argv[3])
    sa, ea, sb, eb = a['start'], a['end'], b['start'] - off, b['end'] - off
except Exception as e:
    print('harness no usable window: %r' % e)
    sys.exit(0)
ov = min(ea, eb) - max(sa, sb)
short = min(ea - sa, eb - sb)
print('%s overlap %.2fs; A %.2fs, B %.2fs, B started %+.2fs after A (clock offset %.3fs applied)' % (
    'pass' if short > 0 and ov >= short / 2 else 'harness', ov, ea - sa, eb - sb, sb - sa, off))
EOF
)"
	e=$(($(date +%s) + 15))
	jb=$(vjob "$B" 4 syncuse-b $(py p4.py) syncuse-b $e)
	ja=$(vjob "$A" 4 syncuse-a $(py p4.py) syncuse-a $e)
	vfinish "$A" "$ja" 4 syncuse-a 120
	vfinish "$B" "$jb" 4 syncuse-b 240
	local sa sb
	sa=$(vx "$A" "cat /var/e2e/state/syncuse-a 2>/dev/null"); sb=$(vx "$B" "cat /var/e2e/state/syncuse-b 2>/dev/null")
	jcheck 4 syncuse-prop "a user change on A reaches B's ssh config within 10s while B has open sessions" "$(judge 10 "$(offset B A)" "$sa" "$sb")"
	vrun "$A" 4 a-reset 60 $(py p4.py) a-reset
	return 0
}

phase5() {
	log "=== phase 5: revocation"
	local t0 tw
	ensure_signed_in cli-r1 || return 1
	vrun "$A" 5 ensure-t1 120 $(py p5.py) ensure-t1
	vrun "$B" 5 b-wait-t1 120 $(py p5.py) b-wait-t1
	vrun "$B" 5 device-id 60 $(py p5.py) device-id
	vrun "$B" 5 localb-setup 240 $(py p5.py) localb-setup
	vrun "$B" 5 access 240 $(py p5.py) access base work

	revoke() { # n: revoke B's current device from A; prints A's start time (empty if it did not start)
		local dev
		dev=$(vx "$B" "cat /var/e2e/state/device-id 2>/dev/null" | tr -d '[:space:]')
		[ -n "$dev" ] || dcheck 5 "harness.device-id-$1" "B's device ID is known before revoke $1" fail "empty" harness
		vrun "$A" 5 revoke 300 $(py p5.py) revoke "$dev" "$1" >&2
		vx "$A" "cat /var/e2e/state/revoke-start-$1 2>/dev/null" | python3 -I -c 'import json,sys
try: print(json.load(sys.stdin)["t"])
except Exception: print("")'
	}
	relogin() { copy_secret kit "$A" "$B" || return 1; vrun "$B" 5 relogin 300 $(py p5.py) relogin "$1"; }
	# cutoff tag t0 limit offset: t0 empty means the change never started
	cutoff() {
		if [ -z "$2" ]; then dcheck 5 "harness.cutoff-$1" "$1: the revoke started" fail "no start time" harness; return 1; fi
		vrun "$B" 5 cutoff 60 $(py p5.py) cutoff "$1" "$2" "$3" "$4"
	}

	# B1: online and idle.
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s1-online 60)
	sleep 2
	t0=$(revoke 1)
	cutoff s1-online "$t0" 30 "$CLOCK_OFF"
	vfinish "$B" "$tw" 5 watch 90
	vrun "$B" 5 access 240 $(py p5.py) access s1-online cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s1-online
	vrun "$B" 5 unlock-after 120 $(py p5.py) unlock-after s1-online
	relogin cli-r2 || return 1

	# B2: sessions open during the revoke.
	vrun "$B" 5 sessions-start 60 $(py p5.py) sessions-start
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s2-session 60)
	sleep 2
	t0=$(revoke 2)
	cutoff s2-session "$t0" 30 "$CLOCK_OFF"
	vfinish "$B" "$tw" 5 watch 90
	vrun "$B" 5 access 240 $(py p5.py) access s2-session cut
	vrun "$B" 5 sessions-end 120 $(py p5.py) sessions-end s2-session
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s2-session
	relogin cli-r3 || return 1

	# B3: offline during the revoke.
	vrun "$B" 5 block 30 $(py p5.py) block 1
	t0=$(revoke 3)
	sleep 15
	vrun "$B" 5 access 240 $(py p5.py) access s3-offline cut r2-P2-1
	vrun "$B" 5 daemon-restart 120 $(py p5.py) daemon-restart s3-offline
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s3u 150)
	sleep 2
	vrun "$B" 5 block 30 $(py p5.py) block 0
	# The unblock time is B's own, so no clock offset applies.
	t0=$(vx "$B" "cat /var/e2e/state/block-0 2>/dev/null" | python3 -I -c 'import json,sys
try: print(json.load(sys.stdin)["t"])
except Exception: print("")')
	cutoff s3u "$t0" 120 0
	vfinish "$B" "$tw" 5 watch 180
	vrun "$B" 5 access 240 $(py p5.py) access s3-reconnected cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s3-offline
	relogin cli-r4 || return 1

	# B4: daemon stopped during the revoke, then started.
	vrun "$B" 5 daemon-stop 60 $(py p3.py) daemon-stop
	t0=$(revoke 4)
	sleep 5
	vrun "$B" 5 stopped 60 $(py p5.py) stopped s4-stopped
	vrun "$B" 5 start-window 120 $(py p5.py) start-window s4-stopped
	vrun "$B" 5 access 240 $(py p5.py) access s4-started cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s4-stopped
	relogin cli-r5 || return 1

	# B5: revoked, then rebooted.
	t0=$(revoke 5)
	sleep 10
	reboot_vm "$B" 5 || return 1
	vrun "$B" 5 start-window 120 $(py p5.py) start-window s5-reboot
	vrun "$B" 5 access 240 $(py p5.py) access s5-reboot cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s5-reboot
	vrun "$B" 5 unlock-after 120 $(py p5.py) unlock-after s5-reboot
	return 0
}

run_phase() { # n
	CUR_PHASE=$1
	step_rec "$1" driver "phase$1" "" phase-start ""
	if "phase$1"; then
		step_rec "$1" driver "phase$1" "" phase-end 0
	else
		dcheck "$1" harness.phase "phase $1 runs to its end" fail "stopped early (see the harness failures before this)" harness
	fi
	CUR_PHASE=0
}
for p in 1 2 3 4 5; do want $p && run_phase $p; done
[ "$NEED_TS" = 1 ] && clock_check clock-end 0 clock-end "the clocks of A and B still agree within ${CLOCK_MAX}s at the end"
log "all selected phases ran"
exit 0
