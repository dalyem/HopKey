#!/usr/bin/env bash
# HopKey end-to-end tests on Kiln. Runs on the orchestrator and talks to the
# test machines only through the kiln CLI; nothing from the repo runs here.
#
#   scripts/e2e/run.sh [--phases 1,2,3,4,5,6] [--keep] [--ttl 4h] [--run-id ID]
#                      [--source <worktree>]         (build hop from another worktree)
#                      [--reuse e2e-out/<old-run>]   (debugging: reset and reuse kept machines)
#
# Phases: 1 local only (both VMs), 2 MCP, 3 sync, 4 SSH over Tailscale,
# 5 revocation matrix, 6 key rotation on real sshd. 3-6 need a Tailscale
# auth key in $HOP_E2E_TS_AUTHKEY_FILE (default ~/hopkey-test/ts-authkey);
# the file is only ever copied by path (kiln vm put/sandbox write
# --from-file), never read here.
#
# The kiln identity (kiln whoami) is printed and kept in the ledger before
# anything is allocated. HOP_E2E_EXPECT_IDENTITY=<name or principal ID>
# refuses any other. Start a run from an agent's own tool call (not with a
# plain &): a process that outlives the call runs as the user's identity.
#
# Output: e2e-out/<run-id>/REPORT.md and results.jsonl. A run ID is used once.
# Exit: 0 every check passed; 1 assertion failures; 2 harness failure (setup,
# collection, masking, a release); 3 missing coverage (a selected phase or step
# did not finish); 128+n interrupted by signal n, whatever the verdict (the
# report notes the signal, and its verdict covers only what ran). Checks with
# status "limit" (a documented limit that holds as documented) never count.
# The cleanup (auth key deletion, release, the check that every machine is
# gone) is recorded as phase 0 checks, and REPORT.md is written after it.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PHASES=1,2,3,4,5,6
KEEP=0
TTL=4h
RUN=""
REUSE=""
SOURCE=""
UBUNTU_IMAGE=${HOP_E2E_UBUNTU_IMAGE:-docker.io/library/ubuntu@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c}
KEYFILE=${HOP_E2E_TS_AUTHKEY_FILE:-$HOME/hopkey-test/ts-authkey}
CLOCK_MAX=0.5 # largest A-B clock offset (plus its uncertainty) the timing checks accept

usage() { sed -n '2,/^set -uo/p' "$0" | sed -n 's/^# \{0,1\}//p'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
	case $1 in
	--phases) PHASES=$2; shift 2 ;;
	--keep) KEEP=1; shift ;;
	--ttl) TTL=$2; shift 2 ;;
	--run-id) RUN=$2; shift 2 ;;
	--reuse) REUSE=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	-h | --help) usage 0 ;;
	*) echo "unknown argument: $1" >&2; usage 2 ;;
	esac
done
[ -n "$RUN" ] || RUN="$(date -u +%m%d%H%M)-$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')"
want() { case ",$PHASES," in *",$1,"*) return 0 ;; esac; return 1; }
NEED_TS=0
for p in 3 4 5 6; do want $p && NEED_TS=1; done
NEED_SBX=0
for p in 4 5 6; do want $p && NEED_SBX=1; done
refuse() { echo "run.sh: $*" >&2; exit 2; } # before the run has a directory of its own

case $RUN in '' | .* | *[!A-Za-z0-9._-]*) refuse "bad --run-id '$RUN': letters, digits, '.', '_' and '-' only" ;; esac
if [ -n "$SOURCE" ]; then
	SOURCE=$(cd "$SOURCE" 2>/dev/null && pwd) || refuse "no such --source directory"
	[ -f "$SOURCE/go.mod" ] && [ -d "$SOURCE/cmd/hop" ] || refuse "--source $SOURCE is not a HopKey checkout (no go.mod or cmd/hop)"
fi
mkdir -p "$REPO/e2e-out"
OUT=$REPO/e2e-out/$RUN
# The run directory is reserved with one mkdir (no -p): it fails when the
# directory exists, so a repeated --run-id never writes to another run's
# ledger, and never releases its machines.
mkdir "$OUT" 2>/dev/null || refuse "run ID $RUN is taken ($OUT exists); pick another --run-id"
mkdir -p "$OUT/bin" "$OUT/results" "$OUT/logs"
install -d -m 0700 "$OUT/tmp"
DLOG=$OUT/driver.log
DRES=$OUT/results/driver.jsonl
STEPS=$OUT/steps.jsonl # step and phase start/end records: report.py checks coverage with them
ALLOC=$OUT/alloc.state  # the ledger: identity, reused machines, auth key copies
ALLOCD=$OUT/alloc       # one record per allocation, written by its own worker (alloc.sh)
LOCKS=${TMPDIR:-/tmp}/hk-e2e-locks-$(id -u) # one lock file per machine ID, held while a run uses the machine
: >"$DRES"; : >"$STEPS"; : >"$ALLOC"
mkdir -p "$ALLOCD"
install -d -m 0700 "$LOCKS"
T_START=$(date +%s)
NODE=hk-$(echo "$RUN" | tr -cd 'a-z0-9')
EMAIL="hoptest+$(echo "$RUN" | tr -cd 'a-z0-9')@example.com"
CUR_PHASE=0
CLOCK_OFF=0 # B's clock minus A's, measured once the tailnet is up

# The log file first, the terminal second: a closed terminal or pipe (the
# caller went away) must never stop a cleanup, so SIGPIPE is ignored too.
trap '' PIPE
log() {
	local l
	l="$(date -u +%H:%M:%S) $*"
	printf '%s\n' "$l" >>"$DLOG"
	printf '%s\n' "$l" >&2 2>/dev/null || true
}

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
command -v flock >/dev/null || die "flock is not on PATH"
WHOAMI=$(kiln whoami --json 2>>"$DLOG") || die "kiln is not logged in (kiln whoami failed)"
IFS=$'\t' read -r K_ID K_NAME K_KIND K_HARNESS <<<"$(python3 -I -c 'import json, sys
try:
    j = json.loads(sys.argv[1]); p = j.get("principal") or {}
    print("\t".join(str(x or "?") for x in (p.get("id"), p.get("name"), p.get("kind"), j.get("harness"))))
except ValueError:
    print("?\t?\t?\t?")' "$WHOAMI")"
echo "identity $K_ID $K_NAME $K_KIND $K_HARNESS" >>"$ALLOC"
printf 'KILN_PRINCIPAL=%s\nKILN_NAME=%s\nKILN_KIND=%s\nKILN_HARNESS=%s\n' "$K_ID" "$K_NAME" "$K_KIND" "$K_HARNESS" >"$OUT/identity.env"
log "kiln identity: $K_NAME ($K_KIND, $K_ID), harness $K_HARNESS; every machine of this run belongs to it"
if [ -n "${HOP_E2E_EXPECT_IDENTITY:-}" ]; then
	case $HOP_E2E_EXPECT_IDENTITY in
	"$K_NAME" | "$K_ID") ;;
	*) die "refusing to run: the kiln identity is $K_NAME ($K_ID), HOP_E2E_EXPECT_IDENTITY wants $HOP_E2E_EXPECT_IDENTITY" ;;
	esac
else
	AGENT_ENV=""
	for v in CLAUDECODE CLAUDE_CODE_ENTRYPOINT AI_AGENT CODEX_SANDBOX CODEX_THREAD_ID OPENCODE CURSOR_AGENT; do
		[ -n "${!v:-}" ] && AGENT_ENV="$AGENT_ENV $v"
	done
	if [ "$K_HARNESS" = shell ] && [ -n "$AGENT_ENV" ]; then
		log "WARNING: kiln sees a plain shell ($K_NAME), but this looks like an agent's run (set:$AGENT_ENV). The machines will belong to $K_NAME, and the agent cannot see or release them. A run started with a plain & from a tool call does this: start it with the tool's background mode, or set HOP_E2E_EXPECT_IDENTITY."
	elif [ "$K_HARNESS" != shell ] && [ -z "$AGENT_ENV" ]; then
		log "WARNING: kiln sees the agent harness $K_HARNESS ($K_NAME), but nothing here looks like an agent's run. The machines will belong to $K_NAME. Set HOP_E2E_EXPECT_IDENTITY to make this explicit."
	fi
fi
log "run $RUN, phases $PHASES, output $OUT${SOURCE:+, building from $SOURCE}"

# ------------------------------------------------------------------ machines

A="" B="" T1="" T2="" T3="" PUBLISHED=0 T3_SETUP=0
MACH=$OUT/machines.env
save_machines() { printf 'A=%s\nB=%s\nT1=%s\nT2=%s\nT3=%s\n' "$A" "$B" "$T1" "$T2" "$T3" >"$MACH"; }

vx() { # vm command-string: stdout of the command (kiln waits at most 8 s)
	kiln vm exec "$1" --command "$2" 2>>"$DLOG"
}
sx() { # sandbox command-string
	kiln sandbox exec "$1" --command "$2" 2>>"$DLOG"
}
q() { printf '%q ' "$@"; }
# Diagnostics from a machine, always masked there first, as a whole file, and only then cut to size.
vtail() { # vm file [bytes]
	vx "$1" "if [ -f /opt/e2e/masklogs.py ]; then python3 /opt/e2e/masklogs.py tail $2 ${3:-600}; else echo '<diagnostics withheld: no masking script on the machine>'; fi" | tr '\n' ' '
}
# Sandboxes hold no hop secret: the Tailscale key and any private key block are
# scrubbed there (a block with no END hides the rest of the file), then the tail is cut.
SBX_MASK='s/tskey-[A-Za-z0-9-]{8,}/<TS-AUTHKEY>/g; /-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/c <PRIVATE-KEY-BLOCK>'
stail() { # sandbox file [bytes]
	sx "$1" "if [ -f $2 ]; then sed -E '$SBX_MASK' $2 | tail -c ${3:-600}; else echo '<no $2>'; fi" | sed -E "$SBX_MASK" | tr '\n' ' '
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

# Every allocation runs in a worker of its own (alloc.sh) under setsid: a
# signal to this script's process group never reaches it, so it always
# records the operation and the machine ID it got, and cleanup releases
# that. Releases run under setsid too.
start_alloc() { # kind who
	local rec=$ALLOCD/$1.$2.rec
	: >"$rec"
	setsid bash "$HERE/alloc.sh" "$1" "$2" "$rec" "$REPO" "$TTL" "$UBUNTU_IMAGE" </dev/null >>"$DLOG" 2>&1 &
}
# wait_allocs max-seconds: until every worker wrote "done" or is gone.
wait_allocs() {
	local f pid t0=$SECONDS said=0
	for f in "$ALLOCD"/*.rec; do
		[ -e "$f" ] || continue
		while ! grep -qx done "$f"; do
			pid=$(sed -n 's/^pid //p' "$f" | head -1)
			[ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null && break
			[ -z "$pid" ] && [ $((SECONDS - t0)) -gt 30 ] && break
			[ $((SECONDS - t0)) -ge "$1" ] && break
			[ "$said" = 0 ] && [ "$CLEANED" = 1 ] && { log "waiting for the allocation workers to record their machines, so they can be released"; said=1; }
			sleep 2
		done
	done
}
ledger() { # "kind who id" of every machine this run holds: reused ones, and every one a worker recorded
	local f b
	grep -hE '^(vm|sbx) ' "$ALLOC"
	for f in "$ALLOCD"/*.rec; do
		[ -e "$f" ] || continue
		b=${f##*/}; b=${b%.rec}
		sed -n "s/^id /${b%%.*} ${b#*.} /p" "$f" | head -1
	done
}
read_allocs() { # set A B T1 T2 T3 from the ledger
	local kind who id
	while read -r kind who id; do printf -v "$who" '%s' "$id"; done < <(ledger)
}
lock_machines() { # id...: hold a lock per machine for the rest of the run; fails if another run holds one
	local id fd
	for id in "$@"; do
		exec {fd}>>"$LOCKS/$id.lock"
		flock -n "$fd" || { log "machine $id is in use by another run (lock $LOCKS/$id.lock)"; return 1; }
	done
}
ALLOC_PIDS=() BG_PIDS=()
reconcile_allocs() {
	local f b op res st
	wait_allocs 1200
	# A worker with no machine ID: ask kiln about its operation once more. What
	# stays unresolved may be a live machine nobody can name, so it is a
	# cleanup failure that names the operation.
	for f in "$ALLOCD"/*.rec; do
		[ -e "$f" ] || continue
		grep -q '^id ' "$f" && continue
		b=${f##*/}; b=${b%.rec}
		op=$(sed -n 's/^op //p' "$f" | head -1)
		res=""
		[ -n "$op" ] && { log "reconciling operation $op for $b"; res=$(setsid -w bash "$HERE/alloc.sh" resolve "${b%%.*}" "$op" 10m 2>>"$DLOG"); }
		case $res in
		"id "*) echo "$res" >>"$f"; continue ;;
		"ended "*) log "operation $op for $b ${res#ended }, with no machine"; continue ;;
		esac
		if [ -z "$op" ] && grep -q '^fail kiln returned no operation' "$f"; then
			log "allocation $b never started: $(sed -n 's/^fail //p' "$f" | head -1)"
			continue
		fi
		if grep -qx done "$f"; then st="its worker finished: $(sed -n 's/^fail //p' "$f" | head -1)"; else st="its worker is still running"; fi
		dcheck 0 "harness.alloc-$b" "every allocation of this run is resolved to a machine and released" fail \
			"unresolved allocation $b: operation ${op:-(none recorded)}; $st; check kiln op status ${op:-?} and kiln vm list / kiln sandbox list" harness
		RELEASE_FAIL=1
	done
	read_allocs
}
# Auth key copies: recorded before each copy, deleted and checked at cleanup on every machine, also with --keep.
key_copied() { echo "key $1 $2 $3" >>"$ALLOC"; } # vm|sbx id path
delete_keys() {
	local kind m path st left=0
	local i
	while read -r _ kind m path; do
		# An empty answer is kiln's exec failing, not the machine's: ask again.
		for i in 1 2 3; do
			if [ "$kind" = vm ]; then
				st=$(vx "$m" "rm -f $path; test -e $path && echo present || echo gone" </dev/null | tr -d '[:space:]')
			else
				st=$(sx "$m" "rm -f $path; test -e $path && echo present || echo gone" </dev/null | tr -d '[:space:]')
			fi
			case $st in gone | present) break ;; esac
			log "no answer from $m about $path (try $i)"
			sleep 3
		done
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
	local kind who id i ok
	while read -r kind who id; do
		ok=0
		for i in 1 2 3; do
			case $kind in
			vm) setsid -w kiln vm release "$id" >>"$DLOG" 2>&1 && { ok=1; break; } ;;
			sbx) setsid -w kiln sandbox destroy "$id" >>"$DLOG" 2>&1 && { ok=1; break; } ;;
			*) continue 2 ;;
			esac
			sleep 5
		done
		log "release $kind $who $id: $([ $ok = 1 ] && echo "done on try $i" || echo "failed 3 times")"
		if [ $ok = 1 ]; then
			dcheck 0 "cleanup.release-$who" "$kind $who ($id) is released" pass "try $i"
		else
			dcheck 0 "harness.release-$who" "$kind $who ($id) is released" fail "kiln refused 3 times; see driver.log" harness
			RELEASE_FAIL=1
		fi
	done < <(ledger | sort -u)
	# Released machines are no ledger for a later --reuse. Only a run that held
	# machines marks anything: a refused --reuse never marks the ledger it was refused.
	[ -n "$(ledger)" ] || return 0
	echo "released by $RUN at $(date -u +%FT%TZ)" >>"$OUT/machines.released"
	grep -q '^reused-from ' "$ALLOC" && echo "released by $RUN at $(date -u +%FT%TZ)" >>"$REUSE/machines.released"
	return 0
}
verify_released() { # every machine of this run is gone; warns about other live ones made since the start
	local v s rc
	local label="every machine of this run is gone (kiln vm list, kiln sandbox list)"
	v=$(kiln vm list --json 2>>"$DLOG") || { dcheck 0 harness.verify-released "$label" fail "kiln vm list failed" harness; RELEASE_FAIL=1; return; }
	s=$(kiln sandbox list --json 2>>"$DLOG") || { dcheck 0 harness.verify-released "$label" fail "kiln sandbox list failed" harness; RELEASE_FAIL=1; return; }
	python3 -I - "$(ledger | awk '{print $3}' | tr '\n' ' ')" "$T_START" "$v" "$s" <<'EOF' >>"$DLOG"
import datetime, json, sys
t0 = int(sys.argv[2])
ours = set(sys.argv[1].split())
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
	rc=${PIPESTATUS[0]}
	grep -E "^(machines of this run|WARNING)" "$DLOG" | tail -2 >&2 2>/dev/null
	if [ "$rc" = 0 ]; then
		dcheck 0 cleanup.verify-released "$label" pass "$(grep '^machines of this run' "$DLOG" | tail -1)"
	else
		dcheck 0 harness.verify-released "$label" fail "$(grep '^machines of this run' "$DLOG" | tail -1)" harness
		RELEASE_FAIL=1
	fi
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
	# A phase 6 that stopped early, or an interrupt, can leave T3's sshd on the test hook.
	[ "$T3_SETUP" = 1 ] && [ "$HURRY" = 0 ] && t3_restore
	if delete_keys && grep -q '^key ' "$ALLOC"; then
		dcheck 0 cleanup.authkeys "the Tailscale auth key is deleted from every machine it was copied to" pass "$(grep -c '^key ' "$ALLOC") copies"
	fi
	if [ "$SETUP_STARTED" = 1 ]; then
		log "collecting results"
		collect
	fi
	if [ "$KEEP" = 1 ]; then
		log "--keep: machines left up: CLI-A $A, CLI-B $B, T1 $T1, T2 $T2, T3 $T3 (release with kiln vm release / kiln sandbox destroy)"
		dcheck 0 cleanup.release "the machines of this run are released" skip "--keep: left up: CLI-A $A, CLI-B $B, T1 $T1, T2 $T2, T3 $T3"
	else
		release_all
		verify_released
	fi
	[ "$PUBLISHED" = 1 ] && kiln unpublish --project "$REPO" >>"$DLOG" 2>&1
	[ "$INTERRUPTED" != 0 ] && echo "$INTERRUPTED" >"$OUT/interrupted"
	# The report comes last, so it holds every cleanup outcome.
	rm -f "$OUT/verdict"
	python3 -I "$HERE/report.py" "$OUT" "$RUN" "$PHASES" "$T_START" "$(date +%s)" "$MACH" >>"$DLOG" 2>&1 || log "report.py failed"
	code=$(cat "$OUT/verdict" 2>/dev/null || echo 2)
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

# ------------------------------------------------------------------ reused machines
# Checked before the build, so a refused --reuse costs nothing.
if [ -n "$REUSE" ]; then
	REUSE=$(cd "$REUSE" 2>/dev/null && pwd) || die "no --reuse directory"
	[ -f "$REUSE/machines.env" ] || die "no $REUSE/machines.env"
	# A ledger whose machines were released (by its run or a later reuse) is stale: never replay it.
	[ -e "$REUSE/machines.released" ] && die "the machines in $REUSE were released ($(tail -1 "$REUSE/machines.released")); lease new ones"
	. "$REUSE/machines.env"
	log "reusing CLI-A $A, CLI-B $B${T1:+, T1 $T1, T2 $T2, T3 $T3}"
	RIDS=$(for who in A B T1 T2 T3; do [ -n "${!who}" ] && echo "${!who}"; done)
	# Locked and checked before they enter this run's ledger: a refusal here
	# must not release machines another run is using.
	# shellcheck disable=SC2086
	lock_machines $RIDS || { A="" B="" T1="" T2="" T3=""; die "another run is using the machines of $REUSE"; }
	# And they must still be up: a ledger can outlive its machines (a TTL, a release by hand).
	LIVE=$(python3 -I -c 'import json, sys
live = set()
for blob, key in ((sys.argv[1], "leases"), (sys.argv[2], "sandboxes")):
    try:
        live |= {i["id"] for i in json.loads(blob).get(key, []) if not str(i.get("state", "")).startswith(("released", "destroyed", "expired", "failed"))}
    except (ValueError, KeyError):
        pass
print(" ".join(sorted(live)))' "$(kiln vm list --json 2>>"$DLOG")" "$(kiln sandbox list --json 2>>"$DLOG")")
	for id in $RIDS; do
		case " $LIVE " in *" $id "*) ;; *) A="" B="" T1="" T2="" T3=""; die "machine $id from $REUSE is not live for $K_NAME; lease new ones" ;; esac
	done
	for who in A B T1 T2 T3; do
		[ -n "${!who}" ] || continue
		case $who in T*) echo "sbx $who ${!who}" ;; *) echo "vm $who ${!who}" ;; esac >>"$ALLOC"
	done
	echo "reused-from $REUSE" >>"$ALLOC"
fi

# ------------------------------------------------------------------ build

# --source: the product comes from another worktree; the suite (this checkout) does not change.
SRC=${SOURCE:-$REPO}
log "building hop and hop-server (linux-amd64) on Kiln from $SRC"
COMMIT=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
SRC_DIRTY=0
[ -z "$(git -C "$SRC" status --porcelain --untracked-files=no 2>/dev/null)" ] || { COMMIT="$COMMIT+dirty"; SRC_DIRTY=1; }
SUITE_COMMIT=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
[ -z "$(git -C "$REPO" status --porcelain --untracked-files=no -- scripts/e2e 2>/dev/null)" ] || SUITE_COMMIT="$SUITE_COMMIT+dirty"
{
	echo "SOURCE_DIR=$SRC"
	echo "SOURCE_BRANCH=$(git -C "$SRC" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
	echo "SOURCE_COMMIT=$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
	echo "SOURCE_DIRTY=$SRC_DIRTY"
	echo "SOURCE_CHANGED=$(git -C "$SRC" status --porcelain --untracked-files=no 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
	echo "SUITE_COMMIT=$SUITE_COMMIT"
} >"$OUT/source.env"
BUILD_CMD='export PATH=$PATH:/usr/local/go/bin GOCACHE=$PWD/.check-cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64; mkdir -p /artifacts && LDF="-s -w -X github.com/dalyem/hopkey/internal/version.Version='$COMMIT'" && go build -trimpath -ldflags "$LDF" -o /artifacts/hop ./cmd/hop && go build -trimpath -ldflags "$LDF" -o /artifacts/hop-server ./cmd/hop-server && cd /artifacts && sha256sum hop hop-server > SHA256SUMS && cat SHA256SUMS'
# Kiln runs at most 3 jobs per identity; other work can hold them for a while.
for i in $(seq 1 40); do
	kiln checks run --project "$SRC" --json --timeout 20m --command "$BUILD_CMD" >"$OUT/build.json" 2>>"$DLOG" && break
	grep -q '"limit_exceeded"' "$OUT/build.json" || die "build failed: see $OUT/build.json"
	[ "$i" = 1 ] && log "kiln's job limit is reached; retrying the build every 30s for up to 20 minutes"
	[ "$i" = 40 ] && die "build failed: kiln's job limit stayed reached for 20 minutes"
	sleep 30
done
OP=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["operation"]["id"])' "$OUT/build.json")
for f in hop hop-server SHA256SUMS; do
	kiln artifacts get "$OP" "$f" -o "$OUT/bin/$f" 2>>"$DLOG" || die "could not fetch artifact $f from $OP"
done
(cd "$OUT/bin" && sha256sum -c SHA256SUMS >>"$DLOG" 2>&1) || die "artifact checksum mismatch"
SHA_HOP=$(awk '$2=="hop"{print $1}' "$OUT/bin/SHA256SUMS")
SHA_SRV=$(awk '$2=="hop-server"{print $1}' "$OUT/bin/SHA256SUMS")
log "built $COMMIT: hop $SHA_HOP, hop-server $SHA_SRV (job $OP)"

# ------------------------------------------------------------------ provision

if [ -z "$REUSE" ]; then
	log "leasing CLI-A and CLI-B$([ "$NEED_SBX" = 1 ] && echo ", creating three sandboxes")"
	start_alloc vm A
	start_alloc vm B
	if [ "$NEED_SBX" = 1 ]; then
		for t in T1 T2 T3; do start_alloc sbx $t; done
	fi
	wait_allocs 1200
	read_allocs
	# shellcheck disable=SC2046
	lock_machines $(ledger | awk '{print $3}') || die "a machine this run just got is locked by another run"
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
	log "CLI-$who set up: $(vx "$vm" "HOME=/root hop --version 2>&1 | head -1; echo ntp=\$(cat /var/e2e/state/ntp)" | tr '\n' ' ')"
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
	vrun "$A" 3 seed 120 $(py p3.py) seed
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
	# cutoff tag t0 limit offset [revoke|reconnect]: t0 empty means the change never started
	cutoff() {
		if [ -z "$2" ]; then dcheck 5 "harness.cutoff-$1" "$1: the ${5:-revoke} has a start time" fail "no start time" harness; return 1; fi
		vrun "$B" 5 cutoff 60 $(py p5.py) cutoff "$1" "$2" "$3" "$4" "${5:-revoke}"
	}

	# B1: online and idle.
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s1-online 60)
	sleep 2
	t0=$(revoke 1)
	cutoff s1-online "$t0" 30 "$CLOCK_OFF"
	vfinish "$B" "$tw" 5 watch 90
	vrun "$B" 5 access 240 $(py p5.py) access s1-online cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s1-online
	vrun "$B" 5 wiped 120 $(py p5.py) wiped s1-online
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

	# B3: offline during the revoke. Documented (README, What revocation does, Offline):
	# with the max-offline policy off, its default, a device that cannot reach the
	# server keeps working, across a daemon restart too, and is cut off once it reconnects.
	vrun "$B" 5 policy-off 90 $(py p5.py) policy-off
	vrun "$B" 5 block 30 $(py p5.py) block 1
	t0=$(revoke 3)
	sleep 15
	vrun "$B" 5 access 240 $(py p5.py) access s3-offline work
	vrun "$B" 5 daemon-restart 120 $(py p5.py) daemon-restart s3-offline work
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s3u 150)
	sleep 2
	vrun "$B" 5 block 30 $(py p5.py) block 0
	# The unblock time is B's own, so no clock offset applies.
	t0=$(vx "$B" "cat /var/e2e/state/block-0 2>/dev/null" | python3 -I -c 'import json,sys
try: print(json.load(sys.stdin)["t"])
except Exception: print("")')
	cutoff s3u "$t0" 120 0 reconnect
	vfinish "$B" "$tw" 5 watch 180
	vrun "$B" 5 access 240 $(py p5.py) access s3-reconnected cut
	# Cut off once it reconnects, it stays cut off across a daemon restart, never serving a key.
	tw=$(vjob "$B" 5 watch $(py p5.py) watch rev2-s3r 40)
	sleep 2
	vrun "$B" 5 daemon-restart 120 $(py p5.py) daemon-restart rev2-s3-reconnected cut
	vfinish "$B" "$tw" 5 watch 90
	vrun "$B" 5 nokeys 30 $(py p5.py) nokeys rev2-s3r
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s3-offline
	vrun "$B" 5 wiped 120 $(py p5.py) wiped s3-reconnected
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
	vrun "$B" 5 wiped 120 $(py p5.py) wiped s5-reboot
	vrun "$B" 5 unlock-after 120 $(py p5.py) unlock-after s5-reboot

	# B6: the account's max-offline policy (1m), signed in and not revoked.
	relogin cli-r6 || return 1
	vrun "$A" 5 policy 60 $(py p5.py) policy 1m
	vrun "$B" 5 policy-seen 120 $(py p5.py) policy-seen 60
	vrun "$B" 5 policy-idle 420 $(py p5.py) policy-idle 240
	vrun "$B" 5 block 30 $(py p5.py) block 1
	vrun "$B" 5 policy-offline 330 $(py p5.py) policy-offline 240
	vrun "$B" 5 block 30 $(py p5.py) block 0
	vrun "$B" 5 policy-clear 240 $(py p5.py) policy-clear 150
	vrun "$A" 5 policy 60 $(py p5.py) policy off
	return 0
}

# Phase 6 helpers. authorized_keys files hold only public keys, so they pass through $OUT/tmp.
AKT="t1-deploy:T1:/home/deploy t2-deploy:T2:/home/deploy t2-deploy2:T2:/home/deploy2 t3-deploy:T3:/home/deploy b-rot:B:/home/rot"
ak_fetch() { # suffix [name]: copy the targets' authorized_keys to A's state/ak/<name>.<suffix>
	local e name who home f m
	mkdir -p "$OUT/tmp/ak"
	for e in $AKT; do
		IFS=: read -r name who home <<<"$e"
		[ -n "${2:-}" ] && [ "$2" != "$name" ] && continue
		f=$OUT/tmp/ak/$name.$1
		m=${!who}
		if [ "$who" = B ]; then
			kiln vm get "$m" "$home/.ssh/authorized_keys" -o "$f" 2>>"$DLOG"
		else
			kiln sandbox read "$m" "$home/.ssh/authorized_keys" -o "$f" 2>>"$DLOG"
		fi || { dcheck 6 "harness.ak-$name-$1" "$name's authorized_keys is copied ($1)" fail "read failed" harness; return 1; }
		kiln vm put "$A" "/var/e2e/state/ak/$name.$1" --from-file "$f" >>"$DLOG" 2>&1 ||
			{ dcheck 6 "harness.ak-$name-$1" "$name's authorized_keys is copied ($1)" fail "copy to A failed" harness; return 1; }
	done
}
rot_targets() { # rotkey's lines on T1-T3, other lines that must survive, and T3's sshd that will refuse the new key
	local k k2 o r
	k=$(cut -d' ' -f1,2 "$OUT/tmp/rotkey.pub")
	k2=$(cut -d' ' -f1,2 "$OUT/tmp/rotkey2.pub")
	o=$(cut -d' ' -f1,2 "$OUT/tmp/bkey.pub")
	printf '%s\n' '# hk-e2e: comment lines and other keys must survive the rotation byte for byte' "restrict $k hk-e2e-rot-t1" \
		"command=\"echo other\",no-pty $o hk-e2e-other-line" >"$OUT/tmp/ak-t1"
	printf '%s\n' "$k2 hk-e2e-rot-cc" >"$OUT/tmp/ak-t1-cc"
	printf '%s\n' "$k hk-e2e-rot-t2" "  $o   hk-e2e-other-spaced" >"$OUT/tmp/ak-t2"
	printf '%s\n' "$k hk-e2e-rot-t2in" >"$OUT/tmp/ak-t2in"
	printf '%s\n' "$k hk-e2e-rot-t3" >"$OUT/tmp/ak-t3"
	kiln sandbox write "$T1" /var/e2e/ak-add --from-file "$OUT/tmp/ak-t1" >>"$DLOG" 2>&1 &&
		kiln sandbox write "$T1" /var/e2e/ak-add-cc --from-file "$OUT/tmp/ak-t1-cc" >>"$DLOG" 2>&1 &&
		kiln sandbox write "$T1" /var/e2e/rot-append.sh --from-file "$HERE/guest/rot-append.sh" >>"$DLOG" 2>&1 &&
		kiln sandbox write "$T1" /var/e2e/bkey.pub --from-file "$OUT/tmp/bkey.pub" >>"$DLOG" 2>&1 &&
		kiln sandbox write "$T2" /var/e2e/ak-add --from-file "$OUT/tmp/ak-t2" >>"$DLOG" 2>&1 &&
		kiln sandbox write "$T2" /var/e2e/ak-add-in --from-file "$OUT/tmp/ak-t2in" >>"$DLOG" 2>&1 &&
		kiln sandbox write "$T3" /var/e2e/ak-add --from-file "$OUT/tmp/ak-t3" >>"$DLOG" 2>&1 &&
		kiln sandbox write "$T3" /var/e2e/rot-t3.sh --from-file "$HERE/guest/rot-t3.sh" >>"$DLOG" 2>&1 ||
		{ dcheck 6 harness.rot-targets "the rotation fixtures are written to T1-T3" fail "kiln sandbox write failed" harness; return 1; }
	T3_SETUP=1 # from here on, T3's sshd may run the test hook: phase6 and cleanup put it back
	r=$(sx "$T1" "cat /var/e2e/ak-add >> /home/deploy/.ssh/authorized_keys && cat /var/e2e/ak-add-cc >> /home/deploy2/.ssh/authorized_keys && echo ok")
	r="$r $(sx "$T2" "cat /var/e2e/ak-add >> /home/deploy/.ssh/authorized_keys && cat /var/e2e/ak-add-in >> /home/deploy2/.ssh/authorized_keys && echo ok")"
	r="$r $(sx "$T3" "cat /var/e2e/ak-add >> /home/deploy/.ssh/authorized_keys && sh /var/e2e/rot-t3.sh setup 2>&1 | tail -3")"
	log "rotation targets: $r"
	[ "$(echo "$r" | tr -s ' \n' ' ' | sed 's/ $//')" = "ok ok ok" ] ||
		{ dcheck 6 harness.rot-targets "the rotation fixtures are written to T1-T3 and T3's sshd reloads" fail "$r" harness; return 1; }
}

# T3's sshd back to stock, verified (rot-t3.sh prints "ok" last only then); a failure is a harness failure.
t3_restore() {
	local out
	out=$(sx "$T3" "sh /var/e2e/rot-t3.sh restore 2>&1 | tail -3")
	log "T3 sshd back to stock: $(echo "$out" | tr '\n' ' ')"
	if [ "$(echo "$out" | tail -1)" = ok ]; then
		T3_SETUP=0
		dcheck 6 rot-t3-restored "T3's sshd is back to its stock config after the rotation tests" pass ""
	else
		dcheck 6 harness.rot-t3-restore "T3's sshd is back to its stock config after the rotation tests" fail "$(echo "$out" | tr '\n' ' ')" harness
		return 1
	fi
}
# sandbox-to-A copy of a public file (no secret): kiln sandbox read, then kiln vm put.
sbx_to_a() { # sandbox path name
	kiln sandbox read "$1" "$2" -o "$OUT/tmp/ak/$3" 2>>"$DLOG" &&
		kiln vm put "$A" "/var/e2e/state/ak/$3" --from-file "$OUT/tmp/ak/$3" >>"$DLOG" 2>&1 ||
		{ dcheck 6 "harness.copy-$3" "$2 is copied from the sandbox to A" fail "kiln sandbox read or vm put failed" harness; return 1; }
}

phase6() {
	local rc
	phase6_steps
	rc=$?
	# An early return leaves T3 on the hook too.
	if [ "$T3_SETUP" = 1 ]; then t3_restore || rc=1; fi
	return $rc
}

phase6_steps() {
	log "=== phase 6: key rotation on real sshd"
	local aip n i rnd cnt ivl e t1ip
	ensure_signed_in cli-k1 || return 1
	vrun "$A" 6 supported 60 $(py p6.py) supported
	case $(vx "$A" "cat /var/e2e/state/rot-supported 2>/dev/null") in
	yes) ;;
	no) log "this build has no hop key rotate (confirmed): phase 6 recorded a skip"; return 0 ;;
	*) return 1 ;; # the detection failed: p6 recorded a harness failure
	esac
	aip=$(sed -n 's/^HK_A_IP=//p' "$OUT/tailnet.env")
	t1ip=$(sed -n 's/^HK_T1_IP=//p' "$OUT/tailnet.env")
	vrun "$A" 6 keys 120 $(py p6.py) keys
	kiln vm get "$A" /var/e2e/state/rotkey.pub -o "$OUT/tmp/rotkey.pub" 2>>"$DLOG" &&
		kiln vm get "$A" /var/e2e/state/rotkey2.pub -o "$OUT/tmp/rotkey2.pub" 2>>"$DLOG" ||
		{ dcheck 6 harness.rot-pub "the rotation keys' public halves come from A" fail "kiln vm get failed" harness; return 1; }
	kiln vm put "$B" /var/e2e/state/rotkey.pub --from-file "$OUT/tmp/rotkey.pub" >>"$DLOG" 2>&1 || return 1
	vrun "$B" 6 b-target 60 $(py p6.py) b-target "$aip"
	rot_targets || return 1
	vrun "$A" 6 hosts 400 $(py p6.py) hosts
	vrun "$B" 6 b-wait 180 $(py p6.py) b-wait
	ak_fetch before || return 1
	vrun "$A" 6 dry-run 300 $(py p6.py) dry-run
	ak_fetch dry || return 1
	vrun "$A" 6 judge 60 $(py p6.py) judge before dry dryrun
	sx "$T3" ": >/var/e2e/ak-hook.log" >/dev/null # the hook log covers the rotation only
	vrun "$A" 6 rotate 900 $(py p6.py) rotate
	xfer "$A" /var/e2e/state/rot-newname "$B" /var/e2e/state/rot-newname && xfer "$A" /var/e2e/state/rot-newpub "$B" /var/e2e/state/rot-newpub || return 1
	ak_fetch after || return 1
	sbx_to_a "$T3" /var/e2e/ak-hook.log t3-hook.log || return 1
	vrun "$A" 6 judge 60 $(py p6.py) judge before after rot
	vrun "$A" 6 judge-rollback 60 $(py p6.py) judge-rollback
	vrun "$A" 6 after-a 300 $(py p6.py) after-a
	vrun "$B" 6 after-b 300 $(py p6.py) after-b

	# Lines appended on T1 while r-cc's key rotates: dense (hop's edits are likely to see the file change
	# under them, and must stop with nothing changed), then sparse (the rotation is likely to finish between two).
	# The appender starts at e on T1's clock, the rotation at e+2 on A's; T1's clock is measured against A's
	# first, so judge-cc can place every append against the rotation's window.
	mkdir -p "$OUT/tmp/ak"
	for rnd in dense:40:0.3 sparse:10:1.5; do
		IFS=: read -r rnd cnt ivl <<<"$rnd"
		log "rotation with lines appended during it ($rnd: $cnt every ${ivl}s)"
		vrun "$A" 6 "t1clock-$rnd" 90 $(py clockoff.py) "t1clock-$rnd" "$t1ip" deploy
		sbx_to_a "$T1" /home/deploy2/.ssh/authorized_keys "t1-deploy2.cc-$rnd-before" || return 1
		e=$(($(date +%s) + 20))
		kiln sandbox exec "$T1" --background --timeout-seconds 180 --command "sh /var/e2e/rot-append.sh /var/e2e/bkey.pub $cnt $ivl $rnd $e" >>"$DLOG" 2>&1 ||
			{ dcheck 6 "harness.rot-append-$rnd" "the appender starts on T1" fail "kiln sandbox exec failed" harness; return 1; }
		vrun "$A" 6 cc 300 $(py p6.py) cc "$rnd" "$e"
		n=""
		for i in $(seq 1 40); do n=$(sx "$T1" "cat /var/e2e/append-$rnd.done 2>/dev/null" | tr -d '[:space:]'); [ -n "$n" ] && break; sleep 2; done
		[ -n "$n" ] || { dcheck 6 "harness.rot-append-$rnd" "the appender on T1 finishes" fail "no append-$rnd.done" harness; return 1; }
		sbx_to_a "$T1" /home/deploy2/.ssh/authorized_keys "t1-deploy2.cc-$rnd-after" || return 1
		sbx_to_a "$T1" "/var/e2e/append-$rnd.log" "t1-append-$rnd.log" || return 1
		vrun "$A" 6 judge-cc 60 $(py p6.py) judge-cc "$rnd" "$n" "$ivl"
	done
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
for p in 1 2 3 4 5 6; do want $p && run_phase $p; done
[ "$NEED_TS" = 1 ] && clock_check clock-end 0 clock-end "the clocks of A and B still agree within ${CLOCK_MAX}s at the end"
log "all selected phases ran"
exit 0
