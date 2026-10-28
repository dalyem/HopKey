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

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
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
: >"$DRES"
T_START=$(date +%s)
NODE=hk-$(echo "$RUN" | tr -cd 'a-z0-9')
EMAIL="hoptest+$(echo "$RUN" | tr -cd 'a-z0-9')@example.com"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$DLOG" >&2; }
die() { log "FATAL: $*"; exit 1; }

# A check recorded by the driver (cross-machine timings, harness failures).
dcheck() { # phase id name status detail [bug]
	python3 -I -c 'import json,sys,time
p,i,n,s,d=sys.argv[1:6]; b=sys.argv[6] if len(sys.argv)>6 and sys.argv[6] else None
print(json.dumps({"run":sys.argv[7],"phase":int(p),"machine":"driver","id":"p%s.%s"%(p,i),"name":n,"status":s,"detail":d,"evidence":"","bug":b,"ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())}))' \
		"$1" "$2" "$3" "$4" "$5" "${6:-}" "$RUN" >>"$DRES"
	log "check $4 p$1.$2 $3 ${5:+| $5}"
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

JOBN=0
# vjob vm phase step cmd... : start a step detached; prints the job name.
vjob() {
	local vm=$1 phase=$2 step=$3; shift 3
	local name="${step//[^a-zA-Z0-9]/-}-$(date +%s%N | tail -c 8)$RANDOM"
	vx "$vm" "systemd-run --unit=hke2e-$name --collect --quiet --setenv=E2E_PHASE=$phase --setenv=E2E_STEP=$step /bin/bash /opt/e2e/job.sh $name $(q "$@")" >/dev/null
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
# vrun vm phase step timeout cmd... : a step, waited for; a crash or timeout is a harness failure.
vrun() {
	local vm=$1 phase=$2 step=$3 to=$4; shift 4
	local who=A; [ "$vm" = "$B" ] && who=B
	log "[$who] p$phase $step: $*"
	local j rc
	j=$(vjob "$vm" "$phase" "$step" "$@")
	rc=$(vwait "$vm" "$j" "$to")
	if [ "$rc" != 0 ]; then
		dcheck "$phase" "harness.$who.$step" "step $step on $who finished" fail "exit $rc: $(vx "$vm" "tail -c 600 /var/e2e/jobs/$j.out" | tr '\n' ' ')" harness
	fi
}
py() { echo python3 "/opt/e2e/$1"; } # guest script path

reboot_vm() { # vm: reboot and wait until it is back, with tailscale up if this run uses it
	local vm=$1 t0=$SECONDS up
	log "rebooting $vm"
	vx "$vm" "nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 &" >/dev/null
	sleep 20
	while [ $((SECONDS - t0)) -lt 300 ]; do
		up=$(vx "$vm" "cut -d. -f1 /proc/uptime" | tr -d '[:space:]')
		if [ -n "$up" ] && [ "$up" -lt 200 ]; then break; fi
		sleep 5
	done
	if [ "$NEED_TS" = 1 ]; then
		for i in $(seq 1 30); do
			[ -n "$(vx "$vm" "tailscale ip -4 2>/dev/null | head -1")" ] && break
			sleep 3
		done
	fi
	vx "$vm" "for i in \$(seq 1 20); do [ -d /run/user/\$(id -u tester) ] && break; sleep 0.3; done; uptime" >>"$DLOG"
	log "$vm is back after $((SECONDS - t0))s"
}

collect() {
	local who vm f
	for who in A B; do
		vm=${!who}
		[ -n "$vm" ] || continue
		for f in $(vx "$vm" "ls /var/e2e/results 2>/dev/null"); do
			kiln vm get "$vm" "/var/e2e/results/$f" --max-bytes 262144 -o "$OUT/results/${f%.jsonl}-$who.jsonl" 2>>"$DLOG"
		done
		# Logs are masked on the machine; fetched as a base64 tarball in pieces.
		vx "$vm" "python3 /opt/e2e/masklogs.py" >/dev/null
		vx "$vm" "cd /var/e2e && tar czf /tmp/hk-logs.tgz logs jobs state/*.json state/watch-* state/mark-* 2>/dev/null; base64 -w0 /tmp/hk-logs.tgz > /tmp/hk-logs.b64; rm -rf /tmp/hk-logs.d; mkdir /tmp/hk-logs.d; split -b 200000 /tmp/hk-logs.b64 /tmp/hk-logs.d/p.; ls /tmp/hk-logs.d" >"$OUT/tmp/parts" || continue
		: >"$OUT/tmp/logs.b64"
		while read -r part; do
			[ -n "$part" ] || continue
			kiln vm get "$vm" "/tmp/hk-logs.d/$part" --max-bytes 262144 -o "$OUT/tmp/part" 2>>"$DLOG" && cat "$OUT/tmp/part" >>"$OUT/tmp/logs.b64"
		done <"$OUT/tmp/parts"
		mkdir -p "$OUT/logs/$who"
		base64 -d "$OUT/tmp/logs.b64" 2>/dev/null | tar xzf - -C "$OUT/logs/$who" 2>>"$DLOG"
	done
}

CLEANED=0
cleanup() {
	local rc=$?
	[ "$CLEANED" = 1 ] && return
	CLEANED=1
	trap - EXIT INT TERM
	log "collecting results"
	collect
	python3 -I "$HERE/report.py" "$OUT" "$RUN" "$PHASES" "$T_START" "$(date +%s)" "$MACH" >>"$DLOG" 2>&1 || log "report.py failed"
	rm -rf "$OUT/tmp"
	if [ "$KEEP" = 1 ]; then
		log "--keep: machines left up: CLI-A $A, CLI-B $B, T1 $T1, T2 $T2, T3 $T3 (release with kiln vm release / kiln sandbox destroy)"
	else
		for vm in "$A" "$B"; do [ -n "$vm" ] && { kiln vm release "$vm" >>"$DLOG" 2>&1 && log "released $vm" || log "could not release $vm"; }; done
		for s in "$T1" "$T2" "$T3"; do [ -n "$s" ] && { kiln sandbox destroy "$s" >>"$DLOG" 2>&1 && log "destroyed $s" || log "could not destroy $s"; }; done
	fi
	[ "$PUBLISHED" = 1 ] && kiln unpublish --project "$REPO" >>"$DLOG" 2>&1
	log "report: $OUT/REPORT.md ($(( $(date +%s) - T_START ))s)"
	exit $rc
}
trap cleanup EXIT
trap 'log "interrupted"; exit 130' INT TERM

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

lease() { kiln vm lease --project "$REPO" --template ubuntu-24.04 --ttl "$TTL" --json 2>>"$DLOG" | python3 -I -c 'import re,sys; m=re.search(r"vml_[a-z0-9]+", sys.stdin.read()); print(m.group(0) if m else "")'; }
mksbx() { kiln sandbox create --project "$REPO" --image "$UBUNTU_IMAGE" --ttl "$TTL" --json 2>>"$DLOG" | python3 -I -c 'import re,sys; m=re.search(r"sbx_[a-z0-9]+", sys.stdin.read()); print(m.group(0) if m else "")'; }

if [ -n "$REUSE" ]; then
	. "$REUSE/machines.env" || die "no $REUSE/machines.env"
	log "reusing CLI-A $A, CLI-B $B${T1:+, T1 $T1, T2 $T2, T3 $T3}"
	save_machines
	for vm in "$A" "$B"; do
		vx "$vm" "test -x /opt/e2e/reset-vm.sh && /opt/e2e/reset-vm.sh" >>"$DLOG" 2>&1
	done
else
	log "leasing CLI-A and CLI-B$([ "$NEED_SBX" = 1 ] && echo ", creating three sandboxes")"
	lease >"$OUT/tmp/a" & lease >"$OUT/tmp/b" &
	if [ "$NEED_SBX" = 1 ]; then mksbx >"$OUT/tmp/t1" & mksbx >"$OUT/tmp/t2" & mksbx >"$OUT/tmp/t3" & fi
	wait
	A=$(cat "$OUT/tmp/a") B=$(cat "$OUT/tmp/b")
	[ "$NEED_SBX" = 1 ] && { T1=$(cat "$OUT/tmp/t1"); T2=$(cat "$OUT/tmp/t2"); T3=$(cat "$OUT/tmp/t3"); }
	save_machines
	log "CLI-A $A, CLI-B $B${T1:+, T1 $T1, T2 $T2, T3 $T3}"
fi
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
	vx "$vm" "mkdir -p /opt/e2e && tar xzf /var/tmp/guest.tgz -C /opt/e2e && chmod 755 /opt/e2e/*.sh /opt/e2e/*.py" >/dev/null
	upload "$vm" "$OUT/bin/hop" /usr/local/bin/hop "$SHA_HOP" || return 1
	if [ "$who" = A ] && [ "$NEED_TS" = 1 ]; then upload "$vm" "$OUT/bin/hop-server" /usr/local/bin/hop-server "$SHA_SRV" || return 1; fi
	vx "$vm" "mkdir -p /var/e2e/jobs" >/dev/null
	j=$(vjob "$vm" 0 setup /bin/bash /opt/e2e/setup-vm.sh "$who" "$RUN" "$NEED_TS")
	rc=$(vwait "$vm" "$j" 900)
	[ "$rc" = 0 ] || { log "setup-vm on $who failed ($rc): $(vx "$vm" "tail -c 400 /var/e2e/jobs/$j.out")"; return 1; }
	log "CLI-$who set up: $(vx "$vm" "hop --version 2>&1 | head -1; echo ntp=\$(cat /var/e2e/state/ntp)" | tr '\n' ' ')"
}
setup_sbx() { # name id
	local name=$1 id=$2
	for f in setup-target.sh tsup.sh; do kiln sandbox write "$id" "/root/$f" --from-file "$HERE/guest/$f" >>"$DLOG" 2>&1 || return 1; done
	kiln sandbox exec "$id" --background --timeout-seconds 1500 --command "sh /root/setup-target.sh $name" >>"$DLOG" 2>&1 || return 1
}

log "setting up the machines"
setup_vm A "$A" >"$OUT/tmp/setupA.log" 2>&1 &
PA=$!
setup_vm B "$B" >"$OUT/tmp/setupB.log" 2>&1 &
PB=$!
if [ "$NEED_SBX" = 1 ]; then setup_sbx t1 "$T1" && setup_sbx t2 "$T2" && setup_sbx t3 "$T3" || die "sandbox setup could not start"; fi
wait $PA || die "CLI-A setup failed: $(cat "$OUT/tmp/setupA.log")"
wait $PB || die "CLI-B setup failed: $(cat "$OUT/tmp/setupB.log")"
cat "$OUT/tmp/setupA.log" "$OUT/tmp/setupB.log" >>"$DLOG"

# Public keys between machines (never private material).
kiln vm get "$A" /var/e2e/state/testkey.pub -o "$OUT/tmp/testkey.pub" 2>>"$DLOG" || die "no testkey.pub on A"
kiln vm get "$B" /var/e2e/state/bkey.pub -o "$OUT/tmp/bkey.pub" 2>>"$DLOG" || die "no bkey.pub on B"
kiln vm put "$A" /var/e2e/state/bkey.pub --from-file "$OUT/tmp/bkey.pub" >>"$DLOG" 2>&1
kiln vm put "$B" /var/e2e/state/testkey-A.pub --from-file "$OUT/tmp/testkey.pub" >>"$DLOG" 2>&1
# B's target accepts A's vault key: phase 4 logs in to B from A over the tailnet.
vx "$B" "cat /var/e2e/state/testkey-A.pub >> /home/target/.ssh/authorized_keys" >/dev/null

# ------------------------------------------------------------------ tailnet and server

envline() { echo "$1=$2"; }
if [ "$NEED_SBX" = 1 ]; then
	log "waiting for the sandbox targets"
	for s in "$T1" "$T2" "$T3"; do
		for i in $(seq 1 120); do
			st=$(sx "$s" "cat /var/e2e/setup.done 2>/dev/null" | tr -d '[:space:]')
			[ -n "$st" ] && break
			sleep 5
		done
		[ "$st" = ok ] || die "sandbox $s setup failed ($st): $(sx "$s" "tail -5 /var/e2e/setup.log")"
		kiln sandbox write "$s" /var/e2e/authorized_keys --from-file "$OUT/tmp/testkey.pub" >>"$DLOG" 2>&1
		sx "$s" "for u in deploy deploy2; do install -d -m 700 -o \$u -g \$u /home/\$u/.ssh; install -m 600 -o \$u -g \$u /var/e2e/authorized_keys /home/\$u/.ssh/authorized_keys; done; echo ok" >>"$DLOG"
	done
	kiln sandbox read "$T2" /var/e2e/internal-hostkey.pub -o "$OUT/tmp/t2-internal.pub" 2>>"$DLOG"
	kiln vm put "$A" /var/e2e/state/t2-internal.pub --from-file "$OUT/tmp/t2-internal.pub" >>"$DLOG" 2>&1
fi

if [ "$NEED_TS" = 1 ]; then
	log "joining the tailnet as $NODE-*"
	declare -A TSJOB
	for who in A B; do
		vm=${!who}
		kiln vm put "$vm" /root/e2e/ts-authkey --from-file "$KEYFILE" >>"$DLOG" 2>&1 || die "could not copy the auth key to $who"
		TSJOB[$who]=$(vjob "$vm" 0 tsup sh /opt/e2e/tsup.sh /root/e2e/ts-authkey "$NODE-$(echo $who | tr A-Z a-z)")
	done
	if [ "$NEED_SBX" = 1 ]; then
		for t in 1 2 3; do
			s=$(eval echo \$T$t)
			kiln sandbox write "$s" /root/ts-authkey --from-file "$KEYFILE" >>"$DLOG" 2>&1 || die "could not copy the auth key to T$t"
			kiln sandbox exec "$s" --background --timeout-seconds 120 --command "sh /root/tsup.sh /root/ts-authkey $NODE-t$t /run/tailscale/tailscaled.sock" >>"$DLOG" 2>&1
		done
	fi
	for who in A B; do
		rc=$(vwait "${!who}" "${TSJOB[$who]}" 120)
		[ "$rc" = 0 ] || die "tailscale up failed on $who: $(vx "${!who}" "cat /var/e2e/tsup.log /var/e2e/tsup.done")"
		left=$(vx "${!who}" "test -e /root/e2e/ts-authkey && echo present || echo gone")
		[ "$left" = gone ] || die "the auth key file is still on $who"
	done
	if [ "$NEED_SBX" = 1 ]; then
		for t in 1 2 3; do
			s=$(eval echo \$T$t)
			for i in $(seq 1 30); do d=$(sx "$s" "cat /var/e2e/tsup.done 2>/dev/null"); [ -n "$d" ] && break; sleep 3; done
			case $d in rc=0*) ;; *) die "tailscale up failed on T$t: $d $(sx "$s" "cat /var/e2e/tsup.log")" ;; esac
			[ "$(sx "$s" "test -e /root/ts-authkey && echo present || echo gone")" = gone ] || die "the auth key file is still on T$t"
		done
	fi
	PEERS="$NODE-b"
	[ "$NEED_SBX" = 1 ] && PEERS="$PEERS $NODE-t1 $NODE-t2 $NODE-t3"
	j=$(vjob "$A" 0 tswait sh /opt/e2e/tswait.sh 180 $PEERS)
	rc=$(vwait "$A" "$j" 240)
	[ "$rc" = 0 ] || die "tailnet peers are not reachable from A ($(vx "$A" "cat /var/e2e/jobs/$j.out")); the ACL must allow tag:hoptest -> tag:hoptest"
	vx "$A" "python3 /opt/e2e/tsnames.py $NODE" >"$OUT/tmp/tsenv"
	grep -q '^HK_A_IP=' "$OUT/tmp/tsenv" && grep -q '^HK_B_IP=' "$OUT/tmp/tsenv" || die "could not read the tailnet names: $(cat "$OUT/tmp/tsenv")"
	SIP=$(sed -n 's/^HK_A_IP=//p' "$OUT/tmp/tsenv")
	{ cat "$OUT/tmp/tsenv"; envline HK_SERVER_IP "$SIP"; envline HK_SERVER_URL "https://$SIP:8443"; envline HK_EMAIL "$EMAIL"; envline HK_RUN "$RUN"; } >"$OUT/tmp/env"
	for who in A B; do kiln vm put "${!who}" /etc/hk-e2e/env --from-file "$OUT/tmp/env" >>"$DLOG" 2>&1; done
	cp "$OUT/tmp/env" "$OUT/tailnet.env"
	log "tailnet: $(tr '\n' ' ' <"$OUT/tmp/env")"

	log "starting the throwaway hop-server on CLI-A at https://$SIP:8443"
	j=$(vjob "$A" 0 server bash /opt/e2e/server.sh "$SIP" "$EMAIL")
	rc=$(vwait "$A" "$j" 120)
	[ "$rc" = 0 ] || die "hop-server did not start: $(vx "$A" "cat /var/e2e/jobs/$j.out")"
	kiln vm get "$A" /var/e2e/state/ca.crt -o "$OUT/tmp/ca.crt" 2>>"$DLOG" || die "no CA certificate"
	kiln vm put "$B" /usr/local/share/ca-certificates/hk-e2e-ca.crt --from-file "$OUT/tmp/ca.crt" >>"$DLOG" 2>&1
	vx "$B" "update-ca-certificates >/dev/null 2>&1; curl -fsS -m 8 https://$SIP:8443/v1/healthz" >>"$DLOG" || die "CLI-B cannot reach the server over the tailnet"
fi

# Secrets between machines: through 0600 files here, never on a command line.
copy_secret() { # name from-vm to-vm
	local f=$OUT/tmp/sec.$1
	(umask 077; kiln vm get "$2" "/root/e2e/sec/$1" -o "$f" 2>>"$DLOG") || return 1
	kiln vm put "$3" "/root/e2e/sec/$1" --from-file "$f" >>"$DLOG" 2>&1
	rm -f "$f"
	vx "$3" "chmod 600 /root/e2e/sec/$1" >/dev/null
}
xfer() { kiln vm get "$1" "$2" -o "$OUT/tmp/xfer" 2>>"$DLOG" && kiln vm put "$3" "$4" --from-file "$OUT/tmp/xfer" >>"$DLOG" 2>&1; }

# Cross-machine propagation: watcher on W, change on C, both clocks NTP-synced.
prop() { # id W C spec hop-args...
	local id=$1 W=$2 C=$3 spec=$4; shift 4
	local jw jm s m
	jw=$(vjob "${!W}" 3 "watch-$id" $(py syncops.py) watch "$id" "$spec" 120)
	for i in $(seq 1 20); do vx "${!W}" "test -s /var/e2e/state/watch-$id" >/dev/null && break; sleep 1; done
	jm=$(vjob "${!C}" 3 "mark-$id" $(py syncops.py) mark "$id" "$@")
	vwait "${!C}" "$jm" 90 >/dev/null
	vwait "${!W}" "$jw" 150 >/dev/null
	m=$(vx "${!C}" "cat /var/e2e/state/mark-$id")
	s=$(vx "${!W}" "cat /var/e2e/state/watch-$id")
	python3 -I - "$m" "$s" <<'EOF' >"$OUT/tmp/prop"
import json, sys
m, s = json.loads(sys.argv[1] or '{}'), json.loads(sys.argv[2] or '{}')
if m.get('rc') != 0:
    print('fail change failed: %s' % m.get('out'))
elif 'seen' in s:
    d = s['seen'] - m['done']
    print('%s %.2fs' % ('pass' if d <= 10 else 'fail', d))
else:
    print('fail not seen within 120s')
EOF
	read -r st det <"$OUT/tmp/prop"
	dcheck 3 "prop.$id" "propagation $id ($C to $W) with no hop sync, within 10s" "$st" "$det"
}

# ------------------------------------------------------------------ phases

phase1() {
	log "=== phase 1: local only"
	local ja jb
	ja=$(vjob "$A" 1 main $(py p1.py) main)
	jb=$(vjob "$B" 1 main $(py p1.py) main)
	for x in "A $ja" "B $jb"; do
		set -- $x
		rc=$(vwait "${!1}" "$2" 1200)
		[ "$rc" = 0 ] || dcheck 1 "harness.$1.main" "phase 1 main on $1 finished" fail "exit $rc" harness
	done
	vrun "$B" 1 before-reboot 120 $(py p1.py) before-reboot
	reboot_vm "$B"
	vrun "$B" 1 after-reboot 300 $(py p1.py) after-reboot
}

phase2() {
	log "=== phase 2: MCP"
	vrun "$A" 2 main 1200 $(py p2.py)
}

ensure_signed_in() { # B's device name if it has to sign in
	vrun "$A" 3 ensure-a 300 $(py p3.py) ensure-a
	copy_secret kit "$A" "$B"; copy_secret masterpw "$A" "$B"
	vrun "$B" 3 ensure-b 300 $(py p3.py) ensure-b "$1"
}

phase3() {
	log "=== phase 3: sync"
	vrun "$A" 3 server-check 60 $(py p3.py) server-check
	vrun "$B" 3 server-check 60 $(py p3.py) server-check
	vrun "$A" 3 signup 300 $(py p3.py) signup
	xfer "$A" /var/e2e/state/hosts-A.json "$B" /var/e2e/state/hosts-A.json
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
			vx "$B" "grep -q 'yes or no' /var/e2e/logs/pty-blogin.log" >/dev/null && break
			sleep 2
		done
		vx "$B" "echo yes > /var/e2e/state/blogin.in" >/dev/null
		vwait "$A" "$ja" 180 >/dev/null
	fi
	rc=$(vwait "$B" "$jl" 360)
	[ "$rc" = 0 ] || dcheck 3 harness.b-login "B's approval login step finished" fail "exit $rc" harness
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
	vwait "$A" "$jw1" 300 >/dev/null; vwait "$A" "$jw2" 300 >/dev/null
	t_un=$(vx "$B" "cat /var/e2e/state/unblocked")
	s1=$(vx "$A" "cat /var/e2e/state/watch-offb1")
	s2=$(vx "$A" "cat /var/e2e/state/watch-offsnip")
	python3 -I - "$t_un" "$s1" "$s2" <<'EOF' >"$OUT/tmp/off"
import json, sys
u = json.loads(sys.argv[1] or '{}').get('t')
ds = [json.loads(x or '{}').get('seen') for x in sys.argv[2:]]
if u and all(ds):
    d = max(ds) - u
    print('%s host and snippet on A %.1fs after the network came back (backoff up to ~60s)' % ('pass' if d <= 120 else 'fail', d))
else:
    print('fail not seen on A within 240s: %s' % ds)
EOF
	read -r st det <"$OUT/tmp/off"
	dcheck 3 outbox-drain "the offline outbox drains on its own when the network returns (no hop sync)" "$st" "$det"

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
	vx "$B" "nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 &" >/dev/null
	sleep 8
	vrun "$A" 3 mark-rb1 60 $(py syncops.py) mark rb1 add rb1 --address 10.9.7.2 --user deploy
	reboot_wait() { local t0=$SECONDS; sleep 10; while [ $((SECONDS - t0)) -lt 300 ]; do up=$(vx "$B" "cut -d. -f1 /proc/uptime" | tr -d '[:space:]'); [ -n "$up" ] && [ "$up" -lt 200 ] && break; sleep 5; done; for i in $(seq 1 30); do [ -n "$(vx "$B" "tailscale ip -4 2>/dev/null")" ] && break; sleep 3; done; }
	reboot_wait
	vrun "$B" 3 after-reboot 240 $(py p3.py) after-reboot rb1
	vrun "$B" 3 service-setup 120 $(py p3.py) service-setup
	vx "$B" "nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 &" >/dev/null
	sleep 8
	vrun "$A" 3 mark-rb2 60 $(py syncops.py) mark rb2 add rb2 --address 10.9.7.3 --user deploy --key testkey
	reboot_wait
	vrun "$B" 3 after-reboot-service 400 $(py p3.py) after-reboot-service rb2

	log "devices, logout"
	local aname
	aname=$(vx "$A" "hostname" | tr -d '[:space:]')
	vrun "$A" 3 devices 60 $(py p3.py) devices cli-b
	vrun "$B" 3 devices 60 $(py p3.py) devices "$aname"
	vrun "$B" 3 logout 180 $(py p3.py) logout
	vrun "$A" 3 a-after-logout 60 $(py p3.py) a-after-logout cli-b
	copy_secret kit "$A" "$B"; copy_secret masterpw "$A" "$B"
	vrun "$B" 3 pwlogin 240 $(py p3.py) pwlogin cli-b2
}

phase4() {
	log "=== phase 4: SSH over Tailscale"
	ensure_signed_in cli-b2
	vrun "$A" 4 a-add 300 $(py p4.py) a-add
	vrun "$A" 4 a-jump 180 $(py p4.py) a-jump
	vrun "$A" 4 a-ts 240 $(py p4.py) a-ts
	vrun "$A" 4 a-ts-b 180 $(py p4.py) a-ts-b
	vrun "$B" 4 b-use 300 $(py p4.py) b-use
	vrun "$B" 4 b-mcp 180 $(py p4.py) b-mcp
	local e ja jb
	e=$(( $(date +%s) + 15 ))
	ja=$(vjob "$A" 4 conc $(py p4.py) conc $e)
	jb=$(vjob "$B" 4 conc $(py p4.py) conc $e)
	vwait "$A" "$ja" 300 >/dev/null; vwait "$B" "$jb" 300 >/dev/null
	e=$(( $(date +%s) + 15 ))
	jb=$(vjob "$B" 4 syncuse-b $(py p4.py) syncuse-b $e)
	ja=$(vjob "$A" 4 syncuse-a $(py p4.py) syncuse-a $e)
	vwait "$A" "$ja" 120 >/dev/null; vwait "$B" "$jb" 240 >/dev/null
	local sa sb
	sa=$(vx "$A" "cat /var/e2e/state/syncuse-a"); sb=$(vx "$B" "cat /var/e2e/state/syncuse-b")
	read -r st det < <(python3 -I -c 'import json,sys
a,b=json.loads(sys.argv[1] or "{}"),json.loads(sys.argv[2] or "{}")
d=(b.get("seen") or 0)-(a.get("done") or 0)
print(("pass %.2fs" % d) if b.get("seen") and a.get("rc")==0 and d<=10 else "fail edit %s, seen %s" % (a, b.get("seen")))' "$sa" "$sb")
	dcheck 4 syncuse-prop "a user change on A reaches B's ssh config within 10s while B has open sessions" "$st" "$det"
	vrun "$A" 4 a-reset 60 $(py p4.py) a-reset
}

phase5() {
	log "=== phase 5: revocation"
	local t0 tw
	ensure_signed_in cli-r1
	vrun "$A" 5 ensure-t1 120 $(py p5.py) ensure-t1
	vrun "$B" 5 b-wait-t1 120 $(py p5.py) b-wait-t1
	vrun "$B" 5 device-id 60 $(py p5.py) device-id
	vrun "$B" 5 localb-setup 240 $(py p5.py) localb-setup
	vrun "$B" 5 access 240 $(py p5.py) access base work

	revoke() { # n: revoke B's current device from A; prints the start time
		local dev
		dev=$(vx "$B" "cat /var/e2e/state/device-id 2>/dev/null" | tr -d '[:space:]')
		[ -n "$dev" ] || dcheck 5 "harness.device-id-$1" "B's device ID is known before revoke $1" fail "empty" harness
		vrun "$A" 5 revoke 300 $(py p5.py) revoke "$dev" "$1"
		vx "$A" "cat /var/e2e/state/revoke-start-$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["t"])'
	}
	relogin() { copy_secret kit "$A" "$B"; vrun "$B" 5 relogin 300 $(py p5.py) relogin "$1"; }

	# B1: online and idle.
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s1-online 60)
	sleep 2
	t0=$(revoke 1)
	vrun "$B" 5 cutoff 60 $(py p5.py) cutoff s1-online "$t0" 30
	vrun "$B" 5 access 240 $(py p5.py) access s1-online cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s1-online
	vrun "$B" 5 unlock-after 120 $(py p5.py) unlock-after s1-online
	relogin cli-r2

	# B2: sessions open during the revoke.
	vrun "$B" 5 sessions-start 60 $(py p5.py) sessions-start
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s2-session 60)
	sleep 2
	t0=$(revoke 2)
	vrun "$B" 5 cutoff 60 $(py p5.py) cutoff s2-session "$t0" 30
	vrun "$B" 5 access 240 $(py p5.py) access s2-session cut
	vrun "$B" 5 sessions-end 120 $(py p5.py) sessions-end s2-session
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s2-session
	relogin cli-r3

	# B3: offline during the revoke.
	vrun "$B" 5 block 30 $(py p5.py) block 1
	t0=$(revoke 3)
	sleep 15
	vrun "$B" 5 access 240 $(py p5.py) access s3-offline cut r2-P2-1
	vrun "$B" 5 daemon-restart 120 $(py p5.py) daemon-restart s3-offline
	tw=$(vjob "$B" 5 watch $(py p5.py) watch s3u 150)
	sleep 2
	t0=$(date +%s)
	vrun "$B" 5 block 30 $(py p5.py) block 0
	vrun "$B" 5 cutoff 60 $(py p5.py) cutoff s3u "$t0" 120
	vrun "$B" 5 access 240 $(py p5.py) access s3-reconnected cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s3-offline
	relogin cli-r4

	# B4: daemon stopped during the revoke, then started.
	vrun "$B" 5 daemon-stop 60 $(py p3.py) daemon-stop
	t0=$(revoke 4)
	sleep 5
	vrun "$B" 5 stopped 60 $(py p5.py) stopped s4-stopped
	vrun "$B" 5 start-window 120 $(py p5.py) start-window s4-stopped
	vrun "$B" 5 access 240 $(py p5.py) access s4-started cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s4-stopped
	relogin cli-r5

	# B5: revoked, then rebooted.
	t0=$(revoke 5)
	sleep 10
	reboot_vm "$B"
	vrun "$B" 5 start-window 120 $(py p5.py) start-window s5-reboot
	vrun "$B" 5 access 240 $(py p5.py) access s5-reboot cut
	vrun "$B" 5 inventory 120 $(py p5.py) inventory s5-reboot
	vrun "$B" 5 unlock-after 120 $(py p5.py) unlock-after s5-reboot
}

want 1 && phase1
want 2 && phase2
want 3 && phase3
want 4 && phase4
want 5 && phase5
log "all selected phases ran"
exit 0
