#!/usr/bin/env bash
# The sshd fixtures of hop access and hop key rotate (spec rev 17, §7.7
# Change 2, §8.4) on a leased Kiln VM. Runs on the orchestrator and talks
# to the VM only through the kiln CLI; nothing from the repo runs here.
#
#   scripts/access-fixtures/run.sh [--ttl 60m] [--run REGEXP] [--keep]
#
# 1. Builds the test binary of internal/cli with the sshdfixture tag on
#    Kiln checks (go test -c), and fetches it.
# 2. Leases one ubuntu-24.04 VM and sets it up (guest/setup.sh): sshd on
#    22 for the target account hkt, two more sshds for the jump account
#    hkj, a hook PATH for hkt (guest/hook.sh) and a sudo helper that mounts
#    a tmpfs on one of hkt's session directories (guest/mount-helper.sh).
# 3. Runs the binary as root with HOPKEY_SSHD_FIXTURE=1 and -test.run
#    '^TestSSHD' (or --run), and fetches test.log, versions.txt and the
#    recorded binding logs into e2e-out/access-fixtures-<id>/.
# 4. Releases the VM, also on failure or interrupt (--keep leaves it, for
#    debugging; release it with kiln vm release).
#
# Start it from a tool call in the foreground, not with a plain &: kiln
# takes its identity from the harness, and the lease must be releasable
# by whoever started it.
#
# The recorded logs under binding/ are what internal/access/testdata/
# holds for this VM's OpenSSH version; copy them there by hand when the
# template's OpenSSH changes (see the README in that directory).
#
# Exit: 0 the tests passed; 1 they failed; 2 a harness failure (build,
# lease, setup, upload, fetch, release).
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
TTL=60m
PAT='^TestSSHD'
KEEP=0
while [ $# -gt 0 ]; do
	case $1 in
	--ttl) TTL=$2; shift 2 ;;
	--run) PAT=$2; shift 2 ;;
	--keep) KEEP=1; shift ;;
	-h | --help) sed -n '2,/^set -uo/p' "$0" | sed -n 's/^# \{0,1\}//p'; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
ID="$(date -u +%m%d%H%M)-$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')"
OUT=$REPO/e2e-out/access-fixtures-$ID
mkdir -p "$OUT/tmp" "$OUT/result"
LOG=$OUT/driver.log
K=(--project "$REPO")
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG" >&2; }
die() { log "FATAL: $*"; exit 2; }

VM="" LEASE_OP=""
cleanup() {
	local rc=$?
	trap '' INT TERM HUP
	if [ -z "$VM" ] && [ -n "$LEASE_OP" ]; then
		VM=$(kiln op status "$LEASE_OP" "${K[@]}" --wait --timeout 10m --json 2>>"$LOG" | grep -oE 'vml_[a-z0-9]+' | head -1)
	fi
	if [ -n "$VM" ]; then
		if [ "$KEEP" = 1 ]; then
			log "kept VM $VM (release it with: kiln vm release $VM)"
		else
			for i in 1 2 3; do
				kiln vm release "$VM" "${K[@]}" >>"$LOG" 2>&1 && { log "released $VM"; break; }
				log "release of $VM failed (try $i)"
				[ "$i" = 3 ] && rc=2
				sleep 5
			done
		fi
	fi
	log "output: $OUT"
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

command -v kiln >/dev/null || die "the kiln CLI is not on PATH"
log "kiln identity: $(kiln whoami 2>&1 | head -1)"

# ------------------------------------------------------------------ build
BUILD='export PATH=$PATH:/usr/local/go/bin GOCACHE=$PWD/.check-cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64; mkdir -p /artifacts && go test -c -tags sshdfixture -o /artifacts/cli.test ./internal/cli && cd /artifacts && sha256sum cli.test > SHA256SUMS && cat SHA256SUMS'
for i in $(seq 1 40); do
	kiln checks run "${K[@]}" --json --timeout 20m --command "$BUILD" >"$OUT/build.json" 2>>"$LOG" && break
	grep -q '"limit_exceeded"' "$OUT/build.json" || die "build failed: see $OUT/build.json"
	[ "$i" = 40 ] && die "kiln's job limit stayed reached for 20 minutes"
	sleep 30
done
BUILD_OP=$(grep -oE 'op_[a-z0-9]+' "$OUT/build.json" | head -1)
for f in cli.test SHA256SUMS; do
	kiln artifacts get "$BUILD_OP" "$f" -o "$OUT/tmp/$f" "${K[@]}" 2>>"$LOG" || die "could not fetch $f from $BUILD_OP"
done
(cd "$OUT/tmp" && sha256sum -c SHA256SUMS >>"$LOG" 2>&1) || die "artifact checksum mismatch"
SHA=$(awk '{print $1}' "$OUT/tmp/SHA256SUMS")
log "built the test binary (job $BUILD_OP, sha256 $SHA)"

# ------------------------------------------------------------------ lease
out=$(kiln vm lease "${K[@]}" --template ubuntu-24.04 --ttl "$TTL" --json --no-wait 2>>"$LOG")
LEASE_OP=$(printf '%s' "$out" | grep -oE 'op_[a-z0-9]+' | head -1)
VM=$(printf '%s' "$out" | grep -oE 'vml_[a-z0-9]+' | head -1)
[ -n "$LEASE_OP$VM" ] || die "kiln vm lease returned nothing: $out"
if [ -z "$VM" ]; then
	VM=$(kiln op status "$LEASE_OP" "${K[@]}" --wait --timeout 15m --json 2>>"$LOG" | grep -oE 'vml_[a-z0-9]+' | head -1)
fi
[ -n "$VM" ] || die "the lease ($LEASE_OP) gave no VM"
log "leased $VM (op $LEASE_OP, ttl $TTL)"
echo "$VM" >"$OUT/lease"

vx() { kiln vm exec "$VM" "${K[@]}" --command "$1" 2>>"$LOG"; }
for i in $(seq 1 60); do vx true >/dev/null && break; sleep 5; done
vx true >/dev/null || die "the VM's guest agent doesn't answer"

# vjob NAME TIMEOUT CMD: run CMD detached on the VM, wait, print its rc.
vjob() {
	local name=$1 to=$2 cmd=$3 t0=$SECONDS rc
	vx "systemd-run --unit=hkfx-$name-$RANDOM --collect --quiet /bin/sh /opt/hkfx/job.sh $name /bin/sh -c $(printf %q "$cmd")" >/dev/null
	while [ $((SECONDS - t0)) -lt "$to" ]; do
		rc=$(vx "cat /var/hkfx/jobs/$name.rc 2>/dev/null || true" | tr -d '[:space:]')
		[ -n "$rc" ] && { echo "$rc"; return; }
		sleep 3
	done
	echo timeout
}

# upload SRC DST: gzip, base64, 500 KB parts, reassembled by a job.
upload() {
	local src=$1 dst=$2 d n=0 rc got sha
	sha=$(sha256sum "$src" | cut -d' ' -f1)
	d=$OUT/tmp/up.$(basename "$src")
	rm -rf "$d"; mkdir -p "$d"
	gzip -9c "$src" | base64 -w0 | split -b 500000 -a 3 - "$d/c."
	vx "rm -rf /var/hkfx/up && mkdir -p /var/hkfx/up" >/dev/null
	for c in "$d"/c.*; do
		kiln vm put "$VM" "/var/hkfx/up/$(basename "$c")" --from-file "$c" "${K[@]}" >>"$LOG" 2>&1 || return 1
		n=$((n + 1))
	done
	rc=$(vjob "up-$(basename "$src" | tr -c 'a-z0-9\n' -)" 300 "cat /var/hkfx/up/c.* | base64 -d | gunzip > $dst && chmod 755 $dst")
	[ "$rc" = 0 ] || return 1
	got=$(vx "sha256sum $dst | cut -d' ' -f1" | tr -d '[:space:]')
	[ "$got" = "$sha" ] || { log "sha256 mismatch for $dst"; return 1; }
	log "uploaded $(basename "$src") in $n parts"
}

# ------------------------------------------------------------------ set up
vx "mkdir -p /opt/hkfx /var/hkfx/jobs" >/dev/null
kiln vm put "$VM" /opt/hkfx/job.sh --from-file "$HERE/guest/job.sh" "${K[@]}" >>"$LOG" 2>&1 || die "could not copy job.sh"
tar czf "$OUT/tmp/guest.tgz" -C "$HERE/guest" .
kiln vm put "$VM" /var/hkfx/guest.tgz.b64 --content "$(base64 -w0 "$OUT/tmp/guest.tgz")" "${K[@]}" >>"$LOG" 2>&1 || die "could not copy the guest scripts"
vx "mkdir -p /opt/hkfx/guest && base64 -d /var/hkfx/guest.tgz.b64 | tar xzf - -C /opt/hkfx/guest" >/dev/null
rc=$(vjob setup 900 "/bin/sh /opt/hkfx/guest/setup.sh /opt/hkfx/guest")
log "setup: rc $rc: $(vx 'tail -c 400 /var/hkfx/jobs/setup.out' | tr '\n' ' ')"
[ "$rc" = 0 ] || die "setup failed"
upload "$OUT/tmp/cli.test" /opt/hkfx/cli.test || die "could not upload the test binary"

# ------------------------------------------------------------------ run
log "running $PAT on $VM"
rc=$(vjob tests 1800 "/bin/sh /opt/hkfx/guest/run-tests.sh /opt/hkfx/cli.test $(printf %q "$PAT")")
log "tests: rc $rc"

# ------------------------------------------------------------------ fetch
parts=$(vx "cd /var/hkfx && rm -rf fetch && mkdir fetch && base64 -w0 out.tgz | split -b 200000 -a 3 - fetch/p. && ls fetch")
[ -n "$parts" ] || die "no output to fetch"
: >"$OUT/tmp/out.b64"
for p in $parts; do
	kiln vm get "$VM" "/var/hkfx/fetch/$p" --max-bytes 262144 -o "$OUT/tmp/$p" "${K[@]}" 2>>"$LOG" || die "could not fetch $p"
	cat "$OUT/tmp/$p" >>"$OUT/tmp/out.b64"
done
base64 -d "$OUT/tmp/out.b64" | tar xzf - -C "$OUT/result" || die "could not unpack the output"
log "versions: $(tr '\n' ' ' <"$OUT/result/versions.txt" 2>/dev/null)"
grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|PASS|FAIL|ok)|^ +--- ' "$OUT/result/test.log" | grep -v '^=== RUN' >"$OUT/summary.txt"
cat "$OUT/summary.txt" >&2
case $rc in
0) log "PASS"; exit 0 ;;
timeout) log "the tests didn't finish in 30 minutes"; exit 2 ;;
*) log "FAIL (see $OUT/result/test.log)"; exit 1 ;;
esac
