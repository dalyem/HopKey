#!/bin/sh
# run-tests.sh TESTBIN [RUN-REGEXP]: run the sshd fixtures as root and pack
# the output (test.log, versions, the binding logs) into /var/hkfx/out.tgz.
set -u
bin=$1
pat=${2:-^TestSSHD}
out=/var/hkfx/out
rm -rf "$out" /var/hkfx/out.tgz
mkdir -p "$out"
work=$(mktemp -d)
cd "$work" || exit 2
HOPKEY_SSHD_FIXTURE=1 HOPKEY_REQUIRE_SSH=1 HKFX_OUT=$out TMPDIR=/tmp \
	"$bin" -test.run "$pat" -test.v -test.count=1 -test.timeout 25m >"$out/test.log" 2>&1
rc=$?
echo "$rc" >"$out/exit-code"
tar czf /var/hkfx/out.tgz -C "$out" .
exit "$rc"
