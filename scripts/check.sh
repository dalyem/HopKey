#!/bin/sh
# Entry points for the Kiln checks in kiln.json: vet, test, race, gofmt.
set -eu

# The golang image keeps the toolchain out of the PATH that Kiln sets.
PATH="$PATH:/usr/local/go/bin"
export PATH

# Kiln's /tmp (and $HOME under it) is a 512 MiB tmpfs. The race build of the
# pure-Go SQLite driver alone needs about 100 MiB of cache, so keep the
# build cache on the workspace disk unless the caller chose a location.
# Build temp files stay in /tmp: tests inherit that directory, and the
# safepath tests need a private one.
: "${GOCACHE:=$PWD/.check-cache/go-build}"
mkdir -p "$GOCACHE"
export GOCACHE

case "${1:-}" in
vet)
	go vet ./...
	# The dev store is compiled only with this tag; vet it too.
	go vet -tags hopdev ./...
	;;
test)
	# The ssh integration test must run on Kiln, not skip.
	HOPKEY_REQUIRE_SSH=1 sh "$(dirname "$0")/with-passwd.sh" go test ./...
	# The dev store and the hop binary's daemon autostart exist only with hopdev.
	HOPKEY_REQUIRE_SSH=1 exec sh "$(dirname "$0")/with-passwd.sh" go test -tags hopdev ./internal/model/devstore/ ./cmd/hop/
	;;
race)
	# Same as test, under the race detector, for the packages with goroutines.
	# Race binaries use several times the memory of plain ones; running
	# packages side by side got the job killed for its memory limit on Kiln
	# (the daemon package alone is the largest), so they run one at a time.
	HOPKEY_REQUIRE_SSH=1 exec sh "$(dirname "$0")/with-passwd.sh" go test -race -p 1 ./internal/...
	;;
gofmt)
	out=$(gofmt -l .)
	if [ -n "$out" ]; then
		echo "gofmt needed:" >&2
		echo "$out" >&2
		exit 1
	fi
	;;
*)
	echo "usage: $0 vet|test|race|gofmt" >&2
	exit 2
	;;
esac
