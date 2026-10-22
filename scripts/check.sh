#!/bin/sh
# Entry points for the Kiln checks in kiln.json: vet, test, race, gofmt.
set -eu

# The golang image keeps the toolchain out of the PATH that Kiln sets.
PATH="$PATH:/usr/local/go/bin"
export PATH

case "${1:-}" in
vet)
	go vet ./...
	;;
test)
	# The ssh integration test must run on Kiln, not skip.
	HOPKEY_REQUIRE_SSH=1 exec sh "$(dirname "$0")/with-passwd.sh" go test ./...
	;;
race)
	# Same as test, under the race detector, for the packages with goroutines.
	HOPKEY_REQUIRE_SSH=1 exec sh "$(dirname "$0")/with-passwd.sh" go test -race ./internal/...
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
