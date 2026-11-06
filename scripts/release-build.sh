#!/bin/sh
# Builds the release binaries, as the release workflow does.
#
#   sh scripts/release-build.sh VERSION OUTDIR
#
# VERSION is the release version without the leading v. OUTDIR gets hop for
# linux and darwin on amd64 and arm64, hop-server for linux on both, and
# SHA256SUMS. The binaries are static (modernc.org/sqlite is pure Go), so
# every one of them cross-compiles from one machine.
set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 VERSION OUTDIR" >&2
	exit 2
fi
version=$1
out=$2

# The golang image keeps the toolchain out of the PATH that Kiln sets.
PATH="$PATH:/usr/local/go/bin"
export PATH
: "${GOCACHE:=$PWD/.check-cache/go-build}"
mkdir -p "$GOCACHE" "$out"
export GOCACHE

ldflags="-s -w -X github.com/dalyem/hopkey/internal/version.Version=$version"

build() {
	echo "building $1 for $2/$3"
	CGO_ENABLED=0 GOOS=$2 GOARCH=$3 go build -trimpath -ldflags "$ldflags" -o "$out/$1-$2-$3" "./cmd/$1"
}

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
	build hop "${target%/*}" "${target#*/}"
done
for arch in amd64 arm64; do
	build hop-server linux "$arch"
done

# Run from OUTDIR so that the sums name the files without a path.
(cd "$out" && sha256sum hop-* >SHA256SUMS)
