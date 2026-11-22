#!/bin/sh
# Assembles the publishable @dalyem/hopkey npm package.
#
#   sh scripts/npm-stage.sh VERSION BINDIR OUTDIR
#
# VERSION is the release version without the leading v. BINDIR holds the
# release binaries (hop-linux-amd64, hop-linux-arm64, hop-darwin-amd64 and
# hop-darwin-arm64, as scripts/release-build.sh names them). OUTDIR is made
# fresh; npm pack and npm publish take it from there.
set -eu

if [ $# -ne 3 ]; then
	echo "usage: $0 VERSION BINDIR OUTDIR" >&2
	exit 2
fi
version=$1
bindir=$2
out=$3

# Anything else in the version would land in package.json as it is. The same
# format as the release tags: MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-(alpha|
# beta|rc).N, N without a leading zero.
if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?$'; then
	echo "npm-stage: not a version: $version" >&2
	exit 2
fi

src=$(cd "$(dirname "$0")/../npm" && pwd)
rm -rf "$out"
mkdir -p "$out/bin" "$out/lib"

# The template is private so that nobody publishes it by accident; the
# staged package is the one meant for publishing.
sed -e '/^  "private": true,$/d' \
	-e "s/^  \"version\": \"0.0.0-template\",\$/  \"version\": \"$version\",/" \
	"$src/package.json" >"$out/package.json"
if ! grep -q "^  \"version\": \"$version\",\$" "$out/package.json" || grep -q '"private"' "$out/package.json"; then
	echo "npm-stage: could not set the version in package.json" >&2
	exit 1
fi

cp "$src/install.js" "$src/README.md" "$src/../LICENSE" "$out/"
cp -R "$src/lib/." "$out/lib/"
cp "$src/bin/hop" "$out/bin/hop"
chmod 0755 "$out/bin/hop"

# release name -> vendor directory (Node's names for the platform and arch).
for pair in linux-amd64:linux-x64 linux-arm64:linux-arm64 darwin-amd64:darwin-x64 darwin-arm64:darwin-arm64; do
	from=$bindir/hop-${pair%%:*}
	to=$out/vendor/${pair##*:}
	if [ ! -f "$from" ]; then
		echo "npm-stage: missing $from" >&2
		exit 1
	fi
	mkdir -p "$to"
	cp "$from" "$to/hop"
	# Artifacts come back from upload and download without their modes.
	chmod 0755 "$to/hop"
done
echo "staged @dalyem/hopkey $version in $out"
