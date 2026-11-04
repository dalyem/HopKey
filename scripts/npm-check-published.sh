#!/bin/sh
# Tells the release workflow whether a package version is already on npm, and
# whether what is there is what is about to be published.
#
#   sh scripts/npm-check-published.sh PACKAGE VERSION TARBALL >>"$GITHUB_OUTPUT"
#
# Prints published=false if the registry has no such version. If it has one,
# the registry's tarball and TARBALL are unpacked and compared, file by file
# and by which files are executable: the same prints published=true (a re-run
# of the same commit, since the Go builds are reproducible), a difference
# prints the differing files to stderr and exits 1. Any other answer from the
# registry exits 1: an unknown answer is never "not published".
#
# The read is anonymous: it leaves out the .npmrc that setup-node wrote. The
# registry's tarball is fetched with npm pack, which installs nothing and runs
# no scripts.
set -eu

if [ $# -ne 3 ]; then
	echo "usage: $0 PACKAGE VERSION TARBALL" >&2
	exit 2
fi
package=$1
version=$2
tarball=$3
[ -f "$tarball" ] || {
	echo "npm-check-published: no such file: $tarball" >&2
	exit 2
}

NPM_CONFIG_USERCONFIG=/dev/null
export NPM_CONFIG_USERCONFIG
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/fetched" "$work/registry" "$work/local"

# A missing package is E404 and a missing version of a package is ETARGET.
if ! out=$(npm pack "$package@$version" --ignore-scripts --registry https://registry.npmjs.org/ --pack-destination "$work/fetched" 2>&1); then
	if printf '%s\n' "$out" | grep -Eq '^npm error code (E404|ETARGET)$'; then
		echo "published=false"
		exit 0
	fi
	printf '%s\n' "$out" >&2
	echo "::error::could not tell whether $package@$version is on npm" >&2
	exit 1
fi

set -- "$work"/fetched/*.tgz
if [ $# -ne 1 ] || [ ! -f "$1" ]; then
	echo "::error::npm pack $package@$version did not leave exactly one tarball" >&2
	exit 1
fi
tar -xzf "$1" -C "$work/registry"
tar -xzf "$tarball" -C "$work/local"

# diff -r ignores modes, and an executable that lost its mode is a broken
# package.
modes() {
	(cd "$1" && find . -type f -perm -100 | sort)
}
modes "$work/registry" >"$work/registry.modes"
modes "$work/local" >"$work/local.modes"

bad=0
if ! diff -rq "$work/registry" "$work/local" >"$work/diff.txt" 2>&1; then
	bad=1
fi
if ! diff -u "$work/registry.modes" "$work/local.modes" >"$work/modes.txt" 2>&1; then
	bad=1
fi
if [ "$bad" -ne 0 ]; then
	echo "::error::$package@$version is on npm, and its contents are not those of $tarball" >&2
	# Names the files; the work directory prefixes are not helpful.
	sed -e "s#$work/registry#registry#g" -e "s#$work/local#local#g" "$work/diff.txt" >&2
	if [ -s "$work/modes.txt" ]; then
		echo "executable files differ (registry first):" >&2
		cat "$work/modes.txt" >&2
	fi
	exit 1
fi
echo "npm-check-published: $package@$version is on npm with the same contents" >&2
echo "published=true"
