#!/bin/sh
# Decides which rolling tags a release may move, so that releasing an older
# version never moves them backward.
#
#   sh scripts/release-tags.sh VERSION <tags
#
# VERSION is the release version without the leading v: MAJOR.MINOR.PATCH or
# MAJOR.MINOR.PATCH-(alpha|beta|rc).N, N a non-negative integer without a
# leading zero. Any other VERSION exits 2. Stdin holds the repository's
# existing release tags, one per line, in the same format with the v. Lines
# that do not match are ignored, and VERSION's own tag may or may not be among
# them. It prints lines for $GITHUB_OUTPUT:
#
#   npm_tag=latest | release-MAJOR.MINOR | next | prerelease-old
#   docker_latest=true | false
#   docker_minor=true | false
#
# A stable release takes latest only if it is at least the highest stable tag,
# and MAJOR.MINOR only if it is at least the highest stable tag of that
# MAJOR.MINOR. A prerelease takes neither, and takes the npm tag next only if
# it is at least the highest prerelease. Prereleases never count against a
# stable release, nor stable releases against a prerelease.
#
# Versions are compared with GNU sort -V. That is not SemVer order in general
# (rc.a10 sorts after rc.a2), but within the format above it agrees: the
# numbers compare as numbers, and alpha, beta and rc sort in that order.
# npm/test/release-tags.test.js checks this against SemVer order.
set -eu

if [ $# -ne 1 ]; then
	echo "usage: $0 VERSION <tags" >&2
	exit 2
fi
version=$1

semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?'
if ! printf '%s\n' "$version" | grep -Eq "^$semver\$"; then
	echo "release-tags: not a version: $version" >&2
	exit 2
fi
LC_ALL=C
export LC_ALL

# The release versions in the tag list, with VERSION added: one per line,
# without the v.
all=$( (
	cat
	printf 'v%s\n' "$version"
) | grep -E "^v$semver\$" | sed 's/^v//' | sort -u)

# highest prints the highest version among the lines on stdin.
highest() {
	sort -V | tail -n 1
}

case "$version" in
*-*)
	pre=$(printf '%s\n' "$all" | grep -e '-' | highest)
	if [ "$pre" = "$version" ]; then
		echo "npm_tag=next"
	else
		echo "npm_tag=prerelease-old"
	fi
	echo "docker_latest=false"
	echo "docker_minor=false"
	;;
*)
	minor=$(printf '%s\n' "$version" | cut -d. -f1,2)
	stable=$(printf '%s\n' "$all" | grep -v -e '-')
	top=$(printf '%s\n' "$stable" | highest)
	minor_re=$(printf '%s' "$minor" | sed 's/\./\\./g')
	top_minor=$(printf '%s\n' "$stable" | grep -E "^$minor_re\\." | highest)
	if [ "$top" = "$version" ]; then
		echo "npm_tag=latest"
		echo "docker_latest=true"
	else
		echo "npm_tag=release-$minor"
		echo "docker_latest=false"
	fi
	if [ "$top_minor" = "$version" ]; then
		echo "docker_minor=true"
	else
		echo "docker_minor=false"
	fi
	;;
esac
