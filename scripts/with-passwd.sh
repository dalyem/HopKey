#!/bin/sh
# Run a command with a passwd entry for the current uid.
#
# OpenSSH refuses to start when getpwuid() fails ("No user exists for uid N").
# Kiln check containers run as an unprivileged uid that has no /etc/passwd
# entry, so the ssh integration tests need nss_wrapper there. On a normal
# machine this script just execs the command.
#
# Kiln cannot run a check in a custom image (`kiln image build` keeps images on
# the build worker and runtime.image must come from a public registry), so the
# library is fetched here. Everything lives in a private mktemp directory that
# is removed on exit, and the .deb is checked against a pinned SHA-256 before
# it is unpacked. The hashes below are the ones in Debian bookworm's signed
# Packages index for libnss-wrapper 1.1.12-1. If bookworm ever ships a new
# version, the download is refused until these are updated.
set -eu

if id -un >/dev/null 2>&1; then
	exec "$@"
fi

version=1.1.12-1
case "$(dpkg --print-architecture)" in
amd64) arch=amd64 sha256=8bdc077d4f69f152da4ebd75f3a60ecbfa7e449e7a73915f11f269699aee4163 ;;
arm64) arch=arm64 sha256=43a5aebe359f29c25c51c9383d83f9d25daedfe577925de445dd597e599198a8 ;;
*)
	echo "with-passwd.sh: no pinned libnss-wrapper for architecture $(dpkg --print-architecture)" >&2
	exit 1
	;;
esac

w=$(mktemp -d)
cleanup() { rm -rf "$w"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

deb="$w/libnss-wrapper.deb"
file="libnss-wrapper_${version}_${arch}.deb"
fetched=
# The pool has the file while the version is current; snapshot.debian.org keeps
# it afterwards. The hash decides whether either is accepted.
for url in \
	"https://deb.debian.org/debian/pool/main/n/nss-wrapper/$file" \
	"https://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/n/nss-wrapper/$file"; do
	if curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --max-time 60 -o "$deb" "$url" >&2 &&
		echo "$sha256  $deb" | sha256sum -c - >&2; then
		fetched=1
		break
	fi
	echo "with-passwd.sh: $url unusable, trying the next source" >&2
done
if [ -z "$fetched" ]; then
	echo "with-passwd.sh: could not fetch a libnss-wrapper matching the pinned SHA-256" >&2
	exit 1
fi

dpkg-deb -x "$deb" "$w/root"
lib=$(find "$w/root" -name 'libnss_wrapper.so' | head -n 1)
if [ -z "$lib" ]; then
	echo "with-passwd.sh: libnss_wrapper.so not found in the package" >&2
	exit 1
fi

uid=$(id -u)
gid=$(id -g)
echo "hopkey:x:$uid:$gid:hopkey:${HOME:-/tmp}:/bin/sh" >"$w/passwd"
echo "hopkey:x:$gid:" >"$w/group"

# Not exec: the shell has to stay to remove the directory afterwards.
rc=0
env LD_PRELOAD="$lib" NSS_WRAPPER_PASSWD="$w/passwd" NSS_WRAPPER_GROUP="$w/group" "$@" || rc=$?
exit "$rc"
