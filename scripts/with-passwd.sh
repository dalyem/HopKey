#!/bin/sh
# Run a command with a passwd entry for the current uid.
#
# OpenSSH refuses to start when getpwuid() fails ("No user exists for uid N").
# Kiln check containers run as an unprivileged uid that has no /etc/passwd
# entry, so the ssh integration tests need nss_wrapper there. On a normal
# machine this script just execs the command.
set -eu

if id -un >/dev/null 2>&1; then
	exec "$@"
fi

w="${TMPDIR:-/tmp}/hopkey-nsswrap"
lib="$w/root/usr/lib/x86_64-linux-gnu/libnss_wrapper.so"
if [ ! -e "$lib" ]; then
	mkdir -p "$w/state/lists/partial" "$w/cache/archives/partial" "$w/root"
	apt="-o Dir::State=$w/state -o Dir::Cache=$w/cache -o Debug::NoLocking=1 -o APT::Sandbox::User="
	# shellcheck disable=SC2086
	apt-get $apt update >&2
	# shellcheck disable=SC2086
	(cd "$w" && apt-get $apt download libnss-wrapper >&2)
	dpkg-deb -x "$w"/libnss-wrapper_*.deb "$w/root"
fi
lib=$(find "$w/root" -name 'libnss_wrapper.so' | head -n 1)

uid=$(id -u)
gid=$(id -g)
echo "hopkey:x:$uid:$gid:hopkey:${HOME:-/tmp}:/bin/sh" >"$w/passwd"
echo "hopkey:x:$gid:" >"$w/group"
LD_PRELOAD="$lib" NSS_WRAPPER_PASSWD="$w/passwd" NSS_WRAPPER_GROUP="$w/group" exec "$@"
