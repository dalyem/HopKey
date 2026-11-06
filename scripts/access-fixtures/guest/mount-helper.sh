#!/bin/sh
# hkfx-mount [-u] DIR: mount (or unmount) a tmpfs on one of hkt's hop
# session directories, ~hkt/.ssh/.hop-s.<32 hex>. The only command hkt may
# run with sudo; any other path is refused.
set -u
u=
if [ "${1:-}" = -u ]; then u=1; shift; fi
d=${1:-}
home=$(getent passwd hkt | cut -d: -f6)
tok=${d#"$home"/.ssh/.hop-s.}
case $d in "$home"/.ssh/.hop-s.*) ;; *) echo "refused: $d" >&2; exit 2 ;; esac
case $tok in *[!0-9a-f]* | '') echo "refused: $d" >&2; exit 2 ;; esac
[ ${#tok} -eq 32 ] || { echo "refused: $d" >&2; exit 2; }
if [ -n "$u" ]; then exec umount "$d"; fi
exec mount -t tmpfs -o "size=1m,mode=0700,uid=$(id -u hkt),gid=$(id -g hkt)" hkfx-session "$d"
