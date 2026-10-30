#!/bin/sh
# The hook: /opt/hkfx/hook/{cksum,cat,ln,mv,rm} for the target account
# (hkt). It runs the real command, and does more only in the modes the
# tests write to /run/hkfx/mode (words, any order):
#
#   argv           cksum: log the ssh clients ps shows (ssh-argv.log)
#   tmpfs-s        cksum: mount a tmpfs on each of hkt's session
#                  directories that isn't one yet (mount.log); the first
#                  cksum after mkdir "$s" is the header's (access) or the
#                  first compare (rotate), before $s/new exists
#   unmount-at-rm  rm of a session's new file: unmount its directory first
#   log            ln and mv: log the arguments, stderr and status
#   slowheader     cat -- FILE while a session directory exists: sleep
#                  $(cat /run/hkfx/sleep) first (the access header)
#   midpayload     cat with no operand (the payload): pass 16 bytes, touch
#                  log/payload-started, wait for /run/hkfx/go, then the rest
#
# ln's stderr is logged before the script's 2>/dev/null drops it. The hook
# itself calls the hooked commands only by full path.
n=${0##*/}
real=/usr/bin/$n
[ -x "$real" ] || real=/bin/$n
L=/run/hkfx/log
m=
read -r m </run/hkfx/mode 2>/dev/null
mode=" $m "
has() { case $mode in *" $1 "*) return 0 ;; esac; return 1; }
sessions() { for d in "$HOME"/.ssh/.hop-s.*; do [ -d "$d" ] && echo "$d"; done; }

case $n in
cksum)
	if has argv; then ps -ww -C ssh -o args= >>"$L/ssh-argv.log" 2>&1; fi
	if has tmpfs-s; then
		for d in $(sessions); do
			mountpoint -q "$d" && continue
			if sudo -n /usr/local/sbin/hkfx-mount "$d" >>"$L/mount.log" 2>&1; then echo "mounted $d" >>"$L/mount.log"; fi
		done
	fi
	;;
rm)
	if has unmount-at-rm; then
		for a in "$@"; do
			case $a in */.hop-s.*/new)
				d=${a%/new}
				if mountpoint -q "$d"; then sudo -n /usr/local/sbin/hkfx-mount -u "$d" >>"$L/mount.log" 2>&1 && echo "unmounted $d" >>"$L/mount.log"; fi
				;;
			esac
		done
	fi
	;;
ln | mv)
	if has log; then
		e=$(mktemp)
		"$real" "$@" 2>"$e"
		rc=$?
		{ echo "$n $* rc=$rc"; /usr/bin/cat "$e"; } >>"$L/$n.log"
		/usr/bin/cat "$e" >&2
		/usr/bin/rm -f "$e"
		exit $rc
	fi
	;;
cat)
	if [ $# -eq 0 ] && has midpayload; then
		dd bs=1 count=16 2>/dev/null
		touch "$L/payload-started"
		i=0
		while [ ! -e /run/hkfx/go ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
		"$real"
		rc=$?
		echo "payload cat: rest rc=$rc" >>"$L/cat.log"
		exit $rc
	fi
	if [ "${1:-}" = -- ] && has slowheader && [ -n "$(sessions)" ]; then
		z=5
		read -r z </run/hkfx/sleep 2>/dev/null
		sleep "${z:-5}"
	fi
	;;
esac
exec "$real" "$@"
