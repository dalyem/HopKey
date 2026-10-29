#!/bin/sh
# Phase 6 on T3 (a sandbox, root): make sshd take, for deploy, only the
# authorized_keys lines it has now, from a root-owned snapshot read by
# AuthorizedKeysCommand. hop then edits ~deploy/.ssh/authorized_keys as
# usual, sshd refuses the new key, and the rotation must put the file back.
# The hook logs each key sshd is offered (its fingerprint), whether the live
# file holds that key at that moment, and whether the snapshot does, to
# /var/e2e/ak-hook.log: the proof that the new key was installed and refused.
#   rot-t3.sh setup | restore    (prints "ok" last only when sshd runs the intended config)
set -u
conf=/etc/ssh/sshd_config
hook=/usr/local/sbin/hk-e2e-ak
case ${1:-} in
setup)
	[ -f $conf.hk-e2e-orig ] || cp -p $conf $conf.hk-e2e-orig
	install -d -m 755 /etc/ssh/hk-e2e-ak
	install -m 644 /home/deploy/.ssh/authorized_keys /etc/ssh/hk-e2e-ak/deploy
	: >/var/e2e/ak-hook.log
	cat >$hook <<'HOOK'
#!/bin/sh
# hk-e2e-ak <user> <fingerprint> <base64 key>: log the offer, answer with the snapshot.
live=/home/$1/.ssh/authorized_keys
lh=0; grep -qF -- " $3" "$live" 2>/dev/null && lh=1
sh=0; grep -qF -- " $3" /etc/ssh/hk-e2e-ak/"$1" 2>/dev/null && sh=1
printf '%s user=%s fp=%s live_has=%s snap_has=%s live_sum=%s\n' "$(date +%s.%N)" "$1" "$2" $lh $sh \
	"$(cksum <"$live" 2>/dev/null | cut -d' ' -f1)" >>/var/e2e/ak-hook.log
exec cat /etc/ssh/hk-e2e-ak/"$1"
HOOK
	chown root:root $hook
	chmod 755 $hook
	cp -p $conf.hk-e2e-orig $conf
	printf '\n# hk-e2e phase 6\nMatch User deploy\n\tAuthorizedKeysFile none\n\tAuthorizedKeysCommand %s %%u %%f %%k\n\tAuthorizedKeysCommandUser root\n' "$hook" >>$conf
	;;
restore)
	[ -f $conf.hk-e2e-orig ] && mv $conf.hk-e2e-orig $conf
	rm -rf /etc/ssh/hk-e2e-ak $hook
	;;
*) echo "usage: rot-t3.sh setup|restore"; exit 2 ;;
esac
/usr/sbin/sshd -t || { echo "sshd -t failed"; exit 1; }
kill -HUP "$(cat /run/sshd.pid)" || { echo "no sshd to reload"; exit 1; }
sleep 1
# What sshd now runs for deploy: the hook after setup, the stock file after restore.
eff=$(/usr/sbin/sshd -T -C user=deploy,host=localhost,addr=127.0.0.1 2>&1 | grep -i '^authorizedkeyscommand ')
case $1 in
setup) case $eff in *"$hook"*) ;; *) echo "sshd -T does not show the hook: $eff"; exit 1 ;; esac ;;
restore)
	grep -q 'hk-e2e phase 6' $conf && { echo "the phase 6 block is still in $conf"; exit 1; }
	case $eff in *hk-e2e*) echo "sshd -T still shows the hook: $eff"; exit 1 ;; esac
	;;
esac
echo ok
