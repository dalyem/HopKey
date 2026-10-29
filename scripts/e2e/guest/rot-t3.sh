#!/bin/sh
# Phase 6 on T3 (a sandbox, root): make sshd take, for deploy, only the
# authorized_keys lines it has now, from a root-owned snapshot read by
# AuthorizedKeysCommand. hop then edits ~deploy/.ssh/authorized_keys as
# usual, sshd refuses the new key, and the rotation must put the file back.
#   rot-t3.sh setup | restore
set -u
conf=/etc/ssh/sshd_config
case ${1:-} in
setup)
	[ -f $conf.hk-e2e-orig ] || cp -p $conf $conf.hk-e2e-orig
	install -d -m 755 /etc/ssh/hk-e2e-ak
	install -m 644 /home/deploy/.ssh/authorized_keys /etc/ssh/hk-e2e-ak/deploy
	printf '#!/bin/sh\nexec cat /etc/ssh/hk-e2e-ak/"$1"\n' >/usr/local/sbin/hk-e2e-ak
	chmod 755 /usr/local/sbin/hk-e2e-ak
	cp -p $conf.hk-e2e-orig $conf
	printf '\n# hk-e2e phase 6\nMatch User deploy\n\tAuthorizedKeysFile none\n\tAuthorizedKeysCommand /usr/local/sbin/hk-e2e-ak %%u\n\tAuthorizedKeysCommandUser nobody\n' >>$conf
	;;
restore)
	[ -f $conf.hk-e2e-orig ] && mv $conf.hk-e2e-orig $conf
	rm -rf /etc/ssh/hk-e2e-ak /usr/local/sbin/hk-e2e-ak
	;;
*) echo "usage: rot-t3.sh setup|restore"; exit 2 ;;
esac
/usr/sbin/sshd -t || { echo "sshd -t failed"; exit 1; }
kill -HUP "$(cat /run/sshd.pid)" || { echo "no sshd to reload"; exit 1; }
sleep 1
echo ok
