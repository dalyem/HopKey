#!/bin/bash
# Debugging only (run.sh --reuse): put a used CLI VM back to a clean test state.
# Every job and every command a job ran lives in hke2e.slice, so stopping the
# slice ends all of an earlier run's work. Only the firewall rules the suite
# added (comment hk-e2e) are removed, in both directions.
systemctl stop hke2e.slice >/dev/null 2>&1
systemctl list-units --all --plain --no-legend 'hke2e-*' 2>/dev/null | awk '{print $1}' | xargs -r systemctl stop >/dev/null 2>&1
systemctl reset-failed 'hke2e-*' >/dev/null 2>&1
systemctl stop hk-server >/dev/null 2>&1
for u in tester tester2 localb; do
	id "$u" >/dev/null 2>&1 || continue
	runuser -u "$u" -- env XDG_RUNTIME_DIR=/run/user/$(id -u "$u") systemctl --user disable --now hopkey.service >/dev/null 2>&1
	pkill -9 -u "$u" -x hop
	rm -rf /home/$u/.local/share/hop* /home/$u/.local/state/hop* /home/$u/.ssh/hop* /home/$u/.ssh/config* /home/$u/.config/systemd/user/hopkey* /home/$u/.hk-kits
done
rm -rf /var/e2e/results /var/e2e/state /var/e2e/logs /var/e2e/jobs /var/e2e/export /var/e2e/tsup.done /var/e2e/tsup.log /var/e2e/tsstatus.json \
	/root/e2e/sec/kit* /root/e2e/sec/invite /root/e2e/sec/revoke-* /root/e2e/ts-authkey /root/e2e/server /var/lib/hk-server
[ "$(cat /etc/hk-e2e/machine 2>/dev/null)" = B ] && rm -f /root/e2e/sec/masterpw
for chain in INPUT OUTPUT; do
	iptables -S "$chain" 2>/dev/null | grep -e '--comment hk-e2e' | sed 's/^-A /-D /' | while read -r rule; do
		iptables $rule
	done
done
left=$(iptables -S 2>/dev/null | grep -c -e '--comment hk-e2e')
tailscale logout >/dev/null 2>&1
[ "$left" = 0 ] || { echo "reset-failed: $left hk-e2e firewall rules left"; exit 1; }
echo reset-ok
