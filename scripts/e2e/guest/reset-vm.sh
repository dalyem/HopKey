#!/bin/bash
# Debugging only (run.sh --reuse): put a used CLI VM back to a clean test state.
systemctl stop hk-server >/dev/null 2>&1
for u in tester tester2 localb; do
	id "$u" >/dev/null 2>&1 || continue
	runuser -u "$u" -- env XDG_RUNTIME_DIR=/run/user/$(id -u "$u") systemctl --user disable --now hopkey.service >/dev/null 2>&1
	pkill -9 -u "$u" -x hop
	rm -rf /home/$u/.local/share/hop* /home/$u/.local/state/hop* /home/$u/.ssh/hop* /home/$u/.ssh/config* /home/$u/.config/systemd/user/hopkey* /home/$u/.hk-kits
done
rm -rf /var/e2e/results /var/e2e/state /var/e2e/logs /var/e2e/jobs /root/e2e/sec/kit* /root/e2e/sec/invite /root/e2e/sec/revoke-* /root/e2e/server /var/lib/hk-server
[ "$(cat /etc/hk-e2e/machine 2>/dev/null)" = B ] && rm -f /root/e2e/sec/masterpw
iptables -F OUTPUT
tailscale logout >/dev/null 2>&1
echo reset-ok
