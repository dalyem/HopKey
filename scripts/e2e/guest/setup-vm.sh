#!/bin/bash
# Base setup of a CLI VM (runs as root). Usage: setup-vm.sh <A|B> <run-id> <with-tailscale 0|1>
set -u
role=$1 run=$2 with_ts=$3
export DEBIAN_FRONTEND=noninteractive
mkdir -p /etc/hk-e2e /var/e2e/results /var/e2e/logs /var/e2e/state /var/e2e/jobs
install -d -m 0700 /root/e2e /root/e2e/sec
echo "$run" > /etc/hk-e2e/run-id
echo "$role" > /etc/hk-e2e/machine
touch /etc/hk-e2e/env

# Keep apt from restarting the guest agent (and the hop daemons in its
# cgroup) in the middle of a run.
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
systemctl mask --now unattended-upgrades >/dev/null 2>&1
for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 2; done

apt-get update -q >/dev/null || exit 10
apt-get install -y -q jq openssh-server python3 openssl ca-certificates curl iptables psmisc >/dev/null || exit 11
if [ "$with_ts" = 1 ] && ! command -v tailscale >/dev/null; then
	curl -fsSL https://tailscale.com/install.sh | sh >/var/e2e/logs/tailscale-install.log 2>&1 || exit 12
fi

# Test users: tester runs hop, target/target2 are local ssh targets,
# tester2 has an unsealed vault, localb a local-only vault (phase 5).
for u in tester tester2 target target2 localb; do
	id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
done
for u in tester tester2 localb; do loginctl enable-linger "$u"; done
for i in $(seq 1 20); do [ -d "/run/user/$(id -u tester)" ] && break; sleep 0.5; done

# sshd: on, and generous with parallel logins (the concurrency checks are
# about hop, not sshd's MaxStartups early drop).
echo 'MaxStartups 200:30:400' > /etc/ssh/sshd_config.d/90-hk-e2e.conf
systemctl enable --now ssh >/dev/null 2>&1
systemctl restart ssh >/dev/null 2>&1 || systemctl restart ssh.socket >/dev/null 2>&1

# Throwaway test secrets, 0600, never printed.
[ -s /root/e2e/sec/devpass ] || (umask 077; echo "dpp-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > /root/e2e/sec/devpass)
[ -s /root/e2e/sec/masterpw ] || [ "$role" != A ] || (umask 077; echo "mpw-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > /root/e2e/sec/masterpw)
# testkey: the vault's ssh key on each VM (A's is the one that syncs);
# the local target accepts it, and its public half goes to the other targets.
[ -f /home/tester/testkey ] || runuser -u tester -- ssh-keygen -q -t ed25519 -N '' -C "hk-e2e-testkey-$role" -f /home/tester/testkey
cp /home/tester/testkey.pub /var/e2e/state/testkey.pub
install -d -m 700 -o target -g target /home/target/.ssh
grep -qF "$(cat /home/tester/testkey.pub)" /home/target/.ssh/authorized_keys 2>/dev/null || cat /home/tester/testkey.pub >> /home/target/.ssh/authorized_keys
chown target: /home/target/.ssh/authorized_keys; chmod 600 /home/target/.ssh/authorized_keys
if [ "$role" = B ]; then
	# B's own key, added on B and used from A in phase 3.
	[ -f /home/tester/bkey ] || runuser -u tester -- ssh-keygen -q -t ed25519 -N '' -C hk-e2e-bkey -f /home/tester/bkey
	cp /home/tester/bkey.pub /var/e2e/state/bkey.pub
	[ -f /home/localb/lkey ] || runuser -u localb -- ssh-keygen -q -t ed25519 -N '' -C hk-e2e-lkey -f /home/localb/lkey
fi
ssh-keyscan -t ed25519 127.0.0.1 2>/dev/null | awk '{print $2" "$3}' > /var/e2e/state/hostkey.pub
chmod 0755 /var/e2e /var/e2e/state
chmod 0644 /var/e2e/state/*.pub
timedatectl show -p NTPSynchronized --value > /var/e2e/state/ntp
echo setup-ok
