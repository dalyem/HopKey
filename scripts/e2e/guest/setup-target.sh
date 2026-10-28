#!/bin/sh
# SSH target in a Kiln sandbox (gVisor, no systemd): sshd plus userspace
# tailscaled. Usage: setup-target.sh <t1|t2|t3> <generation>
# setup.done is "<ok|fail-...> <generation>", so the driver never takes a
# marker from an earlier run (--reuse) for this one.
set -u
role=$1 gen=$2
export DEBIAN_FRONTEND=noninteractive
mkdir -p /var/e2e
rm -f /var/e2e/setup.done /var/e2e/tsup.done
exec >/var/e2e/setup.log 2>&1
mark() { echo "$1 $gen" > /var/e2e/setup.done.tmp && mv /var/e2e/setup.done.tmp /var/e2e/setup.done; }
apt-get update -q || { mark fail-apt; exit 1; }
apt-get install -y -q openssh-server curl ca-certificates iproute2 procps >/dev/null || { mark fail-apt2; exit 1; }
command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh || { mark fail-ts; exit 1; }
mkdir -p /run/sshd /run/tailscale /var/lib/tailscale
for u in deploy deploy2; do id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"; done
# sshd refuses an account with a locked password even for keys under PAM-less setups.
for u in deploy deploy2; do usermod -p '*' "$u"; done
ssh-keygen -A
printf 'MaxStartups 200:30:400\nPasswordAuthentication no\n' > /etc/ssh/sshd_config.d/90-hk-e2e.conf
pgrep -x sshd >/dev/null || /usr/sbin/sshd
if [ "$role" = t2 ]; then
	# A second sshd on loopback only: the jump-host target behind T2.
	[ -f /etc/ssh/internal_host_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/internal_host_ed25519
	/usr/sbin/sshd -p 2222 -o ListenAddress=127.0.0.1 -o HostKey=/etc/ssh/internal_host_ed25519 -o PidFile=/run/sshd-internal.pid
	cp /etc/ssh/internal_host_ed25519.pub /var/e2e/internal-hostkey.pub
fi
pgrep -x tailscaled >/dev/null || setsid nohup tailscaled --tun=userspace-networking --state=mem: \
	--socket=/run/tailscale/tailscaled.sock >/var/e2e/tailscaled.log 2>&1 </dev/null &
sleep 2
ss -ltnp
mark ok
