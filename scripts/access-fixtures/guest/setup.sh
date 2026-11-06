#!/bin/sh
# Sets up a leased Ubuntu VM for the sshd fixtures (runs as root, once).
# Usage: setup.sh <dir with hook.sh and mount-helper.sh>
#
#   hkt   the target account: its ~/.ssh is what hop edits. Its sessions
#         run with PATH=/opt/hkfx/hook:..., where cksum, cat, ln, mv and rm
#         are hook.sh (they run the real ones unless a test sets a mode).
#   hkj   the jump account, on two more sshds: 2201 and 2202, each with an
#         ed25519 host key of its own, so a jump host's key line is never
#         the target's.
#   /run/hkfx        mode, sleep and go (written by the tests, as root)
#   /run/hkfx/log    what the hook saw (written as hkt)
#   /usr/local/sbin/hkfx-mount   mounts a tmpfs on one of hkt's session
#         directories, or unmounts it; hkt may run it with sudo, nothing else.
set -eu
src=$1
export DEBIAN_FRONTEND=noninteractive
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
systemctl mask --now unattended-upgrades >/dev/null 2>&1 || true
for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 2; done
apt-get update -q >/dev/null
apt-get install -y -q openssh-server openssh-client dosfstools procps sudo psmisc >/dev/null

for u in hkt hkj; do id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"; done

install -d -m 0755 /opt/hkfx/hook /etc/hkfx /var/hkfx /var/hkfx/out
install -m 0755 "$src/hook.sh" /opt/hkfx/hook/hkfx-hook
for n in cksum cat ln mv rm; do ln -sf hkfx-hook "/opt/hkfx/hook/$n"; done
install -m 0755 "$src/mount-helper.sh" /usr/local/sbin/hkfx-mount
echo 'hkt ALL=(root) NOPASSWD: /usr/local/sbin/hkfx-mount' >/etc/sudoers.d/hkfx
chmod 0440 /etc/sudoers.d/hkfx
visudo -cf /etc/sudoers.d/hkfx >/dev/null

# /run is a tmpfs: made again at every boot by this script only.
install -d -m 0755 /run/hkfx
install -d -m 0755 -o hkt -g hkt /run/hkfx/log
: >/run/hkfx/mode
chmod 0644 /run/hkfx/mode

# hkt's PATH. A Match block at the end of sshd_config itself: in an
# included file it would swallow the main file's later lines.
if ! grep -q '^# hkfx' /etc/ssh/sshd_config; then
	printf '\n# hkfx\nMatch User hkt\n\tSetEnv PATH=/opt/hkfx/hook:/usr/local/bin:/usr/bin:/bin\n' >>/etc/ssh/sshd_config
fi
echo 'MaxStartups 100:30:200' >/etc/ssh/sshd_config.d/90-hkfx.conf
install -d -m 0755 /run/sshd
sshd -t
systemctl restart ssh.socket >/dev/null 2>&1 || true
systemctl restart ssh

# The jump hosts' sshds.
for j in j1:2201 j2:2202; do
	n=${j%%:*} port=${j#*:}
	[ -f "/etc/hkfx/${n}_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N '' -C "hkfx-$n" -f "/etc/hkfx/${n}_host_ed25519_key"
	# A unit of its own: setup runs in a transient unit too, and systemd
	# ends everything in that unit's cgroup when setup exits.
	systemctl stop "hkfx-sshd-$n" >/dev/null 2>&1 || true
	systemd-run --unit="hkfx-sshd-$n" --quiet /usr/sbin/sshd -D -p "$port" -h "/etc/hkfx/${n}_host_ed25519_key" -o PidFile=none -o AllowUsers=hkj
done
sleep 1
for p in 22 2201 2202; do
	ssh-keyscan -T 5 -p "$p" -t ed25519 127.0.0.1 2>/dev/null | grep -q ssh-ed25519 || { echo "no sshd on port $p" >&2; exit 1; }
done
modprobe vfat 2>/dev/null || true
modprobe loop 2>/dev/null || true
echo "setup ok: $(ssh -V 2>&1); $(uname -r)"
