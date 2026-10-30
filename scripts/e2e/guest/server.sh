#!/bin/bash
# A throwaway hop-server on CLI-A, reachable only on its tailnet address,
# with TLS from a CA made here for this run. Usage: server.sh <tailnet-ip> <email>
set -u
ip=$1 email=$2
d=/root/e2e/server
install -d -m 0700 $d /var/lib/hk-server
cd $d || exit 1
if [ ! -s ca.crt ]; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
		-subj "/CN=hk-e2e throwaway CA" -keyout ca.key -out ca.crt \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null || exit 2
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$ip" \
		-keyout srv.key -out srv.csr 2>/dev/null || exit 3
	printf 'subjectAltName=IP:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$ip" > ext.cnf
	openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out srv.crt 2>/dev/null || exit 4
	chmod 600 ca.key srv.key
fi
cp ca.crt /usr/local/share/ca-certificates/hk-e2e-ca.crt
cp ca.crt /var/e2e/state/ca.crt
update-ca-certificates >/dev/null 2>&1
# The invite code is a credential: it goes to a 0600 file, never to output.
if [ ! -s /root/e2e/sec/invite ]; then
	(umask 077; /usr/local/bin/hop-server invite "$email" --ttl 1d --data /var/lib/hk-server > /root/e2e/sec/invite) || exit 5
fi
systemctl stop hk-server >/dev/null 2>&1
systemctl reset-failed hk-server >/dev/null 2>&1
systemd-run --unit=hk-server --property=Restart=on-failure \
	/usr/local/bin/hop-server serve --listen "$ip:8443" --data /var/lib/hk-server \
	--origin "https://$ip:8443" --tls-cert $d/srv.crt --tls-key $d/srv.key >/dev/null 2>&1 || exit 6
for i in $(seq 1 30); do
	curl -fsS -m 3 "https://$ip:8443/v1/healthz" >/var/e2e/state/healthz 2>/dev/null && break
	sleep 1
done
cat /var/e2e/state/healthz 2>/dev/null || { journalctl -u hk-server --no-pager | tail -5; exit 7; }
