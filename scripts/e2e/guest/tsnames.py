#!/usr/bin/env python3
"""tsnames.py <node-prefix>: HK_<X>_SHORT/FQDN/IP/ID lines for this run's tailnet nodes (ID: the stable node ID)."""
import json
import subprocess
import sys

node = sys.argv[1]
st = json.loads(subprocess.run(['tailscale', 'status', '--json'], capture_output=True, text=True).stdout)
nodes = {}
for p in [st.get('Self') or {}] + list((st.get('Peer') or {}).values()):
    if p.get('HostName') and p.get('TailscaleIPs') and p.get('DNSName'):
        nodes[p['HostName']] = (p['HostName'], p['DNSName'].rstrip('.'), p['TailscaleIPs'][0], p.get('ID') or '')
for k in ('a', 'b', 't1', 't2', 't3'):
    n = nodes.get('%s-%s' % (node, k))
    if n:
        K = k.upper()
        print('HK_%s_SHORT=%s\nHK_%s_FQDN=%s\nHK_%s_IP=%s\nHK_%s_ID=%s' % (K, n[0], K, n[1], K, n[2], K, n[3]))
