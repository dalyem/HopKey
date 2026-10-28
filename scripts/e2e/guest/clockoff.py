#!/usr/bin/env python3
"""clockoff.py <name> <peer-ip>: B's clock minus A's, measured from A over the tailnet.

One ssh session to target@<peer> (B's target accepts A's testkey) echoes B's
time for each line A sends; the sample with the shortest round trip gives the
offset, with half that round trip as its uncertainty (as NTP does).
state/<name> = {offset, rtt, samples, t}
"""
import subprocess
import sys
import time

import e2elib as L

name, peer = sys.argv[1], sys.argv[2]
remote = "python3 -u -c \"import sys,time;[print(repr(time.time()),flush=True) for _ in iter(sys.stdin.readline,'')]\""
argv = L.user_argv('tester', ['ssh', '-F', '/dev/null', '-i', '/home/tester/testkey', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                              '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=10',
                              'target@' + peer, remote], 60)
p = subprocess.Popen(argv, env=L.user_env('tester', nopass=True), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=True, bufsize=1, cwd='/tmp')
best = None
n = 0
try:
    for i in range(25):
        t1 = time.time()
        p.stdin.write('\n')
        p.stdin.flush()
        line = p.stdout.readline()
        t2 = time.time()
        if not line:
            break
        tb = float(line)
        n += 1
        s = (t2 - t1, tb - (t1 + t2) / 2)
        if best is None or s[0] < best[0]:
            best = s
        time.sleep(0.05)
finally:
    try:
        p.stdin.close()
        p.wait(timeout=10)
    except Exception:
        p.kill()
if best is None:
    L.log('clockoff: no samples;', L.mask(p.stderr.read() if p.stderr else '')[:400])
    sys.exit(1)
L.state_put(name, {'offset': best[1], 'rtt': best[0], 'samples': n, 't': time.time()})
print('offset %.4fs rtt %.4fs samples %d' % (best[1], best[0], n))
