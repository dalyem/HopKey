#!/usr/bin/env python3
"""Phase 4: real SSH over Tailscale to the sandbox targets T1-T3.

Steps (driver-ordered): a-add | a-jump | a-ts | a-ts-b | b-use | b-mcp | conc <epoch> | syncuse-a <epoch> | syncuse-b <epoch> | a-reset
"""
import json
import os
import re
import subprocess
import sys
import threading
import time

import e2elib as L
from e2elib import check as c, hop, has, root, ssh, skip
from mcpc import MCP, results

M = L.MACHINE
E = L.env_get
T1S, T2F, T3IP = E('HK_T1_SHORT'), E('HK_T2_FQDN'), E('HK_T3_IP')
T1F, T3S, T3F, BS = E('HK_T1_FQDN'), E('HK_T3_SHORT'), E('HK_T3_FQDN'), E('HK_B_SHORT')
T1IP = E('HK_T1_IP')
TARGETS = ('t1', 't2', 't3')


def step_a_add():
    L.ensure_testkey()
    hs = L.hosts() or {}
    for name, addr in (('t1', T1S), ('t2', T2F), ('t3', T3IP)):
        if name not in hs:
            r = hop('add', name, '--address', addr, '--user', 'deploy', '--key', 'testkey', '--tag', 'ts')
            c('A.add-' + name, 'hop add %s by %s' % (name, {'t1': 'short MagicDNS name', 't2': 'MagicDNS FQDN', 't3': 'tailnet IP'}[name]),
              r.rc == 0, '', r.ev('hop add %s --address %s' % (name, addr)))
    r = hop('which', 't1', '--json')
    j = r.json() or {}
    c('A.which-short', 'a short MagicDNS name is recognised as a tailnet address', (j.get('route') or {}).get('chosen') == 'tailnet',
      'route %s' % json.dumps(j.get('route'))[:200], r.ev('which t1'), 'r2-P3-1')
    for h in ('t2', 't3'):
        r = hop('which', h, '--json')
        j = r.json() or {}
        c('A.which-' + h, 'hop which %s routes via the tailnet' % h, (j.get('route') or {}).get('chosen') == 'tailnet', json.dumps(j.get('route'))[:200])
    r = hop('check', 't1')
    c('A.check-unpinned', 'hop check before trust: TCP reaches T1 over the tailnet, the pin step fails and names hop trust',
      r.rc == 255 and has(r.out, '[pass] tcp_reachable', '[fail] host_key_pinned', 'hop trust t1'), '', r.ev('check t1'))
    for h in TARGETS:
        hop('trust', h, '--yes', timeout=60)
    bad = []
    for h in TARGETS:
        r = hop('check', h, timeout=60)
        if r.rc != 0 or '[fail]' in r.out:
            bad.append(r.ev('check ' + h))
    c('A.check', 'after hop trust, hop check passes for T1-T3', not bad, '', '\n'.join(bad))
    bad = []
    for h in TARGETS:
        r = hop('exec', h, '--', 'sh', '-c', 'echo exec-ok-$(id -un)', timeout=60)
        if r.rc != 0 or 'exec-ok-deploy' not in r.out:
            bad.append(r.ev('exec ' + h))
    c('A.exec', 'hop exec on T1-T3 over the tailnet', not bad, '', '\n'.join(bad))
    r = hop('exec', 't1', '--', 'sh', '-c', 'exit 6')
    c('A.exec-rc', 'remote exit code 6 passes through', r.rc == 6, '', r.ev('exit 6'))
    bad = []
    for h in TARGETS:
        r = ssh(h, 'echo plain-ok')
        if r.rc != 0 or 'plain-ok' not in r.out:
            bad.append(r.ev('ssh ' + h))
    c('A.plain-ssh', 'plain ssh to T1-T3 through the generated config', not bad, '', '\n'.join(bad))


def step_a_jump():
    hs = L.hosts() or {}
    if 't2inner' not in hs:
        hop('add', 't2inner', '--address', '127.0.0.1', '--port', '2222', '--user', 'deploy', '--key', 'testkey', '--jump', 't2', '--tag', 'ts')
    r = hop('trust', 't2inner', '--yes')
    c('A.jump-trust', 'hop trust on a jump-host target refuses and says to pin with hop edit --host-key',
      r.rc == 255 and 'hop edit t2inner --host-key' in r.all, '', r.ev('trust t2inner'))
    r1 = hop('check', 't2inner')
    r2 = hop('info', 't2inner')
    c('A.jump-hints', 'hop check and hop info give the hop edit --host-key hint for a jump target, not hop trust',
      'hop trust t2inner' not in r1.all + r2.all, '', r1.ev('check') + '\n' + r2.ev('info'), 'r2-P3-2')
    key = open('/var/e2e/state/t2-internal.pub').read().split()
    r = hop('edit', 't2inner', '--host-key', '%s %s' % (key[0], key[1]))
    r1 = hop('check', 't2inner', timeout=60)
    c('A.jump-check', 'after pinning by hand, hop check t2inner passes', r.rc == 0 and r1.rc == 0 and '[fail]' not in r1.out, '', r1.ev('check t2inner'))
    r = hop('exec', 't2inner', '--', 'sh', '-c', 'echo "jump-ok conn=$SSH_CONNECTION"', timeout=60)
    c('A.jump-exec', 'hop exec through T2 to its 127.0.0.1:2222 sshd', r.rc == 0 and re.search(r'jump-ok conn=127\.0\.0\.1 \d+ 127\.0\.0\.1 2222', r.out),
      '', r.ev('exec t2inner'))
    r = ssh('t2inner', 'echo plain-jump-ok', extra=['-v'])
    c('A.jump-ssh', 'plain ssh t2inner goes through the jump host', r.rc == 0 and 'plain-jump-ok' in r.out and 'proxy' in r.err.lower(),
      '', '\n'.join(l for l in r.all.splitlines() if 'proxy' in l.lower() or 'plain-jump' in l)[:500])
    skip('A.jump-only', 'port 2222 is reachable only through T2',
         'not provable here: userspace tailscaled on a sandbox forwards inbound tailnet traffic to loopback (REPORT-r2 A7c)')


def step_a_ts():
    nodes = [T1S, T2F.split('.')[0], T3S, BS]
    r = hop('ts', 'import', *nodes, '--dry-run')
    c('A.ts-dryrun', 'hop ts import --dry-run lists what it would do', r.rc == 0 and T3S in r.out, '', r.ev('ts import --dry-run'))
    c('A.ts-dryrun-words', 'the dry run prints readable actions, not would_created', 'would_created' not in r.out and 'would_linked' not in r.out,
      '', r.ev('ts import --dry-run'), 'r1-P3-5')
    r = hop('ts', 'import', T3S, '--user', 'deploy', '--key', 'testkey', '--tag', 'tsimp')
    c('A.ts-import', 'hop ts import of T3\'s node links it to the host added by IP', r.rc == 0 and re.search(r'linked\s+%s\s*->\s*t3' % re.escape(T3S), r.out),
      '', r.ev('ts import ' + T3S))
    r = hop('ts', 'link', 't1', T1S)
    r2 = hop('ts', 'link', 't2', T2F)
    c('A.ts-link', 'hop ts link t1/t2 to their nodes', r.rc == 0 and r2.rc == 0, '', r.ev('ts link t1') + '\n' + r2.ev('ts link t2'))
    r = hop('ts', 'link', 't1', T3S)
    c('A.ts-link-refuse', 'hop ts link refuses a node already linked to another host', r.rc == 255, '', r.ev('ts link t1 <t3 node>'))
    r = hop('which', 't1', '--json')
    j = r.json() or {}
    c('A.ts-which', 'after linking, t1 routes via the tailnet IP', (j.get('route') or {}).get('chosen') == 'tailnet' and (j.get('route') or {}).get('address') == T1IP,
      json.dumps(j.get('route'))[:200])
    bad = []
    for name in (T1S, T3S, T3F):
        r = hop('exec', name, '--', 'echo', 'tsname-ok', timeout=60)
        if r.rc != 0 or 'tsname-ok' not in r.out:
            bad.append(r.ev('exec ' + name))
    c('A.ts-exec-names', 'hop exec by Tailscale short name and FQDN', not bad, '', '\n'.join(bad))


def step_a_ts_b():
    r = hop('ts', 'import', BS, '--user', 'target', '--key', 'testkey', '--tag', 'tsimp')
    hop('trust', BS, '--yes', timeout=60)
    r2 = hop('exec', BS, '--', 'sh', '-c', 'echo "on-b conn=$SSH_CONNECTION"', timeout=60)
    c('A.tsb-exec', 'hop ts import of CLI-B\'s node, then exec over the real tailnet path', r2.rc == 0 and 'on-b conn=100.' in r2.out,
      '', r.ev('ts import') + '\n' + r2.ev('exec'))
    rc, out = L.pty_run('tester', ['hop', BS], [(r'\$ $', 'echo in-hop-shell-$(hostname)-$(id -un)-$(tty); exit 3')], timeout=60)
    c('A.tsb-shell', 'interactive hop <CLI-B node> on a pty (the sandboxes have no pty)', rc == 3 and 'in-hop-shell-' in out and '-target-/dev/pts' in out,
      'pty exit %d' % rc, out[-300:])


def step_b_use():
    want = {'t1', 't2', 't3', 't2inner'}
    got, secs = L.wait_for(lambda: want <= set(L.hosts() or {}), 60, 1)
    hs = L.hosts() or {}
    pins = {n: len((hs.get(n) or {}).get('host_keys') or []) for n in want}
    c('B.synced', 'B has T1-T3 and t2inner, with pins, with nothing added on B', bool(got) and all(pins.values()), 'pins %s' % pins)
    kl = hop('key', 'ls', '--json').json() or []
    c('B.key', 'B has the key the hosts use', any(k.get('name') == 'testkey' for k in kl), '')
    bad = [h for h in TARGETS if 'already pinned' not in hop('trust', h, '--yes', timeout=60).all]
    c('B.trust', 'hop trust on B: already pinned (the pins synced)', not bad, 'not already pinned: %s' % bad)
    bad = []
    for h in ('t1', 't2', 't3', 't2inner'):
        r = hop('check', h, timeout=60)
        if r.rc != 0:
            bad.append(r.ev('check ' + h))
    c('B.check', 'hop check on B passes for all four', not bad, '', '\n'.join(bad))
    bad = []
    for h in ('t1', 't2', 't3', 't2inner'):
        r = hop('exec', h, '--', 'echo', 'B-exec-ok', timeout=60)
        r2 = ssh(h, 'echo B-plain-ok')
        if 'B-exec-ok' not in r.out or 'B-plain-ok' not in r2.out:
            bad.append(r.ev('exec ' + h) + ' | ' + r2.ev('ssh ' + h))
    c('B.exec', 'hop exec and plain ssh from B to T1-T3 and t2inner', not bad, '', '\n'.join(bad))
    r = hop('exec', T3S, '--', 'echo', 'B-tsname', timeout=60)
    c('B.tsname', 'hop exec by Tailscale name on B', 'B-tsname' in r.out, '', r.ev('exec ' + T3S))


def step_b_mcp():
    m = MCP(tag='p4-mcp-b')
    _, st, _ = m.call('list_hosts', {'tag': 'ts'})
    names = sorted(h['name'] for h in (st or {}).get('hosts', []))
    c('B.mcp-list', 'MCP on B: list_hosts tag ts', set(names) >= {'t1', 't2', 't3', 't2inner'}, 'names %s' % names)
    _, st, _ = m.call('resolve_host', {'target': T3S})
    c('B.mcp-resolve', 'MCP resolve_host by Tailscale name', ((st or {}).get('host') or {}).get('name') == 't3', json.dumps(st)[:200])
    _, st, _ = m.call('check_host', {'host': 't1'})
    c('B.mcp-check', 'MCP check_host t1', (st or {}).get('ok') is True, json.dumps(st)[:300])
    _, st, _ = m.call('exec', {'hosts': 'tag:ts', 'command': 'echo mcp-b-ok'})
    res = results(st)
    c('B.mcp-exec', 'MCP exec tag:ts reaches T1-T3 and t2inner', all(res.get(h, {}).get('exit_code') == 0 for h in ('t1', 't2', 't3', 't2inner')),
      json.dumps({h: (r.get('exit_code'), r.get('error')) for h, r in res.items()}))
    m.close()


def step_conc(epoch):
    epoch = float(epoch)
    while time.time() < epoch:
        time.sleep(0.05)
    out = []
    lock = threading.Lock()

    def one(h, i):
        r = hop('exec', h, '--timeout', '40s', '--', 'sh', '-c', 'echo ok-%s-%d' % (h, i), timeout=60)
        with lock:
            out.append((h, i, r.rc, 'ok-%s-%d' % (h, i) in r.out, r.all.strip()[-200:]))
    ths = [threading.Thread(target=one, args=(h, i)) for i in range(5) for h in TARGETS]
    t0 = time.time()
    [t.start() for t in ths]
    [t.join() for t in ths]
    ok = sum(1 for x in out if x[2] == 0 and x[3])
    c('%s.concurrency' % M, 'A and B at once: 5 rounds x 3 targets of hop exec in parallel, all succeed', ok == len(out),
      '%d/%d ok in %.1fs' % (ok, len(out), time.time() - t0), '; '.join('%s/%d rc=%d %s' % (h, i, rc, e) for h, i, rc, good, e in out if not good)[:800])


def step_syncuse_a(epoch):
    epoch = float(epoch)
    while time.time() < epoch:
        time.sleep(0.05)
    r = hop('edit', 't1', '--user', 'deploy2')
    L.state_put('syncuse-a', {'rc': r.rc, 'done': time.time()})


def step_syncuse_b(epoch):
    epoch = float(epoch) - 3
    while time.time() < epoch:
        time.sleep(0.05)
    env = L.user_env('tester')
    p1 = subprocess.Popen(L.user_argv('tester', ['hop', 'exec', 't1', '--', 'sh', '-c', 'for i in $(seq 1 15); do echo "tick $i $(id -un)"; sleep 1; done'], 60),
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, stdin=subprocess.DEVNULL)
    p2 = subprocess.Popen(L.user_argv('tester', ['ssh', '-o', 'BatchMode=yes', 't1', 'for i in $(seq 1 15); do echo "tick $i $(id -un)"; sleep 1; done'], 60),
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, stdin=subprocess.DEVNULL)

    def cfg_has():
        try:
            m = re.search(r'^Host t1\n((?:  .*\n?)*)', open('/home/tester/.ssh/hop/config').read(), re.M)
            return m and re.search(r'^\s+User deploy2$', m.group(1), re.M)
        except OSError:
            return None
    got, _ = L.wait_for(cfg_has, 40, 0.1)
    seen = time.time()
    r1 = hop('exec', 't1', '--', 'sh', '-c', 'echo new-$(id -un)', timeout=60)
    r2 = ssh('t1', 'echo new-plain-$(id -un)')
    o1, o2 = p1.communicate(timeout=60)[0], p2.communicate(timeout=60)[0]
    L.state_put('syncuse-b', {'seen': seen if got else None})
    c('B.syncuse-open', 'sessions open during the change keep running to the end as the old user',
      p1.returncode == 0 and p2.returncode == 0 and o1.count('tick') == 15 and o2.count('tick') == 15 and 'deploy2' not in o1 + o2,
      'rc %s/%s, ticks %d/%d' % (p1.returncode, p2.returncode, o1.count('tick'), o2.count('tick')))
    c('B.syncuse-new', 'new connections after the change use the new user (hop exec and plain ssh)',
      bool(got) and 'new-deploy2' in r1.out and 'new-plain-deploy2' in r2.out, '', r1.ev('exec') + '\n' + r2.ev('ssh'))


def step_a_reset():
    hop('edit', 't1', '--user', 'deploy')


STEPS = {'a-add': step_a_add, 'a-jump': step_a_jump, 'a-ts': step_a_ts, 'a-ts-b': step_a_ts_b, 'b-use': step_b_use,
         'b-mcp': step_b_mcp, 'conc': step_conc, 'syncuse-a': step_syncuse_a, 'syncuse-b': step_syncuse_b, 'a-reset': step_a_reset}

if __name__ == '__main__':
    name = sys.argv[1]
    L.guard('%s.%s' % (M, name), name)(STEPS[name])(*sys.argv[2:])
    L.done()
