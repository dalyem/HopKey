#!/usr/bin/env python3
"""Phase 5: the revocation matrix (REPORT-r2 part B).

The intended behaviour, per the user: "If I revoke one of the synced devices
... it should stop working." Every check below asserts that, so the known
gaps (P1-1 hop unlock restores access, P2-1 offline keeps access, P2-2 the
start-up window) show up as FAIL.

Steps: localb-setup | ensure-t1 | revoke <device> <n> | access <tag> <work|cut> |
       watch <tag> <secs> | cutoff <tag> <t0> <limit> | unlock-after <tag> |
       sessions-start | sessions-end <tag> | block <0|1> | daemon-restart <tag> |
       stopped <tag> | start-window <tag> | inventory <tag> | relogin <name> | b-wait-t1
"""
import glob
import json
import os
import re
import subprocess
import sys
import time

import e2elib as L
from e2elib import check as c, hop, has, root, ssh, skip
from mcpc import MCP, results

M = L.MACHINE
URL, SIP = L.env_get('HK_SERVER_URL'), L.env_get('HK_SERVER_IP')
BUGS = {'unlock': 'r2-P1-1', 'offline': 'r2-P2-1', 'window': 'r2-P2-2'}


def step_localb_setup():
    if not os.path.exists('/home/localb/.local/share/hop/device.key'):
        rc, out = L.init_vault(user='localb', kitname='kit-localb')
    L.authorize('target', open('/home/localb/lkey.pub').read())
    hop('key', 'add', '/home/localb/lkey', '--name', 'lkey', user='localb')
    hop('add', 'lb1', '--address', '127.0.0.1', '--user', 'target', '--key', 'lkey', user='localb')
    hop('trust', 'lb1', '--yes', user='localb')
    r = hop('exec', 'lb1', '--', 'echo', 'localb-ok', user='localb')
    c('B.localb', 'a local-only vault (user localb) works on B', 'localb-ok' in r.out, '', r.ev('exec lb1'))


def step_ensure_t1():
    hs = L.hosts() or {}
    if 't1' not in hs:
        L.ensure_testkey()
        hop('add', 't1', '--address', L.env_get('HK_T1_IP'), '--user', 'deploy', '--key', 'testkey', '--tag', 'ts')
    hop('trust', 't1', '--yes', timeout=60)
    hop('edit', 't1', '--user', 'deploy')


def step_b_wait_t1():
    got, secs = L.wait_for(lambda: (L.hosts() or {}).get('t1', {}).get('host_keys'), 60, 1)
    if not got:
        L.log('t1 never arrived on B')


def step_revoke(dev, n):
    """On A: revoke a device; the kit goes only to 0600 files, then hop auth resume confirms it."""
    kitf = '/root/e2e/sec/revoke-kit-%s.txt' % n
    raw = '/root/e2e/sec/revoke-%s.raw' % n
    root('rm -f %s; install -d -m 700 -o tester /home/tester/.hk-kits' % kitf)
    tkit = '/home/tester/.hk-kits/kit-%s.txt' % n
    t0 = time.time()
    L.state_put('revoke-start-%s' % n, {'t': t0})
    r = hop('auth', 'devices', 'revoke', dev, '--yes', '--json', '--kit-file', tkit, '--password-stdin',
            stdin=L.sec_read('masterpw') + '\n', timeout=180)
    # stdout holds the new kit: keep it only in a 0600 file.
    fd = os.open(raw, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(r.out)
    t1 = time.time()
    L.state_put('revoke-end-%s' % n, {'t': t1, 'rc': r.rc})
    kit = open(tkit).read() if os.path.exists(tkit) else ''
    sk = re.search(r'Secret Key:\s+(\S+)', kit)
    rk = re.search(r'Recovery Key:\s+(\S+)', kit)
    # Without a terminal the new kit stays pending until hop auth resume confirms it (exit 255, by design).
    committed = r.rc == 0 or 'change is committed' in r.all
    c('A.revoke-%s' % n, 'hop auth devices revoke --yes --password-stdin commits and writes the new kit to --kit-file', committed and bool(sk and rk),
      'rc %d in %.1fs; stdout kept in a 0600 file' % (r.rc, t1 - t0), L.mask(r.err)[-300:])
    if sk and rk:
        L.sec_write('kit', 'SECRET_KEY=%s\nRECOVERY_KEY=%s' % (sk.group(1), rk.group(1)))
        conf = '%s,%s' % (sk.group(1).split('-')[-1], rk.group(1).split('-')[-1])
        r2 = hop('auth', 'resume', '--yes', '--password-stdin', env={'HOP_KIT_CONFIRM': conf}, stdin=L.sec_read('masterpw') + '\n', timeout=120)
        c('A.resume-%s' % n, 'hop auth resume confirms the new kit', r2.rc == 0, '', r2.ev('auth resume'))
    root('shred -u %s 2>/dev/null; rm -f %s' % (tkit, tkit))
    j = hop('auth', 'devices', '--json').json() or {}
    names = [d.get('name') for d in j.get('devices', [])]
    c('A.devices-%s' % n, 'the revoked device is gone from A\'s device list', dev not in names, 'names %s' % names)


def m_hop_exec():
    r = hop('exec', 't1', '--', 'echo', 'hopexec-ok', timeout=40)
    return 'hopexec-ok' in r.out, r.ev('hop exec t1')


def m_hop_target():
    r = hop('t1', stdin='echo hopshell-ok; exit 4\n', timeout=40)
    return 'hopshell-ok' in r.out, r.ev('hop t1 <<< cmds')


def m_plain_ssh():
    r = ssh('t1', 'echo plain-ok')
    return 'plain-ok' in r.out, r.ev('ssh t1')


def m_agent():
    n = L.agent_keys()
    return n > 0, 'ssh-add -L on hop\'s agent: %s keys' % n


def m_mcp():
    m = MCP(tag='p5-mcp')
    _, st, _ = m.call('list_hosts', {})
    nh = len((st or {}).get('hosts', []))
    _, st2, text = m.call('exec', {'hosts': 't1', 'command': 'echo mcp-exec-ok'})
    m.close()
    ok = 'mcp-exec-ok' in json.dumps(st2)
    return ok or nh > 0, 'list_hosts %d hosts; exec: %s' % (nh, (json.dumps(results(st2).get('t1', {}).get('error')) if st2 else text)[:200])


def m_localb():
    r = hop('exec', 'lb1', '--', 'echo', 'localb-ok', user='localb', timeout=40)
    return 'localb-ok' in r.out, r.ev('localb: hop exec lb1')


METHODS = [('hop-exec', 'hop exec t1', m_hop_exec), ('hop-target', 'hop t1 (commands on stdin)', m_hop_target),
           ('plain-ssh', 'plain ssh t1', m_plain_ssh), ('agent', 'ssh-add -L on hop\'s agent', m_agent), ('mcp', 'MCP list_hosts/exec', m_mcp)]


def step_access(tag, expect, bug=None):
    for mid, label, fn in METHODS:
        works, ev = fn()
        if expect == 'work':
            c('B.%s.%s' % (tag, mid), '%s: %s works' % (tag, label), works, '', ev)
        else:
            c('B.%s.%s' % (tag, mid), '%s: %s no longer works' % (tag, label), not works, 'still works' if works else '', ev, bug)
    works, ev = m_localb()
    c('B.%s.localb' % tag, '%s: the local-only vault on B is unaffected' % tag, works, '', ev)


def step_watch(tag, secs):
    """Background: record each change in agent keys / ssh config hosts / vault state."""
    out = []
    end = time.time() + float(secs)
    prev = None
    while time.time() < end:
        n = L.agent_keys()
        try:
            h = len(re.findall(r'^Host ', open('/home/tester/.ssh/hop/config').read(), re.M))
        except OSError:
            h = -1
        cur = (n, h)
        if cur != prev:
            out.append({'t': time.time(), 'agent_keys': n, 'config_hosts': h})
            L.state_put('watch5-%s' % tag, out)
            prev = cur
        time.sleep(0.1)
    out.append({'t': time.time(), 'end': True})
    L.state_put('watch5-%s' % tag, out)


def first_cut(tl, after):
    for e in tl:
        if e.get('end'):
            break
        if e['t'] >= after and e['agent_keys'] <= 0:
            return e['t']
    return None


def step_cutoff(tag, t0, limit):
    t0, limit = float(t0), float(limit)
    tl, secs = L.wait_for(lambda: (lambda w: w if first_cut(w, t0) or (w and w[-1].get('end')) else None)(L.state_get('watch5-%s' % tag, [])), limit + 10, 0.5)
    tl = L.state_get('watch5-%s' % tag, [])
    cut = first_cut(tl, t0)
    c('B.%s.cutoff' % tag, '%s: hop\'s agent is empty within %ds of the revoke' % (tag, limit), cut is not None and cut - t0 <= limit,
      'cut at +%.1fs' % (cut - t0) if cut else 'not cut within the watch', json.dumps(tl[-6:])[:600])


def step_unlock_after(tag):
    r = hop('unlock', timeout=40)
    works = [mid for mid, _, fn in METHODS[:3] if fn()[0]]
    c('B.%s.unlock' % tag, '%s: hop unlock on the revoked device does not bring access back' % tag, not works,
      'hop unlock rc=%d; working again: %s' % (r.rc, works), r.ev('hop unlock'), BUGS['unlock'])
    hop('lock')


def step_sessions_start():
    env = L.user_env('tester')
    cmd = 'for i in $(seq 1 45); do echo "tick $i"; sleep 1; done'
    for name, argv in (('open-hopexec', ['hop', 'exec', 't1', '--', 'sh', '-c', cmd]),
                       ('open-plain', ['ssh', '-o', 'BatchMode=yes', 't1', cmd])):
        f = open('/var/e2e/state/%s.out' % name, 'w')
        subprocess.Popen(L.user_argv('tester', argv, 120), env=env, stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=True)
    time.sleep(3)


def step_sessions_end(tag):
    L.wait_for(lambda: not root('pgrep -u tester -f "seq 1 45"').out.strip(), 70, 2)
    o = {n: open('/var/e2e/state/%s.out' % n).read() for n in ('open-hopexec', 'open-plain')}
    survived = [n for n, s in o.items() if 'tick 45' in s]
    c('B.%s.open-sessions' % tag, '%s: sessions open at the revoke are ended (hop exec and plain ssh)' % tag, not survived,
      'ran to the end: %s' % survived, '; '.join('%s: %d ticks' % (n, s.count('tick')) for n, s in o.items()), 'r2-gap4')


def step_block(on):
    for rule in ('OUTPUT -d %s -p tcp --dport 8443 -j DROP' % SIP, 'INPUT -s %s -p tcp --sport 8443 -j DROP' % SIP):
        root('while iptables -D %s 2>/dev/null; do :; done; %s' % (rule, 'iptables -I ' + rule if on == '1' else 'true'))


def step_daemon_restart(tag):
    hop('daemon', 'stop')
    time.sleep(1)
    hop('ls')
    works = [mid for mid, _, fn in METHODS[:3] if fn()[0]]
    c('B.%s.restart' % tag, '%s: after a daemon restart, still offline, the revoked device has no access' % tag, not works,
      'working: %s' % works, '', BUGS['offline'])


def step_stopped(tag):
    pids = L.daemon_pids()
    works = [mid for mid, _, fn in METHODS[2:4] if fn()[0]]
    c('B.%s.stopped' % tag, '%s: with the daemon stopped, plain ssh and the agent give nothing' % tag, not pids and not works,
      'daemon pids %s, working: %s' % (pids, works))


def step_start_window(tag):
    """Start the daemon on a revoked device; nothing may be served before the server check."""
    tl = []
    ssh_ok = []
    stop = time.time() + 12
    p = subprocess.Popen(L.user_argv('tester', ['hop', 'ls'], 30), env=L.user_env('tester'), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    t0 = time.time()
    while time.time() < stop:
        n = L.agent_keys()
        tl.append((round(time.time() - t0, 2), n))
        if n > 0:
            r = ssh('t1', 'echo window-ssh-ok', timeout=10)
            if 'window-ssh-ok' in r.out:
                ssh_ok.append(round(time.time() - t0, 2))
        time.sleep(0.05)
    p.wait(timeout=30)
    served = [t for t, n in tl if n > 0]
    c('B.%s.window' % tag, '%s: a daemon starting on the revoked device serves no keys before it checks with the server' % tag,
      not served and not ssh_ok, 'keys served from +%.2fs to +%.2fs; plain ssh got in at %s' % (served[0], served[-1], ssh_ok) if served else '',
      json.dumps(tl[:40]), BUGS['window'])


def step_inventory(tag):
    d = '/home/tester/.local/share/hop'
    dk = d + '/device.key'
    vault = [v for v in glob.glob(d + '/vault/*') if not v.endswith('lock')]
    revoked = os.path.exists(d + '/vault/revoked.json')
    dk_live = False
    if os.path.exists(dk):
        try:
            j = json.load(open(dk))
            dk_live = 'tomb' not in json.dumps(j).lower()
        except Exception:
            dk_live = True
    c('B.%s.inv-devicekey' % tag, '%s: the revoked device\'s key can no longer open the vault (device.key gone or tombstoned, revoked.json written)' % tag,
      not dk_live and (revoked or not vault), 'device.key live: %s, revoked.json: %s, vault files: %d' % (dk_live, revoked, len(vault)), '', BUGS['unlock'])
    try:
        nh = len(re.findall(r'^Host ', open('/home/tester/.ssh/hop/config').read(), re.M))
    except OSError:
        nh = 0
    c('B.%s.inv-config' % tag, '%s: the generated ssh config lists no hosts' % tag, nh == 0, '%d Host lines' % nh)
    kh = glob.glob('/home/tester/.ssh/hop/known_hosts-*')
    c('B.%s.inv-pins' % tag, '%s: no decrypted vault data stays behind (pinned host keys)' % tag, not kh, '%d known_hosts files' % len(kh), '', 'r2-inv')
    privs = root('grep -rl "PRIVATE KEY" /home/tester/.ssh/hop /home/tester/.local /run/user/$(id -u tester) 2>/dev/null').out.split()
    c('B.%s.inv-private' % tag, '%s: no private key file under hop\'s directories' % tag, not privs, 'files: %s' % privs)
    j = hop('auth', 'status', '--json').json() or {}
    c('B.%s.inv-status' % tag, '%s: hop auth status does not say "signed in" on a revoked device' % tag, j.get('signed_in') is not True,
      'signed_in=%s' % j.get('signed_in'), '', 'r1-P3-13')
    r = hop('status')
    L.log('status after', tag, r.all)


def step_device_id():
    j = hop('auth', 'status', '--json').json() or {}
    L.state_put('device-id', j.get('device_id') or '')
    L.log('device', j.get('device_name'), j.get('device_id'))


def step_relogin(name):
    r = hop('auth', 'logout', '--yes', timeout=90)
    if r.rc != 0:
        hop('auth', 'logout', '--yes', '--local-only', timeout=90)
    hop('daemon', 'stop')
    root('rm -rf /home/tester/.local/share/hop /home/tester/.ssh/hop; sleep 1')
    sk = L.kit()[0]
    r = hop('auth', 'login', '--server', URL, '--email', L.env_get('HK_EMAIL'), '--method', 'password', '--device-key-store', 'file',
            '--name', name, '--password-stdin', env={'HOP_SECRET_KEY': sk}, stdin=L.sec_read('masterpw') + '\n', timeout=120)
    got, _ = L.wait_for(lambda: (L.hosts() or {}).get('t1', {}).get('host_keys'), 60, 1)
    c('B.login-%s' % name, 'B signs in again as %s (--method password) for the next scenario' % name, r.rc == 0 and bool(got), '', r.ev('auth login'))
    step_device_id()


STEPS = {'localb-setup': step_localb_setup, 'ensure-t1': step_ensure_t1, 'b-wait-t1': step_b_wait_t1, 'revoke': step_revoke,
         'access': step_access, 'watch': step_watch, 'cutoff': step_cutoff, 'unlock-after': step_unlock_after,
         'sessions-start': step_sessions_start, 'sessions-end': step_sessions_end, 'block': step_block,
         'daemon-restart': step_daemon_restart, 'stopped': step_stopped, 'start-window': step_start_window,
         'inventory': step_inventory, 'relogin': step_relogin, 'device-id': step_device_id}

if __name__ == '__main__':
    name = sys.argv[1]
    L.guard('%s.%s' % (M, name), name)(STEPS[name])(*sys.argv[2:])
    L.done()
