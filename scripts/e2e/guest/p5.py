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
    L.ensure_include()
    hs = L.hosts() or {}
    if 't1' not in hs:
        L.ensure_testkey()
        hop('add', 't1', '--address', L.env_get('HK_T1_IP'), '--user', 'deploy', '--key', 'testkey', '--tag', 'ts')
    hop('trust', 't1', '--yes', timeout=60)
    hop('edit', 't1', '--user', 'deploy')


def step_b_wait_t1():
    L.ensure_include()
    got, secs = L.wait_for(lambda: (L.hosts() or {}).get('t1', {}).get('host_keys'), 60, 1)
    if not got:
        L.harness('B.wait-t1', 'B has t1 with a pinned host key before the revocation scenarios', 't1 not on B after 60s')


def devices():
    """A's device list by device_id, or None when hop auth devices --json gave no valid answer."""
    r = hop('auth', 'devices', '--json')
    j = r.json()
    if r.rc != 0 or not isinstance(j, dict) or not isinstance(j.get('devices'), list) or \
            not all(isinstance(d, dict) and d.get('device_id') for d in j['devices']):
        return None, r
    return {d['device_id']: d.get('name') for d in j['devices']}, r


def step_revoke(dev, n):
    """On A: revoke a device; the kit goes only to 0600 files, then hop auth resume confirms it."""
    before, rb = devices()
    if before is None or dev not in before:
        L.harness('A.revoke-%s' % n, 'B\'s device %s is in A\'s device list before revoke %s' % (dev or '(empty ID)', n),
                  'no valid device list' if before is None else 'listed: %s' % before, rb.ev('auth devices --json'))
        return
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
    after, ra = devices()
    if after is None:
        L.harness('A.devices-%s' % n, 'the revoked device is gone from A\'s device list', 'no valid device list', ra.ev('auth devices --json'))
    else:
        c('A.devices-%s' % n, 'the revoked device is gone from A\'s device list', dev not in after,
          '%s (%s) was listed before; now: %s' % (dev, before[dev], after))


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
    """Works when exec on t1 or list_hosts answers; denied only on a real answer from hop mcp
    (tool errors, no hosts, or hop mcp refusing to start with a reason). An EOF, hang or crash raises."""
    m = MCP(tag='p5-mcp')
    nh, st2, text = 0, None, ''
    if m.healthy:
        _, st, _ = m.call('list_hosts', {})
        nh = len((st or {}).get('hosts', []))
    if m.healthy:
        _, st2, text = m.call('exec', {'hosts': 't1', 'command': 'echo mcp-exec-ok'})
    m.close()
    tr = m.transport()
    if tr == 'broken':
        raise HarnessError('hop mcp gave no real answer: ' + m.why())
    if tr == 'refused':
        return False, 'hop mcp refused to start: ' + m.why()
    ok = 'mcp-exec-ok' in json.dumps(st2)
    return ok or nh > 0, 'list_hosts %d hosts; exec: %s' % (nh, L.cut((json.dumps(results(st2).get('t1', {}).get('error')) if st2 else text), 200))


def m_localb():
    r = hop('exec', 'lb1', '--', 'echo', 'localb-ok', user='localb', timeout=40)
    return 'localb-ok' in r.out, r.ev('localb: hop exec lb1')


METHODS = [('hop-exec', 'hop exec t1', m_hop_exec), ('hop-target', 'hop t1 (commands on stdin)', m_hop_target),
           ('plain-ssh', 'plain ssh t1', m_plain_ssh), ('agent', 'ssh-add -L on hop\'s agent', m_agent), ('mcp', 'MCP list_hosts/exec', m_mcp)]


class HarnessError(Exception):
    pass


def t1_reachable():
    """The control for every "no longer works" check: T1's sshd answers B over the tailnet."""
    r = root('ssh-keyscan -T 5 -t ed25519 %s 2>/dev/null' % L.env_get('HK_T1_IP'), timeout=20)
    return 'ssh-ed25519' in r.out


def cut_prereq(cid, tag):
    """True when a cut can be judged; otherwise records a harness failure under cid."""
    if t1_reachable():
        return True
    L.harness(cid, '%s: T1 answers on port 22 from B, so a refusal means hop refused' % tag, 'ssh-keyscan of T1 got no key')
    return False


def working(methods):
    """The ids of the methods that still work; a harness error in one raises."""
    return [mid for mid, _, fn in methods if fn()[0]]


def step_access(tag, expect, bug=None):
    if expect == 'cut' and not cut_prereq('B.%s.control' % tag, tag):
        return
    for mid, label, fn in METHODS:
        try:
            works, ev = fn()
        except HarnessError as e:
            L.harness('B.%s.%s' % (tag, mid), '%s: %s (harness error)' % (tag, label), str(e))
            continue
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


def step_cutoff(tag, t0, limit, offset='0'):
    """t0 is on the clock of the machine that started the change; offset is
    B's clock minus that clock (measured by the driver), so B's times map back."""
    t0, limit = float(t0) + float(offset), float(limit)
    name = 'watch5-%s' % tag

    def ready():
        st, w = L.state_read(name)
        if st == 'malformed':
            return 'malformed'
        return w if st == 'ok' and (first_cut(w, t0) or (w and w[-1].get('end'))) else None
    got, secs = L.wait_for(ready, limit + 10, 0.5)
    st, tl = L.state_read(name)
    cid, label = 'B.%s.cutoff' % tag, '%s: hop\'s agent is empty within %ds of the revoke' % (tag, limit)
    if st != 'ok':
        return L.harness(cid, label, 'watch state %s' % st, L.cut(str(tl), 200))
    before = [e for e in tl if not e.get('end') and e['t'] < t0]
    if not before or before[-1]['agent_keys'] <= 0:
        # The agent must hold keys before the change, or "empty" proves nothing.
        return L.harness(cid, label, 'prerequisite: the agent held no keys before the change (%s)' % (before[-1:] or 'no sample'),
                         L.cut(json.dumps(tl[:6]), 600))
    cut = first_cut(tl, t0)
    if cut is not None and cut - t0 < -0.25:
        return L.harness(cid, label, 'implausible: cut %.2fs before the change' % (cut - t0), L.cut(json.dumps(tl[-6:]), 600))
    c(cid, label, cut is not None and cut - t0 <= limit,
      'cut at +%.1fs' % (cut - t0) if cut else 'not cut within the watch', L.cut(json.dumps(tl[-6:]), 600))


def step_unlock_after(tag):
    r = hop('unlock', timeout=40)
    # Sample the agent right after the unlock: a key served even briefly is access.
    samples = []
    end = time.time() + 6
    while time.time() < end:
        samples.append(L.agent_keys())
        time.sleep(0.2)
    if not cut_prereq('B.%s.unlock' % tag, tag):
        return
    works = working(METHODS[:3])
    c('B.%s.unlock' % tag, '%s: hop unlock on the revoked device does not bring access back' % tag, not works,
      'hop unlock rc=%d; working again: %s' % (r.rc, works), r.ev('hop unlock'), BUGS['unlock'])
    c('B.%s.rev2-unlock-refused' % tag, '%s: hop unlock is refused on the revoked device and the agent stays empty' % tag,
      r.rc != 0 and max(samples or [0]) <= 0, 'hop unlock rc=%d; agent key counts after it: max %s over %d samples' % (
          r.rc, max(samples or [0]), len(samples)), r.ev('hop unlock'), BUGS['unlock'])
    hop('lock')


def wiped_state():
    d = '/home/tester/.local/share/hop'
    vault = [v for v in L.glob_files(d + '/vault') if not v.endswith('lock')]
    generated = []
    for f in L.glob_files('/home/tester/.ssh/hop'):
        if f.endswith('lock'):
            continue
        if os.path.basename(f) == 'config':
            try:
                if not re.search(r'^Host ', open(f).read(), re.M):
                    continue  # an empty config (the Include target) holds nothing
            except OSError:
                pass
        generated.append(f)
    return {'vault_files': len(vault), 'device_key': os.path.exists(d + '/device.key'), 'ssh_hop_files': generated[:8],
            'revocation_json': os.path.exists(d + '/revocation.json')}


def step_wiped(tag, secs='45'):
    """After a revocation the device can prove (an honest server): the vault, device.key and
    the generated ~/.ssh/hop files are gone, and revocation.json stays."""
    def done():
        w = wiped_state()
        return w if not w['vault_files'] and not w['device_key'] and not w['ssh_hop_files'] else None
    got, t = L.wait_for(done, float(secs), 1)
    w = wiped_state()
    c('B.%s.rev2-wiped' % tag, '%s: the proven revocation wipes the vault, device.key and the generated ~/.ssh/hop files' % tag,
      bool(got), 'after %.0fs: %s' % (t, json.dumps(w)), '', 'r2-inv')
    c('B.%s.rev2-record' % tag, '%s: revocation.json is kept, so hop auth status can say what happened' % tag, w['revocation_json'],
      json.dumps(w), '', 'r2-inv')
    if w['revocation_json']:
        r = hop('auth', 'status')
        L.log('auth status after the wipe', r.all)


def step_nokeys(tag):
    """The whole watch: the agent never held a key (the device was already cut off when it started)."""
    st, tl = L.state_read('watch5-%s' % tag)
    cid, label = 'B.%s.rev2-nokeys' % tag, '%s: the revoked device serves no key at any point, across a daemon restart' % tag
    if st != 'ok' or not tl or not tl[-1].get('end'):
        return L.harness(cid, label, 'watch state %s' % st, L.cut(str(tl), 200))
    served = [e for e in tl if not e.get('end') and e['agent_keys'] > 0]
    c(cid, label, not served, '%d samples with keys, first at %s' % (len(served), served[0]['t'] if served else '-'),
      L.cut(json.dumps(tl[:12]), 600), BUGS['offline'])


# ---- max-offline policy (scenario s6)

def policy_supported():
    return L.state_get('policy-supported', '') == 'yes'


def step_policy(val):
    """On A: hop auth policy --max-offline <val>."""
    r = hop('auth', 'policy', '--max-offline', val, '--json', timeout=60)
    if r.rc != 0 and 'unknown' in r.all.lower():
        return skip('A.rev2-policy-set-%s' % val, 'hop auth policy --max-offline %s' % val, 'not in this build: ' + L.cut(r.all.strip(), 200))
    c('A.rev2-policy-set-%s' % val, 'hop auth policy --max-offline %s on A' % val, r.rc == 0, '', r.ev('auth policy'))


def step_policy_seen(want):
    r = hop('auth', 'policy', '--json', timeout=30)
    if r.rc != 0 and 'unknown' in r.all.lower():
        L.state_put('policy-supported', 'no')
        return skip('B.rev2-policy-seen', 'the max-offline policy syncs to B', 'not in this build: ' + L.cut(r.all.strip(), 200))
    L.state_put('policy-supported', 'yes')
    want = int(want)

    def seen():
        j = hop('auth', 'policy', '--json', timeout=30).json() or {}
        return j if j.get('max_offline') == want else None
    got, t = L.wait_for(seen, 60, 2)
    c('B.rev2-policy-seen', 'the max-offline policy set on A reaches B (max_offline %ds)' % want, bool(got), 'after %.0fs: %s' % (
        t, L.cut(json.dumps(got or hop('auth', 'policy', '--json').json()), 200)))


def vault_locked():
    st = L.status_json() or {}
    v = st.get('vault') or {}
    return v.get('locked'), v.get('offline_too_long'), st


def step_policy_idle(secs):
    """A healthy, idle B (server reachable) with a 1m policy never locks: sample for secs."""
    if not policy_supported():
        return skip('B.rev2-policy-idle', 'a healthy idle device with a 1m policy does not lock', 'no max-offline policy in this build')
    if not L.server_reachable(URL, 3):
        return L.harness('B.rev2-policy-idle', 'a healthy idle device with a 1m policy does not lock', 'B does not reach the server')
    hop('unlock', timeout=40)
    t0, bad, n, last = time.time(), [], 0, None
    while time.time() - t0 < float(secs):
        k = L.agent_keys()
        n += 1
        if n % 3 == 0:
            locked, offline, _ = vault_locked()
            last = (locked, offline)
            if locked:
                bad.append({'t': round(time.time() - t0), 'locked': locked, 'offline_too_long': offline})
        if k <= 0:
            bad.append({'t': round(time.time() - t0), 'agent_keys': k})
        if bad:
            break
        time.sleep(5)
    c('B.rev2-policy-idle', 'a healthy idle device with a 1m max-offline policy does not lock (%ss)' % secs, not bad,
      'first problem: %s' % bad[0] if bad else '%d samples over %.0fs, last vault state %s' % (n, time.time() - t0, last))


def step_policy_offline(secs):
    """B is blocked from the server: within secs it locks, empties the agent, and refuses hop unlock."""
    if not policy_supported():
        return skip('B.rev2-policy-lock', 'a device offline longer than the policy locks', 'no max-offline policy in this build')
    t0 = time.time()

    def locked():
        lk, off, _ = vault_locked()
        return (lk, off) if lk and L.agent_keys() <= 0 else None
    got, t = L.wait_for(locked, float(secs), 3)
    _, _, st = vault_locked()
    c('B.rev2-policy-lock', 'blocked from the server for over the 1m policy, B locks and its agent is empty (within %ss)' % secs,
      bool(got), 'after %.0fs: locked/offline_too_long %s' % (time.time() - t0, got), L.cut(json.dumps(st.get('vault')), 400))
    r = hop('unlock', timeout=40)
    c('B.rev2-policy-unlock', 'while still offline, hop unlock refuses with "offline too long"', r.rc != 0 and 'offline too long' in r.all
      and L.agent_keys() <= 0, '', r.ev('hop unlock'))


def step_policy_clear(secs):
    """B reaches the server again: a contact clears the lock (hop unlock works, keys back)."""
    if not policy_supported():
        return skip('B.rev2-policy-clear', 'a contact clears the max-offline lock', 'no max-offline policy in this build')
    t0, last = time.time(), None
    while time.time() - t0 < float(secs):
        last = hop('unlock', timeout=40)
        if L.agent_keys() > 0:
            break
        time.sleep(5)
    k = L.agent_keys()
    r = hop('exec', 't1', '--', 'echo', 'policy-clear-ok', timeout=40)
    c('B.rev2-policy-clear', 'once B reaches the server again, the lock clears: hop unlock works and B logs in to t1', k > 0 and 'policy-clear-ok' in r.out,
      'after %.0fs: %d agent keys' % (time.time() - t0, k), (last.ev('hop unlock') if last else '') + '\n' + r.ev('exec t1'))


SESSIONS = ('open-hopexec', 'open-plain')


def step_sessions_start():
    env = L.user_env('tester')
    cmd = 'for i in $(seq 1 45); do echo "tick $i"; sleep 1; done'
    for name, argv in (('open-hopexec', ['hop', 'exec', 't1', '--', 'sh', '-c', cmd]),
                       ('open-plain', ['ssh', '-o', 'BatchMode=yes', 't1', cmd])):
        f = open('/var/e2e/state/%s.out' % name, 'w')
        subprocess.Popen(L.user_argv('tester', argv, 120), env=env, stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=True)

    def connected():
        got = [n for n in SESSIONS if 'tick 1' in open('/var/e2e/state/%s.out' % n).read()]
        return got if len(got) == len(SESSIONS) else None
    got, secs = L.wait_for(connected, 20, 0.5)
    got = got or [n for n in SESSIONS if 'tick 1' in open('/var/e2e/state/%s.out' % n).read()]
    L.state_put('sessions-start', {'connected': got, 't': time.time()})
    if len(got) != len(SESSIONS):
        L.harness('B.sessions-start', 'both sessions are connected and running before the revoke', 'connected: %s' % got)


def step_sessions_end(tag):
    L.wait_for(lambda: not root('pgrep -u tester -f "seq 1 45"').out.strip(), 70, 2)
    o = {n: open('/var/e2e/state/%s.out' % n).read() for n in SESSIONS}
    cid, label = 'B.%s.open-sessions' % tag, '%s: sessions open at the revoke are ended (hop exec and plain ssh)' % tag
    _, pre = L.state_read('sessions-start')
    connected = (pre or {}).get('connected') or []
    if sorted(connected) != sorted(SESSIONS):
        return L.harness(cid, label, 'prerequisite: not every session was running before the revoke (connected: %s)' % connected,
                         '; '.join('%s: %d ticks' % (n, s.count('tick')) for n, s in o.items()))
    survived = [n for n, s in o.items() if 'tick 45' in s]
    c(cid, label, not survived,
      'ran to the end: %s' % survived, '; '.join('%s: %d ticks' % (n, s.count('tick')) for n, s in o.items()), 'r2-gap4')


def step_block(on):
    on = on == '1'
    bad = L.fw_block(['OUTPUT -d %s -p tcp --dport 8443 -j DROP' % SIP, 'INPUT -s %s -p tcp --sport 8443 -j DROP' % SIP]) if on else []
    if not on:
        L.fw_clear()
    t = time.time()
    reach = L.server_reachable(URL, 1 if on else 5)
    ok = not bad and reach != on
    # The driver reads the time from here, so a cutoff after unblocking is timed on B's own clock.
    L.state_put('block-%d' % int(on), {'t': t, 'ok': ok})
    if not ok:
        L.harness('B.block-%s' % ('on' if on else 'off'), 'the firewall %s B\'s path to the server' % ('blocks' if on else 'reopens'),
                  'rules that failed: %s; server reachable: %s' % (bad, reach))


def step_daemon_restart(tag):
    hop('daemon', 'stop')
    time.sleep(1)
    hop('ls')
    if not cut_prereq('B.%s.restart' % tag, tag):
        return
    works = working(METHODS[:3])
    c('B.%s.restart' % tag, '%s: after a daemon restart, the revoked device has no access' % tag, not works,
      'working: %s' % works, '', BUGS['offline'])


def step_stopped(tag):
    pids = L.daemon_pids()
    if not cut_prereq('B.%s.stopped' % tag, tag):
        return
    works = working(METHODS[2:4])
    c('B.%s.stopped' % tag, '%s: with the daemon stopped, plain ssh and the agent give nothing' % tag, not pids and not works,
      'daemon pids %s, working: %s' % (pids, works))


def step_start_window(tag):
    """Start the daemon on a revoked device; nothing may be served before the server check."""
    cid = 'B.%s.window' % tag
    label = '%s: a daemon starting on the revoked device serves no keys before it checks with the server' % tag
    if L.daemon_pids():
        return L.harness(cid, label, 'prerequisite: a daemon was already running before the start')
    if not cut_prereq(cid, tag):
        return
    dlog = '/home/tester/.local/state/hop/daemon.log'
    size0 = os.path.getsize(dlog) if os.path.exists(dlog) else 0
    tl = []
    ssh_ok = []
    seen_pid = False
    stop = time.time() + 12
    p = subprocess.Popen(L.user_argv('tester', ['hop', 'ls'], 30), env=L.user_env('tester'), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    t0 = time.time()
    while time.time() < stop:
        n = L.agent_keys()
        tl.append((round(time.time() - t0, 2), n))
        seen_pid = seen_pid or bool(L.daemon_pids())
        if n > 0:
            r = ssh('t1', 'echo window-ssh-ok', timeout=10)
            if 'window-ssh-ok' in r.out:
                ssh_ok.append(round(time.time() - t0, 2))
        time.sleep(0.05)
    p.wait(timeout=30)
    grew = os.path.exists(dlog) and os.path.getsize(dlog) > size0
    if not seen_pid and not grew:
        # Nothing served because nothing started proves nothing.
        return L.harness(cid, label, 'prerequisite: no daemon started (no process seen, daemon.log unchanged)', json.dumps(tl[:40]))
    served = [t for t, n in tl if n > 0]
    c(cid, label,
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
    r = hop('auth', 'status', '--json')
    j = r.json()
    if not isinstance(j, dict) or not isinstance(j.get('signed_in'), bool):
        L.harness('B.%s.inv-status' % tag, '%s: hop auth status does not say "signed in" on a revoked device' % tag,
                  'no valid answer with a signed_in field', r.ev('auth status --json'))
    else:
        c('B.%s.inv-status' % tag, '%s: hop auth status does not say "signed in" on a revoked device' % tag, j['signed_in'] is False,
          'signed_in=%s' % j['signed_in'], '', 'r1-P3-13')
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
    L.ensure_include()
    step_device_id()


STEPS = {'localb-setup': step_localb_setup, 'ensure-t1': step_ensure_t1, 'b-wait-t1': step_b_wait_t1, 'revoke': step_revoke,
         'access': step_access, 'watch': step_watch, 'cutoff': step_cutoff, 'unlock-after': step_unlock_after,
         'sessions-start': step_sessions_start, 'sessions-end': step_sessions_end, 'block': step_block,
         'daemon-restart': step_daemon_restart, 'stopped': step_stopped, 'start-window': step_start_window,
         'inventory': step_inventory, 'relogin': step_relogin, 'device-id': step_device_id, 'wiped': step_wiped,
         'nokeys': step_nokeys, 'policy': step_policy, 'policy-seen': step_policy_seen, 'policy-idle': step_policy_idle,
         'policy-offline': step_policy_offline, 'policy-clear': step_policy_clear}

if __name__ == '__main__':
    name = sys.argv[1]
    L.guard('%s.%s' % (M, name), name)(STEPS[name])(*sys.argv[2:])
    L.done()
