#!/usr/bin/env python3
"""Phase 3: sync between CLI-A and CLI-B through the run's hop-server.

One step per invocation; the driver orders them across the two machines:
  p3.py <step> [args]
"""
import glob
import json
import os
import re
import sys
import time

import e2elib as L
from e2elib import check as c, hop, has, root, skip

M = L.MACHINE
URL = L.env_get('HK_SERVER_URL')
SIP = L.env_get('HK_SERVER_IP')
EMAIL = L.env_get('HK_EMAIL')
PTYLOG = '/var/e2e/logs/pty-blogin.log'
INBOX = '/var/e2e/state/blogin.in'
REF_FIELDS = 'README, Sync: "Two changes to different protected fields of one item are held too."'


def block(on):
    """Cut B off from the server both ways: outgoing gets a reset, and the
    reply on an already open long-poll is dropped, so nothing arrives late."""
    rules = ['OUTPUT -d %s -p tcp --dport 8443 -j REJECT --reject-with tcp-reset' % SIP,
             'INPUT -s %s -p tcp --sport 8443 -j DROP' % SIP]
    bad = L.fw_block(rules) if on else []
    if not on:
        L.fw_clear()
    t = time.time()
    # The block is a prerequisite of every offline check: prove it took effect.
    reach = L.server_reachable(URL, 1 if on else 5)
    ok = not bad and reach != on
    if not ok:
        L.harness('%s.block-%s' % (M, 'on' if on else 'off'), 'the firewall %s B\'s path to the server' % ('blocks' if on else 'reopens'),
                  'rules that failed: %s; server reachable: %s' % (bad, reach))
    L.state_put('block-%d' % int(on), {'t': t, 'ok': ok})
    return ok


def sync_state():
    st = L.status_json() or {}
    return st.get('sync') or {}


def held():
    """The held changes, or None when hop sync resolve --json gave no valid answer."""
    r = hop('sync', 'resolve', '--json')
    try:
        return json.loads(r.out).get('held') or []
    except Exception:
        return None


def step_server_check():
    r = root('curl -fsS -m 8 %s/v1/healthz' % URL)
    c('%s.server' % M, 'the run\'s hop-server answers over the tailnet with a certificate from the trusted test CA',
      r.rc == 0 and '"ok":true' in r.out.replace(' ', ''), '', r.ev('curl healthz'))


def step_seed():
    """On A, before signup: the hosts, key, snippet and pin that b-received and
    a-after-logout look for. Phases 1-2 make them; a phase-3-only run makes them here.
    Nothing is touched when they are already there."""
    L.ensure_vault()
    L.ensure_testkey()
    hs = L.hosts() or {}
    made = []
    if not any(h.get('host_keys') for h in hs.values()) or 'local1' not in hs and 'm1' not in hs:
        if 'local1' not in hs:
            hop('add', 'local1', '--address', '127.0.0.1', '--user', 'target', '--key', 'testkey', '--tag', 'lab')
        hop('trust', 'local1', '--yes')
        made.append('local1')
    if not (hop('snippet', 'ls', '--json').json() or []):
        hop('snippet', 'add', 'up', '--', 'uptime')
        made.append('snippet up')
    hs = L.hosts() or {}
    keys = [k.get('name') for k in (hop('key', 'ls', '--json').json() or [])]
    snips = hop('snippet', 'ls', '--json').json() or []
    pins = sum(len(h.get('host_keys') or []) for h in hs.values())
    usable = ('local1' in hs or 'm1' in hs) and 'testkey' in keys and snips and pins
    detail = 'seeded: %s; %d hosts, %d pins, keys %s, %d snippets' % (made or 'nothing (phases 1-2 ran)', len(hs), pins, keys, len(snips))
    if usable:
        c('A.fixtures', 'A has the hosts, key, snippet and pin phase 3 syncs to B', True, detail)
    else:
        L.harness('A.fixtures', 'A has the hosts, key, snippet and pin phase 3 syncs to B', detail)


def step_signup():
    had_vault = os.path.exists('/home/tester/.local/share/hop/device.key')
    if not had_vault:
        L.ensure_vault()
    L.ensure_testkey()
    code = L.sec_read('invite')
    r = hop('auth', 'signup', '--server', URL, '--email', EMAIL, '--code', code, '--json', timeout=90)
    j = r.json() or {}
    c('A.signup', 'hop auth signup publishes the existing local vault without a terminal',
      r.rc == 0 and j.get('created') is False and bool(j.get('account_id')), 'had a local vault: %s' % had_vault, r.ev('hop auth signup --json'))
    r = hop('auth', 'status', '--json')
    j = r.json() or {}
    c('A.auth-status', 'hop auth status: signed in to the run\'s server', j.get('signed_in') is True and j.get('server', '').rstrip('/') == URL, '', r.ev('auth status --json'))
    L.state_put('hosts-A.json', sorted(L.hosts() or {}))


def step_b_refusals():
    if os.path.exists('/home/tester/.local/share/hop/device.key'):
        # --method password: an approval login would stop first at "needs a terminal".
        r = hop('auth', 'login', '--server', URL, '--email', EMAIL, '--method', 'password', '--password-stdin', '--json',
                env={'HOP_SECRET_KEY': 'H1-NOTA-REAL-KEYX-XXXX'}, stdin='not-the-password\n', timeout=60)
        c('B.login-local-vault', 'hop auth login on a device with a local-only vault refuses and names --merge',
          r.rc == 255 and '--merge' in r.all, '', r.ev('auth login --json'))
        hop('daemon', 'stop')
        time.sleep(1)
        root('cd /home/tester && for d in .local/share/hop .local/state/hop .ssh/hop; do [ -e "$d" ] && mv "$d" "$d.phase1"; done; true')
    r = hop('auth', 'login', '--server', URL, '--email', EMAIL, '--name', 'cli-b', '--device-key-store', 'file', timeout=60)
    c('B.login-notty', 'hop auth login by approval without a terminal refuses and names --method password',
      r.rc == 255 and 'terminal' in r.all and '--method password' in r.all, '', r.ev('auth login </dev/null'))


def step_b_login_approve():
    """Long-running: the pty login; the driver reads the code from the log and answers via INBOX."""
    for p in (INBOX,):
        if os.path.exists(p):
            os.remove(p)
    rc, out = L.pty_run('tester', ['hop', 'auth', 'login', '--server', URL, '--email', EMAIL, '--name', 'cli-b',
                                   '--device-key-store', 'file'], [], timeout=300, inbox=INBOX, logname='blogin')
    c('B.login-approve', 'hop auth login by approval on a pty signs B in', rc == 0 and 'Signed in' in out, 'pty exit %d' % rc, L.cut(out, -500))


def step_a_approve_start(code):
    r = hop('auth', 'approve', code, timeout=40)
    L.state_put('approve-start', {'rc': r.rc, 'out': L.mask(r.all)[:800]})


def step_a_approve_sas(code, sas):
    r = hop('auth', 'approve', code, '--sas', sas, timeout=120)
    c('A.approve', 'hop auth approve CODE --sas approves B headless', r.rc == 0 and 'Approved' in r.out, '', r.ev('auth approve --sas'))
    # Decided: "Approved <name>." names the device by its name, with no empty parentheses.
    m = re.search(r'Approved (\S.*?)\. ', r.out)
    c('A.approve-id', 'the approval message is "Approved cli-b." (the device\'s name, no empty parentheses)',
      bool(m) and m.group(1) == 'cli-b' and '()' not in r.all, 'named: %r' % (m.group(1) if m else None), r.ev('auth approve'), 'r1-P3-6')


def step_b_received():
    want = L.state_get('hosts-A.json', [])
    got, secs = L.wait_for(lambda: sorted(L.hosts() or {}) if sorted(L.hosts() or {}) == want else None, 60, 1)
    keys = [k['name'] for k in (hop('key', 'ls', '--json').json() or [])]
    snips = [s['name'] for s in (hop('snippet', 'ls', '--json').json() or [])]
    hs = L.hosts() or {}
    pins = sum(len(h.get('host_keys') or []) for h in hs.values())
    c('B.received', 'B receives every host, the key, snippets and pins after the approval',
      got == want and 'testkey' in keys and len(snips) > 0 and pins > 0,
      'hosts %d/%d in %.1fs, keys %s, %d snippets, %d pins' % (len(hs), len(want), secs, keys, len(snips), pins))
    deny = [h for h in hs.values() if h.get('agent_access') == 'deny']
    if 'mdeny' in want:
        c('B.agent-access', 'agent_access deny syncs', bool(deny), 'denied hosts on B: %s' % [h['name'] for h in deny])
    else:
        skip('B.agent-access', 'agent_access deny syncs', 'A has no denied host (phase 2 did not run)')


def step_offline_start():
    block(True)
    r1 = hop('add', 'offb1', '--address', '10.9.9.9', '--user', 'deploy', '--tag', 'synctest')
    r2 = hop('snippet', 'add', 'offsnip', '--', 'echo', 'offline')
    s = sync_state()
    c('B.offline-queue', 'changes made offline are queued', r1.rc == 0 and r2.rc == 0 and s.get('pending', 0) >= 2,
      'pending %s, state %s' % (s.get('pending'), s.get('state')))
    r = hop('sync', timeout=70)
    c('B.offline-sync', 'hop sync while offline fails fast (exit 255 within 10s)', r.rc == 255 and r.secs < 10,
      'took %.1fs (limit 10s), exit %s' % (r.secs, r.rc), r.ev('hop sync'), 'r1-P3-10')
    root('pkill -9 -u tester -f "hop daemon"; sleep 1')
    hop('ls')
    s = sync_state()
    c('B.outbox-survives', 'the outbox survives a killed daemon', s.get('pending', 0) >= 2, 'pending %s after kill -9 and restart' % s.get('pending'))


def step_offline_end():
    block(False)
    L.state_put('unblocked', L.state_get('block-0'))


def step_block(on):
    block(on == '1')


def step_conflict_check():
    """Run on B after unblocking with three conflicting edits queued (cf1 user, cf2 port/user, cf3 description).

    A held change blocks the queue behind it, so changes are held one at a
    time: resolve each as it appears until nothing is pending or held."""
    ids = {h['id']: n for n, h in (L.hosts() or {}).items()}
    ever, resolved = [], {}
    bad_answers = 0
    t0 = time.time()
    while time.time() - t0 < 300:
        hl = held()
        if hl is None:
            bad_answers += 1
            time.sleep(2)
            continue
        if hl:
            x = hl[0]
            name = ids.get(x.get('item_id'), x.get('item_id'))
            if name not in ever:
                ever.append(name)
            n = str(x['n'])
            if name == 'cf2':
                r = hop('sync', 'resolve', n, '--edit', '--set', 'user=uB', '--json')
                prop = (r.json() or {}).get('proposal') or {}
                tok, new_id = prop.get('confirm') or '', prop.get('new_id') or ''
                extra = ['--new-id', new_id] if new_id else []
                resolved[name] = hop('sync', 'resolve', n, '--edit', '--set', 'user=uB', '--confirm', tok, *extra)
            else:
                resolved[name] = hop('sync', 'resolve', n, '--take-theirs', '--yes')
            continue
        s = sync_state()
        if s.get('pending', 1) == 0 and s.get('held', 1) == 0 and time.time() - t0 > 5:
            break
        time.sleep(2)
    hs = L.hosts() or {}
    st = sync_state()
    if bad_answers:
        L.harness('B.conflict-resolve-json', 'hop sync resolve --json answers with JSON while resolving', '%d answers were not JSON' % bad_answers)
    drained = st.get('pending') == 0 and st.get('held') == 0
    c('B.conflict-drained', 'after resolving every held change, nothing is pending or held', drained,
      'held in order: %s; pending %s, held %s after %.0fs' % (ever, st.get('pending'), st.get('held'), time.time() - t0))
    c('B.conflict-held', 'a concurrent edit of the same protected field (user) is held', 'cf1' in ever, 'held: %s' % ever)
    # Documented limit: no field-level merge for protected fields.
    L.limit('B.conflict-fields', 'edits of different protected fields of one item (port on A, user on B) are held, as documented',
            'cf2' in ever, 'held: %s' % ever, '', 'r1-P3-2', REF_FIELDS)
    # Decided: last writer wins on the description, and the device whose push replaced
    # the other's value says so (README, Sync). A pushed first; B, offline, pushed second.
    note, notes = None, []
    if drained:
        def find():
            st2 = L.status_json() or {}
            ws = list(st2.get('warnings') or []) + list((st2.get('sync') or {}).get('warnings') or [])
            notes[:] = [w for w in ws if 'replaced' in w]
            return next((w for w in notes if '"cf3"' in w and 'description' in w), None)
        note, _ = L.wait_for(find, 60, 2)
    desc = hs.get('cf3', {}).get('description')
    c('B.conflict-unprotected', 'a concurrent description edit is not held, B\'s later push wins, and B\'s hop status names cf3 and the field '
      '(never the values)', drained and 'cf3' not in ever and desc == 'fromB' and bool(note) and 'fromA' not in note and 'fromB' not in note,
      'held: %s; final description %r; note: %s' % (ever, desc, note or ('none of %d replaced-edit notes names cf3' % len(notes) if drained
                                                                        else 'not judged: the queue did not drain')), '', 'r1-P3-1')
    if note:
        r = hop('sync', timeout=40)
        L.log('hop sync with the note', r.all)
    if 'cf1' in resolved:
        r = resolved['cf1']
        c('B.resolve-theirs', 'hop sync resolve --take-theirs keeps the server\'s user', r.rc == 0 and hs.get('cf1', {}).get('user') == 'uA',
          'user %s' % hs.get('cf1', {}).get('user'), r.ev('resolve --take-theirs'))
    c('B.cf2-combined', 'cf2 ends with both edits: port 2201 from A, user uB from B', hs.get('cf2', {}).get('user') == 'uB' and hs.get('cf2', {}).get('port') == 2201,
      'user %s port %s%s' % (hs.get('cf2', {}).get('user'), hs.get('cf2', {}).get('port'), ' (via resolve --edit)' if 'cf2' in resolved else ''))
    L.state_put('cf-B', {n: {k: hs.get(n, {}).get(k) for k in ('user', 'port', 'description')} for n in ('cf1', 'cf2', 'cf3')})


def step_converge():
    """On A: the conflict hosts end up as on B."""
    want = L.state_get('cf-B-from', {})
    def same():
        hs = L.hosts() or {}
        cur = {n: {k: hs.get(n, {}).get(k) for k in ('user', 'port', 'description')} for n in ('cf1', 'cf2', 'cf3')}
        return cur if cur == want else None
    got, secs = L.wait_for(same, 60, 1)
    hs = L.hosts() or {}
    c('A.converge', 'after resolving, A and B agree on the conflicting hosts', got is not None,
      'after %.1fs; A: %s; B: %s' % (secs, {n: {k: hs.get(n, {}).get(k) for k in ('user', 'port', 'description')} for n in ('cf1', 'cf2', 'cf3')}, want))


def step_usebkey():
    pub = open('/var/e2e/state/bkey.pub').read()
    root('rm -f /home/target2/.ssh/authorized_keys')
    L.authorize('target2', pub)
    hop('add', 'usebkey', '--address', '127.0.0.1', '--user', 'target2', '--key', 'bkey')
    hop('trust', 'usebkey', '--yes')
    r = hop('exec', 'usebkey', '--', 'sh', '-c', 'echo used-bkey-from-A-$(id -un)')
    c('A.use-bkey', 'A logs in with a key that was added on B (target2 authorizes only that key)',
      r.rc == 0 and 'used-bkey-from-A-target2' in r.out, '', r.ev('hop exec usebkey'))


def step_daemon_stop():
    hop('daemon', 'stop')
    pids, _ = L.wait_for(lambda: not L.daemon_pids(), 10, 0.5)
    left = L.daemon_pids()
    L.state_put('daemon-stopped', {'pids': left})
    if left:
        # The restart checks that follow would prove nothing with the daemon still up.
        L.harness('%s.daemon-stop' % M, 'hop daemon stop leaves no daemon running', 'daemon pids %s' % left)


def step_after_restart(name):
    t0 = time.time()
    hop('ls')
    got, secs = L.wait_for(lambda: name in (L.hosts() or {}), 45, 0.5)
    c('B.restart-resume', 'after a daemon restart, B receives a change made while it was stopped', bool(got),
      '%s seen %.1fs after the first command' % (name, time.time() - t0) if got else 'not seen in 45s')


def step_after_reboot(name):
    pids = L.daemon_pids()
    t0 = time.time()
    hop('ls')
    got, secs = L.wait_for(lambda: name in (L.hosts() or {}), 120, 1)
    c('B.reboot-resume', 'after a reboot (no service), sync resumes once a hop command starts the daemon', bool(got),
      'daemon at boot: %s; %s seen after %.1fs' % (pids, name, time.time() - t0))


def step_service_setup():
    r = hop('setup', '--service', '--yes', timeout=60)
    c('B.service-setup', 'hop setup --service installs the user service', r.rc == 0, '', r.ev('hop setup --service --yes'))
    c('B.service-warns', 'on a sealed file-store device, setup --service warns that its daemon starts locked after a boot until hop unlock',
      has(r.all, 'HOP_DEVICE_PASSPHRASE', 'starts locked', 'hop unlock'), '', r.ev('setup --service'), 'r1-P2-3')
    root('loginctl enable-linger tester')


def user_systemctl(*args):
    return L.run_as('tester', ['systemctl', '--user'] + list(args), 30)


def step_after_reboot_service(name):
    """Decided (README, Sync): on a sealed device key the service's daemon starts locked
    after a boot, says so, and hop unlock (with the passphrase) is all it takes for
    the change made during the reboot to arrive."""
    def config_has():
        try:
            return re.search(r'^Host %s$' % name, open('/home/tester/.ssh/hop/config').read(), re.M)
        except OSError:
            return None
    act, _ = L.wait_for(lambda: user_systemctl('is-active', 'hopkey.service').out.strip() == 'active', 60, 2)
    st = L.status_json() or {}
    v, sy = st.get('vault') or {}, st.get('sync') or {}
    txt = hop('status').all
    c('B.service-locked', 'after the reboot the service daemon runs, locked, and hop status says to run hop unlock (sync paused)',
      bool(act) and v.get('locked') is True and sy.get('state') == 'locked' and 'hop unlock' in txt,
      'service active: %s; vault locked %s, sync %s' % (bool(act), v.get('locked'), sy.get('state')), L.cut(txt, 600), 'r1-P2-3')
    r = hop('unlock', timeout=60)
    t0 = time.time()
    got, secs = L.wait_for(config_has, 120, 1)
    c('B.service-reboot', 'after hop unlock (with the passphrase), the change made during the reboot arrives with no other command',
      r.rc == 0 and bool(got), 'hop unlock rc %d; %s %s' % (r.rc, name, 'in the ssh config %.1fs after the unlock' % (time.time() - t0) if got
                                                               else 'not in the ssh config after 120s'), r.ev('hop unlock'), 'r1-P2-3')
    # Back to command-started daemons for the rest of the run.
    user_systemctl('disable', '--now', 'hopkey.service')
    user_systemctl('daemon-reload')
    hop('ls')


def step_devices(other):
    r = hop('auth', 'devices', '--json')
    j = r.json()
    names = sorted(d.get('name') or d.get('device_name') or '' for d in (j if isinstance(j, list) else (j or {}).get('devices', [])))
    c('%s.devices' % M, 'hop auth devices lists this device and %s' % other, other in names and len(names) >= 2, 'names %s' % names, r.ev('devices --json')[:400])
    r = hop('auth', 'devices')
    c('%s.devices-lastseen' % M, 'hop auth devices shows the devices in a table', r.rc == 0 and other in r.out, '', r.ev('devices'))


def step_logout():
    r = hop('auth', 'logout', '--yes', timeout=90)
    c('B.logout', 'hop auth logout --yes', r.rc == 0, '', r.ev('auth logout --yes'))
    dk = os.path.exists('/home/tester/.local/share/hop/device.key')
    vault = glob.glob('/home/tester/.local/share/hop/vault/*')
    vault = [v for v in vault if not v.endswith(('lock', 'owner.lock'))]
    c('B.logout-keys', 'logout deletes device.key and the vault files', not dk and not vault, 'device.key %s, vault files %s' % (dk, vault))
    try:
        cfg = open('/home/tester/.ssh/hop/config').read()
    except OSError:
        cfg = ''
    nhost = len(re.findall(r'^Host ', cfg, re.M))
    kh = glob.glob('/home/tester/.ssh/hop/known_hosts-*')
    pubs = glob.glob('/home/tester/.ssh/hop/keys/*')
    c('B.logout-config', 'logout leaves no decrypted host data: ssh config, pinned host keys, public keys',
      nhost == 0 and not kh and not pubs, '%d Host lines, %d known_hosts files, %d key files' % (nhost, len(kh), len(pubs)), '', 'r1-P2-2')
    r = hop('ls', timeout=30)
    c('B.after-logout-ls', 'hop ls after logout says there is no vault, quickly', r.rc == 255 and 'no vault' in r.all and r.secs < 5,
      '%.1fs' % r.secs, r.ev('hop ls'), 'r1-P3-8')


def step_a_after_logout(gone):
    r = hop('exec', 'm1' if 'm1' in (L.hosts() or {}) else 'local1', '--', 'echo', 'A-still-works')
    c('A.after-b-logout', 'A keeps working after B logs out', 'A-still-works' in r.out, '', r.ev('exec'))
    r = hop('auth', 'devices', '--json')
    j = r.json()
    if r.rc != 0 or not isinstance(j, dict) or not isinstance(j.get('devices'), list):
        L.harness('A.devices-after-logout', 'the logged-out device is gone from the device list', 'no valid device list', r.ev('auth devices --json'))
        return
    names = [d.get('name') for d in j['devices']]
    c('A.devices-after-logout', 'the logged-out device is gone from the device list', bool(names) and gone not in names, 'names %s' % names)


def step_pwlogin(name):
    """Sign B in with --method password (headless). Needs SEC/kit and SEC/masterpw from A."""
    if (hop('auth', 'status', '--json').json() or {}).get('signed_in'):
        # A logout that failed earlier is already a failed check; don't let it cascade.
        L.log('still signed in before pwlogin: logging out with --discard-pending')
        hop('auth', 'logout', '--yes', '--discard-pending', timeout=90)
    sk = L.kit()[0]
    r = hop('auth', 'login', '--server', URL, '--email', EMAIL, '--method', 'password', '--device-key-store', 'file',
            '--name', name, '--password-stdin', env={'HOP_SECRET_KEY': sk}, stdin=L.sec_read('masterpw') + '\n', timeout=120)
    ok = r.rc == 0 and 'Signed in' in r.all
    c('B.pwlogin-' + name, 'hop auth login --method password signs B in as %s' % name, ok, '', r.ev('auth login --method password'))
    if ok:
        L.wait_for(lambda: len(L.hosts() or {}) > 0, 60, 1)


def step_ensure_a():
    """For runs without phase 3: A signed in."""
    j = hop('auth', 'status', '--json').json() or {}
    if j.get('signed_in'):
        return
    step_signup()


def step_ensure_b(name):
    j = hop('auth', 'status', '--json').json() or {}
    if j.get('signed_in'):
        return
    if os.path.exists('/home/tester/.local/share/hop/device.key'):
        hop('daemon', 'stop')
        time.sleep(1)
        root('cd /home/tester && for d in .local/share/hop .local/state/hop .ssh/hop; do [ -e "$d" ] && mv "$d" "$d.old-$(date +%s)"; done; true')
    step_pwlogin(name)


def step_cf_setup():
    for n in ('cf1', 'cf2', 'cf3'):
        hop('add', n, '--address', '10.9.8.%s' % n[-1], '--user', 'target', '--tag', 'conflict')


def step_wait_host(name, secs='60'):
    got, t = L.wait_for(lambda: name in (L.hosts() or {}), float(secs), 0.5)
    L.log('wait-host', name, bool(got), '%.1fs' % t)


def step_cf_edit(side):
    if side == 'A':
        edits = [('cf1', '--user', 'uA'), ('cf2', '--port', '2201'), ('cf3', '--description', 'fromA')]
    else:
        edits = [('cf1', '--user', 'uB'), ('cf2', '--user', 'uB'), ('cf3', '--description', 'fromB')]
    bad = [e for e in edits if hop('edit', *e).rc != 0]
    c('%s.cf-edit' % M, 'concurrent edits on %s are accepted locally' % side, not bad, 'failed: %s' % bad)


def step_names():
    L.state_put('hosts-A.json', sorted(L.hosts() or {}))


STEPS = {
    'server-check': step_server_check, 'seed': step_seed, 'signup': step_signup, 'b-refusals': step_b_refusals,
    'b-login-approve': step_b_login_approve, 'a-approve-start': step_a_approve_start, 'a-approve-sas': step_a_approve_sas,
    'b-received': step_b_received, 'offline-start': step_offline_start, 'offline-end': step_offline_end,
    'block': step_block, 'conflict-check': step_conflict_check, 'converge': step_converge, 'usebkey': step_usebkey,
    'daemon-stop': step_daemon_stop, 'after-restart': step_after_restart, 'after-reboot': step_after_reboot,
    'service-setup': step_service_setup, 'after-reboot-service': step_after_reboot_service, 'devices': step_devices,
    'logout': step_logout, 'a-after-logout': step_a_after_logout, 'pwlogin': step_pwlogin,
    'ensure-a': step_ensure_a, 'ensure-b': step_ensure_b, 'names': step_names,
    'cf-setup': step_cf_setup, 'wait-host': step_wait_host, 'cf-edit': step_cf_edit,
}

if __name__ == '__main__':
    name = sys.argv[1]
    L.guard('%s.%s' % (M, name), name)(STEPS[name])(*sys.argv[2:])
    L.done()
