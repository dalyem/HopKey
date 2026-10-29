#!/usr/bin/env python3
"""Phase 6: hop key rotate against real sshd (the sandboxes' stock Ubuntu sshd
and CLI-B's), driven from CLI-A; B checks that it follows with nothing done.

One key, rotkey, is used by six host records:
  r-t1   T1 deploy, line "restrict <key>"            rotated (restrict carried over and enforced)
  r-t1b  T1 deploy again, by MagicDNS name            already-rotated (same account as r-t1)
  r-t2   T2 deploy                                    rotated
  r-t2in deploy2 on T2's loopback sshd, jump host t2  rotated
  r-t3   T3 deploy; T3's sshd takes only the lines    failed and put back
         it had before the rotation (AuthorizedKeysCommand on a snapshot; the hook logs
         each offered key's fingerprint and whether the live file holds it, so the
         rollback is proven: new key installed, offered, refused, file put back)
  rb     CLI-B user rot, line 'from="<A>" <key>'      rotated; from= carried over, so B is refused
A second key, rotkey2, is on r-cc (T1 deploy2) for the concurrent-edit check:
T1 appends tagged lines on a coordinated start while A rotates, and judge-cc
proves on one clock (T1's, mapped to A's with a measured offset) that appends
landed inside the rotation, then compares the exact tagged lines.

Steps: supported | keys | b-target <a-ip> | hosts | b-wait | dry-run | rotate |
       judge <before-suffix> <after-suffix> <label> | judge-rollback | after-a | after-b |
       cc <round> <start-epoch> | judge-cc <round> <appended> <interval>
The driver copies the targets' authorized_keys (public data), T3's hook log and
T1's append log to /var/e2e/state/ak/ before each judge step.
"""
import json
import os
import pwd
import re
import sys
import time

import e2elib as L
from e2elib import check as c, has, hop, root, ssh, skip

M = L.MACHINE
E = L.env_get
AK = L.STATE + '/ak'
KEY, KEY2 = 'rotkey', 'rotkey2'
# host -> (address, port, user, jump, target file the driver copies)
HOSTS = {
    'r-t1': (E('HK_T1_IP'), 22, 'deploy', None, 't1-deploy'),
    'r-t1b': (E('HK_T1_FQDN'), 22, 'deploy', None, 't1-deploy'),
    'r-t2': (E('HK_T2_IP'), 22, 'deploy', None, 't2-deploy'),
    'r-t2in': ('127.0.0.1', 2222, 'deploy2', 't2', 't2-deploy2'),
    'r-t3': (E('HK_T3_IP'), 22, 'deploy', None, 't3-deploy'),
    'rb': (E('HK_B_IP'), 22, 'rot', None, 'b-rot'),
}
ROTATED = ('r-t1', 'r-t2', 'r-t2in', 'rb')  # hosts whose authorized_keys is edited
TARGETS = {'t1-deploy': 'rotated', 't2-deploy': 'rotated', 't2-deploy2': 'rotated', 'b-rot': 'rotated', 't3-deploy': 'put-back'}
KEYRX = re.compile(r'(?:^|\s)((?:ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+|sk-\S+)\s+(AAAA[A-Za-z0-9+/=]+))')


def keys():
    """The vault's keys by name, or None when hop key ls --json gave no valid answer."""
    j = hop('key', 'ls', '--json').json()
    if not isinstance(j, list):
        return None
    return {k.get('name'): k for k in j if isinstance(k, dict)}


def key_of(hs, name):
    """The key name a host record points at (hop ls --json)."""
    return ((hs or {}).get(name) or {}).get('key') and hs[name]['key'].get('name')


def blob(pub):
    """The base64 part of a public key line."""
    m = KEYRX.search(pub or '')
    return m.group(2) if m else ''


def split_line(line):
    """(options, base64) of an authorized_keys line, or None for a comment or blank line."""
    if not line.strip() or line.lstrip().startswith('#'):
        return None
    m = KEYRX.search(line)
    if not m:
        return None
    return line[:m.start(1)].strip(), m.group(2)


def rotate(*args, timeout=600):
    r = hop('key', 'rotate', '--yes', '--json', *args, timeout=timeout)
    j = r.json()
    return r, j if isinstance(j, dict) else None


def host_rows(j, key):
    for k in (j or {}).get('keys') or []:
        if k.get('key') == key:
            return k, {h.get('host'): h for h in k.get('hosts') or []}
    return None, {}


HOPCFG = '/home/tester/.ssh/hop/config'


def pssh(host, cmd, extra=(), timeout=40):
    """Plain OpenSSH on hop's generated config (a phase-6-only run never ran hop setup, so ~/.ssh/config may not include it)."""
    return ssh(host, cmd, timeout=timeout, extra=['-F', HOPCFG] + list(extra))


def old_key_ssh(host, cmd):
    """ssh offering only the old key's file (no agent), on hop's generated config for the address and jump host."""
    return pssh(host, cmd, ['-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes', '-i', '/home/tester/' + KEY])


def refused(r):
    """sshd refused the login, as opposed to any other failure (a name that does not resolve, a timeout)."""
    return 'Permission denied' in r.all


def step_supported():
    """rot-supported: yes (the help of hop key rotate), no (only the exact refusal of a
    build without it: exit 255, unknown key subcommand "rotate"), or error: anything
    else is a failed detection, a harness failure, never a skip."""
    r = hop('key', 'rotate', '--help', timeout=20)
    label = 'this build has hop key rotate'
    if r.rc == 0 and has(r.all, 'usage: hop key rotate', '-dry-run', '-new-key'):
        L.state_put('rot-supported', 'yes')
    elif r.rc == 255 and 'unknown key subcommand "rotate"' in r.err:
        L.state_put('rot-supported', 'no')
        skip('A.rot-supported', label, 'confirmed absent: ' + L.cut(r.all.strip(), 200))
    else:
        L.state_put('rot-supported', 'error')
        L.harness('A.rot-supported', label, 'detection failed: neither the help of hop key rotate nor the refusal of a build without it',
                  r.ev('hop key rotate --help'))


def step_keys():
    for name in (KEY, KEY2):
        p = '/home/tester/' + name
        root('rm -f %s %s.pub' % (p, p))
        L.run_as('tester', ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'hk-e2e-' + name, '-f', p], 30)
        ks = keys() or {}
        if name in ks:
            hop('key', 'rm', name, '--yes')
        r = hop('key', 'add', p, '--name', name)
        root('cp %s.pub %s/%s.pub && chmod 644 %s/%s.pub' % (p, L.STATE, name, L.STATE, name))
        if r.rc != 0:
            L.harness('A.rot-keys', 'the rotation keys go into A\'s vault', 'hop key add %s failed' % name, r.ev('key add'))


def step_b_target(a_ip):
    """On B, as root: user rot, whose authorized_keys allows rotkey only from A's tailnet address."""
    L.ensure_user('rot', linger=False)
    root('usermod -p "*" rot')
    pub = open(L.STATE + '/rotkey.pub').read().split()
    other = open('/home/tester/testkey.pub').read().split()
    lines = ['# hk-e2e rotation target on CLI-B: the from= line must survive',
             'from="%s" %s %s hk-e2e-rot-b' % (a_ip, pub[0], pub[1]),
             '%s %s hk-e2e-other-line' % (other[0], other[1])]
    root('install -d -m 700 -o rot -g rot /home/rot/.ssh')
    with open('/home/rot/.ssh/authorized_keys', 'w') as f:
        f.write('\n'.join(lines) + '\n')
    root('chown rot: /home/rot/.ssh/authorized_keys; chmod 600 /home/rot/.ssh/authorized_keys; '
         'install -m 644 /home/rot/.ssh/authorized_keys %s/b-rot.ak' % L.STATE)


def step_hosts():
    L.ensure_include()
    L.ensure_testkey()
    hs = L.hosts() or {}
    if 't2' not in hs:
        hop('add', 't2', '--address', E('HK_T2_FQDN'), '--user', 'deploy', '--key', 'testkey', '--tag', 'ts')
        hop('trust', 't2', '--yes', timeout=60)
    hs = L.hosts() or {}
    for name, (addr, port, user, jump, _) in HOSTS.items():
        if name in hs:
            hop('rm', name, '--yes')
        args = ['add', name, '--address', addr, '--port', port, '--user', user, '--key', KEY, '--tag', 'rot']
        if jump:
            args += ['--jump', jump]
        hop(*args)
        if jump:
            k = open(L.STATE + '/t2-internal.pub').read().split()
            hop('edit', name, '--host-key', '%s %s' % (k[0], k[1]))
        else:
            hop('trust', name, '--yes', timeout=60)
    if 'r-cc' in hs:
        hop('rm', 'r-cc', '--yes')
    hop('add', 'r-cc', '--address', E('HK_T1_IP'), '--user', 'deploy2', '--key', KEY2, '--tag', 'rot')
    hop('trust', 'r-cc', '--yes', timeout=60)
    bad = []
    for name in list(HOSTS) + ['r-cc']:
        r = hop('exec', name, '--', 'echo', 'rot-before-ok', timeout=60)
        if 'rot-before-ok' not in r.out:
            bad.append(r.ev('exec ' + name))
    if bad:
        L.harness('A.rot-before', 'before the rotation, A logs in to every rotation host with the old key', '%d hosts fail' % len(bad), '\n'.join(bad))
    else:
        c('A.rot-before', 'before the rotation, A logs in to every rotation host with the old key', True, 'hosts %s' % (list(HOSTS) + ['r-cc']))
    r = old_key_ssh('r-t3', 'echo old-file-ok')
    L.log('old-key control', r.ev('ssh -i rotkey r-t3'))
    if 'old-file-ok' not in r.out:
        # The "old key refused" checks use this method: it must work while the key is valid.
        L.harness('A.rot-oldfile', 'ssh offering only the old key file logs in before the rotation (control)', 'it did not', r.ev('ssh -i rotkey r-t3'))
    ks = keys() or {}
    L.state_put('rot-keys-before', sorted(ks))


def step_b_wait():
    L.ensure_include()
    want = set(HOSTS)
    got, secs = L.wait_for(lambda: want <= {n for n, h in (L.hosts() or {}).items() if h.get('host_keys')}, 90, 1)
    if not got:
        return L.harness('B.rot-synced', 'B has every rotation host, pinned', 'have: %s' % sorted(L.hosts() or {}))
    r = hop('exec', 'r-t2', '--', 'echo', 'b-before-ok', timeout=60)
    r2 = hop('exec', 'rb', '--', 'echo', 'b-rb-SHOULD-FAIL', timeout=60)
    ok = 'b-before-ok' in r.out and 'b-rb-SHOULD-FAIL' not in r2.out and refused(r2)
    detail, ev = 'r-t2 rc %d; rb rc %d' % (r.rc, r2.rc), r.ev('exec r-t2') + '\n' + r2.ev('exec rb')
    label = 'before the rotation: B logs in to r-t2, and the from= line on rb refuses B'
    # The control for rot-from-new: sshd on B already refuses B on the from= line with the old key.
    if ok:
        c('B.rot-from-control', label, True, detail, ev)
    else:
        L.harness('B.rot-from-control', label, detail, ev)


def step_dry_run():
    before = keys()
    r, j = rotate('--dry-run', KEY)
    after = keys()
    k, rows = host_rows(j, KEY)
    planned = sorted(n for n, h in rows.items() if h.get('status') == 'planned')
    c('A.rot-dryrun-plan', 'hop key rotate --dry-run plans all six hosts that use the key', r.rc == 0 and bool(j) and j.get('dry_run') is True
      and planned == sorted(HOSTS), 'rc %d, planned %s, others %s' % (r.rc, planned, {n: h.get('status') for n, h in rows.items() if n not in planned}),
      r.ev('key rotate --dry-run'))
    c('A.rot-dryrun-vault', '--dry-run adds no key to the vault and changes no host record', before is not None and before == after
      and all(key_of(L.hosts(), n) == KEY for n in HOSTS),
      'keys before %s, after %s' % (sorted(before or {}), sorted(after or {})))


def step_rotate():
    t0 = time.time()
    r, j = rotate(KEY)
    L.state_put('rot-result.json', {'rc': r.rc, 'secs': time.time() - t0, 'json': j})
    k, rows = host_rows(j, KEY)
    if not k:
        return L.harness('A.rot-run', 'hop key rotate --json reports on the key', 'no report for %s' % KEY, r.ev('key rotate'))
    st = {n: rows.get(n, {}).get('status') for n in HOSTS}
    L.log('rotation statuses', st)
    newname = k.get('new_key') or ''
    ks = keys() or {}
    newpub = (ks.get(newname) or {}).get('public_key') or ''
    L.state_put('rot-newname', newname)
    L.state_put('rot-newpub', newpub)
    for n in ROTATED:
        c('A.rot-status-' + n, '%s is rotated' % n, st[n] == 'rotated', 'status %s: %s' % (st[n], rows.get(n, {}).get('reason', '')))
    c('A.rot-already', 'r-t1b, a second record of the account r-t1 rotated, is already-rotated', st['r-t1'] == 'rotated' and st['r-t1b'] == 'already-rotated',
      'r-t1 %s, r-t1b %s: %s' % (st['r-t1'], st['r-t1b'], rows.get('r-t1b', {}).get('reason', '')))
    t3 = rows.get('r-t3', {})
    c('A.rot-rollback-status', 'r-t3, whose sshd refuses the new key, fails and is put back (remote_state unchanged)',
      t3.get('status') == 'failed' and t3.get('remote_state') == 'unchanged', 'status %s, remote_state %s: %s' % (
          t3.get('status'), t3.get('remote_state'), t3.get('reason', '')))
    reason = t3.get('reason') or ''
    c('A.rot-rollback-stage', 'r-t3 fails at the login with the new key (README step 3), and the report says it was put back',
      'the new key did not log in' in reason and 'Permission denied' in reason and 'put back' in reason, 'reason: %s' % reason)
    c('A.rot-exit', 'hop key rotate exits non-zero because a host failed', r.rc != 0 and j.get('ok') is False, 'rc %d, ok %s' % (r.rc, j.get('ok')))
    hs = L.hosts() or {}
    point = {n: key_of(hs, n) for n in HOSTS}
    want = {n: (KEY if n == 'r-t3' else newname) for n in HOSTS}
    c('A.rot-records', 'the rotated hosts point at the new key, r-t3 keeps the old one', bool(newname) and point == want, 'records %s' % point)
    c('A.rot-oldkept', 'the old key stays in the vault while r-t3 uses it', KEY in ks and k.get('old_key') == 'kept',
      'old_key %s (%s)' % (k.get('old_key'), k.get('old_key_reason')))
    c('A.rot-newkey', 'the new key is in the vault, of the old key\'s type', bool(newpub) and (ks.get(newname) or {}).get('key_type') == (ks.get(KEY) or {}).get('key_type'),
      'new key %s, type %s' % (newname, (ks.get(newname) or {}).get('key_type')))


def judge_file(name, before, after, oldb, newb, mode):
    """mode rotated: every old-key line replaced by a new-key line with the same options, everything else byte-identical.
    mode put-back / unchanged: byte-identical."""
    if mode != 'rotated':
        return before == after, 'byte-identical' if before == after else 'changed: %d -> %d bytes' % (len(before), len(after))
    bl, al = before.split('\n'), after.split('\n')
    old_lines = [l for l in bl if (split_line(l) or ('', ''))[1] == oldb]
    new_lines = [l for l in al if (split_line(l) or ('', ''))[1] == newb]
    rest_b = [l for l in bl if l not in old_lines]
    rest_a = [l for l in al if l not in new_lines]
    problems = []
    if not old_lines:
        problems.append('no old-key line before (fixture)')
    if any((split_line(l) or ('', ''))[1] == oldb for l in al):
        problems.append('an old-key line is still there')
    if sorted(split_line(l)[0] for l in old_lines) != sorted(split_line(l)[0] for l in new_lines):
        problems.append('options before %s, after %s' % ([split_line(l)[0] for l in old_lines], [split_line(l)[0] for l in new_lines]))
    if rest_b != rest_a:
        problems.append('other lines differ: before %s, after %s' % (rest_b, rest_a))
    return not problems, '; '.join(problems) or '%d line(s) replaced, options %s, %d other lines byte-identical' % (
        len(new_lines), [split_line(l)[0] for l in new_lines], len([l for l in rest_b if l]))


def step_judge(bsuf, asuf, label):
    oldb = blob(open(L.STATE + '/rotkey.pub').read())
    newb = blob(L.state_get('rot-newpub', '') or '')
    for name, mode in sorted(TARGETS.items()):
        try:
            before = open('%s/%s.%s' % (AK, name, bsuf)).read()
            after = open('%s/%s.%s' % (AK, name, asuf)).read()
        except OSError as e:
            L.harness('A.rot-%s-%s' % (label, name), '%s: %s is as expected' % (label, name), 'no copy of the file: %s' % e)
            continue
        if label == 'dryrun':
            ok, why = judge_file(name, before, after, oldb, newb, 'unchanged')
            c('A.rot-dryrun-%s' % name, '--dry-run leaves %s\'s authorized_keys byte-identical' % name, ok, why)
        elif mode == 'rotated':
            if not newb:
                L.harness('A.rot-ak-%s' % name, '%s holds the new key with the old line\'s options' % name, 'the new public key is unknown')
                continue
            ok, why = judge_file(name, before, after, oldb, newb, mode)
            c('A.rot-ak-%s' % name, '%s: the old key\'s line is replaced by the new key with the same options; every other line is byte-identical' % name, ok, why,
              after)
        else:
            ok, why = judge_file(name, before, after, oldb, newb, mode)
            c('A.rot-rollback-%s' % name, '%s, where the new key was refused, is put back byte-identical' % name, ok, why, after)


def step_after_a():
    hs = L.hosts() or {}
    bad, good = [], []
    for n in ROTATED + ('r-t1b',):
        r = hop('exec', n, '--', 'echo', 'rot-new-ok', timeout=60)
        r2 = pssh(n, 'echo rot-plain-ok')
        (good if 'rot-new-ok' in r.out and 'rot-plain-ok' in r2.out else bad).append(n)
        if n in bad:
            L.log('after-a', n, r.ev('exec'), r2.ev('ssh'))
    c('A.rot-new-works', 'after the rotation, hop exec and plain ssh log in to every rotated host (with the new key)', not bad, 'failed: %s' % bad)
    let_in, other = [], []
    for n in ROTATED:
        r = old_key_ssh(n, 'echo old-SHOULD-FAIL')
        if 'old-SHOULD-FAIL' in r.out:
            let_in.append(n)
        elif not refused(r):
            other.append(r.ev('ssh -i old ' + n))
    r3 = old_key_ssh('r-t3', 'echo old-still-ok')
    label = 'the old key alone is refused on every rotated host (and still works on r-t3, which was put back)'
    if 'old-still-ok' not in r3.out:
        L.harness('A.rot-old-refused', label, 'control: the old key no longer logs in to r-t3 either', r3.ev('ssh -i old r-t3'))
    elif other:
        L.harness('A.rot-old-refused', label, 'a login failed for another reason than sshd refusing the key', '\n'.join(other))
    else:
        c('A.rot-old-refused', label, not let_in, 'still let in: %s' % let_in)
    r = hop('exec', 'r-t3', '--', 'echo', 'rot-t3-ok', timeout=60)
    c('A.rot-rollback-works', 'r-t3 keeps working with the old key after the failed rotation', 'rot-t3-ok' in r.out, '', r.ev('exec r-t3'))
    # restrict means no-pty: sshd answers the pty request that -tt insists on with a failure, and the client
    # says "PTY allocation request failed". The control is r-t2, whose line has no options: its pty request
    # is not refused (gVisor sandboxes cannot then give it a pty, and close the session; that is not a refusal).
    r = pssh('r-t1', 'tty', ['-tt'])
    r2 = pssh('r-t2', 'tty', ['-tt'])
    label = 'the restrict option on r-t1\'s new line is enforced by sshd: its pty request is refused (r-t2, with no options, is not refused)'
    if 'PTY allocation request failed' in r2.all or 'Permission denied' in r2.all:
        L.harness('A.rot-restrict', label, 'control: r-t2\'s pty request was refused too', r2.ev('ssh -tt r-t2 tty'))
    else:
        c('A.rot-restrict', label, 'PTY allocation request failed' in r.all and '/dev/pts/' not in r.out, '',
          r.ev('ssh -tt r-t1 tty') + '\n' + r2.ev('ssh -tt r-t2 tty'))


def step_after_b():
    newname = L.state_get('rot-newname', '')
    newb = blob(L.state_get('rot-newpub', '') or '')
    got, secs = L.wait_for(lambda: all(key_of(L.hosts(), n) == newname for n in ROTATED), 60, 1)
    c('B.rot-records', 'B\'s records of the rotated hosts point at the new key, with nothing done on B', bool(newname) and bool(got),
      'after %.0fs: %s' % (secs, {n: key_of(L.hosts(), n) for n in ROTATED}))
    agent = L.run_as('tester', ['ssh-add', '-L'], 15, env={'SSH_AUTH_SOCK': '/run/user/%d/hop/agent.sock' % pwd.getpwnam('tester').pw_uid})
    pst, pv = L.agent_probe()
    if pst == 'error':
        L.harness('B.rot-agent', 'B\'s agent serves the new key', 'the agent probe failed: %s' % pv)
    else:
        c('B.rot-agent', 'B\'s agent serves the new key', bool(newb) and newb in agent.out, '%s, %s keys' % (pst, pv))
    bad = []
    for n in ('r-t1', 'r-t2', 'r-t2in'):
        r = hop('exec', n, '--', 'echo', 'b-new-ok', timeout=60)
        r2 = pssh(n, 'echo b-plain-ok')
        if 'b-new-ok' not in r.out or 'b-plain-ok' not in r2.out:
            bad.append(n)
            L.log('after-b', n, r.ev('exec'), r2.ev('ssh'))
    c('B.rot-uses-new', 'B logs in to the rotated hosts (hop exec and plain ssh) after the rotation on A', not bad, 'failed: %s' % bad)
    r = hop('exec', 'rb', '--', 'echo', 'b-rb-SHOULD-FAIL', timeout=60)
    c('B.rot-from-new', 'the from= option, carried to the new key, keeps B out of rb (A gets in with the same key)',
      'b-rb-SHOULD-FAIL' not in r.out and refused(r), '', r.ev('exec rb'))


HOOK_RX = re.compile(r'^(?P<t>[0-9.]+) user=(?P<user>\S+) fp=(?P<fp>\S+) live_has=(?P<live>[01]) snap_has=(?P<snap>[01]) live_sum=(?P<sum>\S*)$')


def step_judge_rollback():
    """T3's AuthorizedKeysCommand logged every key sshd was offered for deploy, whether
    the live authorized_keys held it then, and whether the snapshot sshd answers with
    did. A real rollback shows the new key offered while installed in the live file,
    refused (not in the snapshot), and the file byte-identical afterwards."""
    cid, label = 'A.rot-rollback-proof', ('r-t3: the new key was installed, offered and refused by sshd while installed, '
                                          'and the file was put back after that probe')
    res = (L.state_get('rot-result.json', {}) or {}).get('json') or {}
    k, rows = host_rows(res, KEY)
    newfp = (k or {}).get('new_fingerprint') or ''
    oldfp = (k or {}).get('fingerprint') or ''
    newb = blob(L.state_get('rot-newpub', '') or '')
    try:
        lines = open(AK + '/t3-hook.log').read().splitlines()
        after = open(AK + '/t3-deploy.after').read()
    except OSError as e:
        return L.harness(cid, label, 'no copy of the hook log or the file: %s' % e)
    ents = [m.groupdict() for m in map(HOOK_RX.match, lines) if m]
    if not ents or len(ents) != len([l for l in lines if l.strip()]) or not newfp or not oldfp or not newb:
        return L.harness(cid, label, 'instrumentation: %d hook lines, %d parsed; new fingerprint %r, old %r, new key known: %s' % (
            len(lines), len(ents), newfp, oldfp, bool(newb)), L.cut('\n'.join(lines[-10:]), 800))
    olds = [e for e in ents if e['fp'] == oldfp]
    if not any(e['snap'] == '1' for e in olds):
        # The control: the hook saw the old key that logs in, and answered with it.
        return L.harness(cid, label, 'control: the hook never saw the old key offered and accepted', L.cut('\n'.join(lines[-10:]), 800))
    probes = [e for e in ents if e['fp'] == newfp]
    installed = [e for e in probes if e['live'] == '1' and e['snap'] == '0']
    restored = newb not in after
    c(cid, label, bool(installed) and restored,
      'new key offered %d times, %d while installed in the live file and absent from the snapshot sshd uses; after the run the file %s the new key' % (
          len(probes), len(installed), 'lacks' if restored else 'still holds'), L.cut('\n'.join(lines[-12:]), 1000))


# hop key rotate's reason when authorized_keys changed under its edit, and the endings of a
# failure that left the host as it was (internal/cli/cmd_keyrotate.go, cmd_keyrotate_ak.go).
EDIT_CONFLICT = '~/.ssh/authorized_keys changed while hop was editing it'
SAFE_ENDS = ('; nothing was changed', '; put back as it was, and it keeps the old key')


def step_cc(rnd, start):
    """Rotate whatever key r-cc uses now, starting at start + 2 s on A's clock: the
    appender on T1 starts at start on its own, so the rotation runs among its writes."""
    hs = L.hosts() or {}
    key = key_of(hs, 'r-cc')
    old = ((keys() or {}).get(key) or {}).get('public_key', '')
    while time.time() < float(start) + 2:
        time.sleep(0.05)
    t0 = time.time()
    r, j = rotate(key, timeout=300)
    t1 = time.time()
    k, rows = host_rows(j, key)
    h = rows.get('r-cc', {})
    L.state_put('rot-cc-%s.json' % rnd, {'rc': r.rc, 't0': t0, 't1': t1, 'key': key, 'old': old, 'status': h.get('status'),
                                         'remote_state': h.get('remote_state'), 'reason': h.get('reason'),
                                         'new': ((keys() or {}).get((k or {}).get('new_key') or '') or {}).get('public_key', '')})


def step_judge_cc(rnd, manual, interval):
    """Every line T1 appended (counter n, T1's time) must be in the file exactly once,
    at least one append must have landed inside the rotation (on A's clock, with the
    measured T1-A offset and its uncertainty), and the host must end rotated or put back."""
    cid, label = 'A.rot-concurrent-%s' % rnd, 'lines appended every %ss during a rotation are all kept, and the host ends rotated or put back' % interval
    st = L.state_get('rot-cc-%s.json' % rnd, {}) or {}
    try:
        manual = int(manual)
        before = open('%s/t1-deploy2.cc-%s-before' % (AK, rnd)).read()
        after = open('%s/t1-deploy2.cc-%s-after' % (AK, rnd)).read()
        alog = open('%s/t1-append-%s.log' % (AK, rnd)).read().split()
        bk = open(L.STATE + '/bkey.pub').read().split()
    except (OSError, ValueError) as e:
        return L.harness(cid, label, 'no copy of the files: %s' % e)
    clk = L.state_get('t1clock-%s' % rnd) or {}
    if manual <= 0:
        return L.harness(cid, label, 'the appender on T1 wrote nothing: nothing to judge')
    if not isinstance(clk, dict) or not isinstance(clk.get('offset'), (int, float)):
        return L.harness(cid, label, 'no T1-A clock offset measured: %r' % clk)
    ts = {}
    for i in range(0, len(alog) - 1, 2):
        try:
            ts[int(alog[i])] = float(alog[i + 1])
        except ValueError:
            pass
    if sorted(ts) != list(range(1, manual + 1)):
        return L.harness(cid, label, 'the append log does not hold appends 1..%d: %s' % (manual, sorted(ts)[:12]))
    if not isinstance(st.get('t0'), (int, float)) or not isinstance(st.get('t1'), (int, float)):
        return L.harness(cid, label, 'no rotation window recorded', L.cut(json.dumps(st), 300))
    off, unc = clk['offset'], clk.get('rtt', 0) / 2 + 0.05
    t0, t1 = st['t0'], st['t1']
    on_a = {n: t - off for n, t in ts.items()}  # T1 minus A: T1's times on A's clock
    during = sorted(n for n, t in on_a.items() if t0 + unc <= t <= t1 - unc)
    window = 'rotation %.2fs on A; appends from %+.2fs to %+.2fs of its start (T1-A offset %.3fs +- %.3fs)' % (
        t1 - t0, min(on_a.values()) - t0, max(on_a.values()) - t0, off, unc)
    if not during:
        return L.harness(cid, label, 'no append landed inside the rotation, so it proves nothing: ' + window)
    lines = after.split('\n')
    tag = 'hk-e2e-manual-%s-' % rnd
    want = ['%s %s %s%d' % (bk[0], bk[1], tag, n) for n in range(1, manual + 1)]
    counts = {w: lines.count(w) for w in want}
    wrong = {w.rsplit(' ', 1)[1]: n for w, n in counts.items() if n != 1}
    extra = [l for l in lines if tag in l and l not in want]
    oldb, newb = blob(st.get('old') or ''), blob(st.get('new') or '')
    others_b = [l for l in before.split('\n') if split_line(l) is None or split_line(l)[1] != oldb]
    has_old = any((split_line(l) or ('', ''))[1] == oldb for l in lines)
    has_new = bool(newb) and any((split_line(l) or ('', ''))[1] == newb for l in lines)
    lost = [l for l in others_b if l and l not in lines]
    status, rstate, reason = st.get('status'), st.get('remote_state'), st.get('reason') or ''
    # The rotation must have reached the edit: rotated through it, or stopped by hop's own
    # conflict check on authorized_keys and left with the old key. Any other failure (ssh
    # auth, a step before the edit) leaves the file alone and proves nothing about appends.
    if status == 'rotated':
        exercised = rstate == 'old_key_removed'
    elif status == 'failed':
        exercised = rstate == 'unchanged' and EDIT_CONFLICT in reason and reason.endswith(SAFE_ENDS)
    else:
        exercised = False
    consistent = (status == 'rotated' and has_new and not has_old) or (status == 'failed' and has_old and not has_new)
    c(cid, label, not wrong and not extra and exercised and consistent and not lost,
      'rotation of %s %s (%s)%s; %d appends, %d inside the rotation (#%s); tagged lines not exactly once: %s; unexpected tagged lines: %d; '
      'earlier lines lost: %d; old key line %s, new key line %s; %s; %s' % (
          st.get('key'), status, rstate, '' if exercised else ' without reaching the edit or its conflict check', manual, len(during),
          ','.join(map(str, during[:10])), wrong or 'none', len(extra), len(lost), has_old, has_new, window, reason), after)


STEPS = {'supported': step_supported, 'keys': step_keys, 'b-target': step_b_target, 'hosts': step_hosts, 'b-wait': step_b_wait,
         'dry-run': step_dry_run, 'rotate': step_rotate, 'judge': step_judge, 'after-a': step_after_a, 'after-b': step_after_b,
         'cc': step_cc, 'judge-cc': step_judge_cc, 'judge-rollback': step_judge_rollback}

if __name__ == '__main__':
    os.makedirs(AK, exist_ok=True)
    name = sys.argv[1]
    L.guard('%s.%s' % (M, name), name)(STEPS[name])(*sys.argv[2:])
    L.done()
