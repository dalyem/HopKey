#!/usr/bin/env python3
"""Phase 1: local only, no account. Runs on both CLI VMs.

Steps: main | before-reboot | after-reboot
"""
import json
import os
import re
import sys
import time

import e2elib as L
from e2elib import check, hop, has, root, ssh, skip

M = L.MACHINE


def c(cid, *a, **kw):
    return check('%s.%s' % (M, cid), *a, **kw)


def step_init():
    r = hop('init', '--device-key-store', 'file')  # stdin is /dev/null: no terminal
    c('init.notty', 'hop init without a terminal fails with the "needs a terminal" message',
      r.rc == 255 and 'terminal' in r.all and 'inappropriate ioctl' not in r.all,
      'expected exit 255 naming the missing terminal; a raw ioctl error is r1-P3-4', r.ev('hop init </dev/null'), 'r1-P3-4')

    rc, out = L.init_vault()
    c('init.pty', 'hop init --device-key-store file through a pty (sealed with HOP_DEVICE_PASSPHRASE)',
      rc == 0 and bool(L.kit()[0]) and os.path.exists('/home/tester/.local/share/hop/device.key'),
      'exit %d, kit captured to a 0600 file: %s' % (rc, bool(L.kit()[0])), out[-600:])
    hop('ls')  # hop status does not start the daemon (r2-P3-7); ls does
    r = hop('status')
    c('init.sealed', 'hop status reports the device key as file (sealed)', has(r.out, 'file (sealed)'), '', r.ev('hop status'))

    # The kit must not be on disk in the sealed device key, and must be in an unsealed one.
    rc2, out2 = L.init_vault(user='tester2', nopass=True, kitname='kit-tester2')
    hop('ls', user='tester2', nopass=True)
    r2 = hop('status', user='tester2', nopass=True)
    sk2 = [l.split('=', 1)[1] for l in L.sec_read('kit-tester2').splitlines() if l.startswith('SECRET_KEY=')]
    sk = L.kit()[0]
    dk2 = '/home/tester2/.local/share/hop/device.key'
    in_unsealed = bool(sk2) and os.path.exists(dk2) and sk2[0] in open(dk2).read()
    in_sealed = bool(sk) and sk in open('/home/tester/.local/share/hop/device.key').read()
    c('init.unsealed', 'hop init without a passphrase warns and keeps an unsealed file store',
      rc2 == 0 and has(r2.out, 'unsealed') and ('unsealed' in out2.lower() or 'warn' in out2.lower()),
      'status: %s' % [l for l in r2.out.splitlines() if 'device key' in l], out2[-400:])
    c('init.sk-on-disk', 'the Secret Key is in the unsealed device.key and absent from the sealed one',
      bool(sk) and in_unsealed and not in_sealed, 'kit captured: %s, unsealed has it: %s, sealed has it: %s' % (bool(sk), in_unsealed, in_sealed))
    hop('daemon', 'stop', user='tester2', nopass=True)


def step_keys_hosts():
    r = hop('key', 'add', '/home/tester/testkey', '--name', 'testkey')
    c('key.add', 'hop key add', r.rc == 0 and 'added key testkey' in r.out, '', r.ev('hop key add'))
    r = hop('key', 'ls', '--json')
    keys = r.json() or []
    c('key.ls', 'hop key ls --json lists testkey', any(k.get('name') == 'testkey' for k in keys), '', r.ev('hop key ls --json'))

    r1 = hop('add', 'local1', '--address', '127.0.0.1', '--user', 'target', '--key', 'testkey', '--tag', 'lab', '--tag', 'local', '--alias', 'l1')
    r2 = hop('add', 'local2', '--address', 'localhost', '--user', 'target', '--key', 'testkey', '--tag', 'lab', '--description', 'second local')
    c('host.add', 'hop add with tags, alias and description', r1.rc == 0 and r2.rc == 0, '', r1.ev('add local1') + '\n' + r2.ev('add local2'))
    r = hop('ls')
    c('ls.table', 'hop ls lists both hosts', has(r.out, 'local1', 'local2'), '', r.ev('hop ls'))
    r = hop('ls', 'lab', '--json')
    names = sorted(h['name'] for h in (r.json() or []))
    c('ls.tag', 'hop ls lab --json filters by tag', names == ['local1', 'local2'], 'got %s' % names)
    r = hop('ls', 'local', '--json')
    names = sorted(h['name'] for h in (r.json() or []))
    c('ls.tag2', 'hop ls local --json gives only the host tagged local', names == ['local1'], 'got %s' % names)
    r = hop('which', 'local1')
    c('which', 'hop which local1 explains the alias rule', r.rc == 0 and has(r.out, 'rule:', 'alias'), '', r.ev('hop which local1'))
    r = hop('which', 'l1', '--json')
    j = r.json() or {}
    c('which.json', 'hop which l1 --json matches local1 by alias', j.get('status') == 'matched' and (j.get('host') or {}).get('name') == 'local1',
      '', r.ev('hop which l1 --json'))
    r = hop('info', 'local1')
    c('info', 'hop info local1 shows no pinned key yet', r.rc == 0 and has(r.out, 'none pinned'), '', r.ev('hop info'))
    r = hop('info', 'local1', '--json')
    j = r.json() or {}
    c('info.json', 'hop info --json has the host fields', j.get('name') == 'local1' and j.get('user') == 'target' and j.get('aliases') == ['l1'], '', r.ev('hop info --json'))


def step_trust_exec():
    r = hop('check', 'local1')
    c('check.unpinned', 'hop check before trust fails at host_key_pinned and names hop trust',
      r.rc == 255 and has(r.out, '[fail] host_key_pinned', 'hop trust local1'), '', r.ev('hop check local1'))
    r = hop('exec', 'local1', '--', 'echo', 'SHOULD-NOT-RUN')
    c('exec.unpinned', 'hop exec on an unpinned host is refused', r.rc == 255 and 'SHOULD-NOT-RUN' not in r.out, '', r.ev('hop exec local1'))
    c('exec.unpinned-hint', 'the refusal names hop trust (as hop check and MCP do)', 'hop trust' in r.all,
      'ssh only prints "Host key verification failed" without a hop trust hint', r.ev('hop exec local1'), 'r1-P3-11')
    r = hop('trust', 'local1', '--yes')
    c('trust', 'hop trust --yes pins the key', r.rc == 0 and 'pinned' in r.out, '', r.ev('hop trust local1 --yes'))
    r = hop('check', 'local1')
    c('check.ok', 'hop check passes every step after trust', r.rc == 0 and '[fail]' not in r.out and has(r.out, '[pass] auth_ok'), '', r.ev('hop check local1'))
    r = hop('exec', 'local1', '--', 'sh', '-c', 'echo exec-ok-$(id -un)')
    c('exec.ok', 'hop exec runs the command', r.rc == 0 and 'exec-ok-target' in r.out, '', r.ev('hop exec'))
    r = hop('exec', 'local1', '--', 'sh', '-c', 'exit 7')
    c('exec.rc', 'hop exec passes the remote exit code through (7)', r.rc == 7, '', r.ev('exit 7'))
    r = hop('exec', 'local1', '--json', '--', 'sh', '-c', 'echo out; echo err >&2; exit 3')
    j = r.json() or {}
    c('exec.json', 'hop exec --json reports exit_code, stdout, stderr and exits 3',
      r.rc == 3 and j.get('exit_code') == 3 and j.get('stdout') == 'out\n' and j.get('stderr') == 'err\n', '', r.ev('exec --json'))
    r = hop('exec', 'local1', '--timeout', '2s', '--', 'sleep', '10')
    c('exec.timeout', 'hop exec --timeout 2s stops a long command', r.rc == 255 and 'timed out' in r.all and r.secs < 8, '', r.ev('--timeout 2s sleep 10'))
    rc, out = L.pty_run('tester', ['hop', 'local1'], [(r'\$ $', 'echo in-hop-shell-$(id -un); exit 3')], timeout=40)
    c('shell.pty', 'interactive hop <target> on a pty runs a shell; the exit code passes through',
      rc == 3 and 'in-hop-shell-target' in out, 'pty exit %d' % rc, out[-300:])


def step_import_setup():
    root('''install -d -m 700 -o tester -g tester /home/tester/.ssh; cat > /home/tester/.ssh/config <<'EOC'
Host imp1
  HostName 127.0.0.1
  User target
  IdentityFile ~/testkey
Host imp2 imp2alias
  HostName localhost
  User target
  Port 22
Host *
  ServerAliveInterval 30
EOC
chown tester: /home/tester/.ssh/config; chmod 600 /home/tester/.ssh/config''')
    r = hop('import', 'ssh-config', '--dry-run')
    c('import.confirm', 'hop import ssh-config without --yes and no terminal refuses', r.rc == 255 and '--yes' in r.all, '', r.ev('import --dry-run'))
    r = hop('import', 'ssh-config', '--yes')
    hs = L.hosts() or {}
    c('import.yes', 'hop import ssh-config --yes imports imp1 and imp2', r.rc == 0 and 'imp1' in hs and 'imp2' in hs, '', r.ev('import --yes'))
    cfg = open('/home/tester/.ssh/hop/config').read() if os.path.exists('/home/tester/.ssh/hop/config') else ''
    # Absent from the config only counts if imp1 was imported and other hosts are written there.
    c('import.blocked', 'imported hosts without a vault key are kept out of the generated config',
      'imp1' in hs and re.search(r'^Host local1$', cfg, re.M) is not None and not re.search(r'^Host imp1$', cfg, re.M),
      'imp1 imported: %s, config lists local1: %s' % ('imp1' in hs, bool(re.search(r'^Host local1$', cfg, re.M))))
    hop('rm', 'imp1', '--yes'); hop('rm', 'imp2', '--yes')
    r = hop('import', 'ssh-config', '--with-keys', '--yes')
    hs = L.hosts() or {}
    c('import.with-keys', 'hop import ssh-config --with-keys attaches the IdentityFile key (deduped with testkey)',
      r.rc == 0 and ((hs.get('imp1') or {}).get('key') or {}).get('name') is not None, 'imp1 key: %s' % (hs.get('imp1') or {}).get('key'), r.ev('import --with-keys'))
    r = hop('key', 'ls', '--json')
    c('import.dedupe', 'the imported key is deduped with the existing one', len(r.json() or []) == 1, 'keys: %d' % len(r.json() or []))

    r = hop('setup', '--yes')
    head = [l for l in open('/home/tester/.ssh/config').read().splitlines() if l.strip() and not l.startswith('#')][:1]
    backups = [f for f in os.listdir('/home/tester/.ssh') if f.startswith('config.hop-backup')]
    c('setup', 'hop setup puts Include ~/.ssh/hop/config first and saves a backup',
      r.rc == 0 and head == ['Include ~/.ssh/hop/config'] and bool(backups), 'first directive: %s' % head, r.ev('hop setup --yes'))
    hop('trust', 'imp1', '--yes')
    r = ssh('local1', 'echo via-plain-ssh')
    c('ssh.plain', 'plain ssh local1 through the generated config', r.rc == 0 and 'via-plain-ssh' in r.out, '', r.ev('ssh local1'))
    r = ssh('local1', 'exit 5')
    c('ssh.rc', 'plain ssh passes the exit code through (5)', r.rc == 5, '', r.ev('ssh local1 exit 5'))
    r = ssh('imp1', 'echo imp1-ok')
    c('ssh.imported', 'plain ssh to the imported host imp1', r.rc == 0 and 'imp1-ok' in r.out, '', r.ev('ssh imp1'))


LINT_BAD = [
    ('bad_sq', "echo '{{x}}'"), ('bad_dq', 'echo "{{x}}"'), ('bad_eval', 'eval {{x}}'), ('bad_shc', 'sh -c {{x}}'),
    ('bad_bashc', 'bash -c {{x}}'), ('bad_assign', 'v={{x}}; echo $v'), ('bad_arith', 'echo $(( {{x}} + 1 ))'),
    ('bad_dbl', '[[ {{x}} -eq 1 ]] && echo y'), ('bad_name', 'echo {{a-b}}'),
]


def step_snippets():
    r = hop('snippet', 'add', 'greet', '--description', 'say hi', '--', 'echo hello {{name}}')
    c('snip.add', 'hop snippet add with a parameter', r.rc == 0 and 'parameters: name' in r.out, '', r.ev('snippet add greet'))
    hop('snippet', 'add', 'up', '--', 'uptime')
    hop('snippet', 'add', 'twoparam', '--', 'echo {{a}} and {{b}}')
    r = hop('snippet', 'ls', '--json')
    sn = {s['name']: s for s in (r.json() or [])}
    c('snip.ls', 'hop snippet ls --json lists names and parameters',
      sn.get('twoparam', {}).get('params') == ['a', 'b'] and 'up' in sn and 'greet' in sn, '', r.ev('snippet ls --json'))
    bad = []
    for name, cmd in LINT_BAD:
        r = hop('snippet', 'add', name, '--', cmd)
        if r.rc != 255:
            bad.append('%s rc=%d' % (name, r.rc))
    c('snip.lint', 'the lint refuses quoted, eval, sh -c, assignment, arithmetic, [[ ]] and bad-name placeholders (9 cases)',
      not bad, 'accepted: %s' % bad if bad else 'all 9 refused with exit 255')
    r = hop('snippet', 'add', 'ok_shc', '--', "sh -c 'echo \"$1\"' sh {{x}}")
    c('snip.lint-ok', 'the lint accepts a value passed as a positional parameter to sh -c', r.rc == 0, '', r.ev('ok_shc'))
    hop('snippet', 'add', 'tmp1', '--', 'echo', 'tmp')
    r = hop('snippet', 'rm', 'tmp1', '--yes')
    names = [s['name'] for s in (hop('snippet', 'ls', '--json').json() or [])]
    c('snip.rm', 'hop snippet rm', r.rc == 0 and 'tmp1' not in names, '', r.ev('snippet rm'))


def step_lock():
    r = hop('lock')
    c('lock', 'hop lock', r.rc == 0, '', r.ev('hop lock'))
    r1 = hop('exec', 'local1', '--', 'echo', 'SHOULD-NOT-RUN')
    r2 = ssh('local1', 'echo SHOULD-NOT-RUN')
    n = L.agent_keys()
    c('lock.effect', 'locked: hop exec and plain ssh fail, the agent holds no keys',
      r1.rc == 255 and 'SHOULD-NOT-RUN' not in r1.out and r2.rc != 0 and n == 0, 'agent keys: %d' % n, r1.ev('exec') + '\n' + r2.ev('ssh'))
    c('lock.msg', 'the locked error has no internal package prefix', 'lock' in r1.all.lower() and 'model:' not in r1.all,
      '' if 'lock' in r1.all.lower() else 'not judged: the refusal does not mention the lock', r1.ev('exec'), 'r1-P3-7')
    r = hop('unlock')
    r1 = hop('exec', 'local1', '--', 'echo', 'unlocked-ok')
    c('unlock', 'hop unlock opens the vault again', r.rc == 0 and 'unlocked-ok' in r1.out, '', r.ev('hop unlock') + '\n' + r1.ev('exec'))
    r = hop('status', '--json')
    j = r.json() or {}
    c('status.json', 'hop status --json reports an unlocked vault with a sealed file store',
      r.rc == 0 and (j.get('vault') or {}).get('locked') is False and 'file' in str((j.get('vault') or {}).get('device_key_store')),
      '', r.ev('status --json')[:600])
    # The README says every command takes --json.
    bad = []
    for args in (['lock', '--json'], ['unlock', '--json'], ['mcp', 'install', '--client', 'print', '--json']):
        r = hop(*args)
        if r.rc != 0 or r.json() is None:
            bad.append('%s rc=%d %s' % (' '.join(args), r.rc, r.all.strip()[:80]))
    hop('unlock')
    c('json.flag', 'lock, unlock and mcp install take --json (README: every command takes --json)', not bad, '; '.join(bad), '', 'r1-P3-3')


def step_daemon():
    p1 = L.daemon_pids()
    r = hop('daemon', 'stop')
    time.sleep(1)
    gone = not L.daemon_pids()
    r2 = hop('exec', 'local1', '--', 'echo', 'after-restart')
    p2 = L.daemon_pids()
    c('daemon.restart', 'hop daemon stop, then the next command starts a new daemon',
      r.rc == 0 and gone and 'after-restart' in r2.out and p2 and p2 != p1, 'pids %s -> %s' % (p1, p2), r2.ev('exec'))
    hop('daemon', 'stop'); time.sleep(1)
    r = hop('status')
    c('status.starts', 'hop status with no daemon running starts it (as other commands do)', r.rc == 0,
      'README: the first command that needs the daemon starts it', r.ev('hop status'), 'r2-P3-7')
    hop('daemon', 'stop'); time.sleep(1)
    # A daemon started without the passphrase comes up locked; hop unlock from a terminal must fix it.
    r = hop('ls', nopass=True)
    r1 = hop('unlock')
    r2 = hop('exec', 'local1', '--', 'echo', 'unlocked-after-nopass')
    c('unlock.nopass-daemon', 'hop unlock (with HOP_DEVICE_PASSPHRASE) unlocks a daemon started without it',
      r1.rc == 0 and 'unlocked-after-nopass' in r2.out, 'hop unlock sends no passphrase to the daemon', r1.ev('hop unlock'), 'r1-P2-1')
    hop('daemon', 'stop'); time.sleep(1)
    r = hop('exec', 'local1', '--', 'echo', 'recovered')
    if 'recovered' not in r.out:
        L.log('could not recover the daemon after the nopass test')
    r = hop('sync', '--json')
    msg = r.all
    c('sync.local-msg', 'hop sync on a local-only vault explains it once', r.rc == 255 and msg.count('local-only') <= 1, '', r.ev('hop sync --json'), 'r1-P3-14')


def step_hostkey():
    r0 = hop('exec', 'local1', '--', 'echo', 'before-rekey')
    root('rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null; systemctl restart ssh 2>/dev/null || systemctl restart ssh.socket; sleep 1')
    r1 = hop('exec', 'local1', '--', 'echo', 'SHOULD-NOT-PRINT')
    r2 = ssh('local1', 'echo SHOULD-NOT-PRINT')
    c('hostkey.refused', 'a changed host key is refused by hop exec and plain ssh',
      'before-rekey' in r0.out and r1.rc == 255 and 'SHOULD-NOT-PRINT' not in r1.out and r2.rc != 0 and 'SHOULD-NOT-PRINT' not in r2.out,
      '', r1.ev('exec') + '\n' + r2.ev('ssh'))
    r = hop('check', 'local1')
    c('hostkey.check', 'hop check reports the mismatch', r.rc == 255 and has(r.out, '[fail] host_key_matches'), '', r.ev('check'))
    r = hop('trust', 'local1', '--yes')
    c('hostkey.trust-refuses', 'hop trust without --replace refuses a changed key', r.rc == 255 and '--replace' in r.all, '', r.ev('trust'))
    r = hop('trust', 'local1', '--yes', '--replace')
    r2 = hop('exec', 'local1', '--', 'echo', 'after-replace')
    c('hostkey.replace', 'hop trust --replace pins the new key and exec works', r.rc == 0 and 'after-replace' in r2.out, '', r.ev('trust --replace') + '\n' + r2.ev('exec'))
    for h in ('local2', 'imp1'):
        hop('trust', h, '--yes', '--replace')
    root("ssh-keyscan -t ed25519 127.0.0.1 2>/dev/null | awk '{print $2\" \"$3}' > /var/e2e/state/hostkey.pub")


def main():
    for fn in (step_init, step_keys_hosts, step_trust_exec, step_import_setup, step_snippets, step_lock, step_daemon, step_hostkey):
        L.guard('%s.%s' % (M, fn.__name__), fn.__name__)(fn)()


def before_reboot():
    hs = L.hosts() or {}
    L.state_put('p1-hosts', sorted(hs))
    root('date +%s > /var/e2e/state/reboot-before')


def after_reboot():
    before = L.state_get('p1-hosts', [])
    pids = L.daemon_pids()
    r = hop('exec', 'local1', '--', 'echo', 'after-reboot')
    hs = L.hosts() or {}
    c('reboot.persist', 'after a reboot the first hop command starts the daemon and the vault opens with every host',
      'after-reboot' in r.out and sorted(hs) == before, 'daemon before first command: %s; hosts %d of %d' % (pids, len(hs), len(before)), r.ev('exec'))
    r = ssh('local1', 'echo plain-after-reboot')
    c('reboot.ssh', 'plain ssh works after the reboot once the daemon runs', r.rc == 0, '', r.ev('ssh'))


if __name__ == '__main__':
    {'main': main, 'before-reboot': before_reboot, 'after-reboot': after_reboot}[sys.argv[1]]()
    L.done()
