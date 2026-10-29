#!/usr/bin/env python3
"""Phase 2: hop mcp on CLI-A. Builds its own fixtures, so it runs without phase 1."""
import json
import os
import stat
import sys
import time

import e2elib as L
from e2elib import check as c, hop, has, root
from mcpc import MCP, require_ok, results

DENIED_WORDS = ('mdeny', 'md1', 'secret db')
TOOLS7 = sorted(['check_host', 'exec', 'list_hosts', 'list_snippets', 'resolve_host', 'run_snippet', 'ssh_command'])
AUDIT = '/home/tester/.local/state/hop/mcp-audit.jsonl'


def fixtures():
    L.ensure_vault()
    L.ensure_testkey()
    L.authorize('target', open('/home/tester/testkey.pub').read())
    hs = L.hosts() or {}
    want = [
        ('m1', ['--address', '127.0.0.1', '--alias', 'mm1', '--tag', 'mcp']),
        ('m2', ['--address', 'localhost', '--tag', 'mcp']),
        ('mdeny', ['--address', '127.0.0.1', '--alias', 'md1', '--tag', 'mcp', '--agent-access', 'deny', '--description', 'secret db']),
        ('mnopin', ['--address', '127.0.0.2', '--tag', 'np']),
    ]
    for name, extra in want:
        if name not in hs:
            hop('add', name, '--user', 'target', '--key', 'testkey', *extra)
    for name in ('m1', 'm2', 'mdeny'):
        hop('trust', name, '--yes')
        hop('trust', name, '--yes', '--replace')
    if 'mjump' not in hs:
        hop('add', 'mjump', '--address', '127.0.0.1', '--user', 'target', '--key', 'testkey', '--jump', 'mdeny', '--tag', 'jumpy')
    hk = open('/var/e2e/state/hostkey.pub').read().strip()
    hop('edit', 'mjump', '--host-key', hk)
    snips = {s['name'] for s in (hop('snippet', 'ls', '--json').json() or [])}
    for name, cmd in (('greet', 'echo hello {{name}}'), ('up', 'uptime'), ('twoparam', 'echo {{a}} and {{b}}'),
                      ('ok_shc', "sh -c 'echo \"$1\"' sh {{x}}")):
        if name not in snips:
            hop('snippet', 'add', name, '--', cmd)
    # Secrets planted on the target, printed back by a command (secret scan).
    sk = L.kit()[0]
    root('cp /home/tester/testkey /home/target/leak.pem; cat /root/e2e/sec/devpass > /home/target/pp.txt; '
         'cat /root/e2e/sec/masterpw > /home/target/mpw.txt; chown target: /home/target/leak.pem /home/target/*.txt; '
         'rm -f /tmp/pwned*')
    with open('/home/target/sk.txt', 'w') as f:
        f.write(sk + '\n')
    root('chown target: /home/target/sk.txt')


def no_denied(text, typed=()):
    """A denied name appears only where the request typed it."""
    t = text
    for w in typed:
        t = t.replace(w, '')
    return not any(w in t for w in DENIED_WORDS)


def main():
    fixtures()
    m = MCP(tag='p2-mcp-rw')
    texts = []  # (request words typed, response raw) for the denied-name scan

    def call(name, args, typed=()):
        err, st, text = m.call(name, args)
        texts.append((typed, json.dumps(m.last_raw)))
        return err, st, text

    c('init', 'initialize answers with server info', 'result' in m.init, '', L.cut(json.dumps(m.init), 300))
    tools, _ = m.tools()
    c('tools', 'tools/list has the 7 tools', sorted(tools) == TOOLS7, 'got %s' % sorted(tools))

    _, st, _ = call('list_hosts', {})
    names = sorted(h['name'] for h in (st or {}).get('hosts', []))
    c('list.all', 'list_hosts lists the hosts and hides the denied one', 'm1' in names and 'mdeny' not in names, 'names %s' % names)
    jh = [h for h in (st or {}).get('hosts', []) if h['name'] == 'mjump']
    c('list.jump-hidden', 'a host whose jump host is denied shows it as "(a host hidden from agents)"',
      bool(jh) and 'hidden' in json.dumps(jh[0]) and 'mdeny' not in json.dumps(jh[0]), L.cut(json.dumps(jh), 300))
    _, st, _ = call('list_hosts', {'tag': 'mcp'})
    names = sorted(h['name'] for h in (st or {}).get('hosts', []))
    c('list.tag', 'list_hosts tag filter skips the denied host', names == ['m1', 'm2'], 'names %s' % names)
    _, st, _ = call('list_hosts', {'query': 'mdeny'}, typed=('mdeny',))
    c('list.query-denied', 'list_hosts query for the denied name finds nothing', (st or {}).get('hosts') == [], L.cut(json.dumps(st), 200))

    _, st, _ = call('resolve_host', {'target': 'm1'})
    c('resolve.exact', 'resolve_host exact name', ((st or {}).get('host') or {}).get('name') == 'm1', L.cut(json.dumps(st), 200))
    for t in ('mdeny', 'md1'):
        _, st, _ = call('resolve_host', {'target': t}, typed=(t,))
        c('resolve.denied-' + t, 'resolve_host %s (denied) looks like no host' % t, (st or {}).get('status') == 'no_match', L.cut(json.dumps(st), 200))
    _, st, _ = call('resolve_host', {'target': '127.0.0.1'})
    cands = [x['name'] for x in (st or {}).get('candidates', [])]
    c('resolve.ambiguous', 'resolve_host by a shared address returns candidates without the denied host',
      (st or {}).get('status') != 'matched' and len(cands) >= 2 and 'mdeny' not in cands, 'candidates %s' % cands)

    _, st, _ = call('check_host', {'host': 'm1'})
    c('check.ok', 'check_host passes every step', (st or {}).get('ok') is True, L.cut(json.dumps(st), 300))
    _, st, _ = call('check_host', {'host': 'mdeny'}, typed=('mdeny',))
    c('check.denied', 'check_host on the denied host: no host matches', (st or {}).get('ok') is False and 'no host matches' in json.dumps(st), L.cut(json.dumps(st), 200))
    err, st, text = call('ssh_command', {'host': 'm1'})
    c('sshcmd', 'ssh_command gives an ssh -F command line', 'ssh -F' in json.dumps(st), L.cut(json.dumps(st), 200))
    err, st, text = call('ssh_command', {'host': 'mdeny'}, typed=('mdeny',))
    c('sshcmd.denied', 'ssh_command on the denied host fails as not found', err and 'no host' in text, L.cut(text, 200))

    # The output (mcp-42) is not in the command, so the audit check can tell output from command.
    _, st, _ = call('exec', {'hosts': 'm1', 'command': 'echo mcp-$((6*7)); exit 4'})
    r = results(st).get('m1', {})
    c('exec.one', 'exec on one host passes exit code 4 through', r.get('exit_code') == 4 and 'mcp-42' in r.get('stdout', ''), L.cut(json.dumps(r), 300))
    _, st, _ = call('exec', {'hosts': ['m1', 'm2'], 'command': 'echo two'})
    c('exec.list', 'exec on a list of hosts', sorted(results(st)) == ['m1', 'm2'] and all(x.get('exit_code') == 0 for x in results(st).values()), L.cut(json.dumps(st), 300))
    _, st, _ = call('exec', {'hosts': 'tag:mcp', 'command': 'echo tagged'})
    c('exec.tag', 'exec on tag:mcp skips the denied host', sorted(results(st)) == ['m1', 'm2'], 'hosts %s' % sorted(results(st)))
    for t in ('mdeny', 'md1'):
        _, st, _ = call('exec', {'hosts': t, 'command': 'echo SHOULD-NOT-RUN'}, typed=(t,))
        r = results(st).get(t, {})
        c('exec.denied-' + t, 'exec on %s (denied) runs nothing: no host matches' % t,
          'no host matches' in r.get('error', '') and 'SHOULD-NOT-RUN' not in r.get('stdout', ''), L.cut(json.dumps(r), 300))
    _, st, _ = call('exec', {'hosts': 'mnopin', 'command': 'echo SHOULD-NOT-RUN'})
    r = results(st).get('mnopin', {})
    c('exec.unpinned', 'exec on an unpinned host is refused and names hop trust', 'hop trust mnopin' in r.get('error', '') and not r.get('stdout'), L.cut(json.dumps(r), 300))
    _, st, _ = call('exec', {'hosts': 'mjump', 'command': 'echo via-jump-mcp'})
    r = results(st).get('mjump', {})
    c('exec.jump', 'exec through a denied jump host works', r.get('exit_code') == 0 and 'via-jump-mcp' in r.get('stdout', ''), L.cut(json.dumps(r), 300))
    _, st, _ = call('exec', {'hosts': 'm1', 'command': 'sleep 5', 'timeout_s': 1})
    r = results(st).get('m1', {})
    c('exec.timeout', 'exec timeout_s=1 stops the command', 'timed out' in r.get('error', ''), L.cut(json.dumps(r), 300))

    _, st, _ = call('list_snippets', {})
    sn = {s['name'] for s in (st or {}).get('snippets', [])}
    c('snip.list', 'list_snippets', {'greet', 'up', 'twoparam', 'ok_shc'} <= sn, 'got %s' % sorted(sn))
    _, st, _ = call('run_snippet', {'name': 'greet', 'hosts': 'm1', 'params': {'name': 'world'}})
    c('snip.run', 'run_snippet greet world', results(st).get('m1', {}).get('stdout') == 'hello world\n', L.cut(json.dumps(st), 300))
    hostile = ['$(touch /tmp/pwned1)', "'; touch /tmp/pwned2 #", '`touch /tmp/pwned3`']
    lit = True
    for i, v in enumerate(hostile):
        _, st, _ = call('run_snippet', {'name': 'greet', 'hosts': 'm1', 'params': {'name': v}})
        if results(st).get('m1', {}).get('stdout') != 'hello %s\n' % v:
            lit = False
    v = '$(touch /tmp/pwned4); "; touch /tmp/pwned4 \'\n touch /tmp/pwned4'
    _, st, _ = call('run_snippet', {'name': 'ok_shc', 'hosts': 'm1', 'params': {'x': v}})
    lit = lit and results(st).get('m1', {}).get('stdout') == v + '\n'
    pwned = root('ls /tmp/pwned* 2>/dev/null').out.split()
    c('snip.hostile', 'hostile snippet params are printed literally and run nothing', lit and not pwned, 'files created: %s' % pwned)
    err, st, text = call('run_snippet', {'name': 'twoparam', 'hosts': 'm1', 'params': {'a': 'A1'}})
    c('snip.missing', 'run_snippet refuses a missing parameter', 'missing parameter' in text + json.dumps(st), L.cut(text, 200))
    err, st, text = call('run_snippet', {'name': 'twoparam', 'hosts': 'm1', 'params': {'a': 'A1', 'b': 'B1', 'c': 'C1'}})
    c('snip.unknown', 'run_snippet refuses an unknown parameter', 'unknown parameter' in text + json.dumps(st), L.cut(text, 200))
    err, st, text = call('run_snippet', {'name': 'nosuch', 'hosts': 'm1', 'params': {}})
    c('snip.nosuch', 'run_snippet with no such snippet', 'no snippet' in text + json.dumps(st), L.cut(text, 200))
    _, st, _ = call('run_snippet', {'name': 'up', 'hosts': 'mdeny', 'params': {}}, typed=('mdeny',))
    c('snip.denied', 'run_snippet on the denied host runs nothing', 'no host matches' in json.dumps(st), L.cut(json.dumps(st), 200))
    _, st, _ = call('run_snippet', {'name': 'up', 'hosts': 'mnopin', 'params': {}})
    c('snip.unpinned', 'run_snippet on an unpinned host is refused', 'hop trust mnopin' in json.dumps(st), L.cut(json.dumps(st), 200))

    # Secrets the remote prints: private keys and the passphrase hop knows are redacted.
    _, st, _ = call('exec', {'hosts': 'm1', 'command': 'cat leak.pem; echo ---; cat pp.txt; echo ---; cat sk.txt; echo ---; cat mpw.txt'})
    planted = json.dumps(st)
    pem = open('/home/tester/testkey').read().splitlines()[1]
    # The scrub checks judge output, so the command must have run and printed all four parts.
    pr = results(st).get('m1', {})
    if pr.get('exit_code') == 0 and pr.get('stdout', '').count('---') == 3:
        c('scrub.pem', 'a private key block the remote prints is redacted', 'PRIVATE KEY' not in planted and pem not in planted, '')
        c('scrub.devpass', 'the device passphrase the remote prints is redacted', L.sec_read('devpass') not in planted, '')
        leaked = [n for n, v in (('Secret Key', L.kit()[0]), ('master password', L.sec_read('masterpw'))) if v and v in planted]
        c('scrub.unknown-secrets', 'the Secret Key and master password the remote prints are redacted (daemon knows the Secret Key)',
          not leaked, 'passed through: %s (hop mcp was started without them in its env; README calls this best effort)' % leaked, '', 'r1-P1-rule')
    else:
        L.harness('scrub', 'the planted-secret command runs on m1 and prints its four parts', 'result: %s' % L.cut(json.dumps(pr), 200))
    healthy = m.healthy
    m.close()
    require_ok(m, 'mcp-transport.rw', 'hop mcp answered every request of the main session')

    # Denied names: never in an answer where the request did not type them.
    leaks = [L.cut(raw, 160) for typed, raw in texts if not no_denied(raw, typed)]
    if healthy and texts:
        c('deny.invisible', 'the denied host name, alias and description appear in no answer except as typed', not leaks, 'leaks: %s' % leaks[:3])
    else:
        L.harness('deny.invisible', 'the denied host name, alias and description appear in no answer except as typed',
                  'prerequisite: hop mcp answered every request (hung %s, exited %s, %d of %d answered)' % (m.hung, m.exited, m.answered, m.nid))

    # Read-only.
    ro = MCP(['--read-only'], tag='p2-mcp-ro')
    tools, _ = ro.tools()
    c('ro.tools', '--read-only offers no exec or run_snippet', 'exec' not in tools and 'run_snippet' not in tools and 'list_hosts' in tools, 'tools %s' % tools)
    err, st, text = ro.call('exec', {'hosts': 'm1', 'command': 'echo SHOULD-NOT-RUN'})
    c('ro.exec', '--read-only refuses an exec call', ro.healthy and err and 'SHOULD-NOT-RUN' not in text, L.cut(text, 200))
    err, st, text = ro.call('check_host', {'host': 'm1'})
    auth = [s for s in (st or {}).get('steps', []) if s.get('name') == 'auth_ok']
    c('ro.check', '--read-only check_host skips the login step', bool(auth) and auth[0].get('status') == 'skipped', L.cut(json.dumps(auth), 200))
    ro.close()
    require_ok(ro, 'mcp-transport.ro', 'hop mcp --read-only answered every request')

    # With the auth secrets in its env, hop mcp scrubs them from output.
    sk, rk = L.kit()
    env = {'HOP_PASSWORD': L.sec_read('masterpw'), 'HOP_SECRET_KEY': sk}
    pm = MCP(env=env, tag='p2-mcp-pw')
    _, st, _ = pm.call('exec', {'hosts': 'm1', 'command': 'cat mpw.txt; cat sk.txt; cat pp.txt'})
    out = json.dumps(st)
    c('scrub.env-secrets', 'with HOP_PASSWORD and HOP_SECRET_KEY in its env, all three values are redacted',
      L.sec_read('masterpw') not in out and sk not in out and L.sec_read('devpass') not in out and 'redacted' in out, '')
    pm.close()
    require_ok(pm, 'mcp-transport.pw', 'hop mcp with the auth secrets in its env answered every request')

    # Audit log.
    try:
        mode = stat.S_IMODE(os.stat(AUDIT).st_mode)
        audit = open(AUDIT).read()
    except OSError as e:
        mode, audit = None, ''
    c('audit.mode', 'the audit log is mode 0600', mode == 0o600, 'mode %s' % (oct(mode) if mode is not None else 'missing'))
    snip_lines = [json.loads(l) for l in audit.splitlines() if '"run_snippet"' in l]
    c('audit.snippet', 'run_snippet audit lines carry parameter names', any('name' in json.dumps(x.get('params', '')) for x in snip_lines), L.cut(json.dumps(snip_lines[:1]), 300))
    vals = ['world', 'pwned1', 'pwned2', 'pwned3', 'pwned4', 'A1', 'B1', 'hello world', 'mcp-42']
    hits = [v for v in vals if v in audit]
    c('audit.no-values', 'the audit log holds no parameter values and no output', bool(snip_lines) and not hits,
      'found: %s' % hits if snip_lines else 'not judged: no run_snippet lines in the audit log')

    # Secret scan of every response, stderr log, the audit log and daemon.log
    # (the planted call's answer is judged above).
    corpus = {
        'responses': ''.join(raw for _, raw in texts if 'leak.pem' not in raw),
        'mcp stderr': ''.join(open('%s/logs/%s.stderr' % (L.E2E, t)).read() for t in ('p2-mcp-rw', 'p2-mcp-ro', 'p2-mcp-pw')),
        'audit': audit,
        'daemon.log': open('/home/tester/.local/state/hop/daemon.log').read() if os.path.exists('/home/tester/.local/state/hop/daemon.log') else '',
    }
    secrets = {'master password': L.sec_read('masterpw'), 'Secret Key': sk, 'Recovery Key': rk,
               'device passphrase': L.sec_read('devpass'), 'private key body': pem, 'PEM header': 'BEGIN OPENSSH PRIVATE KEY'}
    try:
        dk = json.load(open('/home/tester/.local/share/hop/device.key'))
        fields = []

        def walk(x):
            if isinstance(x, dict):
                [walk(v) for v in x.values()]
            elif isinstance(x, list):
                [walk(v) for v in x]
            elif isinstance(x, str) and len(x) >= 16:
                fields.append(x)
        walk(dk)
        for i, v in enumerate(fields):
            secrets['device.key field %d' % i] = v
    except Exception:
        pass
    found = ['%s in %s' % (sn, cn) for cn, ct in corpus.items() for sn, sv in secrets.items() if sv and sv in ct]
    empty = [cn for cn in ('responses', 'audit') if not corpus[cn]]
    if empty:
        L.harness('scan', 'secret scan: no secret in any MCP response, stderr, audit log or daemon.log', 'prerequisite: empty corpus: %s' % empty)
    else:
        c('scan', 'secret scan: no secret in any MCP response, stderr, audit log or daemon.log', not found,
          'hits: %s; scanned %s' % (found, {cn: len(ct) for cn, ct in corpus.items()}))

    # mcp install.
    r = hop('mcp', 'install', '--client', 'print')
    c('install.print', 'mcp install --client print prints the claude and codex commands, JSON and TOML',
      r.rc == 0 and has(r.out, 'claude mcp add', 'codex mcp add', 'mcpServers'), '', r.ev('mcp install --client print')[:500])
    r = hop('mcp', 'install', '--client', 'print', '--read-only')
    c('install.ro', 'mcp install --read-only adds --read-only', r.rc == 0 and '--read-only' in r.out, '')
    r = hop('mcp', 'install', '--client', 'claude')
    c('install.noclient', 'mcp install --client claude without claude on PATH fails and prints the config', r.rc == 255 and 'not on PATH' in r.all, '', r.ev('install claude'))

    # hop mcp starting the daemon on a sealed device: the tools say hop unlock, which must work.
    hop('daemon', 'stop')
    time.sleep(1)
    lm = MCP(nopass=True, tag='p2-mcp-locked')
    err, st, text = lm.call('list_hosts', {})
    said_unlock = 'hop unlock' in text + json.dumps(st)
    r = hop('unlock')
    err2, st2, text2 = lm.call('exec', {'hosts': 'm1', 'command': 'echo after-unlock'})
    lm.close()
    require_ok(lm, 'mcp-transport.locked', 'hop mcp on a locked daemon answered every request')
    c('locked.hint', 'hop mcp starts a locked daemon on a sealed device and the tools say to run hop unlock', said_unlock, L.cut(text, 200))
    c('locked.unlock', 'the hop unlock the tools ask for unlocks that daemon', r.rc == 0 and 'after-unlock' in json.dumps(st2),
      'hop unlock: rc=%d %s' % (r.rc, L.cut(r.all.strip(), 200)), '', 'r1-P2-1')
    hop('daemon', 'stop')
    time.sleep(1)
    hop('ls')


if __name__ == '__main__':
    L.guard('main', 'phase 2')(main)()
    L.done()
