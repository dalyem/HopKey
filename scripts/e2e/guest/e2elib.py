"""Shared helpers for the HopKey end-to-end checks that run on the test machines.

Every check writes one JSON line to /var/e2e/results/<phase>.jsonl:
  {run, phase, machine, id, name, status: pass|fail|skip, detail, evidence, bug, ts}

Secrets (the master password, device passphrase, Emergency Kit, invite code)
live in 0600 files under /root/e2e/sec. They are passed to hop through the
environment or stdin, never on a command line, and every string this module
writes (results, logs) is masked first.
"""
import json
import os
import pty
import pwd
import re
import select
import signal
import subprocess
import sys
import time

E2E = '/var/e2e'
SEC = '/root/e2e/sec'
STATE = E2E + '/state'
RUN = open('/etc/hk-e2e/run-id').read().strip() if os.path.exists('/etc/hk-e2e/run-id') else 'local'
MACHINE = open('/etc/hk-e2e/machine').read().strip() if os.path.exists('/etc/hk-e2e/machine') else os.uname().nodename
PHASE = os.environ.get('E2E_PHASE', '0')
STEP = os.environ.get('E2E_STEP', 'step')

for d in (E2E + '/results', E2E + '/logs', STATE):
    os.makedirs(d, exist_ok=True)
_log = open('%s/logs/p%s-%s-%s.log' % (E2E, PHASE, MACHINE, STEP), 'a')

# ---------------------------------------------------------------- secrets

_sec_cache = (None, [])


def sec_path(name):
    return os.path.join(SEC, name)


def sec_read(name, default=''):
    try:
        with open(sec_path(name)) as f:
            return f.read().strip()
    except OSError:
        return default


def sec_write(name, value):
    os.makedirs(SEC, mode=0o700, exist_ok=True)
    p = sec_path(name)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(value + '\n')
    os.chmod(p, 0o600)


def kit():
    """The current Emergency Kit as (secret_key, recovery_key)."""
    sk = rk = ''
    for line in sec_read('kit').splitlines():
        if line.startswith('SECRET_KEY='):
            sk = line.split('=', 1)[1]
        if line.startswith('RECOVERY_KEY='):
            rk = line.split('=', 1)[1]
    return sk, rk


def _secret_values(strict=False):
    """Every secret value under SEC. strict: raise instead of masking with
    fewer values than there are (an unreadable SEC or secret file)."""
    global _sec_cache
    try:
        stamp = tuple((n, os.stat(sec_path(n)).st_mtime) for n in sorted(os.listdir(SEC)))
    except OSError:
        if strict:
            raise
        stamp = ()
    if _sec_cache[0] == stamp and _sec_cache[0] is not None:
        return _sec_cache[1]
    vals = set()
    for n, _ in stamp:
        try:
            for line in open(sec_path(n)):
                line = line.strip()
                v = line.split('=', 1)[1] if re.match(r'^[A-Z_]+=', line) else line
                if len(v) >= 6:
                    vals.add(v)
        except OSError:
            if strict:
                raise
    vals = sorted(vals, key=len, reverse=True)
    _sec_cache = (stamp, vals)
    return vals


def mask(s, strict=False):
    if s is None:
        return ''
    if not isinstance(s, str):
        s = str(s)
    for v in _secret_values(strict):
        s = s.replace(v, '<SECRET>')
    s = re.sub(r'\btskey-[A-Za-z0-9-]{8,}', '<TS-AUTHKEY>', s)
    s = re.sub(r'\bH1-[A-Z0-9]{4,}(-[A-Z0-9]{2,}){3,}', '<SECRET-KEY>', s)
    s = re.sub(r'\bR1-[A-Z0-9$]{4,}(-[A-Z0-9$]{2,}){3,}', '<RECOVERY-KEY>', s)
    s = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '<PRIVATE-KEY-BLOCK>', s, flags=re.S)
    # Part of a block (output cut short, a block split between reads): withhold
    # everything from a lone BEGIN on, and everything up to a lone END.
    s = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*', '<PRIVATE-KEY-BLOCK-INCOMPLETE>', s, flags=re.S)
    s = re.sub(r'^.*-----END [A-Z ]*PRIVATE KEY-----', '<PRIVATE-KEY-BLOCK-INCOMPLETE>', s, flags=re.S)
    return s


def cut(s, n):
    """Mask the whole string, then keep its first n characters (its last -n when n < 0).
    Never the other way round: a cut can split a secret, and a part of one no longer matches."""
    s = mask(s)
    return s[:n] if n >= 0 else s[n:]


def log(*parts):
    _log.write(mask(' '.join(str(p) for p in parts)) + '\n')
    _log.flush()


# ---------------------------------------------------------------- results

_counts = {'pass': 0, 'fail': 0, 'skip': 0}


def short(s, n=900):
    s = mask(s)
    return s if len(s) <= n else s[:n // 2] + ' ... ' + s[-n // 2:]


def check(cid, name, ok, detail='', evidence='', bug=None, status=None):
    """Record one check. ok is a bool; status overrides it (skip)."""
    st = status or ('pass' if ok else 'fail')
    rec = {
        'run': RUN, 'phase': int(PHASE) if str(PHASE).isdigit() else PHASE, 'machine': MACHINE,
        'id': 'p%s.%s' % (PHASE, cid), 'name': name, 'status': st,
        'detail': short(detail, 600), 'evidence': short(evidence),
        'bug': bug, 'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    with open('%s/results/p%s.jsonl' % (E2E, PHASE), 'a') as f:
        f.write(json.dumps(rec) + '\n')
    _counts[st] += 1
    log('CHECK', st.upper(), rec['id'], name, '|', rec['detail'])
    return st == 'pass'


def skip(cid, name, why, bug=None):
    return check(cid, name, False, why, '', bug, status='skip')


def harness(cid, name, detail, evidence=''):
    """A failure of the harness or of a check's prerequisite, never a product verdict."""
    return check(cid, name, False, detail, evidence, 'harness')


def guard(cid, name):
    """Decorator-free helper: run fn, turn an exception into a failed check."""
    def wrap(fn):
        def inner(*a, **kw):
            try:
                return fn(*a, **kw)
            except Exception as e:  # a harness error is a failed check, never a silent pass
                import traceback
                check(cid, name + ' (harness error)', False, 'exception: %r' % e, cut(traceback.format_exc(), -800), 'harness')
        return inner
    return wrap


def done():
    log('STEP DONE', _counts)
    print(json.dumps({'step': STEP, 'counts': _counts}))


# ---------------------------------------------------------------- running things

class R:
    def __init__(self, rc, out, err, secs):
        self.rc, self.out, self.err, self.secs = rc, out, err, secs

    @property
    def all(self):
        return (self.out or '') + (self.err or '')

    def json(self):
        try:
            return json.loads(self.out)
        except Exception:
            return None

    def ev(self, cmd=''):
        return mask('%s -> rc=%s (%.1fs) %s' % (cmd, self.rc, self.secs, self.all.strip()))


def user_env(user, nopass=False, extra=None):
    pw = pwd.getpwnam(user)
    env = {
        'HOME': pw.pw_dir, 'USER': user, 'LOGNAME': user, 'SHELL': '/bin/bash', 'TERM': 'xterm',
        'LANG': 'C.UTF-8', 'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
        'XDG_RUNTIME_DIR': '/run/user/%d' % pw.pw_uid,
        'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/%d/bus' % pw.pw_uid,
    }
    if not nopass:
        env['HOP_DEVICE_PASSPHRASE'] = sec_read('devpass')
    if extra:
        env.update(extra)
    return env


def user_argv(user, argv, timeout):
    # Each command gets its own systemd scope, so a hop daemon it starts
    # outlives the step (and the guest agent) instead of dying with it.
    # hke2e.slice holds everything the suite starts, so reset-vm.sh can stop it all.
    return ['systemd-run', '--scope', '--quiet', '--collect', '--slice=hke2e.slice', '--',
            'timeout', '-k', '3', str(int(timeout)), 'runuser', '-u', user, '--'] + list(argv)


def run_as(user, argv, timeout=60, nopass=False, env=None, stdin=None, cwd='/tmp'):
    t0 = time.time()
    try:
        p = subprocess.run(user_argv(user, argv, timeout), env=user_env(user, nopass, env), cwd=cwd,
                           input=stdin, capture_output=True, text=True, timeout=timeout + 10,
                           stdin=None if stdin is not None else subprocess.DEVNULL)
        r = R(p.returncode, p.stdout, p.stderr, time.time() - t0)
    except subprocess.TimeoutExpired as e:
        r = R(-9, e.stdout or '', (e.stderr or '') + '\n<harness timeout>', time.time() - t0)
    log('$', user, ' '.join(argv), '->', r.rc, '(%.1fs)' % r.secs)
    if r.all.strip():
        log('   ' + cut(r.all.strip(), 4000).replace('\n', '\n   '))
    return r


def hop(*args, user='tester', timeout=60, nopass=False, env=None, stdin=None):
    return run_as(user, ['hop'] + [str(a) for a in args], timeout, nopass, env, stdin)


def ush(cmd, user='tester', timeout=60, nopass=False, env=None, stdin=None):
    """A shell command line as a test user (with the hop environment)."""
    return run_as(user, ['bash', '-c', cmd], timeout, nopass, env, stdin)


def root(cmd, timeout=120):
    t0 = time.time()
    try:
        p = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        r = R(p.returncode, p.stdout, p.stderr, time.time() - t0)
    except subprocess.TimeoutExpired as e:
        r = R(-9, e.stdout or '', (e.stderr or '') + '\n<harness timeout>', time.time() - t0)
    log('# root:', cut(cmd, 300), '->', r.rc)
    if r.all.strip():
        log('   ' + cut(r.all.strip(), 3000).replace('\n', '\n   '))
    return r


def ssh(host, cmd, user='tester', timeout=30, extra=()):
    """Plain OpenSSH through the generated config (no hop process involved)."""
    return run_as(user, ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'] + list(extra) + [host, cmd], timeout)


def agent_keys(user='tester'):
    """How many identities hop's agent socket serves (-1: no agent)."""
    uid = pwd.getpwnam(user).pw_uid
    r = run_as(user, ['ssh-add', '-L'], 15, env={'SSH_AUTH_SOCK': '/run/user/%d/hop/agent.sock' % uid})
    if 'no identities' in r.all:
        return 0
    if r.rc != 0:
        return -1
    return sum(1 for l in r.out.splitlines() if l.startswith(('ssh-', 'ecdsa-')))


def daemon_pids(user='tester'):
    r = root("pgrep -u %s -x hop -a | grep -w daemon | awk '{print $1}'" % user)
    return [int(x) for x in r.out.split()]


def wait_for(fn, timeout, interval=0.25):
    """Poll fn until it returns a truthy value; return (value, seconds)."""
    t0 = time.time()
    while True:
        v = fn()
        if v:
            return v, time.time() - t0
        if time.time() - t0 > timeout:
            return v, time.time() - t0
        time.sleep(interval)


def hosts(user='tester'):
    r = hop('ls', '--json', user=user, timeout=30)
    try:
        return {h['name']: h for h in json.loads(r.out)}
    except Exception:
        return None


def status_json(user='tester'):
    r = hop('status', '--json', user=user, timeout=30)
    try:
        return json.loads(r.out)
    except Exception:
        return None


def state_put(name, value):
    """Write a state file atomically: a reader sees the old or the new content, never part of it."""
    p = os.path.join(STATE, name)
    tmp = '%s/.%s.%d.tmp' % (STATE, name, os.getpid())
    with open(tmp, 'w') as f:
        f.write(value if isinstance(value, str) else json.dumps(value))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def state_read(name):
    """(status, value) of a JSON state file: status is missing, ok or malformed."""
    try:
        with open(os.path.join(STATE, name)) as f:
            s = f.read()
    except OSError:
        return 'missing', None
    try:
        return 'ok', json.loads(s)
    except ValueError:
        return 'malformed', cut(s, 200)


def state_get(name, default=None):
    """A state value: JSON if it parses, else the stripped text (plain values like device-id)."""
    try:
        with open(os.path.join(STATE, name)) as f:
            s = f.read()
    except OSError:
        return default
    try:
        return json.loads(s)
    except Exception:
        return s.strip()


FW_TAG = 'hk-e2e'


def fw_clear():
    """Remove the firewall rules the suite added (and only those), both chains."""
    return root("for c in INPUT OUTPUT; do iptables -S $c | grep -e '--comment %s' | sed 's/^-A /-D /' | "
                "while read -r r; do iptables $r; done; done; iptables -S | grep -c -e '--comment %s'" % (FW_TAG, FW_TAG))


def fw_block(rules):
    """Replace the suite's rules with these (iptables -I specs ending in -j TARGET), tagged."""
    fw_clear()
    bad = []
    for rule in rules:
        r = root('iptables -I ' + rule.replace(' -j ', ' -m comment --comment %s -j ' % FW_TAG, 1))
        if r.rc != 0:
            bad.append(rule)
    return bad


def server_reachable(url, tries=1):
    """Whether this machine reaches the run's hop-server (a TCP connect plus TLS, 3 s each)."""
    for i in range(tries):
        if root('curl -fsS -m 3 %s/v1/healthz' % url, timeout=10).rc == 0:
            return True
        if i + 1 < tries:
            time.sleep(1)
    return False


def env_get(name, default=''):
    """Values the driver hands down (tailnet names, server URL): /etc/hk-e2e/env."""
    try:
        for line in open('/etc/hk-e2e/env'):
            if line.startswith(name + '='):
                return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return default


# ---------------------------------------------------------------- pty

def pty_run(user, argv, answers, timeout=120, nopass=False, env=None, inbox=None, logname=None, raw=False):
    """Run argv on a pty as user.

    answers: list of (regex, reply) where reply is a string or a function of
    the output so far returning a string (or None to wait). Each regex fires
    once. inbox: a file whose content, when it appears, is typed and the file
    removed (the driver answers cross-machine prompts that way). Returns
    (exit code, masked output); raw=True returns the output unmasked, for a
    caller that reads a secret from it and records only masked text."""
    full = user_argv(user, argv, timeout)
    e = user_env(user, nopass, env)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(full[0], full, e)
    out = ''
    fired = set()
    t0 = time.time()
    # The log is rewritten whole from the masked transcript: masking each read
    # on its own would miss a secret split between two reads.
    lf = '%s/logs/pty-%s.log' % (E2E, logname) if logname else None
    shown = ''

    def flush_log(extra=''):
        if lf:
            tmp = lf + '.tmp'
            with open(tmp, 'w') as f:
                f.write(mask(shown) + extra)
            os.replace(tmp, lf)
    while True:
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd in r:
            try:
                d = os.read(fd, 4096)
            except OSError:
                d = b''
            if not d:
                break
            s = d.decode(errors='replace')
            out += s
            shown += s
            flush_log()
        for i, (rx, reply) in enumerate(answers):
            if i in fired:
                continue
            if re.search(rx, out[-2000:]):
                v = reply(out) if callable(reply) else reply
                if v is None:
                    continue
                fired.add(i)
                os.write(fd, v.encode() + b'\r')
        if inbox and os.path.exists(inbox):
            v = open(inbox).read().strip()
            os.remove(inbox)
            shown += '\n<<typed: %s>>\n' % v
            flush_log()
            os.write(fd, v.encode() + b'\r')
        if time.time() - t0 > timeout + 5:
            os.kill(pid, signal.SIGKILL)
            out += '\n<harness pty timeout>'
            break
    _, st = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(st) if os.WIFEXITED(st) else -1
    flush_log('\nPTY_EXIT=%d (%.1fs)\n' % (rc, time.time() - t0))
    log('pty', user, ' '.join(argv), '-> rc', rc)
    log('   ' + cut(out.strip(), -3000).replace('\n', '\n   '))
    return rc, out if raw else mask(out)


def init_vault(user='tester', nopass=False, kitname='kit'):
    """hop init --device-key-store file through a pty; the kit goes to SEC/<kitname>."""
    pwname = 'masterpw'
    if not sec_read(pwname):
        sec_write(pwname, 'mpw-' + os.urandom(12).hex())
    pw = sec_read(pwname)
    found = {}

    def sk(out):
        m = re.search(r'Secret Key:\s+(\S+)', out)
        return m.group(1).split('-')[-1] if m else None

    def rk(out):
        m = re.search(r'Recovery Key:\s+(\S+)', out)
        return m.group(1).split('-')[-1] if m else None

    def grab(out):
        for k, rx in (('sk', r'Secret Key:\s+(\S+)'), ('rk', r'Recovery Key:\s+(\S+)')):
            m = re.search(rx, out)
            if m:
                found[k] = m.group(1)

    answers = [
        (r'Repeat it[^:]*:\s*$', pw),
        (r'[Mm]aster password[^:\n]*:\s*$', pw),
        (r'last group of your Secret Key', lambda o: (grab(o), sk(o))[1]),
        (r'last group of your Recovery Key', lambda o: (grab(o), rk(o))[1]),
    ]
    rc, out = pty_run(user, ['hop', 'init', '--device-key-store', 'file'], answers, timeout=120, nopass=nopass, raw=True)
    grab(out)
    if found.get('sk'):
        sec_write(kitname, 'SECRET_KEY=%s\nRECOVERY_KEY=%s' % (found.get('sk', ''), found.get('rk', '')))
    return rc, mask(out)


def ensure_user(name, shell='/bin/bash', linger=True):
    root('id %s >/dev/null 2>&1 || useradd -m -s %s %s' % (name, shell, name))
    if linger:
        root('loginctl enable-linger %s; for i in 1 2 3 4 5 6 7 8 9 10; do [ -d /run/user/$(id -u %s) ] && break; sleep 0.5; done' % (name, name))


def authorize(user, pubkey_line):
    """Append a public key to user's authorized_keys (idempotent)."""
    pw = pwd.getpwnam(user)
    d = os.path.join(pw.pw_dir, '.ssh')
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, 'authorized_keys')
    cur = open(p).read() if os.path.exists(p) else ''
    if pubkey_line.strip() not in cur:
        with open(p, 'a') as f:
            f.write(pubkey_line.strip() + '\n')
    for x in (d, p):
        os.chown(x, pw.pw_uid, pw.pw_gid)
    os.chmod(d, 0o700)
    os.chmod(p, 0o600)


def ensure_testkey():
    """The vault's ssh key, testkey, made on CLI-A at setup; added once."""
    r = hop('key', 'ls', '--json')
    try:
        if any(k['name'] == 'testkey' for k in json.loads(r.out)):
            return True
    except Exception:
        pass
    return hop('key', 'add', '/home/tester/testkey', '--name', 'testkey').rc == 0


def ensure_include(user='tester'):
    """Plain ssh <alias> reads hop's generated config only through the Include that
    hop setup adds. Phase 1 runs hop setup; a run without phase 1 must too, or every
    "plain ssh no longer works" check would pass on a name that never resolved."""
    try:
        cfg = open(os.path.join(pwd.getpwnam(user).pw_dir, '.ssh', 'config')).read()
    except OSError:
        cfg = ''
    if re.search(r'^Include ~/\.ssh/hop/config$', cfg, re.M):
        return True
    r = hop('setup', '--yes', user=user)
    if r.rc != 0:
        harness('%s.ssh-include' % MACHINE, 'hop setup --yes adds the Include plain ssh needs', 'hop setup failed', r.ev('hop setup --yes'))
    return r.rc == 0


def ensure_vault():
    if os.path.exists('/home/tester/.local/share/hop/device.key'):
        return True
    rc, _ = init_vault()
    return rc == 0


def glob_files(d):
    """Every file under d (recursive), [] when d is missing."""
    out = []
    for root_, _, files in os.walk(d):
        out.extend(os.path.join(root_, f) for f in files)
    return sorted(out)


def has(s, *needles):
    return all(n in (s or '') for n in needles)
