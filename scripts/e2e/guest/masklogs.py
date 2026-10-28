#!/usr/bin/env python3
"""Mask every file the driver exports into a separate directory, failing closed.

  masklogs.py export                 results, logs, job output and state into /var/e2e/export
  masklogs.py tail <file> [bytes]    print the masked tail of one file (driver diagnostics)

The originals are left alone. A file that cannot be read, masked or written,
or that still holds a known secret after masking, is not exported: it is
listed in export/MASK-FAILURES and the exit code is 3. Without the secret
list (an unreadable /root/e2e/sec) nothing is exported at all.
"""
import glob
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('E2E_STEP', 'masklogs')
import e2elib as L

SRC = L.E2E
DST = L.E2E + '/export'
PATTERNS = ('results/*', 'logs/*', 'jobs/*.out', 'jobs/*.rc', 'state/*')


def masked(path):
    # The whole file: masking a tail cut mid-secret would leave the rest of it.
    with open(path, 'rb') as f:
        s = f.read().decode('utf-8', errors='replace')
    m = L.mask(s, strict=True)
    left = [v for v in L._secret_values(strict=True) if v in m]
    if left:
        raise ValueError('%d secret values left after masking' % len(left))
    return m


def export():
    shutil.rmtree(DST, ignore_errors=True)
    os.makedirs(DST, mode=0o700)
    failures = []
    try:
        L._secret_values(strict=True)
    except OSError as e:
        failures.append('* no secret list (%s): nothing exported' % e.__class__.__name__)
        files = []
    else:
        files = sorted(p for pat in PATTERNS for p in glob.glob(os.path.join(SRC, pat))
                       if os.path.isfile(p) and not os.path.basename(p).startswith('.'))
    n = 0
    for p in files:
        rel = os.path.relpath(p, SRC)
        try:
            m = masked(p)
            out = os.path.join(DST, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            tmp = out + '.part'
            with open(tmp, 'w') as f:
                f.write(m)
            os.replace(tmp, out)
            n += 1
        except Exception as e:  # any failure: the file stays behind
            failures.append('%s: %s' % (rel, e.__class__.__name__))
            try:
                os.remove(os.path.join(DST, rel) + '.part')
            except OSError:
                pass
    with open(os.path.join(DST, 'MASK-FAILURES'), 'w') as f:
        f.write(''.join(x + '\n' for x in failures))
    print('exported %d files, %d not exported' % (n, len(failures)))
    for x in failures:
        print('not exported: ' + x)
    return 3 if failures else 0


def tail(path, limit=600):
    try:
        print(masked(path).replace('\n', ' ')[-int(limit):])
    except FileNotFoundError:
        print('<no %s>' % path)
    except Exception as e:
        print('<%s withheld: masking failed (%s)>' % (path, e.__class__.__name__))
        return 3
    return 0


if __name__ == '__main__':
    if sys.argv[1:2] == ['export']:
        sys.exit(export())
    if sys.argv[1:2] == ['tail'] and len(sys.argv) >= 3:
        sys.exit(tail(*sys.argv[2:4]))
    sys.exit(__doc__)
