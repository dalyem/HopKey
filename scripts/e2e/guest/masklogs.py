#!/usr/bin/env python3
"""Mask every log and job output file in place before the driver fetches them."""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('E2E_STEP', 'masklogs')
import e2elib as L

for p in glob.glob('/var/e2e/logs/*') + glob.glob('/var/e2e/jobs/*.out'):
    try:
        s = open(p, errors='replace').read()
        m = L.mask(s)
        if m != s:
            open(p, 'w').write(m)
    except OSError:
        pass
