#!/usr/bin/env python3
"""Cross-machine timing helpers. The driver pairs them up.

  syncops.py mark <id> <hop args...>   run a hop change; state/mark-<id> = {rc, done}
  syncops.py watch <id> <spec> <secs>  poll until spec holds; state/watch-<id> = {started, initially, seen|timeout}

spec: kind:name[:field=value | :absent], kind one of hosts|keys|snippets|config
      (hosts:synca1:user=deploy2, hosts:synca1:absent, config:rb2)
"config" looks for a Host block in ~/.ssh/hop/config without running hop.
"""
import json
import re
import sys
import time

import e2elib as L


def parse(s):
    parts = s.split(':')
    spec = {'kind': parts[0], 'name': parts[1]}
    if len(parts) > 2:
        if parts[2] == 'absent':
            spec['absent'] = True
        else:
            f, v = parts[2].split('=', 1)
            spec['field'], spec['eq'] = f, int(v) if v.isdigit() else v
    return spec


def holds(spec):
    kind, name = spec['kind'], spec['name']
    if kind == 'config':
        try:
            cfg = open('/home/tester/.ssh/hop/config').read()
        except OSError:
            cfg = ''
        m = re.search(r'^Host %s\n((?:  .*\n?)*)' % re.escape(name), cfg, re.M)
        if spec.get('absent'):
            return m is None
        if m is None:
            return False
        if 'field' in spec:
            return re.search(r'^\s+%s %s$' % (re.escape(spec['field']), re.escape(str(spec['eq']))), m.group(1), re.M) is not None
        return True
    cmd = {'hosts': ['ls', '--json'], 'keys': ['key', 'ls', '--json'], 'snippets': ['snippet', 'ls', '--json']}[kind]
    r = L.hop(*cmd, timeout=20)
    try:
        items = {x['name']: x for x in json.loads(r.out)}
    except Exception:
        return False
    if spec.get('absent'):
        return name not in items
    if name not in items:
        return False
    if 'field' in spec:
        return items[name].get(spec['field']) == spec['eq']
    return True


def main():
    op, wid = sys.argv[1], sys.argv[2]
    if op == 'mark':
        r = L.hop(*sys.argv[3:], timeout=60)
        L.state_put('mark-' + wid, {'rc': r.rc, 'done': time.time(), 'out': L.mask(r.all)[:300]})
    elif op == 'watch':
        spec = parse(sys.argv[3])
        secs = float(sys.argv[4])
        t0 = time.time()
        # Holding before any change was made means the watch can prove nothing.
        initially = holds(spec)
        L.state_put('watch-' + wid, {'started': t0, 'initially': initially})
        while True:
            if holds(spec):
                L.state_put('watch-' + wid, {'seen': time.time(), 'started': t0, 'initially': initially})
                return
            if time.time() - t0 > secs:
                L.state_put('watch-' + wid, {'timeout': time.time(), 'started': t0, 'initially': initially})
                return
            time.sleep(0.2 if spec['kind'] == 'config' else 0.15)


if __name__ == '__main__':
    main()
