#!/usr/bin/env python3
"""Merge the per-machine results into results.jsonl and write REPORT.md.

usage: report.py <out-dir> <run-id> <phases> <start-epoch> <end-epoch> <machines.env>
Runs on the orchestrator; it only reads JSON lines.
"""
import glob
import json
import os
import sys
import time

out, run, phases, t0, t1, mach = sys.argv[1:7]
t0, t1 = int(t0), int(t1)
PH = {1: 'Local only, no account', 2: 'MCP', 3: 'Sync', 4: 'Real SSH over Tailscale', 5: 'Revocation matrix'}

rows = []
for f in sorted(glob.glob(os.path.join(out, 'results', '*.jsonl'))):
    for line in open(f, errors='replace'):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            rows.append({'phase': 0, 'id': 'harness.unparsable', 'name': 'unparsable result line in %s' % os.path.basename(f),
                         'status': 'fail', 'detail': line[:200], 'evidence': '', 'bug': 'harness', 'machine': '?'})
rows.sort(key=lambda r: (str(r.get('phase')), r.get('ts', '')))
with open(os.path.join(out, 'results.jsonl'), 'w') as f:
    for r in rows:
        f.write(json.dumps(r) + '\n')

machines = {}
try:
    for line in open(mach):
        k, _, v = line.strip().partition('=')
        machines[k] = v
except OSError:
    pass


def esc(s):
    return str(s or '').replace('|', '\\|').replace('\n', ' ')


sel = [int(p) for p in phases.split(',') if p.strip().isdigit()]
md = ['# HopKey end-to-end report: run %s' % run, '']
md.append('- Time: %s to %s UTC (%dm%02ds)' % (time.strftime('%Y-%m-%d %H:%M', time.gmtime(t0)), time.strftime('%H:%M', time.gmtime(t1)),
                                             (t1 - t0) // 60, (t1 - t0) % 60))
md.append('- Phases selected: %s' % phases)
md.append('- Machines: ' + ', '.join('%s `%s`' % (k, v) for k, v in machines.items() if v))
try:
    b = json.load(open(os.path.join(out, 'build.json')))
    sn = b.get('snapshot', {})
    md.append('- Build: commit `%s`%s, branch `%s`, job `%s`' % (sn.get('commit', '?')[:12], ' (dirty)' if sn.get('dirty') else '',
                                                             sn.get('branch', '?'), b['operation']['id']))
except Exception:
    md.append('- Build: unknown (no build.json)')
try:
    md.append('- Binaries: ' + ', '.join('`%s` %s' % (l.split()[1], l.split()[0][:16]) for l in open(os.path.join(out, 'bin', 'SHA256SUMS'))))
except OSError:
    pass
md.append('')
md.append('Assertions encode the intended behaviour. A known product gap shows up as FAIL with its bug ID from the earlier reports '
          '(`r1-` is /tmp/hk/e2e/REPORT.md, `r2-` is REPORT-r2.md). `harness` marks a failure of the test harness itself.')
md.append('')
md.append('## Summary')
md.append('')
md.append('| Phase | Pass | Fail | Skip | Known-bug fails | Other fails |')
md.append('| --- | ---: | ---: | ---: | ---: | ---: |')
tot = {'pass': 0, 'fail': 0, 'skip': 0}
for p in sorted(set(sel) | {r.get('phase') for r in rows if isinstance(r.get('phase'), int)}):
    pr = [r for r in rows if r.get('phase') == p]
    n = {s: sum(1 for r in pr if r['status'] == s) for s in ('pass', 'fail', 'skip')}
    for k in tot:
        tot[k] += n[k]
    kb = sum(1 for r in pr if r['status'] == 'fail' and r.get('bug') and r['bug'] != 'harness')
    md.append('| %s. %s | %d | %d | %d | %d | %d |' % (p, PH.get(p, 'setup'), n['pass'], n['fail'], n['skip'], kb, n['fail'] - kb))
md.append('| **Total** | **%d** | **%d** | **%d** | | |' % (tot['pass'], tot['fail'], tot['skip']))
md.append('')

fails = [r for r in rows if r['status'] == 'fail']
if fails:
    md.append('## Failures')
    md.append('')
    by_bug = {}
    for r in fails:
        by_bug.setdefault(r.get('bug') or 'untagged', []).append(r)
    md.append('| Bug | Checks |')
    md.append('| --- | --- |')
    for bug in sorted(by_bug):
        md.append('| %s | %s |' % (bug, ', '.join('`%s`' % r['id'] for r in by_bug[bug])))
    md.append('')
    for r in fails:
        md.append('### `%s` (%s)%s' % (r['id'], r.get('machine', '?'), ' [%s]' % r['bug'] if r.get('bug') else ''))
        md.append('')
        md.append('- %s' % r['name'])
        if r.get('detail'):
            md.append('- Detail: %s' % esc(r['detail']))
        if r.get('evidence'):
            md.append('')
            md.append('```')
            md.append(str(r['evidence'])[:1200])
            md.append('```')
        md.append('')

for p in sorted({r.get('phase') for r in rows}, key=str):
    pr = [r for r in rows if r.get('phase') == p]
    md.append('## Phase %s: %s' % (p, PH.get(p, 'setup')))
    md.append('')
    md.append('| Check | Machine | Status | Bug | Detail |')
    md.append('| --- | --- | --- | --- | --- |')
    for r in pr:
        st = {'pass': 'PASS', 'fail': '**FAIL**', 'skip': 'skip'}.get(r['status'], r['status'])
        md.append('| `%s` %s | %s | %s | %s | %s |' % (r['id'], esc(r['name']), r.get('machine', ''), st, r.get('bug') or '', esc(r.get('detail'))[:300]))
    md.append('')

with open(os.path.join(out, 'REPORT.md'), 'w') as f:
    f.write('\n'.join(md) + '\n')
print('report: %d checks, %d pass, %d fail, %d skip' % (len(rows), tot['pass'], tot['fail'], tot['skip']))
