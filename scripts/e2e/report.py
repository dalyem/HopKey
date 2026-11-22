#!/usr/bin/env python3
"""Merge the per-machine results into results.jsonl and write REPORT.md.

usage: report.py <out-dir> <run-id> <phases> <start-epoch> <end-epoch> <machines.env>
Runs on the orchestrator; it only reads JSON lines.

It also checks coverage with <out-dir>/steps.jsonl (the driver's step and
phase records): every selected phase must have started and ended, every step
must have finished with exit 0, and each machine the phase uses must have
reported checks. The verdict goes to <out-dir>/verdict, which run.sh exits with:
0 all pass, 1 assertion failures, 2 harness failures, 3 missing coverage.
A check with status limit is a documented limit of the product that holds as
documented: it is listed with its README reference and never counts as a failure.
<out-dir>/interrupted (a signal number), when present, is noted in the report:
run.sh then exits 128+n whatever the verdict, which covers only what ran.
"""
import glob
import json
import os
import sys
import time

out, run, phases, t0, t1, mach = sys.argv[1:7]
t0, t1 = int(t0), int(t1)
PH = {1: 'Local only, no account', 2: 'MCP', 3: 'Sync', 4: 'Real SSH over Tailscale', 5: 'Revocation matrix', 6: 'Key rotation on real sshd'}

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

# Coverage: which selected phases or steps did not finish.
MACHINES = {1: {'A', 'B'}, 2: {'A'}, 3: {'A', 'B'}, 4: {'A', 'B'}, 5: {'A', 'B'}, 6: {'A', 'B'}}
if any(r.get('id') == 'p6.A.rot-supported' and r.get('status') == 'skip' and str(r.get('detail', '')).startswith('confirmed absent')
       for r in rows):
    MACHINES[6] = {'A'}  # a build without hop key rotate: A records the skip, B has nothing to do
steps = []
try:
    for line in open(os.path.join(out, 'steps.jsonl')):
        try:
            steps.append(json.loads(line))
        except ValueError:
            pass
except OSError:
    pass
gaps = []
started = {}
for e in steps:
    if e.get('event') == 'start':
        started[e.get('job')] = e
    elif e.get('event') == 'end':
        st = started.pop(e.get('job'), None)
        if e.get('rc') != '0':
            gaps.append('phase %s: step %s on %s ended with %s' % (e.get('phase'), e.get('step'), e.get('who'), e.get('rc') or 'no exit code'))
for e in started.values():
    gaps.append('phase %s: step %s on %s never finished (nobody waited for it)' % (e.get('phase'), e.get('step'), e.get('who')))
for p in sel:
    ev = {e.get('event') for e in steps if e.get('phase') == p and e.get('who') == 'driver'}
    if 'phase-start' not in ev:
        gaps.append('phase %d: never started' % p)
    elif 'phase-end' not in ev:
        gaps.append('phase %d: stopped before its end' % p)
    got = {r.get('machine') for r in rows if r.get('phase') == p}
    for m in sorted(MACHINES.get(p, set()) - got):
        gaps.append('phase %d: no checks from %s' % (p, m))
harness_rows = [r for r in rows if r.get('status') == 'fail' and r.get('bug') == 'harness']
fail_rows = [r for r in rows if r.get('status') == 'fail']
verdict = 3 if gaps else 2 if harness_rows else 1 if fail_rows else 0
VERDICT = {0: 'pass', 1: 'assertion failures', 2: 'harness failures', 3: 'missing coverage'}

md = ['# HopKey end-to-end report: run %s' % run, '']
md.append('**Verdict: %s** (exit %d)' % (VERDICT[verdict], verdict))
md.append('')
try:
    sig = int(open(os.path.join(out, 'interrupted')).read().strip())
except (OSError, ValueError):
    sig = 0
if sig:
    md.append('**Interrupted by signal %d**: run.sh exits %d whatever the verdict. The verdict covers only the checks that ran; '
              'the coverage section lists what did not.' % (sig, 128 + sig))
    md.append('')
md.append('- Time: %s to %s UTC (%dm%02ds)' % (time.strftime('%Y-%m-%d %H:%M', time.gmtime(t0)), time.strftime('%H:%M', time.gmtime(t1)),
                                             (t1 - t0) // 60, (t1 - t0) % 60))
md.append('- Phases selected: %s' % phases)
md.append('- Machines: ' + ', '.join('%s `%s`' % (k, v) for k, v in machines.items() if v))
def envfile(name):
    d = {}
    try:
        for line in open(os.path.join(out, name)):
            k, _, v = line.rstrip('\n').partition('=')
            d[k] = v
    except OSError:
        pass
    return d


src, ident = envfile('source.env'), envfile('identity.env')
if ident:
    md.append('- Kiln identity: %s (%s, `%s`), harness %s' % (ident.get('KILN_NAME'), ident.get('KILN_KIND'), ident.get('KILN_PRINCIPAL'),
                                                         ident.get('KILN_HARNESS')))
if src:
    md.append('- Source: `%s`, branch `%s`, commit `%s`%s; suite commit `%s`' % (
        src.get('SOURCE_DIR'), src.get('SOURCE_BRANCH'), src.get('SOURCE_COMMIT', '?')[:12],
        ' (dirty: %s)' % src.get('SOURCE_CHANGED', '').strip() if src.get('SOURCE_DIRTY') == '1' else '', src.get('SUITE_COMMIT')))
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
          '(`r1-` is /tmp/hk/e2e/REPORT.md, `r2-` is REPORT-r2.md). `harness` marks a failure of the test harness itself. '
          'Checks named `rev2-*` (revocation enforcement) and `rot-*` (key rotation) test features newer than those reports; on a build '
          'without them they fail under the r2 bug they close, or are skipped when the command is confirmed absent (a failed detection is a '
          'harness failure). Where the README documents a limit, the check asserts the documented behaviour: status `limit` means it holds '
          'as documented (listed under Documented limits, not a failure, no effect on the exit code), and a FAIL means the product differs '
          'from its documentation. A revoked device that is offline keeps working until it reaches the server (README, What revocation does, '
          'Offline): scenario s3 asserts that, then the cutoff after it reconnects. Cleanup outcomes (auth key deletion, release, the check '
          'that every machine is gone) are phase 0 checks; this report is written after them.')
md.append('')
md.append('## Summary')
md.append('')
md.append('| Phase | Pass | Fail | Skip | Limit | Known-bug fails | Other fails |')
md.append('| --- | ---: | ---: | ---: | ---: | ---: | ---: |')
tot = {'pass': 0, 'fail': 0, 'skip': 0, 'limit': 0}
for p in sorted(set(sel) | {r.get('phase') for r in rows if isinstance(r.get('phase'), int)}):
    pr = [r for r in rows if r.get('phase') == p]
    n = {s: sum(1 for r in pr if r['status'] == s) for s in tot}
    for k in tot:
        tot[k] += n[k]
    kb = sum(1 for r in pr if r['status'] == 'fail' and r.get('bug') and r['bug'] != 'harness')
    md.append('| %s. %s | %d | %d | %d | %d | %d | %d |' % (p, PH.get(p, 'setup'), n['pass'], n['fail'], n['skip'], n['limit'], kb, n['fail'] - kb))
md.append('| **Total** | **%d** | **%d** | **%d** | **%d** | | |' % (tot['pass'], tot['fail'], tot['skip'], tot['limit']))
md.append('')
md.append('## Coverage')
md.append('')
if gaps:
    md.extend('- %s' % g for g in gaps)
else:
    md.append('Every selected phase ran to its end, every step finished with exit 0, and every machine reported checks.')
md.append('')

lims = [r for r in rows if r['status'] == 'limit']
md.append('## Documented limits')
md.append('')
if lims:
    md.append('Behaviour the README documents as a limit, observed as documented. Not failures; they do not affect the exit code.')
    md.append('')
    md.append('| Check | Machine | Bug | Observed | README |')
    md.append('| --- | --- | --- | --- | --- |')
    for r in lims:
        md.append('| `%s` %s | %s | %s | %s | %s |' % (r['id'], esc(r['name']), r.get('machine', ''), r.get('bug') or '', esc(r.get('detail'))[:300],
                                                  esc(r.get('ref'))))
else:
    md.append('None observed.')
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
        st = {'pass': 'PASS', 'fail': '**FAIL**', 'skip': 'skip', 'limit': 'limit'}.get(r['status'], r['status'])
        md.append('| `%s` %s | %s | %s | %s | %s |' % (r['id'], esc(r['name']), r.get('machine', ''), st, r.get('bug') or '', esc(r.get('detail'))[:300]))
    md.append('')

with open(os.path.join(out, 'REPORT.md'), 'w') as f:
    f.write('\n'.join(md) + '\n')
with open(os.path.join(out, 'verdict'), 'w') as f:
    f.write('%d\n' % verdict)
print('report: %d checks, %d pass, %d fail (%d harness), %d skip, %d limit, %d coverage gaps: verdict %d (%s)' % (
    len(rows), tot['pass'], tot['fail'], len(harness_rows), tot['skip'], tot['limit'], len(gaps), verdict, VERDICT[verdict]))
