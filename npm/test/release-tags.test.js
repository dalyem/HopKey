'use strict';
// scripts/release-tags.sh decides which rolling tags (npm latest, Docker
// latest and MAJOR.MINOR) a release may move. These run it as the workflow
// does: the existing tags on stdin, the version as the argument. A release
// version is MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-(alpha|beta|rc).N; within
// that format the script's sort -V agrees with SemVer order, which "SemVer
// order" below checks against an implementation of the SemVer rules.

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { describe, test } = require('node:test');
const h = require('./helpers.js');

const SCRIPT = path.join(h.REPO, 'scripts', 'release-tags.sh');

// run returns what the script prints as an object: { npm_tag, docker_latest,
// docker_minor }.
function run(version, tags) {
  const res = spawnSync('sh', [SCRIPT, version], { input: tags.join('\n') + '\n', encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  const out = {};
  for (const line of res.stdout.trim().split('\n')) {
    const i = line.indexOf('=');
    out[line.slice(0, i)] = line.slice(i + 1);
  }
  assert.deepEqual(Object.keys(out), ['npm_tag', 'docker_latest', 'docker_minor']);
  return out;
}

// semverCompare implements SemVer 2.0.0 precedence (section 11) for any
// version, not only the release format: negative if a < b, 0 if equal.
function semverCompare(a, b) {
  const parse = (v) => {
    const [core, pre] = v.split(/-(.*)/s);
    return { nums: core.split('.').map(Number), pre: pre === undefined ? null : pre.split('.') };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    if (x.nums[i] !== y.nums[i]) return x.nums[i] < y.nums[i] ? -1 : 1;
  }
  if (x.pre === null || y.pre === null) return x.pre === y.pre ? 0 : x.pre === null ? 1 : -1;
  for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    if (p === q) continue;
    const pn = /^[0-9]+$/.test(p);
    const qn = /^[0-9]+$/.test(q);
    if (pn && qn) return Number(p) < Number(q) ? -1 : 1;
    if (pn !== qn) return pn ? -1 : 1;
    return p < q ? -1 : 1;
  }
  return Math.sign(x.pre.length - y.pre.length);
}

const latest = { npm_tag: 'latest', docker_latest: 'true', docker_minor: 'true' };

describe('a stable release', () => {
  test('the first one takes everything', () => {
    assert.deepEqual(run('1.0.0', []), latest);
    assert.deepEqual(run('1.0.0', ['v1.0.0']), latest);
  });

  test('a newer one takes everything', () => {
    assert.deepEqual(run('1.2.0', ['v1.0.0', 'v1.1.0', 'v1.2.0']), latest);
    assert.deepEqual(run('1.2.0', ['v1.0.0', 'v1.1.0']), latest);
  });

  test('an older patch of the newest minor takes nothing but its own version', () => {
    assert.deepEqual(run('1.1.0', ['v1.0.0', 'v1.1.0', 'v1.1.1']), {
      npm_tag: 'release-1.1',
      docker_latest: 'false',
      docker_minor: 'false',
    });
  });

  test('an older minor, newest of its own, takes its MAJOR.MINOR only', () => {
    assert.deepEqual(run('1.0.5', ['v1.0.0', 'v1.0.4', 'v1.0.5', 'v1.1.0']), {
      npm_tag: 'release-1.0',
      docker_latest: 'false',
      docker_minor: 'true',
    });
  });

  test('1.10.0 is newer than 1.9.0, and 1.9.1 is older than 1.10.0', () => {
    assert.deepEqual(run('1.10.0', ['v1.9.0', 'v1.10.0']), latest);
    assert.deepEqual(run('1.9.1', ['v1.9.0', 'v1.9.1', 'v1.10.0']), {
      npm_tag: 'release-1.9',
      docker_latest: 'false',
      docker_minor: 'true',
    });
  });

  test('1.1 is not 1.10 and 1.10 is not 1.1', () => {
    assert.equal(run('1.1.9', ['v1.10.0', 'v1.1.0', 'v1.1.9']).docker_minor, 'true');
    assert.equal(run('1.10.1', ['v1.1.9', 'v1.10.0', 'v1.10.1']).docker_minor, 'true');
    assert.equal(run('1.10.0', ['v1.10.0', 'v1.10.1']).docker_minor, 'false');
  });

  test('a major version counts above every minor', () => {
    assert.deepEqual(run('2.0.0', ['v1.9.9', 'v2.0.0']), latest);
    assert.equal(run('1.9.10', ['v2.0.0', 'v1.9.10']).npm_tag, 'release-1.9');
  });

  test('prereleases never count against a stable release', () => {
    assert.deepEqual(run('1.0.0', ['v1.0.0-rc.1', 'v1.1.0-rc.1', 'v1.0.0']), latest);
  });
});

describe('a prerelease', () => {
  const next = { npm_tag: 'next', docker_latest: 'false', docker_minor: 'false' };

  test('the first one is next', () => {
    assert.deepEqual(run('1.0.0-rc.1', []), next);
    assert.deepEqual(run('1.0.0-rc.1', ['v1.0.0-rc.1']), next);
  });

  test('never moves latest or MAJOR.MINOR, even above every stable tag', () => {
    assert.deepEqual(run('2.0.0-rc.1', ['v1.0.0', 'v2.0.0-rc.1']), next);
  });

  test('rc.10 is newer than rc.2', () => {
    assert.deepEqual(run('1.0.0-rc.10', ['v1.0.0-rc.2', 'v1.0.0-rc.10']), next);
    assert.deepEqual(run('1.0.0-rc.2', ['v1.0.0-rc.2', 'v1.0.0-rc.10']), {
      npm_tag: 'prerelease-old',
      docker_latest: 'false',
      docker_minor: 'false',
    });
  });

  test('one older than an existing prerelease is not next', () => {
    assert.equal(run('1.0.0-rc.1', ['v1.0.0-rc.1', 'v1.0.0-rc.2']).npm_tag, 'prerelease-old');
    assert.equal(run('1.0.0-beta.1', ['v1.1.0-alpha.1']).npm_tag, 'prerelease-old');
  });

  test('stable tags do not count against it', () => {
    assert.equal(run('1.0.0-rc.1', ['v1.0.0', 'v1.0.0-rc.1']).npm_tag, 'next');
  });
});

describe('SemVer order', () => {
  // Ascending, by the SemVer rules (checked below, not assumed).
  const ascending = [
    '1.0.0-alpha.1',
    '1.0.0-alpha.2',
    '1.0.0-alpha.10',
    '1.0.0-beta.1',
    '1.0.0-rc.1',
    '1.0.0-rc.2',
    '1.0.0-rc.10',
    '1.9.0-rc.1',
    '1.10.0-rc.1',
    '2.0.0-rc.1',
    '10.0.0-rc.1',
  ];

  test('the table is in SemVer order', () => {
    for (let i = 1; i < ascending.length; i++) {
      assert.ok(semverCompare(ascending[i - 1], ascending[i]) < 0, `${ascending[i - 1]} < ${ascending[i]}`);
    }
    // And the comparator is not the script's: it knows rc.a10 < rc.a2.
    assert.ok(semverCompare('1.0.0-rc.a10', '1.0.0-rc.a2') < 0);
  });

  test('the script agrees for every pair: a prerelease is next only if it is the newer', () => {
    for (let i = 0; i < ascending.length; i++) {
      for (let j = 0; j < ascending.length; j++) {
        if (i === j) continue;
        const got = run(ascending[i], ['v' + ascending[i], 'v' + ascending[j]]).npm_tag;
        const want = semverCompare(ascending[i], ascending[j]) > 0 ? 'next' : 'prerelease-old';
        assert.equal(got, want, `${ascending[i]} against ${ascending[j]}`);
      }
    }
  });

  test('the newest of the whole table is next, and no other is', () => {
    const tags = ascending.map((v) => 'v' + v);
    for (const v of ascending) {
      assert.equal(run(v, tags).npm_tag, v === ascending[ascending.length - 1] ? 'next' : 'prerelease-old', v);
    }
  });

  test('1.9.0-rc.1 is older than 1.10.0-rc.1, and 2.0.0-rc.1 older than 10.0.0-rc.1', () => {
    assert.equal(run('1.9.0-rc.1', ['v1.10.0-rc.1']).npm_tag, 'prerelease-old');
    assert.equal(run('1.10.0-rc.1', ['v1.9.0-rc.1']).npm_tag, 'next');
    assert.equal(run('2.0.0-rc.1', ['v10.0.0-rc.1']).npm_tag, 'prerelease-old');
  });
});

describe('the tag list', () => {
  test('lines that are not release tags are ignored', () => {
    const junk = ['', 'latest', 'v1', 'v1.2', 'v1.2.3.4', 'v01.2.3', 'v9.9.9-', '1.9.9', 'vx.y.z', 'release-9.9', 'v9.9.9 ', 'v9.9.9\r', 'refs/tags/v9.9.9'];
    assert.deepEqual(run('1.0.0', junk), latest);
    assert.deepEqual(run('1.0.0-rc.1', junk), { npm_tag: 'next', docker_latest: 'false', docker_minor: 'false' });
  });

  test('an empty list is the first release', () => {
    const res = spawnSync('sh', [SCRIPT, '0.1.0'], { input: '', encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout, 'npm_tag=latest\ndocker_latest=true\ndocker_minor=true\n');
  });

  // Valid SemVer, but not a format a release may use: its order would not be
  // the one sort -V gives.
  const refused = [
    '1.0.0-rc.a10',
    '1.0.0-denied',
    '1.0.0-rc',
    '1.0.0-rc.01',
    '1.0.0-rc.1.1',
    '1.0.0-RC.1',
    '1.0.0-alpha',
    '1.0.0-rc.-1',
    '1.0.0-rc.1-x',
    '1.0.0-gamma.1',
    '1.0.0-foo',
    '1.0.0-0',
    '1.0.0+build.1',
    '1.0.0-rc.1+build.1',
    '01.0.0',
    '1.0.0-',
  ];

  test('a version that is not one is refused', () => {
    for (const bad of ['', 'v1.0.0', '1.0', '1.0.0; echo x', ...refused]) {
      const res = spawnSync('sh', [SCRIPT, bad], { input: '', encoding: 'utf8' });
      assert.equal(res.status, 2, `${bad}: ${res.stdout}`);
      assert.equal(res.stdout, '');
    }
  });

  test('a tag of a refused format is ignored, whatever it would sort as', () => {
    const tags = refused.map((v) => 'v' + v);
    assert.deepEqual(run('1.0.0', tags), latest);
    assert.deepEqual(run('1.0.0-rc.1', tags), { npm_tag: 'next', docker_latest: 'false', docker_minor: 'false' });
    // rc.1.1 would sort above rc.99 under sort -V; it must not count.
    assert.equal(run('1.0.0-rc.99', ['v1.0.0-rc.1.1']).npm_tag, 'next');
  });
});
