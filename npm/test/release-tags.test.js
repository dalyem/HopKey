'use strict';
// scripts/release-tags.sh decides which rolling tags (npm latest, Docker
// latest and MAJOR.MINOR) a release may move. These run it as the workflow
// does: the existing tags on stdin, the version as the argument.

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

  test('a version that is not one is refused', () => {
    for (const bad of ['', 'v1.0.0', '1.0', '1.0.0; echo x']) {
      const res = spawnSync('sh', [SCRIPT, bad], { input: '', encoding: 'utf8' });
      assert.equal(res.status, 2, `${bad}: ${res.stdout}`);
      assert.equal(res.stdout, '');
    }
  });
});
