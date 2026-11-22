'use strict';
// scripts/npm-check-published.sh decides whether the release publishes to
// npm. The registry is a fake npm on the PATH that answers the way the real
// one did when this was written (npm 11: ETARGET for a missing version, E404
// for a missing package, ECONNREFUSED with the registry unreachable), so the
// tests need no network.

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { after, before, describe, test } = require('node:test');
const h = require('./helpers.js');

const SCRIPT = path.join(h.REPO, 'scripts', 'npm-check-published.sh');

const FAKE_NPM = `#!/bin/sh
# Only "npm pack SPEC ... --pack-destination DIR" is faked.
dest=
while [ $# -gt 0 ]; do
	[ "$1" = --pack-destination ] && dest=$2
	shift
done
case "$FAKE_NPM_MODE" in
fetch)
	cp "$FAKE_NPM_TARBALL" "$dest/dalyem-hopkey-1.2.3.tgz"
	;;
etarget)
	echo "npm error code ETARGET" >&2
	echo "npm error notarget No matching version found for @dalyem/hopkey@1.2.3." >&2
	exit 1
	;;
e404)
	echo "npm error code E404" >&2
	echo "npm error 404 Not Found - GET https://registry.npmjs.org/@dalyem%2fhopkey - Not found" >&2
	exit 1
	;;
down)
	echo "npm error code ECONNREFUSED" >&2
	echo "npm error request to https://registry.npmjs.org/@dalyem%2fhopkey failed" >&2
	exit 1
	;;
unknown)
	echo "npm error something else" >&2
	exit 1
	;;
esac
`;

describe('npm-check-published.sh', () => {
  const root = h.tmpdir('check-published');
  const bin = path.join(root, 'bin');
  before(() => {
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'npm'), FAKE_NPM, { mode: 0o755 });
  });
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  // tarball makes name.tgz holding package/<files>; a file whose name is in
  // exec gets mode 0755, the rest 0644.
  function tarball(name, files, exec = []) {
    const dir = path.join(root, name);
    fs.mkdirSync(path.join(dir, 'package'), { recursive: true });
    for (const [file, body] of Object.entries(files)) {
      const p = path.join(dir, 'package', file);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, body);
      fs.chmodSync(p, exec.includes(file) ? 0o755 : 0o644);
    }
    const out = path.join(root, `${name}.tgz`);
    execFileSync('tar', ['-czf', out, '-C', dir, 'package']);
    return out;
  }

  // check runs the script with the fake registry in the given mode.
  function check(mode, local, registry) {
    return spawnSync('sh', [SCRIPT, '@dalyem/hopkey', '1.2.3', local], {
      encoding: 'utf8',
      env: {
        PATH: `${bin}${path.delimiter}${process.env.PATH}`,
        FAKE_NPM_MODE: mode,
        FAKE_NPM_TARBALL: registry || '',
      },
    });
  }

  const files = { 'package.json': '{"version":"1.2.3"}\n', 'bin/hop': 'hop\n', 'README.md': 'readme\n' };

  test('a version the registry does not have is published=false', () => {
    const local = tarball('local-a', files);
    for (const mode of ['etarget', 'e404']) {
      const res = check(mode, local);
      assert.equal(res.status, 0, res.stderr);
      assert.equal(res.stdout, 'published=false\n');
    }
  });

  test('the same contents are published=true, whatever the archive metadata', () => {
    const local = tarball('local-b', files, ['bin/hop']);
    const registry = tarball('registry-b', files, ['bin/hop']);
    const res = check('fetch', local, registry);
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout, 'published=true\n');
  });

  test('different contents fail and name the files', () => {
    const local = tarball('local-c', { ...files, 'extra.txt': 'extra\n', 'README.md': 'new readme\n' });
    const registry = tarball('registry-c', files);
    const res = check('fetch', local, registry);
    assert.equal(res.status, 1);
    assert.equal(res.stdout, '');
    assert.match(res.stderr, /README\.md/);
    assert.match(res.stderr, /extra\.txt/);
  });

  test('a lost executable bit fails', () => {
    const local = tarball('local-d', files, ['bin/hop']);
    const registry = tarball('registry-d', files);
    const res = check('fetch', local, registry);
    assert.equal(res.status, 1);
    assert.equal(res.stdout, '');
    assert.match(res.stderr, /executable files differ/);
    assert.match(res.stderr, /bin\/hop/);
  });

  // Entries diff -r would follow or tar would place outside package/. Each
  // fixture is listed first, to show that the archive really holds the entry
  // (GNU tar strips or refuses some of these when asked the usual way).
  function listing(tgz) {
    return execFileSync('tar', ['-tvzf', tgz], { encoding: 'utf8' });
  }

  // linked makes name.tgz from package/{real.js,install.js,package.json}, with
  // install.js made by link(dir) instead of written as a regular file.
  function linked(name, link) {
    const dir = path.join(root, name);
    fs.mkdirSync(path.join(dir, 'package'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'package', 'package.json'), '{"version":"1.2.3"}\n');
    fs.writeFileSync(path.join(dir, 'package', 'real.js'), 'same\n');
    link(path.join(dir, 'package'));
    const out = path.join(root, `${name}.tgz`);
    execFileSync('tar', ['-czf', out, '-C', dir, 'package']);
    return out;
  }

  const symlink = (pkg) => fs.symlinkSync('real.js', path.join(pkg, 'install.js'));
  const hardlink = (pkg) => fs.linkSync(path.join(pkg, 'real.js'), path.join(pkg, 'install.js'));
  // The same content as a regular file, for the other side to match.
  const regular = (pkg) => fs.writeFileSync(path.join(pkg, 'install.js'), 'same\n');

  const unsafe = [
    ['a symlink', symlink, /^l.* package\/install\.js -> real\.js$/m, /install\.js/],
    ['a hard link', hardlink, /^h.* package\/(install|real)\.js link to package\/(install|real)\.js$/m, /install\.js/],
  ];
  for (const [what, link, entry, named] of unsafe) {
    for (const side of ['registry', 'local']) {
      test(`${what} in the ${side} tarball is refused, though the contents match`, () => {
        const tag = `${what.replace(/ /g, '-')}-${side}`;
        const bad = linked(`bad-${tag}`, link);
        const good = linked(`good-${tag}`, regular);
        assert.match(listing(bad), entry, 'the fixture holds the entry');
        assert.doesNotMatch(listing(good), /^[lh]/m);
        const res = side === 'registry' ? check('fetch', good, bad) : check('fetch', bad, good);
        assert.equal(res.status, 1, res.stdout + res.stderr);
        assert.equal(res.stdout, '');
        assert.match(res.stderr, named);
        assert.match(res.stderr, /not a regular file or a directory/);
      });
    }
  }

  for (const side of ['registry', 'local']) {
    test(`a path with .. in the ${side} tarball is refused and nothing is extracted`, () => {
      const dir = path.join(root, `dots-${side}`);
      fs.mkdirSync(path.join(dir, 'package'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'package', 'package.json'), '{"version":"1.2.3"}\n');
      fs.writeFileSync(path.join(dir, 'package', 'escape.txt'), 'out\n');
      const bad = path.join(root, `dots-${side}.tgz`);
      execFileSync('tar', ['-czf', bad, '-C', dir, '--transform', 's,^package/escape\\.txt$,package/../escape.txt,', 'package']);
      assert.match(execFileSync('tar', ['-tzf', bad], { encoding: 'utf8' }), /^package\/\.\.\/escape\.txt$/m, 'the fixture holds the entry');
      const good = tarball(`dots-good-${side}`, { 'package.json': '{"version":"1.2.3"}\n' });
      const res = side === 'registry' ? check('fetch', good, bad) : check('fetch', bad, good);
      assert.equal(res.status, 1, res.stdout + res.stderr);
      assert.equal(res.stdout, '');
      assert.match(res.stderr, /package\/\.\.\/escape\.txt/);
    });
  }

  test('a path outside package/ is refused', () => {
    const dir = path.join(root, 'outside');
    fs.mkdirSync(path.join(dir, 'package'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'package', 'package.json'), '{}\n');
    fs.writeFileSync(path.join(dir, 'other.txt'), 'x\n');
    const bad = path.join(root, 'outside.tgz');
    execFileSync('tar', ['-czf', bad, '-C', dir, 'package', 'other.txt']);
    const good = tarball('outside-good', { 'package.json': '{}\n' });
    const res = check('fetch', bad, good);
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.equal(res.stdout, '');
    assert.match(res.stderr, /other\.txt/);
  });

  test('a registry that cannot be reached, or that answers something else, fails and never says published=false', () => {
    const local = tarball('local-e', files);
    for (const mode of ['down', 'unknown']) {
      const res = check(mode, local);
      assert.equal(res.status, 1, mode);
      assert.equal(res.stdout, '', mode);
    }
  });

  test('a tarball that is not there is refused', () => {
    const res = check('etarget', path.join(root, 'nope.tgz'));
    assert.equal(res.status, 2);
    assert.equal(res.stdout, '');
  });
});
