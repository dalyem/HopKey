'use strict';
// The release check: installs the real staged tarball (the one that is about
// to be published) and runs the Go binary it carries. It needs
//
//   HOPKEY_NPM_TARBALL   the packed hopkey tarball
//   HOPKEY_NPM_VERSION   the version it was staged with
//
// and skips itself without them, so that `node --test npm/test/` stays
// self-contained.

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { after, before, describe, test } = require('node:test');
const h = require('./helpers.js');

const tarball = process.env.HOPKEY_NPM_TARBALL;
const version = process.env.HOPKEY_NPM_VERSION;
const skip = tarball && version ? false : 'HOPKEY_NPM_TARBALL and HOPKEY_NPM_VERSION are not set';

// What the first bytes of each vendored binary must say, so that a build
// copied to the wrong directory is caught: [os, arch] -> the header.
function header(buf) {
  if (buf.length > 20 && buf.readUInt32BE(0) === 0x7f454c46) {
    // ELF: little endian, e_machine at 18.
    assert.equal(buf[5], 1, 'little-endian ELF');
    return { os: 'linux', arch: { 0x3e: 'x64', 0xb7: 'arm64' }[buf.readUInt16LE(18)] };
  }
  if (buf.length > 8 && buf.readUInt32LE(0) === 0xfeedfacf) {
    // 64-bit Mach-O: cputype at 4.
    return { os: 'darwin', arch: { 0x01000007: 'x64', 0x0100000c: 'arm64' }[buf.readUInt32LE(4)] };
  }
  return {};
}

describe('the staged package', { skip }, () => {
  const root = h.tmpdir('staged');
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  test('carries the right binary in every vendor directory, executable', () => {
    const inst = h.install(tarball, path.join(root, 'contents'), { ignoreScripts: true });
    assert.equal(JSON.parse(fs.readFileSync(path.join(inst.pkg, 'package.json'), 'utf8')).version, version);
    for (const [, dir] of h.BINARIES) {
      const file = path.join(inst.pkg, 'vendor', dir, 'hop');
      const mode = fs.statSync(file).mode;
      assert.equal(mode & 0o111, 0o111, `${dir} is executable`);
      const head = fs.readFileSync(file).subarray(0, 32);
      assert.deepEqual(header(head), { os: dir.split('-')[0], arch: dir.split('-')[1] }, `${dir} is a binary for ${dir}`);
    }
  });

  for (const ignoreScripts of [false, true]) {
    describe(ignoreScripts ? 'with --ignore-scripts' : 'with scripts', () => {
      let inst;
      before(() => {
        inst = h.install(tarball, root, { ignoreScripts });
      });
      const hop = (args) => spawnSync(inst.link, args, { env: inst.env, encoding: 'utf8' });

      test('hop version prints the release version and nothing else', () => {
        const r = hop(['version']);
        assert.equal(r.status, 0);
        assert.equal(r.stdout, `hop ${version}\n`);
        assert.equal(r.stderr, '');
      });

      test("hop's own failure exits 255 with stdout empty", () => {
        const r = hop(['--no-such-flag']);
        assert.equal(r.status, 255);
        assert.equal(r.stdout, '');
        assert.notEqual(r.stderr, '');
      });

      test('what hop runs is the vendored build, the native binary after a normal install', () => {
        const binHop = path.join(inst.pkg, 'bin', 'hop');
        const vendored = fs.readFileSync(path.join(inst.pkg, 'vendor', `${process.platform}-${process.arch}`, 'hop'));
        assert.equal(fs.readFileSync(binHop).equals(vendored), !ignoreScripts);
        assert.equal(fs.statSync(inst.link).ino, fs.statSync(binHop).ino);
      });
    });
  }
});
