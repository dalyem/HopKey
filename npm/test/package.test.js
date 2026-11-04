'use strict';
// Tests run against a real packed tarball, installed with npm into a
// throwaway prefix, once with the postinstall and once with --ignore-scripts.
// The "binaries" are copies of fake-hop.js.

const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { after, before, describe, test } = require('node:test');
const h = require('./helpers.js');

const PLATFORM = `${process.platform}-${process.arch}`;
const VENDOR = { 'linux-x64': 1, 'linux-arm64': 1, 'darwin-x64': 1, 'darwin-arm64': 1 };
const SHEBANG = '#!/usr/bin/env node\n';

const root = h.tmpdir('pkg');
let tarball;

before(() => {
  assert.ok(PLATFORM in VENDOR, `these tests need linux or darwin on x64 or arm64, not ${PLATFORM}`);
  tarball = h.pack(h.stagePackage(root, '1.2.3-test.1'), path.join(root, 'tarball'));
});
// Processes the tests start and may leave running when one fails.
const started = new Set();
after(() => {
  for (const pid of started) {
    try {
      process.kill(pid, 'SIGKILL');
    } catch (e) {
      // Gone already.
    }
  }
  fs.rmSync(root, { recursive: true, force: true });
});

function hopOf(inst) {
  return (args, opts) => spawnSync(inst.link, args, { env: inst.env, ...opts });
}

function waitFor(file, ms = 10000) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      if (fs.existsSync(file) && fs.readFileSync(file, 'utf8') !== '') return resolve(fs.readFileSync(file, 'utf8'));
      if (Date.now() - t0 > ms) return reject(new Error(`timed out waiting for ${file}`));
      setTimeout(tick, 20);
    };
    tick();
  });
}

// startWaiter starts `hop wait` and returns once hop has installed its
// handlers: the process started, a promise of how it ends, hop's own pid, and
// the file it logs the signals it gets to.
async function startWaiter(inst, tag) {
  const ready = path.join(root, `ready-${tag}`);
  const log = path.join(root, `log-${tag}`);
  const p = spawn(inst.link, ['wait', ready, log], { env: inst.env, stdio: 'ignore' });
  started.add(p.pid);
  const exited = new Promise((r) => p.on('exit', (code, signal) => r({ code, signal })));
  const hopPid = Number(await waitFor(ready));
  started.add(hopPid);
  return { p, exited, hopPid, log };
}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

for (const ignoreScripts of [false, true]) {
  describe(ignoreScripts ? 'installed with --ignore-scripts (the shim)' : 'installed with scripts (the native binary)', () => {
    let inst;
    let hop;
    before(() => {
      inst = h.install(tarball, root, { ignoreScripts });
      hop = hopOf(inst);
    });

    test('bin/hop is the native binary after a normal install and the shim after --ignore-scripts', () => {
      const binHop = path.join(inst.pkg, 'bin', 'hop');
      const vendored = path.join(inst.pkg, 'vendor', PLATFORM, 'hop');
      const content = fs.readFileSync(binHop);
      assert.ok(fs.statSync(binHop).mode & 0o111, 'bin/hop is executable');
      if (ignoreScripts) {
        assert.equal(content.toString().split('\n')[0] + '\n', SHEBANG);
        assert.match(content.toString(), /lib\/shim\.js/);
      } else {
        assert.deepEqual(content, fs.readFileSync(vendored), 'bin/hop is a copy of the vendored binary');
        assert.notEqual(fs.statSync(binHop).ino, fs.statSync(vendored).ino, 'a copy, not the same inode');
      }
      // The link on PATH leads to bin/hop, which is the file hop's own
      // path check (os.SameFile) compares.
      assert.equal(fs.statSync(inst.link).ino, fs.statSync(binHop).ino);
      assert.deepEqual(fs.readdirSync(path.join(inst.pkg, 'bin')), ['hop'], 'no temp file is left');
    });

    test('every vendored binary is executable', () => {
      for (const dir of Object.keys(VENDOR)) {
        const mode = fs.statSync(path.join(inst.pkg, 'vendor', dir, 'hop')).mode;
        assert.equal(mode & 0o111, 0o111, `${dir}: mode ${(mode & 0o777).toString(8)}`);
      }
    });

    test('exit codes pass through', () => {
      for (const code of [0, 3, 75, 255]) {
        const r = hop(['exit', String(code)]);
        assert.equal(r.status, code);
        assert.equal(r.signal, null);
      }
    });

    test('a hop killed by a signal is reported as that signal', () => {
      for (const sig of ['SIGUSR2', 'SIGTERM', 'SIGINT', 'SIGHUP']) {
        const r = hop(['signal', sig]);
        assert.equal(r.signal, sig);
        assert.equal(r.status, null);
      }
    });

    test('stdin and stdout are passed byte for byte, and stderr too', () => {
      // More than a pipe holds, with every byte value in it.
      const input = Buffer.alloc(512 * 1024);
      for (let i = 0; i < input.length; i++) input[i] = (i * 7 + (i >> 8)) & 0xff;
      const r = hop(['cat'], { input, maxBuffer: 8 << 20 });
      assert.equal(r.status, 0);
      assert.ok(input.equals(r.stdout), 'stdout equals stdin');
      assert.equal(r.stderr.length, 0);

      const b = hop(['bytes']);
      const all = Buffer.alloc(256);
      for (let i = 0; i < 256; i++) all[i] = i;
      assert.ok(all.equals(b.stdout));
      assert.ok(Buffer.from([0x65, 0x72, 0x72, 0xff]).equals(b.stderr));
    });

    test('nothing is added to stdout or stderr', () => {
      const r = hop(['exit', '0']);
      assert.equal(r.stdout.length, 0);
      assert.equal(r.stderr.length, 0);
    });

    test('SIGTERM reaches hop', async () => {
      const w = await startWaiter(inst, `term-${ignoreScripts}`);
      w.p.kill('SIGTERM');
      assert.deepEqual(await w.exited, { code: 0, signal: null });
      assert.equal(fs.readFileSync(w.log, 'utf8'), 'SIGTERM\n');
    });

    test(ignoreScripts ? 'SIGINT to the shim alone is not forwarded' : 'SIGINT goes to hop itself, there is no shim', async () => {
      const w = await startWaiter(inst, `int-${ignoreScripts}`);
      if (ignoreScripts) {
        assert.notEqual(w.hopPid, w.p.pid, 'hop runs under the shim');
      } else {
        assert.equal(w.hopPid, w.p.pid, 'hop is the process that was started');
      }
      w.p.kill('SIGINT');
      w.p.kill('SIGHUP');
      await pause(500);
      if (ignoreScripts) {
        assert.equal(w.p.exitCode, null, 'the shim survives SIGINT and SIGHUP');
        assert.equal(fs.existsSync(w.log), false, 'hop got neither');
      } else {
        // The fake logs what it gets, as hop catching them would.
        assert.deepEqual(fs.readFileSync(w.log, 'utf8').split('\n').filter(Boolean).sort(), ['SIGHUP', 'SIGINT']);
      }
      w.p.kill('SIGTERM');
      assert.deepEqual(await w.exited, { code: 0, signal: null });
    });
  });
}

describe('an install the postinstall cannot finish', () => {
  test('exits 0, leaves the shim, and the shim says why', () => {
    // A package with no vendor directory: the postinstall finds nothing to copy.
    const dir = path.join(root, 'novendor');
    fs.mkdirSync(path.join(dir, 'bin'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'lib'));
    for (const f of ['install.js', 'README.md']) fs.copyFileSync(path.join(h.NPM_DIR, f), path.join(dir, f));
    for (const f of ['platform.js', 'shim.js']) fs.copyFileSync(path.join(h.NPM_DIR, 'lib', f), path.join(dir, 'lib', f));
    fs.copyFileSync(path.join(h.NPM_DIR, 'bin', 'hop'), path.join(dir, 'bin', 'hop'));
    fs.chmodSync(path.join(dir, 'bin', 'hop'), 0o755);
    const pj = JSON.parse(fs.readFileSync(path.join(h.NPM_DIR, 'package.json'), 'utf8'));
    pj.version = '1.0.0';
    delete pj.private;
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pj));

    const inst = h.install(h.pack(dir, path.join(root, 'tarball-novendor')), path.join(root, 'novendor-root'), { ignoreScripts: false });
    assert.equal(inst.out.trim(), `added 1 package in ${inst.out.trim().split(' in ')[1]}`, 'npm printed nothing of its own');
    assert.ok(fs.readFileSync(path.join(inst.pkg, 'bin', 'hop'), 'utf8').startsWith(SHEBANG), 'still the shim');
    const r = spawnSync(inst.link, ['exit', '0'], { env: inst.env, encoding: 'utf8' });
    assert.equal(r.status, 255);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, new RegExp(`^hop: the binary for ${PLATFORM} is missing from this install \\(.*\\); reinstall the hopkey package\\n$`));
  });

  test('install() leaves bin/hop alone when the vendored file is not a file', () => {
    const { install } = require(path.join(h.NPM_DIR, 'install.js'));
    const dir = path.join(root, 'notafile');
    fs.mkdirSync(path.join(dir, 'bin'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'vendor', PLATFORM, 'hop'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'bin', 'hop'), 'shim');
    assert.equal(install({ root: dir, platform: process.platform, arch: process.arch }), false);
    assert.equal(fs.readFileSync(path.join(dir, 'bin', 'hop'), 'utf8'), 'shim');
    assert.deepEqual(fs.readdirSync(path.join(dir, 'bin')), ['hop']);
  });

  test('install() leaves bin/hop alone and no temp file when the rename fails', () => {
    const { install } = require(path.join(h.NPM_DIR, 'install.js'));
    const dir = path.join(root, 'norename');
    fs.mkdirSync(path.join(dir, 'vendor', PLATFORM), { recursive: true });
    fs.writeFileSync(path.join(dir, 'vendor', PLATFORM, 'hop'), 'native');
    // bin/hop is a non-empty directory: the rename onto it fails.
    fs.mkdirSync(path.join(dir, 'bin', 'hop'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'bin', 'hop', 'x'), '');
    assert.equal(install({ root: dir, platform: process.platform, arch: process.arch }), false);
    assert.deepEqual(fs.readdirSync(path.join(dir, 'bin')), ['hop']);
  });
});

describe('install.js', () => {
  const { install } = require(path.join(h.NPM_DIR, 'install.js'));

  // A package directory with the shim in bin/hop and, optionally, a vendored binary.
  function pkgDir(name, { vendored }) {
    const dir = path.join(root, name);
    fs.mkdirSync(path.join(dir, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'bin', 'hop'), 'shim');
    fs.copyFileSync(path.join(h.NPM_DIR, 'install.js'), path.join(dir, 'install.js'));
    fs.cpSync(path.join(h.NPM_DIR, 'lib'), path.join(dir, 'lib'), { recursive: true });
    if (vendored) {
      fs.mkdirSync(path.join(dir, 'vendor', PLATFORM), { recursive: true });
      fs.writeFileSync(path.join(dir, 'vendor', PLATFORM, 'hop'), 'native');
    }
    return dir;
  }

  test('replaces bin/hop through a new inode and never writes into the old one', () => {
    const dir = pkgDir('replace', { vendored: true });
    const old = path.join(dir, 'old-hop');
    fs.linkSync(path.join(dir, 'bin', 'hop'), old);
    const before = fs.statSync(old).ino;
    assert.equal(install({ root: dir, platform: process.platform, arch: process.arch }), true);
    const after = fs.statSync(path.join(dir, 'bin', 'hop'));
    assert.notEqual(after.ino, before);
    assert.equal(fs.readFileSync(path.join(dir, 'bin', 'hop'), 'utf8'), 'native');
    assert.equal(after.mode & 0o777, 0o755);
    assert.equal(fs.readFileSync(old, 'utf8'), 'shim', 'the old inode is untouched');
    assert.deepEqual(fs.readdirSync(path.join(dir, 'bin')), ['hop']);
  });

  for (const vendored of [true, false]) {
    test(`run as the postinstall, ${vendored ? 'with' : 'without'} a binary to install, it prints nothing and exits 0`, () => {
      const dir = pkgDir(`quiet-${vendored}`, { vendored });
      const r = spawnSync(process.execPath, [path.join(dir, 'install.js')], { cwd: dir, encoding: 'utf8' });
      assert.equal(r.status, 0);
      assert.equal(r.stdout, '');
      assert.equal(r.stderr, '');
      assert.equal(fs.readFileSync(path.join(dir, 'bin', 'hop'), 'utf8'), vendored ? 'native' : 'shim');
    });
  }
});

describe('a binary that cannot be started', () => {
  test('the shim says so on stderr, exits 255, and writes nothing to stdout', () => {
    const dir = path.join(root, 'noexec');
    fs.mkdirSync(path.join(dir, 'vendor', PLATFORM), { recursive: true });
    fs.writeFileSync(path.join(dir, 'vendor', PLATFORM, 'hop'), 'not executable');
    fs.chmodSync(path.join(dir, 'vendor', PLATFORM, 'hop'), 0o644);
    const shim = path.join(h.NPM_DIR, 'lib', 'shim.js');
    const code = `require(${JSON.stringify(shim)}).run({ root: ${JSON.stringify(dir)}, platform: process.platform, arch: process.arch, argv: [] })`;
    const r = spawnSync(process.execPath, ['-e', code], { encoding: 'utf8' });
    assert.equal(r.status, 255);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /^hop: cannot run .*: EACCES\n$/);
  });
});

describe('an unsupported platform', () => {
  const { resolveBinary } = require(path.join(h.NPM_DIR, 'lib', 'platform.js'));

  test('resolveBinary says so in one line', () => {
    for (const [platform, arch] of [['win32', 'x64'], ['freebsd', 'x64'], ['linux', 'ia32'], ['darwin', 'ppc64']]) {
      const r = resolveBinary({ root, platform, arch });
      assert.equal(r.path, undefined);
      assert.match(r.error, new RegExp(`^hop: no hop binary for ${platform}-${arch}; [^\\n]*$`));
    }
  });

  test('the shim exits 255 with that line on stderr and nothing on stdout', () => {
    const shim = path.join(h.NPM_DIR, 'lib', 'shim.js');
    const code = `require(${JSON.stringify(shim)}).run({ platform: 'win32', arch: 'x64', argv: ['version'] })`;
    const r = spawnSync(process.execPath, ['-e', code], { encoding: 'utf8' });
    assert.equal(r.status, 255);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /^hop: no hop binary for win32-x64; .*\n$/);
  });
});
