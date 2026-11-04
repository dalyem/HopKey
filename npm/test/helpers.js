'use strict';
// Shared setup for the package tests: stage, pack and install the package
// the way a user's npm would, into throwaway directories.

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO = path.resolve(__dirname, '..', '..');
const NPM_DIR = path.join(REPO, 'npm');
const STAGE = path.join(REPO, 'scripts', 'npm-stage.sh');

// The release names of the binaries and the vendor directory each one
// goes to.
const BINARIES = [
  ['hop-linux-amd64', 'linux-x64'],
  ['hop-linux-arm64', 'linux-arm64'],
  ['hop-darwin-amd64', 'darwin-x64'],
  ['hop-darwin-arm64', 'darwin-arm64'],
];

function tmpdir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `hopkey-npm-${label}-`));
}

function npm(args, opts) {
  return execFileSync('npm', args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...opts,
    env: {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_update_notifier: 'false',
      npm_config_loglevel: 'error',
      ...(opts && opts.env),
    },
  });
}

// stagePackage builds a package whose four binaries are copies of fake-hop.js.
// The copies get mode 0644, as artifacts do, so that the staging has to
// restore the exec bit.
function stagePackage(root, version) {
  const bins = path.join(root, 'bins');
  fs.mkdirSync(bins);
  for (const [name] of BINARIES) {
    fs.copyFileSync(path.join(__dirname, 'fake-hop.js'), path.join(bins, name));
    fs.chmodSync(path.join(bins, name), 0o644);
  }
  const out = path.join(root, 'stage');
  execFileSync('sh', [STAGE, version, bins, out], { stdio: ['ignore', 'pipe', 'pipe'] });
  return out;
}

// pack runs npm pack on dir and returns the tarball's path.
function pack(dir, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const name = npm(['pack', '--silent', '--pack-destination', dest], { cwd: dir }).trim().split('\n').pop();
  return path.join(dest, name);
}

// install puts the tarball into a new global prefix, with or without the
// postinstall, and returns where things are.
function install(tarball, root, { ignoreScripts }) {
  const prefix = path.join(root, ignoreScripts ? 'prefix-ignore-scripts' : 'prefix-scripts');
  const args = ['install', '--global', '--prefix', prefix, tarball];
  if (ignoreScripts) args.push('--ignore-scripts');
  const out = npm(args, { env: { npm_config_cache: path.join(root, 'npm-cache') } });
  const pkg = path.join(prefix, 'lib', 'node_modules', '@dalyem', 'hopkey');
  return {
    prefix,
    pkg,
    out,
    link: path.join(prefix, 'bin', 'hop'),
    // The environment to run hop in: the install's bin first, and Node
    // where the shebang finds it.
    env: {
      PATH: [path.join(prefix, 'bin'), path.dirname(process.execPath), '/usr/bin', '/bin'].join(path.delimiter),
      HOME: root,
    },
  };
}

module.exports = { REPO, NPM_DIR, BINARIES, tmpdir, npm, stagePackage, pack, install };
