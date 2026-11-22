'use strict';

// postinstall: put the native hop binary where bin/hop is, so that `hop` on
// PATH is the Go binary itself and not a Node launcher: exact signals, exact
// exit codes, no Node at runtime, and the same file hop finds for itself
// (os.Executable, os.SameFile) when it starts its daemon or writes a service
// unit or an MCP client entry.
//
// This is an optimisation, and never a reason for the install to fail. If
// anything goes wrong it leaves the shim (lib/shim.js) in place, prints
// nothing and exits 0. It makes no network request: the binaries are in the
// package, under vendor/.

const fs = require('fs');
const path = require('path');
const { resolveBinary } = require('./lib/platform.js');

// install copies the binary for this platform over bin/hop, through a temp
// file in the same directory and a rename. Overwriting bin/hop in place would
// keep its inode, and on macOS arm64 a changed signed binary on an old inode
// can get the process killed. It returns whether bin/hop was replaced.
function install({ root, platform, arch }) {
  const found = resolveBinary({ root, platform, arch });
  if (found.error) {
    return false;
  }
  const bin = path.join(root, 'bin');
  const dest = path.join(bin, 'hop');
  const tmp = path.join(bin, `.hop.${process.pid}.tmp`);
  try {
    fs.copyFileSync(found.path, tmp);
    fs.chmodSync(tmp, 0o755);
    fs.renameSync(tmp, dest);
    return true;
  } catch (e) {
    try {
      fs.unlinkSync(tmp);
    } catch (e2) {
      // It may not have been made.
    }
    return false;
  }
}

module.exports = { install };

if (require.main === module) {
  try {
    install({ root: __dirname, platform: process.platform, arch: process.arch });
  } catch (e) {
    // Leave the shim.
  }
  process.exit(0);
}
