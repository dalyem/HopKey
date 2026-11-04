'use strict';

// Where the hop binary for a platform lives inside this package. The shim
// (lib/shim.js) and the postinstall (install.js) both use it.

const fs = require('fs');
const path = require('path');

const PLATFORMS = ['linux', 'darwin'];
const ARCHES = ['x64', 'arm64'];

// resolveBinary returns {path} for the binary that fits platform and arch
// (as process.platform and process.arch name them), or {error}, one line
// of text for stderr, when there is none.
function resolveBinary({ root, platform, arch }) {
  if (!PLATFORMS.includes(platform) || !ARCHES.includes(arch)) {
    return {
      error: `hop: no hop binary for ${platform}-${arch}; the hopkey package ships linux and darwin, on x64 and arm64`,
    };
  }
  const file = path.join(root, 'vendor', `${platform}-${arch}`, 'hop');
  let st;
  try {
    st = fs.statSync(file);
  } catch (e) {
    st = null;
  }
  if (!st || !st.isFile()) {
    return { error: `hop: the binary for ${platform}-${arch} is missing from this install (${file}); reinstall the hopkey package` };
  }
  return { path: file };
}

module.exports = { resolveBinary };
