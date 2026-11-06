'use strict';

// The fallback launcher behind bin/hop. A normal install never reaches it:
// install.js (postinstall) replaces bin/hop with the native binary, so hop
// runs with no Node in between. The shim is what runs when the postinstall
// did not: npm --ignore-scripts, pnpm and bun, which skip it by default.
//
// It stays out of hop's way:
//   - stdio is inherited, so the shim never reads or writes hop's stdin or
//     stdout (hop mcp speaks MCP on them, and --json must stay pure), and
//     it writes to stderr only to say it cannot start hop.
//   - hop's exit code is passed on as it is; a child killed by a signal is
//     reported by killing this process with the same signal.
//   - SIGTERM is forwarded. SIGINT and SIGHUP are not: the terminal sends
//     them to the whole foreground process group, hop included, and hop
//     exits at once on a second one without restoring the terminal. They
//     are caught here only so that Node does not die first and leave hop
//     running in the shell's background.
//
// Known limit: libuv resets every signal to its default in the child, so a
// SIGHUP that was ignored when the shim started (nohup hop ...) is not
// ignored in hop, which respects an ignored SIGHUP only when it starts
// that way. Under the shim, a nohup'd hop dies on hangup. Run the native
// binary (a normal install, or the file in vendor/) when that matters.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { resolveBinary } = require('./platform.js');

const EXIT_FAILURE = 255; // hop's own code for its failures

// say writes one line to stderr. It uses the file descriptor directly:
// touching process.stderr could change how the descriptor, which hop shares,
// is set up.
function say(line) {
  try {
    fs.writeSync(2, line + '\n');
  } catch (e) {
    // Nobody to tell.
  }
}

function run({ root = path.resolve(__dirname, '..'), platform, arch, argv }) {
  const found = resolveBinary({ root, platform, arch });
  if (found.error) {
    say(found.error);
    process.exit(EXIT_FAILURE);
    return;
  }

  const child = spawn(found.path, argv, { stdio: 'inherit' });

  const forward = () => child.kill('SIGTERM');
  const ignore = () => {};
  process.on('SIGTERM', forward);
  process.on('SIGINT', ignore);
  process.on('SIGHUP', ignore);

  child.on('error', (err) => {
    say(`hop: cannot run ${found.path}: ${err.code || err.message}`);
    process.exit(EXIT_FAILURE);
  });

  child.on('exit', (code, signal) => {
    if (signal === null) {
      process.exit(code);
      return;
    }
    // Hand the signal back to ourselves with our handlers gone, so that
    // whoever waits for us sees the same death as hop's.
    process.removeListener('SIGTERM', forward);
    process.removeListener('SIGINT', ignore);
    process.removeListener('SIGHUP', ignore);
    try {
      process.kill(process.pid, signal);
    } catch (e) {
      // Fall through to the exit code the shell would report.
    }
    // The signal ends us at once; this runs only if it did not (one whose
    // default action is to be ignored).
    setTimeout(() => process.exit(128 + (os.constants.signals[signal] || 0)), 200);
  });
}

module.exports = { run };
