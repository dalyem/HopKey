#!/usr/bin/env node
'use strict';
// A stand-in for the hop binary, driven by its arguments. The shim and
// install tests run it where the Go binary would be.
//
//   exit N                  exit with code N
//   signal NAME             kill itself with the signal NAME
//   cat                     copy stdin to stdout
//   bytes                   write every byte value to stdout and "err" plus 0xff to stderr
//   wait READY LOG          note its pid in READY, then wait; log each SIGTERM,
//                           SIGINT or SIGHUP it gets to LOG and exit 0 on SIGTERM
const fs = require('fs');

const [cmd, a, b] = process.argv.slice(2);
switch (cmd) {
  case 'exit':
    process.exit(Number(a));
    break;
  case 'signal':
    process.kill(process.pid, a);
    setTimeout(() => process.exit(99), 5000);
    break;
  case 'cat':
    process.stdin.pipe(process.stdout);
    break;
  case 'bytes': {
    const all = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) all[i] = i;
    fs.writeSync(1, all);
    fs.writeSync(2, Buffer.from([0x65, 0x72, 0x72, 0xff]));
    break;
  }
  case 'wait':
    for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
      process.on(sig, () => {
        fs.appendFileSync(b, sig + '\n');
        if (sig === 'SIGTERM') process.exit(0);
      });
    }
    fs.writeFileSync(a, String(process.pid));
    setInterval(() => {}, 1000);
    break;
  default:
    process.exit(2);
}
