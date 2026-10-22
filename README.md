# HopKey

HopKey is an end-to-end encrypted vault for SSH hosts and keys. The `hop` CLI and a local daemon keep decrypted keys in memory and serve them to the OpenSSH client through an ssh-agent socket, so plain `ssh <alias>` works on every device. `hop-server` is the Docker server that syncs ciphertext between devices. The design is a work in progress. The repository holds the local `hop` CLI and daemon (phase 1) with the encrypted local vault; the server is separate work.

## The `hop` CLI

```
hop <target>                      shell on a vault host: alias, hostname, IP, Tailscale name or IP (user@ works)
hop exec <target> [--timeout D] [--sudo] [--json] -- <cmd...>
hop check|which|trust <target>    diagnose, explain resolution, pin the server's host key
hop ls [tag] | info <target> | add | edit | rm
hop key add <path> | ls | rm
hop import ssh-config [path] [--with-keys] [--dry-run] [--yes]
hop ts import | ts link <host> <node-id-or-dns-name>   (never links an ambiguous match; pick the node with ts link)
hop setup                         put `Include ~/.ssh/hop/config` above every other directive in ~/.ssh/config
hop init [--device-key-store keychain|file] [--kit-file F]
hop lock | unlock [--password] | passwd [--kit-file F]
hop status | daemon [stop]
```

`hop import ssh-config` reads your config with `ssh -G`, the way `ssh <host>` does, so it runs any `Match exec` commands in it and may do DNS lookups. It lists what its own scan found (best effort, not a guarantee) and asks before it runs ssh; without a terminal, or with `--json`, it refuses unless you pass `--yes`. Importing your config carries the same trust as using it.

Every command takes `--json`. hop's own failures exit 255, and `hop <target>` and `hop exec` pass the remote exit code through. Resolution is interactive (DNS, fuzzy match, picker, plain-ssh fallback) only when stdout is a terminal and `--json` is not given; otherwise it stops after the Tailscale step and returns candidates. `hop exec` is never fuzzy.

The first command that needs the daemon starts it (`hop daemon`, detached, logging to `$XDG_STATE_HOME/hop/daemon.log`). The daemon serves the read-only ssh-agent socket and a control socket in `$XDG_RUNTIME_DIR/hop/` (or `~/.ssh/hop/run/`), and regenerates `~/.ssh/hop/config` after every change, so plain `ssh <alias>` works too.

## The vault

The vault lives in `$XDG_DATA_HOME/hop` (or `~/.local/share/hop`) as a signed, encrypted log; only ciphertext and digests are written to disk. The daemon is the one process that opens it, and every command goes through the daemon.

- `hop init` creates the account and the vault. It asks for a master password and prints the Emergency Kit: the Secret Key and the Recovery Key. You type back the last group of each before anything is written. `--kit-file` also saves the kit to a new 0600 file.
- `hop lock` drops every secret from memory and empties the agent. `hop unlock` opens the vault again with the device key. `hop unlock --password` uses the master password and Secret Key instead and sets up a new device key, for when the old one is gone. The old device stays in the log as stale until the next `hop passwd`.
- `hop passwd` changes the master password. That re-keys the whole vault and makes a new Secret Key and Recovery Key, so keep the new kit. It also revokes the stale devices that password unlocks left behind.
- The device key is kept in the OS keychain by default. On a machine without one, `hop init --device-key-store file` keeps it in `device.key` next to the vault, sealed with a passphrase when `HOP_DEVICE_PASSPHRASE` is set (it must be set for every unlock after that). hop never falls back from one store to the other. `hop status` shows the store in use, `keychain`, `file (sealed)` or `file (unsealed)`, and warns about anything pending.

For development, build with `-tags hopdev`: the vault is then a plaintext JSON file (`$HOPKEY_DEVSTORE`, default `~/.local/state/hop/devstore.json`) that holds private keys unencrypted. A test checks that a normal build contains none of that code.

## Checks

Checks run on Kiln, not on the orchestrator:

```
kiln checks run            # go vet, go test, gofmt -l
kiln checks run test       # one check
```

`test` also runs the packages that only exist under `-tags hopdev` (the dev store and the real `hop` binary starting its own daemon).

`scripts/check.sh` defines each check. The ssh integration test needs an `ssh` binary and a passwd entry for the current uid; `scripts/with-passwd.sh` supplies the entry on Kiln. With `HOPKEY_REQUIRE_SSH=1` the test fails instead of skipping when `ssh` is missing.
