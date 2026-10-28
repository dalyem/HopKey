# HopKey

HopKey is an end-to-end encrypted vault for SSH hosts and keys. The `hop` CLI and a local daemon keep decrypted keys in memory and serve them to the OpenSSH client through an ssh-agent socket, so plain `ssh <alias>` works on every device. `hop-server` is the Docker server that syncs ciphertext between devices; it never sees a key or a host in plain form.

The repository holds both. Phase 1 is the local `hop` CLI and daemon with the encrypted vault, which works on its own with no server. Phase 2 adds `hop-server`, automatic sync in the daemon and the `hop auth` account commands. `hop mcp` gives local AI agents the hosts, under the rules below.

## The `hop` CLI

```
hop <target>                      shell on a vault host: alias, hostname, IP, Tailscale name or IP (user@ works)
hop exec <target> [--timeout D] [--sudo] [--json] -- <cmd...>
hop check|which|trust <target>    diagnose, explain resolution, pin the server's host key
hop ls [tag] | info <target> | add | edit | rm
hop key add <path> | ls | rm
hop snippet add <name> [--description D] -- <cmd...> | ls | rm <name>
hop import ssh-config [path] [--with-keys] [--dry-run] [--yes]
hop ts import | ts link <host> <node-id-or-dns-name>   (never links an ambiguous match; pick the node with ts link)
hop setup                         put `Include ~/.ssh/hop/config` above every other directive in ~/.ssh/config
hop init [--device-key-store keychain|file] [--kit-file F]
hop lock | unlock [--password] | passwd [--kit-file F]
hop status | daemon [stop]
hop sync [resolve]                sync now, settle a change the daemon held
hop auth signup|login|approve|status|devices|logout|rotate|passwd|merge|resume
hop mcp [--read-only] | mcp install [--client claude|codex|print]
```

`hop import ssh-config` reads your config with `ssh -G`, the way `ssh <host>` does, so it runs any `Match exec` commands in it and may do DNS lookups. It lists what its own scan found (best effort, not a guarantee) and asks before it runs ssh; without a terminal, or with `--json`, it refuses unless you pass `--yes`. Importing your config carries the same trust as using it.

Every command takes `--json`. hop's own failures exit 255, and `hop <target>` and `hop exec` pass the remote exit code through. Resolution is interactive (DNS, fuzzy match, picker, plain-ssh fallback) only when stdout is a terminal and `--json` is not given; otherwise it stops after the Tailscale step and returns candidates. `hop exec` is never fuzzy.

The first command that needs the daemon starts it (`hop daemon`, detached, logging to `$XDG_STATE_HOME/hop/daemon.log`). The daemon serves the read-only ssh-agent socket and a control socket in `$XDG_RUNTIME_DIR/hop/` (or `~/.ssh/hop/run/`), and regenerates `~/.ssh/hop/config` after every change, so plain `ssh <alias>` works too.

## The vault

The vault lives in `$XDG_DATA_HOME/hop` (or `~/.local/share/hop`) as a signed log. The contents of vault items (hosts, keys, credentials, snippets) are encrypted on disk. The log's public metadata and the verified state are not encrypted and are not secret: account, device and item IDs, item types and versions, device names, public keys, sequence numbers, times and digests. `hop init` creates and opens the vault itself; after that the daemon is the one process that opens it, and every other command goes through the daemon.

- `hop init` creates the account and the vault. It asks for a master password and prints the Emergency Kit: the Secret Key and the Recovery Key. You type back the last group of each before anything is written. `--kit-file` also saves the kit to a new 0600 file.
- `hop lock` drops every secret from memory and empties the agent. `hop unlock` opens the vault again with the device key. `hop unlock --password` uses the master password and Secret Key instead and sets up a new device key, for when the old one is gone. The old device stays in the log as stale until the next `hop passwd`.
- `hop passwd` changes the master password. That re-keys the whole vault and makes a new Secret Key and Recovery Key, so keep the new kit. It also revokes the stale devices that password unlocks left behind.
- The device key record (this device's private keys and the Secret Key) is kept in the OS keychain by default. On a machine without one, `hop init --device-key-store file` keeps it in `device.key` next to the vault, sealed with a passphrase when `HOP_DEVICE_PASSPHRASE` is set (it must be set for every unlock after that). Without the passphrase the file is unsealed: it holds the device private keys and the Secret Key in plain form, protected only by its 0600 file permissions, and `hop init` warns about that. hop never falls back from one store to the other. `hop status` shows the store in use, `keychain`, `file (sealed)` or `file (unsealed: private keys on disk)`, and warns about anything pending.

For development, build with `-tags hopdev`: the vault is then a plaintext JSON file (`$HOPKEY_DEVSTORE`, default `~/.local/state/hop/devstore.json`) that holds private keys unencrypted. A test checks that a normal build contains none of that code.

## Using hop with AI agents (MCP)

`hop mcp` is an MCP server on stdin and stdout for local agents such as Claude Code and Codex. It is a thin layer over the daemon, like every other command: it never opens the vault, and works the same on a local-only vault and a signed-in one. If the vault is locked or missing, a tool says so and names the fix (`hop unlock`, `hop init`); the server keeps running.

Register it once with the client's own CLI:

```
hop mcp install --client claude          # runs: claude mcp add --scope user hop -- /path/to/hop mcp
hop mcp install --client codex           # runs: codex mcp add hop -- /path/to/hop mcp
hop mcp install --client claude --read-only
hop mcp install                          # prints the commands, the JSON (mcpServers) and Codex TOML to paste
```

hop never edits a client's config file itself. If the client already has a server named `hop`, remove it first (`claude mcp remove --scope user hop`, `codex mcp remove hop`).

Tools:

| Tool | What it does |
| --- | --- |
| `list_hosts(query?, tag?)` | Hosts: name, aliases, addresses, user, port, tags, description, auth (`key`, `credential` or `agent-only`), Tailscale status, whether a host key is pinned. |
| `resolve_host(target)` | One host, or candidates, as `hop which --json`. Nothing is guessed. |
| `exec(hosts, command, timeout_s=60)` | Runs a command on one host, a list, or `tag:x`, eight at a time. Per host: `exit_code`, `stdout` and `stderr` (the last 64 KiB each), `truncated`, and `error` when hop could not run it. |
| `check_host(host)` | The step-by-step diagnosis of `hop check`. |
| `ssh_command(host)` | The `ssh -F ...` command line for an agent that has its own shell. |
| `list_snippets()` | Saved commands and their `{{name}}` parameters. |
| `run_snippet(name, hosts, params)` | Runs a snippet as `exec` does. Each value is quoted as one shell word; a missing or unknown parameter is refused. |

Commands run with no terminal, stdin closed, `PAGER=cat` and a timeout per host, so a password prompt fails instead of hanging. Use `sudo -n`. One host failing does not stop the others.

Snippets are saved with `hop snippet add restart --description "restart a unit" -- systemctl restart {{unit}}`. One word after `--` is a shell command line, as with ssh; several words are quoted one by one. Write a placeholder bare, outside quotes: hop quotes each value itself and refuses `'{{x}}'`. Snippets sync like hosts.

Safety rules:

- No tool or error returns a private key, a password, the Secret Key or any other secret. The daemon never sends them, and every answer is also scrubbed of private key blocks (from remote output too) and of the hop auth secrets the process started with.
- A host with `agent_access: deny` is invisible to every tool: not listed, never resolved or offered as a candidate, skipped by `tag:`, and `exec`, `check_host` and `ssh_command` treat it as not found. Set it with `hop edit <host> --agent-access deny`.
- An agent never trusts a host key on first use. `exec` and `run_snippet` refuse a host with no pinned key, or one behind a jump host with none, and say to run `hop trust <host>`. ssh runs with `StrictHostKeyChecking yes` against the pinned keys only, so a changed key blocks the call.
- Every `exec` and `run_snippet` is logged before and after it runs to `$XDG_STATE_HOME/hop/mcp-audit.jsonl` (mode 0600): time, tool, client name, hosts, command and exit codes, never output. If the log cannot be written, nothing runs.
- `hop mcp --read-only` offers no tool that runs a command: no `exec`, no `run_snippet`, and `check_host` skips its login step.
- The hop auth secrets (`HOP_PASSWORD` and the others) are removed from the server's environment and from ssh's.

`agent_access: deny` is a guardrail for well-behaved agents, not a security boundary. An agent runs as you and can use your agent socket and unlocked daemon directly. For a real boundary, run the agent in a container or VM.

## Checks

Checks run on Kiln, not on the orchestrator:

```
kiln checks run            # go vet, go test, gofmt -l
kiln checks run test       # one check
```

`test` also runs the packages that only exist under `-tags hopdev` (the dev store and the real `hop` binary starting its own daemon).

`scripts/check.sh` defines each check. The ssh integration test needs an `ssh` binary and a passwd entry for the current uid; `scripts/with-passwd.sh` supplies the entry on Kiln. With `HOPKEY_REQUIRE_SSH=1` the test fails instead of skipping when `ssh` is missing.
