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
hop ts import [--dry-run] | ts link <host> <node-id-or-dns-name>   (never links an ambiguous match; pick the node with ts link)
hop setup                         put `Include ~/.ssh/hop/config` above every other directive in ~/.ssh/config
hop init [--device-key-store keychain|file] [--kit-file F] [--json]
hop lock | unlock [--password] | passwd [--kit-file F]
hop status | daemon [stop [--json]]
hop sync [resolve]                sync now, settle a change the daemon held
hop auth signup|login|approve|status|devices|logout|rotate|passwd|merge|resume
hop mcp [--read-only] | mcp install [--client claude|codex|print] [--read-only] [--json]
```

`hop import ssh-config` reads your config with `ssh -G`, the way `ssh <host>` does, so it runs any `Match exec` commands in it and may do DNS lookups. It lists what its own scan found (best effort, not a guarantee) and asks before it runs ssh; without a terminal, or with `--json`, it refuses unless you pass `--yes`. Importing your config carries the same trust as using it.

Every command takes `--json`, except `hop <target>` (`hop connect`), which opens a shell, `hop daemon`, which runs in the foreground, `hop mcp` itself, which speaks MCP on stdin and stdout (`hop mcp install` takes it), and `hop passwd`, which prints the new Emergency Kit and so has no output that is safe to parse (on a server, `hop auth passwd --json` takes it, with the kit on stderr). A first word that is not a command, followed by more words, is refused as an unknown command, not taken as a target. hop's own failures exit 255, and `hop <target>` and `hop exec` pass the remote exit code through. `hop daemon` exits 75 when another hop process owns the vault: a command that started it then waits for that other daemon. Resolution is interactive (DNS, fuzzy match, picker, plain-ssh fallback) only when stdout is a terminal and `--json` is not given; otherwise it stops after the Tailscale step and returns candidates. `hop exec` is never fuzzy.

`hop ts import --dry-run` prints `would create` and `would link`; its `--json` report has the statuses `would_created` and `would_linked`.

A host with no pinned host key is refused by ssh, since hop never trusts a key on first use. `hop <target>` and `hop exec` say so before they run ssh, and name the fix: `hop trust <host>`, or, for a host behind a jump host (whose key hop cannot read directly), `hop edit <host> --host-key '<ssh-ed25519 AAAA...>'`.

The first command that needs the daemon starts it (`hop daemon`, detached, logging to `$XDG_STATE_HOME/hop/daemon.log`; the daemon of the login service, `hop setup --service`, logs to the journal on Linux: `journalctl --user -u hopkey`). `hop status` does not start the daemon: it says so, and `hop daemon` (in the foreground) or any command such as `hop ls` starts it. The daemon serves the read-only ssh-agent socket and a control socket in `$XDG_RUNTIME_DIR/hop/` (or `~/.ssh/hop/run/`), and regenerates `~/.ssh/hop/config` after every change, so plain `ssh <alias>` works too. While the daemon is down or the vault is locked, the agent has no key to offer and plain `ssh <alias>` fails with `Permission denied (publickey)`; any hop command starts the daemon again, and `hop unlock` unlocks the vault.

## The vault

The vault lives in `$XDG_DATA_HOME/hop` (or `~/.local/share/hop`) as a signed log. The contents of vault items (hosts, keys, credentials, snippets) are encrypted on disk. The log's public metadata and the verified state are not encrypted and are not secret: account, device and item IDs, item types and versions, device names, public keys, sequence numbers, times and digests. `hop init` creates and opens the vault itself; after that the daemon is the one process that opens it, and every other command goes through the daemon.

- `hop init` creates the account and the vault. It asks for a master password and prints the Emergency Kit: the Secret Key and the Recovery Key. You type back the last group of each before anything is written. `--kit-file` also saves the kit to a new 0600 file. It needs a terminal (stdin) for the password and the type-back, so it refuses to run without one. With `--json`, stdout holds one JSON result (the data directory, the device key store, the kit file if any, and no secret) and the kit and the prompts stay on the terminal, on stderr.
- `hop lock` drops every secret from memory and empties the agent. `hop unlock` opens the vault again with the device key. `hop unlock --password` uses the master password and Secret Key instead and sets up a new device key, for when the old one is gone. The old device stays in the log as stale until the next `hop passwd`.
- `hop passwd` changes the master password. That re-keys the whole vault and makes a new Secret Key and Recovery Key, so keep the new kit. It also revokes the stale devices that password unlocks left behind.
- The device key record (this device's private keys and the Secret Key) is kept in the OS keychain by default. On a machine without one, `hop init --device-key-store file` keeps it in `device.key` next to the vault, sealed with a passphrase when `HOP_DEVICE_PASSPHRASE` is set. Every unlock after that needs the passphrase. A daemon started with `HOP_DEVICE_PASSPHRASE` in its environment uses it. One started without it (by `hop mcp`, or by the login service) comes up locked, and `hop unlock` opens it: it sends the daemon the passphrase from its own `HOP_DEVICE_PASSPHRASE`, or asks for it on a terminal. The daemon uses it for that unlock only and does not keep it, so after `hop lock` the next `hop unlock` needs it again. Without the passphrase the file is unsealed: it holds the device private keys and the Secret Key in plain form, protected only by its 0600 file permissions, and `hop init` warns about that. hop never falls back from one store to the other. `hop status` shows the store in use, `keychain`, `file (sealed)` or `file (unsealed: private keys on disk)`, and warns about anything pending.

For development, build with `-tags hopdev`: the vault is then a plaintext JSON file (`$HOPKEY_DEVSTORE`, default `~/.local/state/hop/devstore.json`) that holds private keys unencrypted. A test checks that a normal build contains none of that code.

## Sync

Once a vault is signed in to a server (`hop auth signup` or `hop auth login`), the daemon keeps it in sync on its own: it pushes each change as it is made and holds a long-poll open for the other devices' changes. A change made offline is queued (`pending` in `hop ls`) and goes up once the server answers again. `hop status` and `hop sync` show where sync stands: `online` once the server has answered, `retrying` with the last error and the next try when a pull or a push failed (a push, in the background or by `hop sync`, gives up after 15 seconds), and `paused` while the vault is locked. `hop setup --service` runs the daemon from login, so sync goes on with no hop command run. On a device whose key is a sealed file, that daemon has no passphrase: it starts locked after every boot, and sync is paused until `hop unlock`. Setup warns about this. hop writes the passphrase to no file, so for a service that unlocks by itself keep the device key in the keychain or an unsealed file.

When two devices change the same item before either sees the other's change, the merge goes by field:

- Protected fields (every field but a host's or a snippet's description) are held: the change that reaches the server second waits in `hop sync resolve` until you keep yours, edit it, or take theirs. Two changes to different protected fields of one item are held too.
- The description is merged on its own, and the last change to reach the server wins. Nothing is held, so the other device's description is lost. The device whose change won says so in `hop status`, `hop sync` and its daemon log, naming the item and the field (never the values), until its daemon restarts. It does so even when the server's answer to its push was lost and a later sync, or a `hop auth` command run meanwhile, found the change committed: the vault keeps the note, sealed, until the daemon has shown it (the newest 50; older ones are dropped with a line in the daemon log).

`hop auth devices` shows, under LAST SEEN, when each device last wrote to the vault or made any request to the server, whichever is later. The server records a device's requests at most once a minute.

`hop auth login` by approval waits for a signed-in device to run `hop auth approve CODE`. An approving device allows 3 approvals per rolling hour; when it has used them, its error says when the next one frees up, and the new device, which cannot see that, prints a hint after a minute: sign in with `--method password` instead. An unfinished approval login on a device makes the other methods refuse to start; `hop auth login --discard` (with `--yes` or a question) deletes it, and the approving device's `hop auth approve --abort` ends its side. `hop auth login` and `hop auth approve` stop, and release the vault, on SIGHUP and when the terminal they run in goes away.

`hop auth logout` deletes this device's keys and its copy of the vault, and with them what the vault decrypted into `~/.ssh/hop`: the config is left with no hosts (so an `Include` of it still works), and the key files and pinned host keys there are removed. A revoked device's daemon does the same. hop removes only the names it generates there (`keys/<id>.pub`, `known_hosts-<id>`, where `<id>` is 16 hex digits, and its own temp files), so a file of yours in `~/.ssh/hop`, such as `keys/company.pub`, stays. It leaves your own `~/.ssh/config`, `~/.ssh/known_hosts` and key files alone. If a logout is cut short after it was recorded (a crash, say), the next hop command finishes it, `~/.ssh/hop` included, and if `~/.ssh/hop` cannot be emptied then, every later start of the daemon tries again until it can.

## Using hop with AI agents (MCP)

`hop mcp` is an MCP server on stdin and stdout for local agents such as Claude Code and Codex. It is a thin layer over the daemon, like every other command: it never opens the vault, and works the same on a local-only vault and a signed-in one. If the vault is locked or missing, a tool says so and names the fix (`hop unlock`, `hop init`); the server keeps running. If no daemon is running, `hop mcp` starts one, without `HOP_DEVICE_PASSPHRASE`: on a device whose key file is sealed with a passphrase, that daemon comes up locked, and the tools say to run `hop unlock` from a terminal, which sends the daemon the passphrase.

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
| `exec(hosts, command, timeout_s=60)` | Runs a command on one host, a list, or `tag:x`, eight at a time. Per host: `exit_code`, `stdout` and `stderr` (the last 64 KiB each), `truncated`, `error` when hop could not run it, and `warning` when the output may be incomplete (ssh exited but left a process holding its output, which hop cuts off after a second; `truncated` is set too). `hop exec --json` has the same fields, and without `--json` hop prints the warning on stderr. |
| `check_host(host)` | The step-by-step diagnosis of `hop check`. |
| `ssh_command(host)` | The `ssh -F ...` command line for an agent that has its own shell. |
| `list_snippets()` | Saved commands and their `{{name}}` parameters. |
| `run_snippet(name, hosts, params)` | Runs a snippet as `exec` does. Each value arrives as one word and never becomes shell source text (see below for what that does not cover); a missing or unknown parameter is refused. The answer names the snippet; it does not show the command with the values filled in. |

Commands run with no terminal, stdin closed, `PAGER=cat` and a timeout per host, so a password prompt fails instead of hanging. Use `sudo -n`. One host failing does not stop the others. `exec` and `run_snippet` hand the command to the remote user's login shell, which must be POSIX `sh` compatible (sh, bash, dash, ksh, zsh). fish and csh quote differently, and are not supported.

Snippets are saved with `hop snippet add restart --description "restart a unit" -- systemctl restart {{unit}}`. One word after `--` is a shell command line, as with ssh; several words are quoted one by one. Snippets sync like hosts.

A parameter's name is letters, digits and `_`, not starting with a digit. hop puts each value in a shell variable at the top of the script and the placeholder becomes a reference to it, so `systemctl restart {{unit}}` runs as `HOP_P_unit='...'; systemctl restart "${HOP_P_unit}"`. Param values never become shell source text: not in a word, a comment, a here-document or `$(...)`, whatever quotes, newlines or `$` they hold. A template that itself evaluates a value (eval, sh -c, arithmetic, indirect expansion) can still run it, and the snippet's author is responsible for that. Write a placeholder bare, outside quotes: hop refuses `'{{x}}'`, which would not expand, and `"{{x}}"`, which would nest the quotes. In a here-document body the variable's double quotes are printed with the value; to avoid them, write `$(printf '%s' {{x}})` there instead of `{{x}}`.

hop also refuses, when a snippet is saved and again when it runs, a placeholder in the places where a shell evaluates text, since a value such as `a[$(cmd)]` runs `cmd` there in bash:

- inside `$((...))`, `((...))`, `$[...]` or `${...}` (an array index or offset is arithmetic);
- inside `[[ ... ]]` (its `-eq`, `-lt` and the like are arithmetic); use `[ ... ]`;
- each of these to its end, over line breaks too;
- as an argument of `eval`, `let` or `trap`;
- as the command string of `sh -c`, `bash -c`, `zsh -c`, `dash -c`, `ksh -c` or `su -c`; pass the value as a positional parameter instead: `sh -c '... "$1"' sh {{x}}`;
- in an assignment, `v={{x}}`, `a[{{x}}]=1`, `export v={{x}}`, and in `$(...)` whose output is assigned (`v=$(... {{x}})`), since a variable can be evaluated later with `${!v}`, a nameref or arithmetic. To put a value in a command's environment, use `env NAME={{x}} command`.

This check is best effort: it is a lint, not a shell parser. It misses evaluation it does not know (`ssh other-host {{x}}`, `xargs sh -c`, a value piped to a shell, or saved by `for` or `read` and evaluated later), and may refuse a placeholder that only looks like one of these (`echo eval {{x}}`).

Migrating snippets saved before this version: a parameter name with a `-` (`{{a-b}}`) is now refused, so rename such parameters to use `_` (`{{a_b}}`); a snippet that assigns a value (`v={{x}}`, the old here-document advice) or uses one of the places above is refused when it runs. Re-save it with `hop snippet add` in the new form.

A snippet's command is shown to agents by `list_snippets`, so keep secrets out of it: pass one as a parameter instead.

Safety rules:

- hop never returns the vault's secret fields: private keys, credential passwords, the Secret Key, auth values. The daemon never sends them to `hop mcp`.
- Command output (`stdout`, `stderr`) is what the remote printed. hop removes private key blocks from it, and the values of the hop auth secrets and `HOP_DEVICE_PASSPHRASE` the server started with, every non-empty value however short. All of them are found before any is replaced, and before hidden names are masked, so none breaks up another, and a secret that runs into a key block goes whole. hop mcp's own stderr, which the MCP client keeps in its log, is scrubbed the same way. This is best effort: a secret the remote prints in another form, or one hop does not know, passes through. Do not run commands that print secrets.
- Snippet commands are shown to agents as they are; keep secrets out of them.
- A host with `agent_access: deny` is invisible to every tool: not listed, never resolved or offered as a candidate, skipped by `tag:`, and `exec`, `check_host` and `ssh_command` treat it as not found. Its Tailscale node is left out of resolution too, so its Tailscale name or IP does not find it. A node is the denied host's when the host is linked to it, or one of the host's addresses is one of the node's IPs or its MagicDNS name (ignoring case and a trailing dot). An address that is the MagicDNS name's first label or the node's host name makes the node the denied host's only when no other node has that name and the host is not linked to another node: two machines can report the same host name, and such a name does not say which one the host is. An allowed host's node with that name stays visible, and so does the denied host's own node if nothing else names it: link the host to it with `hop ts link` to hide it. Set it with `hop edit <host> --agent-access deny`.
- A denied host can still be another host's jump host, and commands through it work. Its name stays hidden: the jump host shows as `(a host hidden from agents)`, and its names and addresses read `<hidden host>` in `ssh_problem`, check steps, errors and ssh's stderr. A name or address an allowed host also has is not hidden. A name is hidden where it stands as a whole host token: a denied `db` reads `<hidden host>` in `db:5432` and `db.` at the end of a sentence, but not inside `db.prod.example`, and `10.0.0.1` is hidden in `10.0.0.1:22` but not inside `10.0.0.10`. A longer name hop does not know the denied host by (an FQDN that is not one of its addresses) is not hidden.
- An answer about a denied name looks like one about a name that does not exist: what you typed, as the target, the user or a tag, is echoed as you typed it, never masked, where hop echoes it and where ssh names your user on its login to the target. Everything else hop says, from the vault, is masked.
- An agent never trusts a host key on first use. `exec` and `run_snippet` refuse a host with no pinned key, or one behind a jump host with none, and say to run `hop trust <host>`. ssh runs with `StrictHostKeyChecking yes` against the pinned keys only, so a changed key blocks the call.
- Every `exec` and `run_snippet` is logged before and after it runs to `$XDG_STATE_HOME/hop/mcp-audit.jsonl` (mode 0600): time, tool, client name, hosts and exit codes, never output. For `exec` it logs the command the agent sent; for `run_snippet` the snippet's name and the names of the parameters, never their values. Every string is scrubbed as answers are, and control characters are written as escapes. If the log cannot be written, nothing runs.
- `hop mcp --read-only` offers no tool that runs a command: no `exec`, no `run_snippet`, and `check_host` skips its login step.
- The hop auth secrets (`HOP_PASSWORD` and the others) and `HOP_DEVICE_PASSPHRASE` are removed from the server's environment, from ssh's, and from a daemon the server starts.

`agent_access: deny` is a guardrail for well-behaved agents, not a security boundary. An agent runs as you and can use your agent socket and unlocked daemon directly. For a real boundary, run the agent in a container or VM.

## Checks

Checks run on Kiln, not on the orchestrator:

```
kiln checks run            # go vet, go test, gofmt -l
kiln checks run test       # one check
```

`test` also runs the packages that only exist under `-tags hopdev` (the dev store and the real `hop` binary starting its own daemon).

`scripts/check.sh` defines each check. The ssh integration test needs an `ssh` binary and a passwd entry for the current uid; `scripts/with-passwd.sh` supplies the entry on Kiln. With `HOPKEY_REQUIRE_SSH=1` the test fails instead of skipping when `ssh` is missing.
