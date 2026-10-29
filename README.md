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

`hop mcp` is an MCP server on stdin and stdout for local agents such as Claude Code and Codex. It is a thin layer over the daemon, like every other command: it never opens the vault, and works the same on a local-only vault and a signed-in one. If the vault is locked or missing, a tool says so and names the fix (`hop unlock`, `hop init`); the server keeps running. If no daemon is running, `hop mcp` starts one, without `HOP_DEVICE_PASSPHRASE`: on a device whose key file is sealed with a passphrase, that daemon comes up locked, and the tools say to run `hop unlock` from a terminal.

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

## End-to-end tests on Kiln

`scripts/e2e/run.sh` runs the whole product on real machines. It builds `hop` and `hop-server` from the worktree with `kiln checks run`, leases two Ubuntu VMs (CLI-A, CLI-B), creates three sandboxes as SSH targets (T1-T3), runs the phases, writes a report and releases everything, also on failure. Nothing from the repository runs on the orchestrator.

Prerequisites:

- the `kiln` CLI, logged in;
- for phases 3-6, a Tailscale auth key that is reusable, ephemeral and tagged `tag:hoptest`, in a file (default `~/hopkey-test/ts-authkey`, or `HOP_E2E_TS_AUTHKEY_FILE`). The tailnet policy must let `tag:hoptest` reach `tag:hoptest`, for example `{"action":"accept","src":["tag:hoptest"],"dst":["tag:hoptest:*"]}`. The script copies the file only by path. Each machine deletes it when `tailscale up` ends, whatever the outcome. The driver deletes it again at cleanup on every machine that got a copy, also with `--keep`, and checks that it is gone.

```
scripts/e2e/run.sh                    # all phases
scripts/e2e/run.sh --phases 1,2       # local only and MCP; no Tailscale key needed
scripts/e2e/run.sh --keep             # leave the machines up and print their IDs
scripts/e2e/run.sh --phases 6 --source ../other-worktree   # build hop from another worktree
```

`--source <dir>` builds `hop` and `hop-server` from another checkout (a branch in review, say) and runs this checkout's suite against them. The report names that checkout's branch, commit and uncommitted files.

The run's kiln identity (`kiln whoami`) is printed and kept in the ledger before anything is allocated, and the report names it. `HOP_E2E_EXPECT_IDENTITY=<name or principal ID>` refuses to run under any other. Without it, the run warns when kiln sees a plain shell but the environment is an agent's, or the reverse. An agent should start a run from its own tool call (the tool's background mode), not with a plain `&`: a process that outlives the call runs as the user's identity, and the agent can then neither see nor release its machines.

The phases:

1. Local use with no account, on both VMs.
2. MCP.
3. Sync, through a throwaway `hop-server` on CLI-A that is reachable only on the tailnet, with a CA made for the run. A description both devices edit is not held, the later push (B's) wins, and B names the item and the field, never either value, in the text of `hop status`, in `hop sync` and in its `daemon.log`.
4. SSH over Tailscale, including a jump host.
5. The revocation matrix, and what revocation does on the device: an online revoke leaves `hop unlock` refused and the agent empty, a proven revocation wipes the vault, `device.key` and `~/.ssh/hop` but keeps `revocation.json`, a device revoked offline keeps working while offline with the policy off (documented, so asserted as working), is cut off within 120 s after it reconnects and stays cut off across a restart, and the account's `--max-offline 1m` policy locks a device blocked from the server and never an idle healthy one (`rev2-*` checks). MCP access counts as working when `list_hosts` lists a host or `exec` ran on T1, whatever else `hop mcp` did. It counts as denied only on one of hop's own refusals (revoked, locked, offline too long, no vault), given in answer to both tool calls, or by a `hop mcp` that exits with one before answering any tool call. "No vault" counts only when the same step sees the proven revocation's wipe of that store (no vault, no `device.key`, a `revocation.json`); a store that is merely empty does not. Any other answer, or a `hop mcp` that hangs or exits, is a harness failure, as is an agent probe that gives no clear answer.
6. `hop key rotate` against real sshd: the sandboxes' stock Ubuntu sshd (StrictModes on), T2's jump-host target and CLI-B's sshd. `--dry-run` changes nothing; rotated hosts keep every other `authorized_keys` line byte for byte and the old line's options (`restrict` and `from=`, which sshd then enforces on the new key); the old key is refused; T3, whose sshd is set to take only the lines it had before (`AuthorizedKeysCommand` on a snapshot, with a hook that logs each offered key's fingerprint and whether the live file holds it), refuses the new key and is put back, and the hook log proves the new key was installed and refused before the restore; a second record of a rotated account is `already-rotated`; B follows with nothing done there; lines appended on T1 during a rotation are kept, each exactly once, and the T1 clock is measured against A's so at least one append is shown to land inside the rotation (none is a harness failure, as are zero appends); the rotation must reach its edit, so it either ends `rotated` (`old_key_removed`) or fails on hop's own conflict check (`~/.ssh/authorized_keys changed while hop was editing it`) with the host `unchanged`, and any other failure fails the check (`rot-*` checks). T3's sshd is put back to stock and checked, also when the phase stops early: `sshd -T` must succeed and show deploy the same `AuthorizedKeysFile` and `AuthorizedKeysCommand` (`none`) as the stock config did at setup. A build without `hop key rotate` (exit 255, `unknown key subcommand "rotate"`) records a skip; a detection that gets any other answer is a harness failure. The same goes for `hop auth policy`.

Every check is one JSON line in `e2e-out/<run-id>/results.jsonl`. `REPORT.md` next to it has a table per phase and the failures in detail. Assertions encode the intended behaviour, so known product gaps show up as FAIL, tagged with their bug ID. Where the product README documents a limit (no field-level merge for protected fields, secrets hop does not know pass through MCP output, open sessions survive a revoke), the check asserts the documented behaviour: status `limit` means it holds as documented, and the report lists it under Documented limits with the README reference. A limit never counts as a failure and never changes the exit code; behaviour that differs from the documentation is a FAIL. A check whose prerequisite did not hold (a session that never connected, a daemon that never started, an answer that was not valid JSON, a firewall block that did not take effect) fails as `harness`; it never passes. A full run takes about 20 minutes: about 6 to build, lease and set up the machines, then about 14 for the phases. Phases 1-2 alone should take under 10 minutes.

The exit code is the verdict:

| Exit | Meaning |
| --- | --- |
| 0 | every check passed |
| 1 | assertion failures (known product bugs show up here) |
| 2 | harness failures: setup, a `harness` check, log collection or masking, or a machine that could not be released |
| 3 | missing coverage: a selected phase that did not run to its end, a step that did not finish with exit 0, or a machine that reported no checks |
| 128+n | interrupted by signal n, whatever the verdict; `REPORT.md` notes the signal, and its verdict covers only what ran |

A run ID is used once: the run's directory is reserved with a plain `mkdir`, so a repeated `--run-id` is refused before it can touch another run's ledger.

Cleanup runs on every exit, including Ctrl-C. Each allocation runs in a worker of its own under `setsid` (`scripts/e2e/alloc.sh`), which ignores INT, TERM and HUP and writes the operation ID and the machine ID to `alloc/<kind>.<who>.rec` the moment kiln returns them, so a signal to the run's whole process group cannot lose one. Cleanup waits for those workers, asks kiln about any operation still without a machine, and reports one it cannot resolve as a harness failure that names the operation. It then releases everything this run asked for and checks with `kiln vm list` and `kiln sandbox list` that it is gone. Each of these outcomes (auth key deleted, each release, the final check) is a phase 0 check in the results, and `REPORT.md` is written after them, so a release that failed shows up in the saved report. A second Ctrl-C only skips the rest of the log collection; the releases still run. Logs leave a machine only after its suite jobs are stopped and each file is masked into a separate export directory. A file that cannot be masked is withheld and counted as a harness failure. Cross-machine timings are corrected by the A-B clock offset, measured over the tailnet at the start and the end; an offset over 0.5 s is a harness failure.

`--reuse e2e-out/<run>` (with machines kept by `--keep`) is for debugging. Each machine has a lock file (`$TMPDIR/hk-e2e-locks-<uid>/<id>.lock`, held with `flock` for the whole run), so two runs never share machines; a ledger whose machines were released (`machines.released`) or are no longer live is refused. It stops every job of the earlier run (they all run in `hke2e.slice`), removes only the firewall rules the suite added (tagged `hk-e2e`), and clears the completion markers, which carry the run ID.
