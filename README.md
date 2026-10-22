# HopKey

HopKey is an end-to-end encrypted vault for SSH hosts and keys. The `hop` CLI and a local daemon keep decrypted keys in memory and serve them to the OpenSSH client through an ssh-agent socket, so plain `ssh <alias>` works on every device. `hop-server` is the Docker server that syncs ciphertext between devices. The design is a work in progress; right now the repository holds the scaffold and a spike for the ssh-agent and ssh config integration (`internal/sshagent`, `internal/sshconfig`).

## Checks

Checks run on Kiln, not on the orchestrator:

```
kiln checks run            # go vet, go test, gofmt -l
kiln checks run test       # one check
```

`scripts/check.sh` defines each check. The ssh integration test needs an `ssh` binary and a passwd entry for the current uid; `scripts/with-passwd.sh` supplies the entry on Kiln. With `HOPKEY_REQUIRE_SSH=1` the test fails instead of skipping when `ssh` is missing.
