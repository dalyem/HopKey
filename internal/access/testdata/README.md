# Recorded OpenSSH logs for the binding parse

Each `openssh-VERSION-SYSTEM/` directory holds `ssh -vv -E` logs of real
connections from one OpenSSH client version, recorded on a leased Kiln VM by
`scripts/access-fixtures/run.sh` (test `TestSSHDBindingLogs` in
`internal/cli/access_sshd_fixture_test.go`). `TestBoundKeyRecordedLogs` runs
`BoundKey` over them in the normal checks.

- `pins`: the host keys of that run (`target`, `jump1`, `jump2`), all
  throwaway keys made on the VM.
- `hop-direct.log`, `hop-jump1.log`, `hop-jump2.log`: hop's own binding
  preflight (`hop access add`), direct and through one and two jump hosts
  (hop's ProxyCommand, which runs ssh with hop's config).
- `openssh-direct.log`, `openssh-proxyjump1.log`, `openssh-proxyjump2.log`:
  plain ssh with a config of hop's kind, direct and with `-J` chains of one
  and two jump hosts. The jump hosts' own key lines go to stderr, which the
  VM test checks; they are not in these files.
- `openssh-rekey.log`: `RekeyLimit=1K` and 256 KiB of output, so the key is
  logged once per key exchange.

To add a version, run `scripts/access-fixtures/run.sh` on a VM template with that
client, then copy `e2e-out/access-fixtures-*/result/binding/*` into a new
`openssh-VERSION-SYSTEM/` directory. A version without a directory here is not
claimed as supported (spec rev 17, §8.4).
