# hopkey

The `hop` command of [HopKey](https://github.com/dalyem/HopKey), an end-to-end encrypted vault for SSH hosts and keys. `hop` is a Go program; this package is only a way to get it.

```
npm i -g hopkey          # a release
npm i -g hopkey@next     # the latest prerelease
```

Linux and macOS, on x64 and arm64, with Node 18 or later for the install. The package holds all four builds and downloads nothing when it installs. The server, `hop-server`, is a Docker image: `docker pull ghcr.io/dalyem/hop-server`.

## What `hop` is after the install

The package's postinstall copies the build for your platform over `bin/hop`, so `hop` on your PATH is the native binary: no Node when it runs, and its signals and exit codes are its own. The package contains a small Node launcher at `bin/hop` for installs that skip postinstall scripts (`npm i -g --ignore-scripts`, pnpm and bun by default). The launcher starts `vendor/<os>-<arch>/hop`, passes stdin, stdout and stderr straight through, and exits with hop's exit code, or with hop's signal. It forwards SIGTERM. It does not forward SIGINT or SIGHUP: the terminal already sends those to hop, and a second one makes hop quit at once.

One thing the launcher cannot do: a `nohup hop ...` that should ignore hangups does not, because Node starts its child with default signal handling. If that matters, run the native binary: reinstall without `--ignore-scripts`, or run `vendor/<os>-<arch>/hop` from the package directory (`$(npm root -g)/hopkey`).

If the postinstall cannot replace `bin/hop` for any reason, it says nothing, the install still succeeds, and the launcher stays.

## Upgrading

A running `hop daemon` keeps running the code it started with. After an upgrade, run `hop daemon stop`; the next hop command starts the new one. The login service (`hop setup --service`) and the MCP client entries (`hop mcp install`) name the path of the `hop` file. If an upgrade or a different Node version (nvm, say) changes that path, run `hop setup --service` and `hop mcp install` again.

More in the [HopKey README](https://github.com/dalyem/HopKey#readme).
