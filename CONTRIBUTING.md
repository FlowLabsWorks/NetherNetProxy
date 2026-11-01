# Contributing

Thanks for helping! Bug reports, test results from other consoles and pull requests are welcome.

## Reporting problems

Use the bug report form. The most useful details are: console and its Minecraft version, the Bedrock
Dedicated Server version, the NetherNetProxy version (`nethernet-proxy -version`) and the log
(`journalctl -u nethernet-proxy`, or run with `-v`). Please remove host names or addresses you do not
want to publish.

Reports that a console other than an Xbox works or fails are especially valuable – the project is
only tested with an Xbox so far.

## Development setup

You need Go 1.25 or newer (or Docker: `scripts/docker-build.sh` vets, tests and builds in the official
golang container).

```sh
go vet ./...
go test ./...        # includes RFC 5769 STUN vectors and a loopback test of the ICE-lite agent
gofmt -l .           # must print nothing
make dist            # cross-compiles into dist/
```

## Branches and pull requests

`main` is protected: nobody pushes to it directly, not even the maintainer. Every change reaches it
through a pull request that passes CI (tests and `govulncheck`). The maintainer works on the
long-lived `develop` branch and merges it into `main` with a pull request and a **merge commit**
(squash and rebase merges are disabled: they would make `develop` diverge from `main`). Afterwards
`develop` is brought up to date with `git merge --ff-only origin/main`. There are no feature
branches – the project is small enough that they would only add ceremony. Releases are tags on
`main`.

If you contribute from a fork, open the pull request against `develop`; one against `main` is fine
too and will be retargeted.

## Guidelines

- Keep the dependency list short. The binary links seven modules, all needed for DTLS and SCTP; new
  third-party modules need a good reason and an entry in `THIRD_PARTY_NOTICES.md`.
- Comments, log messages and documentation are in English.
- Code is formatted with `gofmt`. New behaviour comes with a test where that is practical.
- Do not log or store anything from the console's `Login` packet. The proxy deliberately ignores it.
- Do not commit configuration containing real host names (`config.json` is git-ignored).
- Keep pull requests focused, and describe what you tested (console, Minecraft version, server).

## When Minecraft changes a packet

The replayed handshake packets in `cmd/nethernet-proxy/bedrock.go` are recordings of one protocol version. How to
re-record them is described in [docs/UPDATING.md](docs/UPDATING.md) – a pull request with fresh
recordings for a new Minecraft version is the most welcome kind of contribution.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
