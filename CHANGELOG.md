# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First version, published as pre-releases.

### Added

- Announces NetherNet Bedrock servers as LAN worlds (UDP 7551) with cards read live from the servers
  (`GET /v1/join`).
- Lets a console join a LAN world and sends it a Transfer packet to the real server, so it reconnects as
  a remote server with its own identity.
- Own implementation of NetherNet LAN discovery and signaling, SDP, ICE-lite (STUN), data channels
  (DCEP) and the minimal Bedrock handshake; DTLS and SCTP from `pion`.
- Configuration by JSON file or `-server host:port` flags; `-check` to verify the servers; `-v`,
  `-dump` and `-version`.
- `go install github.com/FlowLabsWorks/NetherNetProxy/cmd/nethernet-proxy@latest`; a binary built that way
  reports the module version.
- systemd unit and install script, Makefile and Docker build script.
- CI (gofmt, vet, race tests, govulncheck) and a release workflow that builds Linux and Windows
  binaries and signs them with build provenance attestations.
- Protocol watch: a scheduled workflow (`tools/protocolwatch`) compares the packet schemas Mojang
  publishes with `docs/protocol-baseline.json` every four hours and opens an issue when a packet the
  proxy depends on changes. The issue also says whether the recorded packets would change on the wire
  under the new schemas (`internal/schemacodec`).
- Community files: code of conduct, issue and pull request templates, CODEOWNERS, SUPPORT.md and a
  social preview image (`docs/assets`).
- Compatibility table in the README: which proxy version was tested with which game and server
  version on Xbox and Windows PC.

### Known limitations

- Tested on an Xbox and a Windows PC with Minecraft Bedrock 26.60 (protocol 2225) only, see the
  compatibility table in the README. IPv4 only.
- The replayed handshake packets are recordings of one protocol version; see `docs/UPDATING.md`.

[Unreleased]: https://github.com/FlowLabsWorks/NetherNetProxy/commits/main
