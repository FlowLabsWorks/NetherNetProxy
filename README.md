# NetherNetProxy

[![CI](https://github.com/FlowLabsWorks/NetherNetProxy/actions/workflows/ci.yml/badge.svg)](https://github.com/FlowLabsWorks/NetherNetProxy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/FlowLabsWorks/NetherNetProxy?include_prereleases)](https://github.com/FlowLabsWorks/NetherNetProxy/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/FlowLabsWorks/NetherNetProxy)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Join your own NetherNet-only Minecraft Bedrock server from Xbox, PlayStation or Nintendo Switch**
through the console's **LAN list** – no extra account, no DNS tricks, no changes on the server.
NetherNetProxy is a small LAN proxy for a Raspberry Pi, a Linux box or Windows. It works where
RakNet-based LAN proxies such as Phantom and BedrockTogether stop: since Bedrock 26.50 servers
default to the NetherNet transport (WebRTC), and 26.60 removes RakNet from the client.

- [Quick start](#quick-start) · [Why](#why) · [How it works](#how-it-works) ·
  [Requirements](#requirements)
- [Server setup](#1-server-setup) · [Install](#2-install) · [Configure](#3-configure) ·
  [Run](#4-run) · [Join from the console](#5-join-from-the-console)
- [FAQ](#faq) · [Troubleshooting](#troubleshooting) · [Update and uninstall](#update-and-uninstall) ·
  [Compatibility](#compatibility) · [Limitations](#status-and-limitations) ·
  [Development](#development)

## Quick start

1. Check that your server speaks NetherNet – a JSON answer means yes:
   `curl http://minecraft.example.com:19132/v1/join`
2. On an always-on machine in the same LAN as the console, download a
   [release](https://github.com/FlowLabsWorks/NetherNetProxy/releases) (or
   [build it](#2-install)) and run `./nethernet-proxy -server minecraft.example.com:19132`.
3. On the console, open Minecraft's list of **LAN games** and join your server.

A permanent setup (systemd service, several servers) and troubleshooting are described below.

## Why

Consoles (Xbox, PlayStation, Switch) cannot add custom servers. The usual workaround is a LAN proxy
that advertises the remote server as a LAN game – Phantom, BedrockTogether and friends. Those tools
speak **RakNet**, which current clients and servers no longer use: since 1.26.50 Bedrock servers
default to **NetherNet** (WebRTC), and 1.26.60 removes RakNet from the client.

A NetherNet server with `online-mode=true` rejects every join that does not carry the player's
Microsoft-issued identity (error `IDENTITY_NOT_ALLOWED (37)`). A console that joins a *LAN* world
never sends one, so a plain relay cannot work – and the token cannot be forwarded, because it is
bound to the key and the DTLS fingerprint of the console's own connection.

## How it works

A console that joins a *remote* server does attach its identity. So:

1. The proxy advertises your servers as **LAN worlds** (UDP 7551, NetherNet discovery).
2. When the console joins one, the proxy answers like a tiny LAN host, lets the console "enter" an
   empty world and immediately sends a Bedrock **Transfer packet** to the real server.
3. The console reconnects to the address in the Transfer packet **as a remote server** – with its own
   identity. Your server authenticates the real player, the allow-list and `online-mode` stay
   untouched, and the game traffic never passes through the proxy.

```
console ──LAN list──▶ NetherNetProxy ──Transfer packet──▶ console
console ──HTTP signaling + UDP (own identity)─────────────▶ your server
```

The proxy never sees or forwards the player's credentials. The console therefore connects twice in a
row, which is by design – [why](#why-the-join-happens-twice-by-design). Details:
[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## Requirements

| What | Needed |
| --- | --- |
| Bedrock Dedicated Server | `transport=nethernet`, reachable **directly from the console** (see below) |
| Proxy host | any always-on machine **in the same LAN / broadcast domain as the consoles** (a Raspberry Pi is plenty); UDP **7551** free; can reach the server's TCP `server-port` |
| Console | nothing – no DNS, no account, no settings |
| To build | Go 1.25+ (or Docker, or a release binary) |

## 1. Server setup

Nothing is installed on the server. Check that it is set up for NetherNet and reachable:

```properties
# server.properties
transport=nethernet
server-port=19132                # TCP: signaling (HTTP). This is also the port the proxy announces.
server-udp-ports=22500-22530     # UDP: game traffic (one port per player)
online-mode=true                 # unchanged - the real server still authenticates every player
```

On the server's firewall / router, forward **TCP `server-port`** and the **UDP `server-udp-ports`
range** to the server (the same ports a console or tablet needs when it adds the server by address).
The proxy host itself does not need any of these ports.

Quick test from any machine – a JSON answer means the server speaks NetherNet:

```sh
curl http://minecraft.example.com:19132/v1/join
# {"name":"My Server","protocol":2225,"version":"1.26.60","level":"SURVIVAL","players":0,"maxPlayers":2,"gameType":0}
```

## 2. Install

**Pre-built binary** – download the archive for your platform from the
[Releases](https://github.com/FlowLabsWorks/NetherNetProxy/releases) page (Linux amd64 / arm64 /
armv7 / armv6, Windows amd64), verify it (below), unpack it.

<a id="verify-a-download"></a>
**Verify a download.** Every archive and `SHA256SUMS` carry a signed *build provenance
attestation* (Sigstore, created by the release workflow – there is no key to trust or lose). It proves
that the file was built by this repository's release workflow from the tagged commit and has not been
changed since:

```sh
sha256sum -c SHA256SUMS --ignore-missing           # the download is intact
gh attestation verify nethernet-proxy-v0.1.0-linux-arm64.tar.gz \
  --repo FlowLabsWorks/NetherNetProxy           # …and genuine
```

Checksums alone only show that a file is not corrupted; the attestation is what ties it to this
repository. If you prefer not to trust binaries at all, build from source (below).

**With Go** (1.25+) – installs `nethernet-proxy` into `$(go env GOPATH)/bin`:

```sh
go install github.com/FlowLabsWorks/NetherNetProxy/cmd/nethernet-proxy@latest
```

**From source** (Go 1.25+):

```sh
git clone https://github.com/FlowLabsWorks/NetherNetProxy.git
cd NetherNetProxy
go build -o nethernet-proxy ./cmd/nethernet-proxy   # or: make build
```

**Without Go** – build inside the official golang container (needs Docker; run it on the target
machine, e.g. the Raspberry Pi, to get a binary for that CPU):

```sh
scripts/docker-build.sh                # writes dist/nethernet-proxy
```

## 3. Configure

For one or a few servers you do not need a file at all – pass them as `host:port`:

```sh
./nethernet-proxy -server minecraft.example.com:19132 -server minecraft.example.com:19134
```

Check the setup first (queries each server once, then exits with 0 if all answered):

```sh
./nethernet-proxy -check -server minecraft.example.com:19132
# OK    minecraft.example.com:19132  level="SURVIVAL" version=1.26.60 protocol=2225 players=0/2
```

For a permanent setup use a JSON file (`config.json` next to the binary, or `-config path`):

```json
{
  "host": "minecraft.example.com",
  "worlds": [
    { "name": "survival", "port": 19132 },
    { "name": "creative", "port": 19134 },
    { "name": "elsewhere", "host": "other.example.com", "port": 19136 }
  ]
}
```

| Key | Meaning | Default |
| --- | --- | --- |
| `host` | host of the servers below (a world can override it) | – |
| `worlds[].port` | the server's `server-port` (TCP signaling, also the transfer target) | – |
| `worlds[].host` | host for this world only | `host` |
| `worlds[].name` | label for the log only | `host:port` |
| `bind` | UDP address for LAN discovery | `:7551` |

Name, version, player count and game mode of each LAN card are read from the server every 30
seconds, so the cards always match the real server. `-server` and the file can be combined.

| Flag | Meaning |
| --- | --- |
| `-server host:port` | announce this server (repeatable; no config file needed) |
| `-config path` | JSON config file (default `config.json`, optional when `-server` is used) |
| `-check` | query the configured servers once and exit |
| `-v` | debug log |
| `-dump` | log the ID of every Bedrock packet (debugging) |
| `-version` | print the version and exit |

## 4. Run

**Try it in a terminal** (Ctrl+C stops it; on Windows allow UDP 7551 in the firewall when asked):

```sh
./nethernet-proxy -server minecraft.example.com:19132
```

**As a service on Linux (systemd)** – installs an unprivileged user, the binary, a hardened unit and
starts it at boot:

```sh
sudo deploy/install.sh ./nethernet-proxy          # or dist/nethernet-proxy-linux-armv7 etc.
sudo $EDITOR /etc/nethernet-proxy/config.json     # created from config.example.json on first install
sudo systemctl restart nethernet-proxy
journalctl -u nethernet-proxy -f
```

Layout: binary `/opt/nethernet-proxy/nethernet-proxy`, config `/etc/nethernet-proxy/config.json`,
unit `/etc/systemd/system/nethernet-proxy.service`.

## 5. Join from the console

Open Minecraft on the console and look at the list of **LAN games**. Your servers appear with their
real name, version and player count. Join one: the console shows the connection screen twice in a
row – first the proxy, then your server – and you are in. Nothing has to be entered or confirmed in
between.

### Why the join happens twice (by design)

The double connection screen is not a glitch; it is how the proxy works, and it cannot be avoided
without giving up something you probably want:

1. **First join – to the proxy.** A LAN game is joined without the player's Microsoft-issued
   identity; a console simply does not send one for LAN worlds. Your real server requires it (that is
   what `online-mode=true` means), so the console cannot join the real server straight from the LAN
   list, and the proxy cannot do it on the console's behalf: the identity is cryptographically bound
   to the key and the DTLS fingerprint of the console's *own* connection, so it cannot be forwarded
   or reused by anyone else.
2. **Transfer.** The proxy therefore only receives the console for a moment and tells it, with a
   Bedrock *Transfer* packet (the mechanism big servers use to move players between lobbies), to
   connect to the real server.
3. **Second join – to your server.** The console now joins a *remote* server, and a console does
   attach its identity there. Your server authenticates the real player exactly as it would for a
   join by address: allow-list, permissions and `online-mode` apply to the actual account. From here
   on the game traffic runs directly between console and server – the proxy is no longer involved.

The alternatives would be a proxy that carries the game traffic itself and logs in with its own
Microsoft account (every player would then appear as that one account), a server with
`online-mode=false` (anyone can join under any name), or DNS redirection of a console's server list
(needs changes on the console or network). A second connection setup that takes a moment is the
price for none of those.

## FAQ

**Why can't I just add the server on the console?** Xbox, PlayStation and Switch have no "add
server by address" – only the featured servers, friends' worlds and the LAN list. NetherNetProxy puts
your server into the LAN list.

**Does the game traffic go through the proxy?** No. The proxy only receives the console for a moment
and sends it on to your server; after that console and server talk directly. The proxy can be a very
small machine, and it needs no open ports towards the internet.

**Does the proxy need a Microsoft account, or see mine?** Neither. The console authenticates itself
against your server with its own account on the second join; the proxy never sees or forwards it.
`online-mode` and the allow-list keep working as before.

**Does it work on PlayStation and Switch?** It uses the same LAN mechanism, but only an Xbox and a
Windows PC have been tested so far. Reports are welcome – please open an issue.

**What happens when Minecraft updates?** The proxy replays a few recorded server packets, which can
change between versions. A workflow checks Mojang's published protocol documentation every four
hours and opens an issue when a packet the proxy uses changes, saying whether the recorded packets
are affected. See [docs/UPDATING.md](docs/UPDATING.md).

**Can I run it on Windows?** Yes, there is a `windows-amd64` build. Allow UDP 7551 in the firewall.

## Troubleshooting

Run with `-v` (and `-dump` if needed) and watch the log.

| Symptom | Likely cause / fix |
| --- | --- |
| `-check` says `FAIL … HTTP 404` | the server does not run `transport=nethernet` |
| `-check` says `FAIL … timeout / refused` | the server's TCP `server-port` is blocked or the host name is wrong |
| No LAN worlds on the console | proxy host and console are not in the same broadcast domain (guest Wi-Fi, "AP isolation", VLANs), or UDP 7551 is blocked; log should say `world announced` for each server |
| Worlds appear, join returns to the menu | the console cannot reach the server directly: check the TCP `server-port`, the UDP `server-udp-ports` range and that the console can resolve the host name |
| Log shows `negotiation failed` | network problem between console and proxy (UDP blocked, several network interfaces); the message names the phase (ICE / DTLS / SCTP) |
| `negotiation failed … list network interfaces` or `no usable local IPv4 address` | the proxy cannot see a usable address: it has no IPv4 address outside loopback / docker / bridge interfaces, or a sandbox blocks netlink sockets (the shipped unit allows `AF_NETLINK`; keep it if you tighten `RestrictAddressFamilies`) |
| Join hangs after a Minecraft update; log stops after `StartGame` | the replayed packets no longer match the new version – see [docs/UPDATING.md](docs/UPDATING.md) |
| Service does not start | `journalctl -u nethernet-proxy`; usually a config error (the message names the problem) or UDP 7551 already in use |

## Update and uninstall

**Update:** build or download the new binary and run `deploy/install.sh` again. It keeps the config and
the previous binary as `nethernet-proxy.previous`.

**Uninstall:**

```sh
sudo systemctl disable --now nethernet-proxy
sudo rm -r /opt/nethernet-proxy /etc/nethernet-proxy /etc/systemd/system/nethernet-proxy.service
sudo systemctl daemon-reload
sudo userdel nethernet-proxy
```

## Compatibility

Every release is tested on an **Xbox** and a **Windows PC**, each joining through the LAN list
against Bedrock Dedicated Server with `transport=nethernet`, `online-mode=true` and an allow-list.
The table shows what was actually tried; "not yet tested" means exactly that.

| Proxy | Game version of the client | Server version (BDS) | Protocol | Xbox | Windows PC |
| --- | --- | --- | --- | --- | --- |
| 0.1.0-rc1 | 26.60 | 1.26.60, 1.26.61 | 2225 | ✔ (server 1.26.60) | ✔ (servers 1.26.60 and 1.26.61) |
| 0.1.0-rc2 | 26.60 (PC) | 1.26.60 | 2225 | not yet tested | ✔ (server 1.26.60) |

- ✔ means the console or PC joined a server through the proxy and arrived on the real server.
- 0.1.0-rc2 only updates dependencies (`golang.org/x/crypto`, `golang.org/x/sys`); no code of the
  proxy changed.
- The game version that matters is the one of the **client**: it decides which protocol the client
  speaks. The server version only has to be one the client can join.
- New Minecraft versions, including previews, are checked against Mojang's published protocol
  documentation by a scheduled workflow; see [docs/UPDATING.md](docs/UPDATING.md). That check does not
  replace a test on a real console, and the table lists only tested versions.

## Status and limitations

Tested on an **Xbox** and a **Windows PC**, see [Compatibility](#compatibility) for the versions.
PlayStation and Switch are untested. IPv4 only.

- **Version coupling.** The few packets the console needs before it accepts a Transfer
  (`StartGame` and friends) are replayed from recordings of one protocol version (`cmd/nethernet-proxy/bedrock.go`). If
  Mojang changes one of them the join breaks until the templates are re-recorded – see
  [docs/UPDATING.md](docs/UPDATING.md). The protocol number itself is not checked.
- **No authentication on the LAN side.** Anyone in the LAN can use the proxy; all it does is redirect
  them to the configured server, which authenticates them as usual. See [SECURITY.md](SECURITY.md).
- The console must reach the server's signaling port and UDP range directly.
- LAN discovery relies on UDP broadcast.

## Development

```sh
go vet ./... && go test ./...      # or: make
make dist                          # linux amd64, arm64, armv7, armv6 and windows amd64 into dist/
```

Repository layout:

| Path | Contents |
| --- | --- |
| `cmd/nethernet-proxy/` | the proxy (`package main`): discovery, signaling, ICE-lite, data channels, Bedrock handshake |
| `internal/schemacodec/` | reads and writes packet payloads from Mojang's protocol schemas (used by the protocol watch) |
| `tools/protocolwatch/` | the tool behind the scheduled "Protocol watch" workflow |
| `deploy/`, `scripts/` | systemd unit, install script, Docker build script |
| `docs/` | [how it works](docs/HOW-IT-WORKS.md), [keeping up with Minecraft updates](docs/UPDATING.md) |

Contributions are welcome – see [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).
Seven Go modules end up in the binary, all needed for DTLS and SCTP (`pion/dtls`, `pion/sctp`,
`pion/transport`, `pion/logging`, `pion/randutil`, `golang.org/x/crypto`,
`golang.org/x/sys`); everything else is
implemented here. Licenses of third-party code: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Credits

The NetherNet wire formats follow [df-mc/nethernet-spec](https://github.com/df-mc/nethernet-spec) and
the behaviour of [df-mc/go-nethernet](https://github.com/df-mc/go-nethernet) (MIT). The Transfer
approach was inspired by the architecture notes of
[Rynzewind/minecraft-bedrock-panel](https://github.com/Rynzewind/minecraft-bedrock-panel).

## Disclaimer

Not affiliated with, endorsed by or sponsored by Mojang Studios, Microsoft or Xbox. *Minecraft* is a
trademark of Mojang Synergies AB. Use at your own risk.

## License

MIT – see [LICENSE](LICENSE).
