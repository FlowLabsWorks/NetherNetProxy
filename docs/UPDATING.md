# Keeping up with Minecraft updates

The proxy is independent of the game version in almost every respect: the LAN card is read from the
real server, and the client's protocol number is not checked. The one version-dependent part is the
set of **server packets replayed before the Transfer** (`tpl*` constants in `cmd/nethernet-proxy/bedrock.go`). They were
recorded from Minecraft Bedrock 26.60 (protocol 2225).

## Early warning: the protocol watch

Mojang publishes the schemas of all Bedrock packets in
[Mojang/bedrock-protocol-docs](https://github.com/Mojang/bedrock-protocol-docs), with a tag per
release and per preview. The "Protocol watch" workflow (`.github/workflows/protocol-watch.yml`) runs
every four hours, hashes the schemas of the packets the proxy replays, builds or reads
(`tools/protocolwatch`) and compares them with `docs/protocol-baseline.json`. For a change in a newer
version it opens an issue labelled `protocol-change` with the schema diff, which notifies the
repository owner. Each change is reported once; a failing run (for example after Mojang restructured
the repository) is reported by GitHub as a failed workflow.

### Template check

A schema change often does not touch the bytes the proxy sends: a new optional field that the
recorded packet leaves out, or a boolean that became a one-byte enum, look the same on the wire.
So the issue also answers the question that matters. The bot decodes the recorded packets
(`tools/protocolwatch/templates.json`, kept in step with `cmd/nethernet-proxy/bedrock.go` by a test) with the schemas of
the baseline version, proves that it gets the recorded bytes back, and writes them with the schemas
of the new version (`internal/schemacodec`). The issue gets one of three labels:

- `templates-unchanged`: every template encodes to identical bytes. The documented change needs no
  template update.
- `templates-changed`: some bytes differ. The issue lists the recorded and the candidate bytes. The
  candidates come from the schemas (new fields get the schema's default, removed ones are dropped)
  and have not been tried on a console.
- `templates-unknown`: the check could not be completed, for example because a schema uses a
  construct the codec does not know. Treat the schema diff as the only information.

### What the watch cannot tell

The watch only sees what Mojang documents. New packets in the login sequence, new checks in the
client or a different meaning of a value are invisible to it, so it does not prove that a join works
or fails, and the issue may be about a preview version that has not reached the consoles yet. When
the console runs the new version:

1. Join through the proxy. If it works, accept the new state:
   `go run ./tools/protocolwatch -update <tag>`, commit `docs/protocol-baseline.json`. If the
   issue listed candidate bytes, take them over first (see "Re-recording the templates", step 3).
2. If the join hangs, re-record the templates (below), then update the baseline.

Run `go run ./tools/protocolwatch` by hand to check right now (`-tags v1.2.3,...` to name tags).

## Symptoms of a changed packet

- The console shows the LAN world, accepts the join, then hangs on "connecting" or returns to the
  menu with an error, **and** the log (`-v -dump`) stops after `StartGame` (packet 11) or after
  `ResourcePackStack` (packet 7) without `console transferred`.
- The server and the game are on a newer version than the proxy was recorded against.

If the join works, nothing needs to be done – packets the proxy does not know are ignored.

## Re-recording the templates

You need *any* server implementation that is current for the new version and joinable from the
console over the LAN list (for example a Bedrock library such as
[gophertunnel](https://github.com/Sandertv/gophertunnel) with a `minecraft.ListenConfig`, a
NetherNet listener and `PacketFunc` set). Log every packet **sent to the client** with its ID and
payload, skipping `Login`:

1. Join the test server from the console and let it complete `StartGame`.
2. Keep the payloads (without the packet header) of: `NetworkSettings` (143), `PlayStatus` (2, login
   success and spawn), `ResourcePacksInfo` (6), `ResourcePackStack` (7), 313, 337, `StartGame` (11),
   `ItemRegistry` (162), `ChunkRadiusUpdated` (70) and 145.
3. Replace the matching `tpl*` hex strings in `cmd/nethernet-proxy/bedrock.go` and the same entries in
   `tools/protocolwatch/templates.json` (`go test` fails if they differ). The world name inside `StartGame` is
   replaced in code (`tplStartGame`); keep that string replacement working, the replacement must
   have the same length as the recorded name.
4. `go test ./...`, build, and try it with the console.

Run the proxy with `-v -dump` while testing: it logs the ID and size of every packet in both
directions, which shows quickly where the console stops answering.

If a packet's *layout* grew (a new field), the safest route is to take the new bytes unchanged from
the recording – the proxy never interprets these templates.
