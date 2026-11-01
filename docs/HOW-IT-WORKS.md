# How it works

This document describes what happens between a console and NetherNetProxy, layer by layer,
and the pitfalls that cost time while building it. Everything was observed against Minecraft
Bedrock 26.60 (protocol 2225); treat details as "worked there", not as a specification.

## 1. LAN discovery (UDP 7551)

Clients broadcast a *Request*; every host answers with a *Response* that carries its world card.
All packets are sealed the same way:

```
HMAC-SHA256(32 bytes) || AES-256-ECB, PKCS#7( uint16 length | uint16 type | uint64 sender | 8 zero bytes | body )
key = SHA-256( little-endian uint64 0xdeadbeef )          # the "application ID" of vanilla
```

| type | body |
| --- | --- |
| 0 request | empty |
| 1 response | `uint32 length` + **hex text** of the world card |
| 2 message | `uint64 recipient` + `uint32 length` + signaling text (≤ ~1140 bytes) |

The world card (*ServerData*, version 7) holds server name, protocol, version, level name, player
counts, game mode, two "accepts online / self-signed auth" flags, a nonce and the connection type
(4 = LAN). The proxy builds one card per configured world from `GET /v1/join` on the real server
and answers each request with all cards, each under its own network ID.

## 2. Signaling

Signals are text: `TYPE connectionId data`.

| type | data |
| --- | --- |
| `CONNECTREQUEST` | SDP offer of the console |
| `CONNECTRESPONSE` | SDP answer of the host |
| `CANDIDATEADD` | one ICE candidate (not needed here, see below) |
| `CONNECTERROR` | numeric session error |

A console that joins a **LAN** world sends an offer **without** `a=identity`. The vanilla server
answer carries a host identity, which makes the message larger than the ~1140 bytes a LAN message
may have – the console silently drops it. The answer written here has none and is ~700 bytes.

## 3. WebRTC pieces

- **SDP** – plain text, written and read by hand (`cmd/nethernet-proxy/session.go`). The answer contains `a=ice-lite`,
  the host candidates, a SHA-256 fingerprint, `a=setup`, `sctp-port 5000`,
  `max-message-size 262144`.
- **ICE-lite** (`cmd/nethernet-proxy/icelite.go`, `cmd/nethernet-proxy/stun.go`) – the console is the controlling ICE agent and sends the
  connectivity checks. The proxy listens on one UDP socket per connection, answers STUN Binding
  requests (short-term credential `ufrag:ufrag`, `MESSAGE-INTEGRITY`, `FINGERPRINT`,
  `XOR-MAPPED-ADDRESS`) and remembers the sender. STUN (first byte 0–3) and DTLS (20–63) share the
  socket. No gathering, no TURN, no mDNS.
- **DTLS** (pion) – the host is the DTLS server unless the console insists on being one. A fresh
  self-signed ECDSA P-256 certificate per connection; the console's certificate is checked against
  the fingerprint in its offer.
- **SCTP** (pion) – one association, MTU 1191.
- **Data channels** (`cmd/nethernet-proxy/session.go`) – the console opens `ReliableDataChannel` and
  `UnreliableDataChannel` with DCEP (`DATA_CHANNEL_OPEN` 0x03, answered with `ACK` 0x02 on PPID 50).
  Only the reliable channel carries the game. Messages are prefixed with one byte counting the
  *remaining* segments; one Bedrock batch is one message (no `0xFE` prefix, no encryption).

## 4. The Bedrock handshake

The console must believe it joined a world before it processes a Transfer packet – sending the
Transfer earlier is silently ignored. The proxy therefore plays a minimal server (`cmd/nethernet-proxy/bedrock.go`):

| console → proxy | proxy → console |
| --- | --- |
| `RequestNetworkSettings` (193) | `NetworkSettings` (143): flate, threshold 256 |
| `Login` (1) – ignored on purpose | `PlayStatus` login success (2), `ResourcePacksInfo` (6) |
| `ClientCacheStatus` (129) | |
| `ResourcePackClientResponse` (8) "all downloaded" | `ResourcePackStack` (7) |
| `ResourcePackClientResponse` (8) "stack finished" | packets 313, 337, `StartGame` (11), `ItemRegistry` (162) |
| `RequestChunkRadius` (69) | `ChunkRadiusUpdated` (70), `PlayStatus` spawn (2), 145 |
| `SetLocalPlayerAsInitialised` (113) | **`Transfer` (85)** → real server host and port |

Packet 8 starts with a varuint response code: 0 refused, 1 send packs, 2 all packs downloaded,
3 stack finished (followed by the name as a string). Everything except the Transfer packet is a
byte-for-byte template recorded from a working session. The `Login` packet is never parsed or
stored; the real server authenticates the player after the transfer.

## 5. After the transfer

The console leaves the proxy and joins `host:port` from the Transfer packet like any remote server:
`GET /v1/join`, `POST /v1/join/<id>` with its own identity over HTTP, then DTLS/SCTP straight to the
server's UDP range. The proxy hangs up three seconds after sending the Transfer packet.

## Pitfalls (short)

- LAN answers larger than ~1140 bytes are dropped by the console → no host identity in the answer.
- A Transfer before `StartGame` is ignored → replay the whole sequence above.
- pion's `sctp`, `dtls` need a logger factory, otherwise they dereference nil.
- `dtls` wants a `net.PacketConn`; the ICE-lite socket is wrapped accordingly (`liteConn`).
- Bedrock packet 8 codes are 0–3, not 1–4.
