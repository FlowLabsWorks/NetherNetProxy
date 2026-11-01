# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: **Security → Report a vulnerability** on the
repository page. Do not open a public issue for them. You will get an answer as soon as possible;
this is a small hobby project maintained in spare time.

Only the latest release is supported.

## Trust model

What the proxy does and does not protect:

- It never sees, stores or forwards the player's Microsoft identity. The `Login` packet is ignored,
  and the real server authenticates the player after the Transfer packet.
- The LAN side is **unauthenticated** by design: any device in the LAN can ask the proxy for a
  Transfer to the configured server. That is the same exposure as the server's own address. Run the
  proxy only in networks where this is acceptable.
- LAN discovery uses a fixed, publicly known key (the "application ID" of the vanilla game). It
  provides no secrecy.
- Each connection is protected by DTLS with a throw-away self-signed certificate, checked against
  the fingerprint in the console's offer.
- The service runs as an unprivileged user with a hardened systemd unit (no capabilities, read-only
  filesystem, only IPv4/IPv6 sockets). Concurrent connection setups are capped and message sizes
  are bounded.

## Releases

Release archives and `SHA256SUMS` are built by the release workflow from a tagged commit and carry a
signed build provenance attestation (Sigstore). Verify a download with
`gh attestation verify <file> --repo FlowLabsWorks/NetherNetProxy`. The repository is configured so
that only the maintainer (and later explicitly invited collaborators) can push; everyone else
contributes through pull requests.

## In scope

Memory safety or denial-of-service problems reachable from the LAN (malformed discovery, STUN,
DTLS/SCTP or Bedrock packets), and mistakes in the unit or install script that grant more access
than described above.

## Out of scope

Vulnerabilities in Minecraft, in Bedrock Dedicated Server, or in your own network configuration, and
issues that need an attacker who already controls the proxy host.
