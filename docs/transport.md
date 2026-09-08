# fsh Transport Protocol

## Overview

The fsh transport layer provides a confidential, integrity-protected,
mutually-bound channel over which user authentication and connection
protocols run. It mirrors SSH's transport layer (RFC 4251, RFC 4253)
in purpose — server authentication, session binding, and entry into
services — but delegates all key exchange, record protection, and
forward secrecy to QUIC version 1 (RFC 9000) with embedded TLS 1.3
(RFC 8446, RFC 9001).

There is no fsh key exchange, no fsh record layer, no rekeying, and no
compression. A single QUIC connection carries one fsh session; QUIC
bidirectional streams carry connection-protocol channels.

fsh is capability-minimal QUIC-native remote execution for controlled
fleets and edge nodes over unreliable networks; it is NOT a drop-in
SSH replacement. Status: experimental protocol-design scaffold.

Terms reused from RFC 4251: transport layer, session identifier,
algorithm negotiation, name-list, service request.

## Transport (QUIC+TLS 1.3 profile)

Implementations MUST run over QUIC version 1 (RFC 9000) with TLS 1.3
(RFC 8446, RFC 9001) as the only handshake. TLS 1.2 and below MUST NOT
be offered or accepted. QUIC version negotiation handles versioning;
there is no SSH-style version-string exchange.

- ALPN: endpoints MUST offer and select `fsh/1`. A server that does
  not recognize the ALPN MUST abort the connection. No other ALPN
  token is defined.
- TLS parameters: TLS 1.3 only. AEAD suites only:
  `tls-aes-128-gcm-sha256`, `tls-aes-256-gcm-sha384`,
  `tls-chacha20-poly1305-sha256` (TLS 1.3 cipher suites, lowercase-
  hyphenated per fsh naming, max 64 chars). Finite-field and
  elliptic-curve groups used inside the TLS handshake are a TLS
  concern, not fsh negotiation; implementations MUST NOT offer
  FFDHE groups below 3072 bits or non-NIST curves outside TLS policy.
  PSK-only handshakes without (EC)DHE MUST NOT be offered or accepted;
  any handshake without forward secrecy MUST be refused (see RFC 8446,
  Section 2).
- 0-RTT: clients MUST NOT send application data in 0-RTT. Servers
  MUST reject 0-RTT. Replay protection for session data comes from
  QUIC/TLS nonce handling (RFC 9001), not fsh sequence numbers.
- Keepalive: fsh defines no ping message. Idle detection uses QUIC
  PING frames and `max_idle_timeout` transport parameters (RFC 9000).
  `SSH_MSG_IGNORE` MAY be sent as an application-level keepalive.
- Algorithm negotiation at the fsh layer: none. There is no
  `KEXINIT` name-list exchange for kex, host-key, encryption, MAC,
  or compression. Cipher/MAC choice is a TLS 1.3 handshake outcome
  (RFC 9001). Public-key signature algorithms are negotiated in the
  user authentication protocol, not here.

## Framing

EVERY fsh message on ANY stream is framed as:

```
u32-BE length || u8 msg-number || payload
```

Length covers type + payload (i.e. 1 + len(payload)). There is no
bare msg-number framing anywhere: receivers MUST NOT parse a stream
as a bare `msg-number || payload` sequence.

Rationale: QUIC streams (RFC 9000) are byte streams; QUIC preserves
no message boundaries — a STREAM frame segment carries an arbitrary
byte slice at an arbitrary offset, and one fsh message may span many
STREAM frames while one STREAM frame may carry fragments of several
messages. The u32-BE length prefix restores message boundaries: the
receiver buffers stream bytes, reads the 4-octet length, then waits
for exactly that many following bytes before dispatching one message.
Stream segments therefore have no message meaning; only the
reassembled length-delimited unit is a message.

The rule applies uniformly to the control stream and to every channel
stream. Senders MUST emit exactly one length prefix per message;
receivers MUST reject (treat as fatal decode error) a length that
would exceed the remaining stream or a sane maximum (RECOMMENDED
35000, matching SSH's 35000-byte packet ceiling in spirit).

## Streams

- Stream 0 — control stream, reserved. QUIC stream 0 is the
  client-initiated bidirectional stream with stream ID 0. It carries
  all transport messages (1-19, 20-29), all userauth messages
  (50-79), and all channel lifecycle messages (open/close/EOF and
  channel requests). No channel data travels on stream 0. Both
  endpoints MUST reserve stream 0 for this purpose; channel streams
  MUST NOT use stream ID 0.
- Channels — client-initiated bidirectional QUIC streams only
  (RFC 9000, Section 2). Channel id = stream_id / 4: the first
  channel stream is QUIC stream ID 4 (channel 1), then 8 (channel 2),
  12 (channel 3), and so on. The mapping is exact; endpoints derive
  the channel id by integer division of the QUIC stream ID by 4.
- NO server-initiated channels in v0. Servers MUST NOT open
  bidirectional streams for channels; clients MUST treat a
  server-initiated channel stream as a protocol violation and abort
  the connection with `SSH_MSG_DISCONNECT`.
- All channel lifecycle messages travel on the control stream and
  reference the channel by its uint32 channel id — never by raw QUIC
  stream ID on the wire except through the deterministic mapping
  above. Channel data (payload bytes) travels on the channel's own
  QUIC stream, framed per the Framing section.
- Stream-level and connection-level flow control is QUIC's (RFC 9000);
  there is no fsh-level window. Stream FIN / RESET_STREAM /
  STOP_SENDING map to channel close semantics (see connection
  protocol).

## Host identity

Single model: the TLS server certificate with SPKI pinning. There is
no separate host-key-blob identity and no cert-chain-vs-TOFU duality.

- The server presents a TLS 1.3 server certificate (RFC 8446, RFC 9001).
  The client authenticates the server by pinning the Subject Public
  Key Info (SPKI) of that certificate.
- Trust-on-first-use (TOFU) on first connect with explicit user
  confirmation is the default policy; enterprise deployments MAY
  pre-provision pins. The client maintains a persistent pin store —
  the OpenSSH known-hosts equivalent — keyed by hostname, port, and
  SPKI hash, and compares the presented SPKI against it on every
  subsequent connect.
- The server proves possession implicitly via the TLS handshake
  (RFC 8446): only the holder of the private key matching the pinned
  SPKI can complete the handshake. No separate host-key signature or
  out-of-handshake host-key assertion exists.
- Fingerprint format: SHA-256 over the DER-encoded SPKI, base64-encoded
  without padding, displayed as OpenSSH-style `SHA256:` fingerprints
  so operators can compare out of band.
- On pin mismatch the client MUST abort with `SSH_MSG_DISCONNECT`
  and MUST NOT proceed to userauth. Rotation is a pin-store operation
  (add the new SPKI pin, optionally retain the old during migration);
  there is no in-protocol multi-key assertion.
- Public-key algorithm names for SPKI keys reuse OpenSSH exactly
  (see authentication protocol); TLS internals (signatureScheme
  negotiation) remain a TLS 1.3 concern (RFC 8446).

## Channel binding

All application-layer authentication is bound to the transport so a
signature captured on one session cannot be replayed on another
(RFC 8446, Section 7.5 exporter semantics; RFC 9001 for QUIC/TLS
composition).

- Binding value: both sides compute exactly 32 bytes via the TLS 1.3
  exporter (RFC 8446, Section 7.5) with label `"fsh-binding-v0"`,
  empty context, and 32 bytes of output length. It is constant for
  the life of the QUIC connection and MUST NOT be renegotiated (TLS
  key updates do not change it).
- Every userauth public-key signature MUST cover this binding value
  concatenated with the request fields (see authentication protocol).
  Signatures that omit or mismatch the binding value MUST be rejected.
- There is no handshake-hash field and no fsh `KEX-H` transcript
  hash. QUIC connection IDs are routing identifiers (RFC 9000) and
  MUST NOT be described or used as channel bindings.
- PSK-only TLS handshakes without (EC)DHE provide no forward secrecy
  and MUST be refused; only (EC)DHE handshakes yielding fresh
  exporter output are acceptable.

## Message numbers

Transport owns 1-19 (generic) and 20-29 (negotiation). All other
ranges belong to userauth (50-79), connection (80-127), reservation
(128-191), and local extensions (192-255).

Generic (control stream):

| Number | Name                    | Notes                                  |
|--------|-------------------------|----------------------------------------|
| 1      | SSH_MSG_DISCONNECT      | Reason code + description; then close  |
| 2      | SSH_MSG_IGNORE          | No-op; keepalive-safe                  |
| 3      | SSH_MSG_UNIMPLEMENTED   | Reply to unknown msg-number            |
| 4      | SSH_MSG_DEBUG           | `always-display` flag + text           |
| 5      | SSH_MSG_SERVICE_REQUEST | Service name: `fsh-userauth`, `fsh-connection` |
| 6      | SSH_MSG_SERVICE_ACCEPT  | Echo of accepted service name          |
| 7-19   | reserved                | No message defined; see unknown rule   |

Negotiation (20-29): reserved for future transport extensions.
Currently no message in this range is defined; endpoints MUST NOT
send them. There is no `KEXINIT` (20), `NEWKEYS` (21), `KEXDH_*`
(30-49), `USERAUTH_BANNER` (53), or `EXT_INFO` equivalent — those
numbers MUST NOT be reused, and 7-19 stay reserved.

Unknown-message handling — one rule: an unknown message in assigned
ranges received on the control stream MUST elicit
`SSH_MSG_UNIMPLEMENTED`; an unknown message in the 192-255 local
range MUST be ignored.

Service setup: after the QUIC/TLS handshake the client sends
`SSH_MSG_SERVICE_REQUEST` with `fsh-userauth`; the server replies
`SSH_MSG_SERVICE_ACCEPT`. `fsh-connection` runs only after userauth
success.

## Security properties

- Confidentiality and integrity: provided by TLS 1.3 AEAD records
  inside QUIC packets (RFC 9001). fsh adds no cipher or MAC of its own.
- Replay protection: QUIC packet-number / TLS-nonce uniqueness
  plus TLS handshake transcript integrity (RFC 9000, RFC 9001).
  fsh sequence numbers do not exist.
- Forward secrecy: every session uses an ephemeral (EC)DHE TLS 1.3
  handshake (RFC 8446); PSK-only (no-PFS) handshakes are refused.
  Compromise of long-term host or user keys does not decrypt past
  sessions.
- No downgrade: only one QUIC version handshake and one TLS
  version (1.3) with an AEAD-only suite policy and a single ALPN
  token. There is no version-string or name-list haggling an
  attacker can weaken; failed negotiation aborts rather than falls
  back.
- Server authentication: single layer — TLS handshake possession of
  the private key matching the pinned SPKI, verified against the
  persistent pin store (TOFU by default). Pin failure aborts the
  session before userauth.
- Rekeying: unnecessary. TLS 1.3 key updates (QUIC key phases,
  RFC 9001) rotate traffic keys transparently; fsh defines no
  `NEWKEYS` and no 1 GiB rekey threshold.

## SSH differences (what was dropped and why)

Mirrored on RFC 4253; dropped where QUIC + TLS 1.3 absorbs the need:

- Key exchange (`KEXINIT`, `KEXDH_*`, `NEWKEYS`, Diffie-Hellman
  group negotiation): dropped. TLS 1.3 (RFC 8446) performs an
  audited, ephemeral handshake; a second fsh kex would add code and
  attack surface for zero security gain.
- Record protection (ciphers, MACs, compression negotiation,
  sequence numbers, binary packet length/padding): dropped as a
  record layer. QUIC packet protection + TLS AEAD (RFC 9001)
  provide confidentiality, integrity, and replay resistance. fsh
  framing is only the u32-BE length prefix that restores message
  boundaries on byte streams — not encryption or padding.
- Rekeying (~1 GiB / time-based): dropped. QUIC key updates rotate
  keys without an fsh-visible handshake.
- Compression: dropped. Modern payloads (already compressed media,
  encrypted streams) gain nothing; compression-before-encryption
  invites CRIME-style oracles. Transport parameters negotiate
  nothing about compression.
- Version-string exchange and extensible `KEXINIT` name-lists:
  dropped. ALPN `fsh/1` plus the TLS handshake negotiate the only
  parameters that vary. Public-key algorithm choice lives in
  userauth.
- Server host-key-blob assertion and certificate-chain-vs-TOFU
  duality: dropped. Single SPKI-pin model (TOFU + pin store);
  possession proved implicitly by the TLS handshake.
- Session-identifier / handshake-hash binding (`KEX-H`, `ssh session
  id` exporter): replaced by the single `"fsh-binding-v0"` TLS 1.3
  exporter (32 bytes, empty context). QUIC connection IDs are
  routing-only, never bindings.
- `USERAUTH_BANNER`, `EXT_INFO`, and server-initiated channels:
  dropped / not in v0. Pubkey advertisement, if any, is the
  `USERAUTH_FAILURE` continuable-methods name-list (see
  authentication protocol); channels are client-initiated only.

Kept from SSH: SPKI-pinning semantics analogous to known-hosts,
exporter binding of authentication signatures, service-request
multiplexing (`fsh-userauth`, `fsh-connection`), and the 1-19
generic message block discipline shared with the registry.
