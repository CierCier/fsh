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
  token is defined in v0. QUIC version negotiation does not negotiate
  FSH semantics; it negotiates only the QUIC wire version (RFC 9000).
  Future incompatible revisions of FSH MUST use distinct ALPN strings
  (`fsh/2`, and so on). Compatible evolution within one ALPN uses
  `@fsh.dev` extension names, never a new ALPN token.
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
stream. Senders MUST emit exactly one length prefix per message.

Maximum framed message size is 35000 bytes total (the u32-BE
length-field value, i.e. 1 + len(payload)). Endpoints MUST NOT send a
message larger than 35000 bytes. Receipt of an oversize message on the
control stream REQUIRES the receiver to send `SSH_MSG_DISCONNECT`
with reason code 1 (protocol-error) and then close the QUIC
connection. Oversize channel-stream messages are a fatal decode
error: the receiver MUST abort the channel stream and SHOULD treat a
repeated or egregious violation as a connection protocol error.

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
  pre-provision pins. The client maintains a persistent pin store
  keyed by hostname, port, and SPKI hash, and compares the presented
  SPKI against it on every subsequent connect.
- The server proves possession implicitly via the TLS handshake
  (RFC 8446): only the holder of the private key matching the pinned
  SPKI can complete the handshake. No separate host-key signature or
  out-of-handshake host-key assertion exists.
- Public-key algorithm names for SPKI keys reuse OpenSSH exactly
  (see authentication protocol); TLS internals (signatureScheme
  negotiation) remain a TLS 1.3 concern (RFC 8446).

### SPKI validation details

Pinning REPLACES PKIX validation. Self-signed server certificates are
expected and MUST be accepted subject to the pin rules below.
Endpoints MUST NOT enforce SNI/SAN matching, certificate expiry,
or EKU constraints on the fsh server certificate; they MUST ignore
those fields for authentication purposes (they MAY still log them
for diagnostics).

- Fingerprint: base64-encoded (without padding) SHA-256 over the
  DER-encoded SPKI. Displayed with the distinct prefix `FSH-SHA256:`
  followed by the base64 value (e.g.
  `FSH-SHA256:AbCdEf...`). It MUST NOT be labelled `SHA256:` alone
  and MUST NOT be confused with any other ecosystem's fingerprint format.
- First contact: when no pin exists for the host/port, the client
  MUST display the `FSH-SHA256:` fingerprint to the user and require
  explicit user confirmation (SSH-style TOFU prompt: show
  host, port, and fingerprint, and proceed only on affirmative
  answer) before proceeding. On confirmation the client stores the
  pin; on refusal it aborts the QUIC connection without sending
  further fsh messages.
- Pin mismatch: when a pin exists and the presented SPKI does not
  match, the client MUST refuse the connection: it MUST send
  `SSH_MSG_DISCONNECT` with reason code 3 (host-key-changed) where
  possible and then close the QUIC connection, and MUST NOT proceed
  to userauth. Rotation is a pin-store operation (add the new SPKI
  pin, optionally retain the old during migration); there is no
  in-protocol multi-key assertion.

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

All messages below travel on the control stream (QUIC stream 0) and
are length-framed per the Framing section: `u32-BE length || u8
msg-number || payload`. Field encodings follow RFC 4251 conventions:
`uint32` is 4 octets big-endian, `string` is `uint32 length || bytes`
(UTF-8 where text), `boolean` is a single octet (`0` = FALSE,
nonzero = TRUE; senders MUST send `0` or `1`), `u8` is a single
octet. There are no SSH sequence numbers anywhere in v0.

### SSH_MSG_DISCONNECT (1)

```
u8 msg-number (= 1) || uint32 reason-code || string message
```

| Field       | Type   | Notes                                              |
|-------------|--------|----------------------------------------------------|
| msg-number  | u8     | Always 1                                           |
| reason-code | uint32 | One of the codes below                             |
| message     | string | UTF-8 human-readable explanation; no language tag  |

Reason codes:

| Code | Name             | Meaning                                |
|------|------------------|----------------------------------------|
| 1    | protocol-error   | Generic protocol violation / decode error, incl. oversize framed message |
| 2    | auth-failed      | Authentication failed, no further attempts possible |
| 3    | host-key-changed | Server SPKI pin mismatch               |
| 4    | shutting-down    | Sender is closing down                 |
| 5    | too-many-requests| Rate limit / request overload          |

Behavior: a sender that transmits DISCONNECT MUST close the QUIC
connection immediately after sending it (no further fsh messages on
any stream). A receiver that gets DISCONNECT SHOULD log the
reason-code and message, MUST NOT send further fsh messages except
to flush already-queued transport state, and MUST treat the session
as terminated once the QUIC connection closes. There is no
language-tag field (unlike RFC 4253); receivers MUST parse exactly
reason-code + message and reject trailing bytes as a decode error.

### SSH_MSG_IGNORE (2)

```
u8 msg-number (= 2) || opaque bytes (any length, including zero)
```

| Field      | Type    | Notes                                    |
|------------|---------|------------------------------------------|
| msg-number | u8      | Always 2                                 |
| data       | opaque  | Zero or more arbitrary bytes; no structure |

Behavior: the receiver MUST ignore the entire message (all payload
bytes after the msg-number) and MUST NOT send any reply in response
to IGNORE — never UNIMPLEMENTED, DEBUG, or any other message. Either
side MAY send IGNORE as an application-level keepalive; it carries
no semantics.

### SSH_MSG_UNIMPLEMENTED (3)

```
u8 msg-number (= 3) || u8 offending-msg-number
```

| Field                | Type | Notes                                        |
|----------------------|------|----------------------------------------------|
| msg-number           | u8   | Always 3                                     |
| offending-msg-number | u8   | The msg-number that was not understood       |

The payload is the single offending message number — the msg-number
the sender did not understand or cannot process. There are no
sequence numbers in fsh, so unlike RFC 4253 there is no rejected
sequence-number field. Behavior: sent only on the control stream in
reply to an unknown or unsupported message received on the control
stream (see unknown-handling rule below). It MUST NOT be sent in
reply to IGNORE, DISCONNECT, or itself; a receiver MUST NOT reply
to UNIMPLEMENTED with UNIMPLEMENTED. Receipt of UNIMPLEMENTED is
advisory (log / diagnosed); it does not close the connection by
itself.

### SSH_MSG_DEBUG (4)

```
u8 msg-number (= 4) || boolean always-display || string message
```

| Field          | Type    | Notes                                              |
|----------------|---------|----------------------------------------------------|
| msg-number     | u8      | Always 4                                           |
| always-display | boolean | TRUE = display even when debugging is off          |
| message        | string  | UTF-8 debug text; no language tag                  |

Behavior: purely informational; the receiver MUST NOT reply to
DEBUG. If `always-display` is TRUE the implementation SHOULD display
the text to the user; otherwise it SHOULD display it only when
debugging is enabled. There is no language-tag field.

### SSH_MSG_SERVICE_REQUEST (5) / SSH_MSG_SERVICE_ACCEPT (6)

```
u8 msg-number (= 5 or 6) || string service-name
```

| Field        | Type   | Notes                                |
|--------------|--------|--------------------------------------|
| msg-number   | u8     | 5 = REQUEST, 6 = ACCEPT              |
| service-name | string | UTF-8 service name (listed below)    |

Defined services: `fsh-userauth`, `fsh-connection`. No other service
name is defined in v0.

Behavior: after the QUIC/TLS handshake the client sends
`SSH_MSG_SERVICE_REQUEST` with `fsh-userauth`; the server replies
`SSH_MSG_SERVICE_ACCEPT` echoing the accepted service name. A server
that does not accept the requested service MUST reply with
`SSH_MSG_DISCONNECT` (reason 1, protocol-error) and close the
connection — there is no failure reply distinct from DISCONNECT.
`fsh-connection` runs only after userauth success: the client sends
a second SERVICE_REQUEST for `fsh-connection` and the server echoes
SERVICE_ACCEPT. An ACCEPT with a service name the client did not
request is a protocol error (treat as DISCONNECT protocol-error).

### Reserved and unknown messages

7-19: reserved. No message is defined in this range; endpoints MUST
NOT send them.

Negotiation (20-29): reserved for future transport extensions.
Currently no message in this range is defined; endpoints MUST NOT
send them. There is no `KEXINIT` (20), `NEWKEYS` (21), `KEXDH_*`
(30-49), `USERAUTH_BANNER` (53), or `EXT_INFO` equivalent — those
numbers MUST NOT be reused, and 7-19 stay reserved.

Unknown-message handling — one rule: an unknown message in assigned
ranges (including the reserved ranges 7-29 and any other assigned
but unimplemented number) received on the control stream MUST elicit
`SSH_MSG_UNIMPLEMENTED` carrying the offending msg-number; an
unknown message in the 192-255 local range MUST be ignored (never
elicits a reply). Reserved ranges therefore receive exactly like
unknown messages: UNIMPLEMENTED on the control stream.

Registry baseline: v0 `@fsh.dev` extension names recorded in the
registry (including `keepalive@fsh.dev`) are baseline-known to every
v0 implementation and need no advertisement. Future `@`-suffixed
extension names need an advertisement mechanism; that mechanism is
TBD and explicitly out of scope for v0.

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
