# fsh Architecture

Mirrors RFC 4251 (SSH architecture). Adapts the three-layer model to
QUIC (RFC 9000) + TLS 1.3 (RFC 8446, RFC 9001) transport with
modern-only cryptography.

Status: experimental protocol-design scaffold (v0). This document
describes the design; it is not a conformance test, implementation,
or deployment guide.

Positioning: fsh is capability-minimal QUIC-native remote execution
for controlled fleets and edge nodes over unreliable networks. It is
explicitly NOT a drop-in SSH replacement: no port-forwarding
ecosystem, no X11, no agent forwarding, no general-purpose SSH
compatibility. Where SSH behavior is reused, it is for operator
familiarity, not wire compatibility.

## 1. Overview

fsh provides secure remote command execution and subsystem
invocation over QUIC. Like SSH, it is layered:

```
transport -> user authentication -> connection
```

All three layers run over a single QUIC connection. QUIC provides the
reliable, multiplexed stream substrate (RFC 9000); TLS 1.3 provides
handshake secrecy and record protection (RFC 8446, RFC 9001). fsh
specifies only what TLS 1.3 and QUIC do not already provide: host
identity policy, user authentication, and channel semantics.

Every fsh message on any stream is `u32-BE length || u8 msg-number ||
payload`, where length covers type plus payload. There is no bare
msg-number framing anywhere. QUIC stream segments carry no message
meaning; a message may span segments.

Message numbers 1-255 are partitioned by layer (see transport,
authentication, and connection specifications for the registries):

* transport: 1-19 generic, 20-29 negotiation
* user authentication: 50-59 generic, 60-79 method-specific
* connection: 80-89 generic, 90-127 channel
* 128-191: reserved
* 192-255: local extensions

Message 53 (USERAUTH_BANNER) is unassigned; v0 defines no banner
message. Messages 7-19 (SSH EXT_INFO range) stay reserved; v0
defines no EXT_INFO equivalent. Pubkey algorithm advertisement is
the USERAUTH_FAILURE (51) continuable-methods name-list; v0 defines
no separate advertisement message.

Unknown-message handling, one rule: an unknown message number in an
assigned range received on the control stream elicits UNIMPLEMENTED;
an unknown message number in the 192-255 local range is ignored.

Algorithm and extension names reuse OpenSSH key/signature names
exactly for key-blob interop (see Section 3). All NEW fsh protocol
names (methods, requests, extensions) use `@fsh.dev`, never
`@openssh.com`.

## 2. Layers

### 2.1 Transport layer

Runs directly over QUIC, inside TLS 1.3 protection. Responsibilities:

* Minimal version framing (no SSH-style banner, no KEXINIT exchange).
* Server host identity: single model only -- TLS server certificate
  with SPKI pinning (TOFU on first connect plus a persistent pin
  store, the OpenSSH known-hosts equivalent). The server proves
  possession implicitly via the TLS 1.3 handshake (RFC 8446) by
  holding the private key matching the pinned SPKI. There is no
  separate host-key-blob identity and no cert-chain-vs-TOFU duality.
* Channel binding: TLS 1.3 exporter (RFC 8446 Section 7.5) with
  label `"fsh-binding-v0"`, empty context, exactly 32 bytes output.
  The exporter output (not any handshake hash) is the session
  identifier bound by userauth signatures. QUIC connection IDs are
  mutable routing identifiers and MUST NOT be described or used as
  channel bindings.
* PSK-only TLS 1.3 handshakes without (EC)DHE -- i.e. without forward
  secrecy -- are prohibited and MUST be refused.

TLS 1.3 absorbs what RFC 4253 assigns to transport: key exchange,
server authentication of the handshake, record
confidentiality/integrity (AEAD suites only), forward secrecy, and
rekeying (TLS key update). fsh specifies NO kex algorithms, NO
ciphers/MACs beyond the TLS 1.3 AEAD set, NO rekey at ~1 GiB, and NO
compression.

### 2.2 User authentication protocol

Runs over the control stream after transport establishment.
Responsibilities:

* Service request multiplexing (`fsh-userauth`, `fsh-connection`
  service names).
* Single supported method: `publickey`, including FIDO2-backed keys
  as key types, not separate methods.
* Publickey probe-then-sign flow: client proves possession by signing
  over the TLS exporter binding plus request fields; server checks
  authorization (account key list) before signaling SUCCESS (52).
  The server advertises supported pubkey algorithms in the
  USERAUTH_FAILURE (51) continuable-methods name-list. No other
  advertisement channel exists.

No other methods exist: no password, hostbased, keyboard-interactive,
or none.

### 2.3 Connection protocol

Runs after successful user authentication. Responsibilities:

* Stream discipline: QUIC stream 0 (client-initiated bidirectional)
  is the control stream and is reserved. Channels are
  client-initiated bidirectional QUIC streams only (streams 4, 8,
  12, ...); channel id = stream_id / 4. There are NO
  server-initiated channels in v0. All channel lifecycle messages
  travel on the control stream and reference the uint32 channel id.
* Channel lifecycle on the control stream: OPEN (90),
  OPEN_CONFIRMATION (91), OPEN_FAILURE (92), DATA is carried on the
  channel stream itself, CHANNEL_EOF, CHANNEL_CLOSE. No
  WINDOW_ADJUST (93): QUIC stream and connection flow control (RFC
  9000) replaces SSH windowing.
* Channel requests: `exec`, `shell`, `subsystem`, minimal `pty-req`,
  `signal`, `exit-status`, `exit-signal`, plus `window-change`
  (terminal resize). The subsystem mechanism stays; `fcp` file copy
  is deferred past v0 and has no v0 wire claims.
* Global requests on the control stream are kept minimal, including
  `keepalive@fsh.dev`. No forwarding requests.

Dropped from RFC 4254: `tcpip-forward` / `direct-tcpip`, X11
forwarding, environment passing, and SSH window management.

Shutdown reconciliation. A sender half-close (FIN) on a channel
stream means EOF for that direction. The full close sequence is:

1. Sender transmits CHANNEL_EOF on the control stream for the
   channel id, then half-closes (FIN) the data direction of the
   channel stream.
2. Receiver observes CHANNEL_EOF followed by FIN as end-of-data for
   that direction; either direction may EOF independently
   (half-close).
3. Either side transmits CHANNEL_CLOSE on the control stream when it
   will send no more data or requests for that channel.
4. After both sides have sent CHANNEL_CLOSE for a channel id, each
   endpoint issues RESET_STREAM / STOP_SENDING on any residual
   direction of that channel stream (RFC 9000) and releases the
   channel id. A channel id MUST NOT be reused within the
   connection.

| State | Local action | Remote observation |
| ----- | ------------ | ------------------ |
| open | send/receive DATA on channel stream | DATA on channel stream |
| local EOF | CHANNEL_EOF on control, then FIN | CHANNEL_EOF, then FIN = remote EOF |
| remote EOF | receive CHANNEL_EOF, then FIN | no more DATA from that direction |
| closing | send CHANNEL_CLOSE on control | peer's CLOSE pending |
| closed | both sides sent CHANNEL_CLOSE; RESET_STREAM / STOP_SENDING residue, release id | same |

## 3. Terminology

Reuses RFC 4251 terms with fsh bindings:

| Term | Meaning in fsh |
| ---- | -------------- |
| transport layer | QUIC + TLS 1.3 substrate; SPKI-pin host identity, exporter binding |
| user authentication protocol | publickey-only client authentication over the control stream |
| connection protocol | channel multiplexing over client-initiated QUIC streams; exec/shell/subsystem |
| control stream | QUIC stream 0, client-initiated bidi; carries all lifecycle, request, and auth messages |
| channel | one client-initiated bidirectional QUIC stream plus control-stream open/close/request state; id = stream_id / 4 |
| service request | `fsh-userauth` / `fsh-connection` service selector |
| host identity | pinned SPKI of the TLS server certificate (TOFU + pin store) |
| session identifier / binding | exactly 32 bytes from the TLS 1.3 exporter, label `"fsh-binding-v0"`, empty context |
| algorithm negotiation | TLS 1.3 negotiation plus fsh pubkey-algorithm / subsystem name-lists (FAILURE name-list) |
| name-list | comma-separated algorithm/key/request names in negotiation messages |

Supported host/user key and signature types reuse OpenSSH names
exactly for key-blob interop: `ssh-ed25519`, `ecdsa-sha2-nistp256` /
`ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`,
`rsa-sha2-256` / `rsa-sha2-512` with RFC 8332 semantics
(RSASSA-PKCS1-v1_5 with SHA-2, NOT PSS),
`sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` with the OpenSSH PROTOCOL.u2f
authenticator-data format, and `ssh-ed448` per RFC 8032 fully
specified. Excluded: `ssh-dss`, RSA < 3072, `ssh-rsa` (SHA-1).

## 4. Session lifecycle

1. QUIC + TLS 1.3 handshake (RFC 9001). Client validates the server
   certificate against the SPKI pin store (TOFU on first use). Both
   sides export the 32-byte `fsh-binding-v0` binding. PSK-only
   handshakes without (EC)DHE are refused.
2. Service request for `fsh-userauth` on the control stream. Server
   pubkey algorithm support is conveyed in the USERAUTH_FAILURE (51)
   continuable-methods name-list.
3. User authentication: optional publickey probe, then signed
   USERAUTH_REQUEST bound to the exporter output. FAILURE (51)
   carries the continuable list (always `publickey`); SUCCESS (52)
   advances.
4. Service request for `fsh-connection` on the control stream. Only
   the client opens channels (client-initiated bidi streams 4, 8,
   12, ...; id = stream_id / 4) via control-stream lifecycle
   messages.
5. Channel operation: requests (exec/shell/subsystem/pty/signal/
   window-change), DATA on the channel stream, EOF then FIN per
   direction, exit-status, CLOSE. Unknown assigned-range messages on
   the control stream elicit UNIMPLEMENTED; 192-255 local-range
   unknowns are ignored.
6. Connection teardown: CHANNEL_CLOSE both directions per channel,
   RESET_STREAM / STOP_SENDING residue, close streams, then the QUIC
   connection. No session resumption carries authentication across
   connections; each new QUIC connection re-authenticates.

## 5. Security properties

* Mutual authentication: server via TLS 1.3 possession of the
  pinned-SPKI private key (+ local TOFU pin policy); client via
  publickey signature bound to the `fsh-binding-v0` exporter output
  (binding defeats replay across connections).
* Confidentiality + integrity: inherited from TLS 1.3 AEAD (RFC
  8446); fsh adds no record layer and MUST NOT negotiate weaker
  primitives.
* Forward secrecy: inherited from (EC)DHE in TLS 1.3 (RFC 8446); no
  static-kex or PSK-only fallback.
* No downgrade: single TLS 1.3 stack, single publickey mechanism,
  single channel model. Negotiation name-lists contain only
  modern-only entries, so there is no legacy option to force.
* Replay protection: QUIC packet protection (RFC 9001) plus exporter
  binding of auth signatures; signatures are invalid on any other
  connection. Connection IDs provide no binding property.

## 6. Non-goals

Explicitly out of scope; MUST NOT be added without a new architecture
revision:

* TCP/IP forwarding (`tcpip-forward`, `direct-tcpip`) and X11
  forwarding.
* Password, hostbased, keyboard-interactive, and none authentication.
* Legacy cryptography: DSA (`ssh-dss`), RSA < 3072, `ssh-rsa`
  (SHA-1), CBC-era ciphers, non-AEAD suites, custom kex/compression.
* Compatibility fallback, drop-in SSH replacement behavior, or
  version-downgrade paths.
* Environment propagation beyond the minimal pty/shell contract.
* Server-initiated channels (no server-initiated channel opens in
  v0).
* `fcp` file copy: deferred past v0. The subsystem mechanism stays,
  but v0 makes no `fcp` wire claims.
* OS-agent or keychain integration beyond raw key-type support
  (handled elsewhere, not by the protocol layers).

## 7. Future work

Pointers only; none of these artifacts are created by v0:
conformance message vectors, fuzzing harnesses, a second independent
implementation, benchmarks against OpenSSH / Mosh / SSH3 over lossy
and high-latency links, and license / security-policy / governance
documents.

## 8. Next gate

Next gate: v0 now defines the exact control-stream grammar and the
channel state machine (see the transport and connection
specifications); implementation may begin against them.
