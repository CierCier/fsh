# fsh Assigned Numbers

Mirrors RFC 4250 for fsh: QUIC (RFC 9000) + TLS 1.3 (RFC 8446, RFC 9001)
transport, mutual auth, modern-only crypto. No legacy, no compat fallback.
Status: experimental protocol-design scaffold, not a drop-in SSH replacement.

## Message number blocks

Message numbers 1-255, partitioned by layer. All writers MUST use
these blocks consistently. Numbers outside a layer's blocks MUST NOT
be sent for that layer.

| Block   | Layer      | Use                        |
|---------|------------|----------------------------|
| 1-19    | transport  | generic (disconnect, ignore, debug, service negotiation) |
| 20-29   | transport  | negotiation and handshake framing |
| 30-49   | —          | unassigned (SSH kex range; no equivalent in fsh) |
| 50-59   | auth       | generic userauth messages  |
| 60-79   | auth       | method-specific messages   |
| 80-89   | connection | generic (global requests)  |
| 90-127  | connection | channel operations         |
| 128-191 | —          | reserved; MUST NOT assign without a protocol revision |
| 192-255 | —          | local extensions only      |

TLS 1.3 absorbs key exchange, record protection, and rekey; QUIC
absorbs reliability and stream flow control. Blocks are retained for
framing shape even where fsh defines no message in them.

## Initial assignments

`—` means the number is retained but has no fsh message.

Unknown handling (applies everywhere): an endpoint that receives an
unknown message whose number lies in an assigned range on the control
stream MUST reply with UNIMPLEMENTED (3); an endpoint that receives an
unknown message whose number lies in 192-255 MUST ignore it.

Transport, generic (1-19):

| Number | Message       | Notes                          |
|--------|---------------|--------------------------------|
| 1      | DISCONNECT    | error text + reason code       |
| 2      | IGNORE        | keepalive / traffic shaping    |
| 3      | UNIMPLEMENTED | response to unknown sequence   |
| 4      | DEBUG         | human-readable only            |
| 5      | SERVICE_REQUEST | request `fsh-userauth` / `fsh-connection` |
| 6      | SERVICE_ACCEPT  | accept a requested service     |
| 7-19   | unassigned    | reserved; no EXT_INFO in v0    |

There is no EXT_INFO message in v0. Numbers 7-19 stay reserved and
MUST NOT be sent.

Transport, negotiation (20-29): 20-29 reserved for handshake
framing and channel binding. No initial assignment; kex, NEWKEYS,
and compression messages do not exist in fsh.

Auth, generic (50-59):

| Number | Message          |
|--------|------------------|
| 50     | USERAUTH_REQUEST |
| 51     | USERAUTH_FAILURE |
| 52     | USERAUTH_SUCCESS |
| 53     | unassigned (no banners in v0) |
| 54-59  | unassigned       |

USERAUTH_BANNER (53 in SSH) is not assigned in v0. Servers MUST NOT
send banners; clients MUST NOT expect them.

Auth, method-specific (60-79):

| Number | Message         | Method     |
|--------|-----------------|------------|
| 60     | USERAUTH_PK_OK  | publickey probe |
| 61-79  | unassigned      |            |

Password, hostbased, keyboard-interactive, and none have no
messages. New methods, if ever defined, take numbers from 61-79.

Public-key algorithm advertisement uses the USERAUTH_FAILURE (51)
continuable-methods name-list. There is no separate advertisement
message and no EXT_INFO in v0.

Connection, generic (80-89):

| Number | Message         |
|--------|-----------------|
| 80     | GLOBAL_REQUEST  |
| 81     | REQUEST_SUCCESS |
| 82     | REQUEST_FAILURE |
| 83-89  | unassigned      |

Global request names:

| Name | Notes |
|------|-------|
| `keepalive@fsh.dev` | keepalive; both sides SHOULD accept and reply REQUEST_SUCCESS with no payload |

Connection, channel (90-127):

| Number  | Message            | Notes                          |
|---------|--------------------|--------------------------------|
| 90      | OPEN               | only `session` channel type    |
| 91      | OPEN_CONFIRMATION  |                                |
| 92      | OPEN_FAILURE       |                                |
| 93      | —                  | WINDOW_ADJUST dropped; QUIC flow control replaces it; MUST NOT send |
| 94      | DATA               | per-stream bytes               |
| 95      | EXTENDED_DATA      | type 1 (stderr) only           |
| 96      | EOF                | half-close                     |
| 97      | CLOSE              |                                |
| 98      | CHANNEL_REQUEST    | `shell`, `exec`, `subsystem`, `pty-req`, `signal`, `exit-status`, `exit-signal`, `window-change` |
| 99      | CHANNEL_SUCCESS    |                                |
| 100     | CHANNEL_FAILURE    |                                |
| 101-127 | unassigned         |                                |

Extended data types: 1 = stderr. No other type is defined.

Channel request names: `shell`, `exec`, `subsystem`, `pty-req`
(minimal, interactive shell only), `signal`, `exit-status`,
`exit-signal`, `window-change` (terminal size change; payload follows
the SSH `window-change` shape). No `tcpip-forward`, `direct-tcpip`,
`x11`, or `env`.

## Algorithm names

Public-key / signature algorithms only. TLS 1.3 negotiates bulk
ciphers itself; no transport cipher, MAC, or compression names exist.

Key and signature algorithm names reuse OpenSSH exactly for key-blob
interop (see naming exception below):

| Name | Key type | Notes |
|------|----------|-------|
| `ssh-ed25519` | Ed25519 | RECOMMENDED; EdDSA per RFC 8032 |
| `ssh-ed448` | Ed448 | OPTIONAL to implement; when implemented, EdDSA per RFC 8032 exactly as specified in authentication.md; endpoints without it MUST refuse the algorithm, never negotiate down |
| `ecdsa-sha2-nistp256` | ECDSA P-256 | as in OpenSSH / RFC 5656 profile |
| `ecdsa-sha2-nistp384` | ECDSA P-384 | as in OpenSSH / RFC 5656 profile |
| `ecdsa-sha2-nistp521` | ECDSA P-521 | as in OpenSSH / RFC 5656 profile |
| `rsa-sha2-256` | RSA, >= 3072 bits, SHA-2 | RFC 8332 semantics: RSASSA-PKCS1-v1_5 + SHA-256, NOT PSS; keys < 3072 bits MUST be rejected |
| `rsa-sha2-512` | RSA, >= 3072 bits, SHA-2 | RFC 8332 semantics: RSASSA-PKCS1-v1_5 + SHA-512, NOT PSS; keys < 3072 bits MUST be rejected |
| `sk-ssh-ed25519@openssh.com` | FIDO2 Ed25519 | OpenSSH PROTOCOL.u2f authenticator-data signature format |
| `sk-ecdsa-sha2-nistp256@openssh.com` | FIDO2 ECDSA P-256 | OpenSSH PROTOCOL.u2f authenticator-data signature format |

Excluded, MUST NOT offer or accept: `ssh-dss`, `ssh-rsa`
(SHA-1), RSA keys under 3072 bits, passwords, hostbased,
keyboard-interactive, `none`, X11/TCP forwarding, compression.

Channel type: `session` only. Subsystem mechanism stays, but `fcp`
(file copy) is deferred past v0: no `fcp` subsystem wire claims are
defined in v0.

## Service names

| Name | Purpose |
|------|---------|
| `fsh-userauth` | user authentication protocol (replaces `ssh-userauth`) |
| `fsh-connection` | connection protocol (replaces `ssh-connection`) |

Requested via SERVICE_REQUEST (5) / accepted via SERVICE_ACCEPT
(6). Authentication MUST complete under `fsh-userauth` before
`fsh-connection` is requested.

## Naming rules

Applies to algorithm, service, channel-type, request, subsystem,
and extension names:

- Printable US-ASCII only; no `@`, comma, or whitespace except as
  the single `@` separator in local names.
- Case-sensitive; lowercase-hyphenated for standard names.
- Max 64 characters including any `@` suffix.
- All new fsh protocol names MUST take the form `name@fsh.dev`,
  never `name@openssh.com`. Standard (non-`@`) names are closed in
  v0; any new name is local to `fsh.dev` until a protocol revision
  standardizes it.
- Exception, key-blob interop only: the following OpenSSH key and
  signature algorithm names are reused verbatim and are NOT renamed
  under `@fsh.dev`: `ssh-ed25519`, `ssh-ed448`,
  `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`,
  `ecdsa-sha2-nistp521`, `rsa-sha2-256`, `rsa-sha2-512`,
  `sk-ssh-ed25519@openssh.com`,
  `sk-ecdsa-sha2-nistp256@openssh.com`. No other `@openssh.com`
  name is valid in fsh.
- Local extensions MUST take the form `name@FQDN`, where FQDN is a
  domain the definer controls (e.g. `zerortt@example.com`).
- Standard names MUST NOT contain `@`. A name with `@` MUST be
  treated as local even inside 1-191 blocks.
- Message numbers 192-255 are local extensions only and MUST pair
  with a `name@FQDN` identifier in the payload.

## Registry

STANDARDS-ACTION-style discipline, adapted for a single-repo spec:

- New assignments in 1-127 and 128-191 require a protocol-doc
  update describing the message or name, its wire format, and
  which layer sends it. Unreviewed or undocumented use is
  non-conforming, even experimentally.
- Numbers and names, once assigned, are never reused or
  redefined. Deprecated items are marked HISTORIC, never removed
  from the tables.
- 128-191 stays reserved until a protocol revision assigns it;
  implementations MUST NOT send on it.
- Unknown handling (same rule as above): an endpoint that receives
  an unknown message whose number lies in an assigned range on the
  control stream MUST reply with UNIMPLEMENTED (3); an endpoint that
  receives an unknown message whose number lies in 192-255 MUST
  ignore it.
- 192-255 and any `name@FQDN` need no central approval but MUST
  NOT collide with assigned numbers or standard names, and MUST
  NOT be sent unless the peer advertised support by explicit
  configuration. There is no EXT_INFO advertisement in v0.
- All five protocol docs MUST use the block and naming rules in
  this document; on conflict, this document wins for numbers
  and names.
