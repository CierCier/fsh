# fsh User Authentication Protocol

Replaces RFC 4252. Publickey-only authentication over the fsh secure
transport (QUIC + TLS 1.3). All method and message numbers follow the
shared registry: auth generic 50-59, method-specific 60-79.

## 1. Overview

Authentication runs after the transport handshake, inside the
confidential, integrity-protected QUIC connection. One party is the
client (proves identity); the other is the server (authorizes access).

- Service name: `fsh-userauth`. The client requests it via the
  transport service-request mechanism before sending any auth message.
- Follow-on service on success: `fsh-connection`.
- Single method: `publickey` (includes FIDO2 `sk-*` keys as key
  types, not separate methods). No other method exists.
- Usernames are UTF-8, max 256 bytes, case-sensitive. Empty user is
  invalid; servers MUST reject it.
- Algorithm names are lowercase-hyphenated, max 64 chars. Local
  extensions use `name@fqdn` form.
- Session identifier: exactly 32 bytes from the TLS 1.3 exporter
  (RFC 8446, Section 7.5) with label "fsh-binding-v0" and empty
  context. All signatures cover it. It binds authentication to this
  connection; replays on another connection fail verification.
  QUIC connection IDs are routing identifiers and MUST NOT be
  described or used as bindings. There is no handshake-hash field.
  Handshakes without (EC)DHE (PSK-only, no forward secrecy) MUST
  be refused.

## 2. Message flow

Generic messages (50-59). All strings are `string` (uint32 length +
bytes); `boolean` is one byte (`0`/`1`); `name-list` is a
comma-separated string list.

```
byte      SSH_MSG_USERAUTH_REQUEST       50
string    user name
string    service name ("fsh-connection")
string    method name ("publickey")
...       method-specific fields
```

```
byte      SSH_MSG_USERAUTH_FAILURE       51
name-list authentications that can continue
boolean   partial success (MUST be 0; no partial success in fsh)
```

```
byte      SSH_MSG_USERAUTH_SUCCESS       52
(no payload)
```

Flow:

1. Client sends `USERAUTH_REQUEST(50)` for each attempt. Method field
   is always `"publickey"`.
2. Server replies `SUCCESS(52)` (access granted, proceed to
   `fsh-connection`) or `FAILURE(51)` (attempt rejected, may retry).
3. `FAILURE` continuations list contains exactly `"publickey"`.
   Clients MUST NOT interpret any other name; servers MUST NOT send
   any other name. This name-list advertises authentication methods
   only and MUST NOT be interpreted as advertising public-key
   algorithms. There is no algorithm advertisement in fsh: the probe
   (`PK_OK`) / direct-sign-then-`FAILURE` exchange in section 3 IS the
   complete negotiation mechanism. A client learns whether an
   (algorithm, key) pair is acceptable by sending a probe and observing
   `PK_OK` vs `FAILURE`, or by sending a signed request directly and
   observing `SUCCESS` vs `FAILURE`. There is no separate
   advertisement message, no `EXT_INFO` (7-19 stay reserved), and no
   extension negotiation for algorithms.
4. Unrecognized methods: server MUST reply `FAILURE(51)` with
   `["publickey"]`. There is no fallback negotiation.
5. Servers SHOULD rate-limit and cap consecutive failures (RECOMMENDED:
   10 attempts, then drop the connection) to blunt online guessing of
   authorized-key identities.

## 3. Publickey method

Method name: `publickey`. Two steps: probe, then signed request.
Both use `USERAUTH_REQUEST(50)` with a boolean flag distinguishing
them. Method-specific reply: `SSH_MSG_USERAUTH_PK_OK(60)`.

### 3.1 Probe (key acceptability check)

```
byte      50
string    user name
string    service name ("fsh-connection")
string    "publickey"
boolean   FALSE
string    public-key algorithm name
string    public-key blob
```

Server replies:

```
byte      SSH_MSG_USERAUTH_PK_OK         60
string    public-key algorithm name
string    public-key blob
```

- Server sends `PK_OK(60)` iff the algorithm is supported AND the key
  is authorized for the user. Otherwise it sends `FAILURE(51)`.
- `PK_OK` is advisory only. It grants nothing and MUST NOT be treated
  as authentication.
- Clients SHOULD probe before signing (avoids pointless signatures,
  hides which key would sign from a non-authorizing server), but MAY
  skip the probe and send the signed request directly.

### 3.2 Signed request

```
byte      50
string    user name
string    service name ("fsh-connection")
string    "publickey"
boolean   TRUE
string    public-key algorithm name
string    public-key blob
string    signature
```

Signature input (signed blob) is:

```
string    session identifier
byte      50
string    user name
string    service name ("fsh-connection")
string    "publickey"
boolean   TRUE
string    public-key algorithm name
string    public-key blob
```

- The signature MUST cover the session identifier first, then the
  exact request fields above, in order, in wire encoding.
- Server verifies and replies `SUCCESS(52)` or `FAILURE(51)`.
- A `PK_OK(60)` received without a preceding probe (unsolicited) MUST
  be ignored.

### 4.1 Supported

| Wire name (OpenSSH-interop)              | Key / signature scheme                          | Notes                          |
|------------------------------------------|-------------------------------------------------|--------------------------------|
| `ssh-ed25519`                            | Ed25519 per RFC 8032                            | RECOMMENDED default            |
| `ssh-ed448`                              | Ed448 per RFC 8032 (see below)                  | full spec below                |
| `ecdsa-sha2-nistp256`                    | ECDSA P-256 + SHA-256                           |                                |
| `ecdsa-sha2-nistp384`                    | ECDSA P-384 + SHA-384                           |                                |
| `ecdsa-sha2-nistp521`                    | ECDSA P-521 + SHA-512                           |                                |
| `rsa-sha2-256`                           | RSA >= 3072 bit signature algorithm, RSASSA-PKCS1-v1_5 + SHA-256 per RFC 8332 (NOT PSS) | public-key blob uses `ssh-rsa` format (see below); keys < 3072 bit MUST be refused |
| `rsa-sha2-512`                           | RSA >= 3072 bit signature algorithm, RSASSA-PKCS1-v1_5 + SHA-512 per RFC 8332 (NOT PSS) | public-key blob uses `ssh-rsa` format (see below); keys < 3072 bit MUST be refused |
| `ssh-rsa` (blob only)                    | RSA public-key blob format: `string "ssh-rsa" \|\| mpint e \|\| mpint n` | MUST be accepted as key material; MUST NOT be accepted as a signature algorithm name |
| `sk-ssh-ed25519@openssh.com`             | FIDO2 Ed25519, OpenSSH PROTOCOL.u2f encoding    | see below                      |
| `sk-ecdsa-sha2-nistp256@openssh.com`     | FIDO2 ECDSA P-256, OpenSSH PROTOCOL.u2f encoding| see below                      |

Key/signature wire names reuse OpenSSH exactly for key-blob interop.
All NEW fsh protocol names use `@fsh.dev`, never `@openssh.com`.

RSA blob vs signature (RFC 8332): the RSA public-key blob format is
`string "ssh-rsa" || mpint e || mpint n` and MUST be accepted as key
material for `rsa-sha2-256` / `rsa-sha2-512` keys. The algorithm name
field in the probe and signed request for RSA keys MUST be
`rsa-sha2-256` or `rsa-sha2-512`. The signature algorithm name
`ssh-rsa` (RSA + SHA-1) MUST NOT be sent and MUST be refused: a server
receiving algorithm name `ssh-rsa` in a probe or signed request MUST
reply `FAILURE(51)` without verifying. RSA signatures MUST use
RSASSA-PKCS1-v1_5 with SHA-256 / SHA-512 per RFC 8332.
RSASSA-PSS MUST NOT be sent or accepted.

`ssh-ed448` (RFC 8032): public-key blob is `string "ssh-ed448" ||
string 57-byte public key` (Ed448 public key, RFC 8032 Section 5.2).
Signature blob is `string "ssh-ed448" || string 114-byte signature`
(Ed448 sign/verify, RFC 8032 Section 5.3, pure-EdDSA, no prehash).
Servers MUST verify with RFC 8032 Ed448 verification and reject any
non-114-byte signature or non-57-byte key.

`sk-*` (OpenSSH PROTOCOL.u2f, reproduced normatively): the
OpenSSH interoperability claim in this section holds ONLY for the exact
wire encodings below, quoted from OpenSSH PROTOCOL.u2f. The canonical
names are `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` (never bare `sk-ssh-ed25519` or
`sk-ecdsa-sha2-*`).

The format of a `sk-ecdsa-sha2-nistp256@openssh.com` public key is:

```
string		"sk-ecdsa-sha2-nistp256@openssh.com"
string		curve name
ec_point	Q
string		application (user-specified, but typically "ssh:")
```

The format of a `sk-ssh-ed25519@openssh.com` public key is:

```
string		"sk-ssh-ed25519@openssh.com"
string		public key
string		application (user-specified, but typically "ssh:")
```

The corresponding private halves additionally contain `uint8 flags`,
`string key_handle`, and `string reserved`; these are local key-store
fields and are never sent as part of the public-key blob in the probe
or signed request.

The U2F signature operation signs a blob consisting of:

```
byte[32]	SHA256(application)
byte		flags (including "user present", extensions present)
uint32		counter
byte[]		extensions
byte[32]	SHA256(message)
```

No extensions are defined for SSH use. In fsh, `message` is the
session-identifier-prefixed signed blob defined in section 3.2, and
`application` is the application string from the public-key blob.

The signature format used on the wire in the signed request is, for
ECDSA:

```
string		"sk-ecdsa-sha2-nistp256@openssh.com"
string		ecdsa_signature
byte		flags
uint32		counter
```

where the `ecdsa_signature` field follows the RFC 5656 ECDSA signature
encoding (`mpint r || mpint s`). This encoding avoids server-side ASN.1
parsing of the X9.62 hardware format in the pre-authentication attack
surface. For Ed25519 keys the wire signature is encoded as:

```
string		"sk-ssh-ed25519@openssh.com"
string		signature
byte		flags
uint32		counter
```

Servers SHOULD check the user-presence / user-verification flags
against local policy. Certificate forms
(`sk-ecdsa-sha2-nistp256-cert-v01@openssh.com`,
`sk-ssh-ed25519-cert-v01@openssh.com`) and
`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signatures are NOT part
of fsh v0 and MUST be refused as unknown key-type names.

Rules:
- RSA keys shorter than 3072 bits MUST be refused at parse time.
- Unknown key-type names: server MUST reply `FAILURE(51)`, never
  `PK_OK(60)`.

### 4.2 Excluded

The following are NOT key types or methods in fsh and MUST NOT be
implemented:

- `ssh-dss` (DSA): insecure key size; removed.
- `ssh-rsa` as a signature algorithm (RSA + SHA-1): broken hash; use `rsa-sha2-256` / `rsa-sha2-512`. The `ssh-rsa` public-key blob format itself MUST still be accepted as key material (see section 4.1).
- RSA keys < 3072 bit, regardless of hash.
- `ssh-rsa-cert-v01`, `ssh-ed25519-cert-v01` (OpenSSH certificates):
  no cert-based user auth in this revision (host identity is handled
  at the transport layer; see transport doc).
- Any password, hostbased, keyboard-interactive, or `none` material:
  those are authentication methods, not key types, and are dropped
  entirely (see section 6).

## 5. Verification

On each signed `USERAUTH_REQUEST(50)` the server MUST, in order:

1. Reject malformed packets (bad lengths, trailing bytes, empty user,
   unknown/unsupported algorithm name) with `FAILURE(51)`.
2. Reject excluded key material (DSA, `ssh-rsa` signature algorithm,
   RSA < 3072 bit) with `FAILURE(51)`, without signature verification.
   The `ssh-rsa` public-key blob format is key material, not excluded:
   it MUST be accepted for `rsa-sha2-256` / `rsa-sha2-512` keys.
3. Look up the user; unknown users get `FAILURE(51)`. Implementations
   SHOULD take constant time to this point where practical (do not
   leak user existence via timing beyond what the probe already
   reveals by design).
4. Check the key blob is authorized for the user (authorized-keys
   store or equivalent). Unauthorized: `FAILURE(51)`.
5. Reconstruct the signed blob (session identifier + request fields,
   section 3.2) and verify the signature with the presented public
   key. Invalid: `FAILURE(51)`.
6. Apply local authorization policy (account locked, source
   restrictions, UV policy for `sk-*`). Denied: `FAILURE(51)`.
7. On pass: reply `SUCCESS(52)` and bind the connection to
   (user, key, session identifier). The binding MUST NOT migrate to
   another QUIC connection.

Notes:

- Servers MUST verify the session identifier matches the current
  connection. A signature over any other value MUST fail.
- Servers MUST NOT accept a signature that omits or reorders signed
  fields.
- Replay within the same connection: each signed request is a fresh
  authentication decision; a previously observed (session-id, blob,
  signature) tuple MUST NOT be cached as success for a different user
  or service.

## 6. SSH differences (dropped methods and why)

RFC 4252 defines `publickey`, `password`, `hostbased`,
`keyboard-interactive`, and `none`. fsh keeps `publickey` only.

| Dropped             | Why                                                        |
|---------------------|------------------------------------------------------------|
| `password`          | Phishable, guessable, needs server-side secrets; public keys + FIDO2 cover human and automated use. |
| `keyboard-interactive` | Password/OTP prompting over the auth channel; same secrets problem, plus interactive downgrade surface. |
| `hostbased`         | Trusts client host keys for user auth; fragile delegation, confusing semantics. |
| `none`              | Grants access without proof; only ever useful for probing, which `FAILURE` continuations already handle. |
| `ssh-rsa` signatures / DSA / short RSA | Legacy crypto; TLS 1.3 transport is modern-only, auth matches it. `ssh-rsa` (SHA-1) signatures are refused; the `ssh-rsa` public-key blob format is still accepted as key material for `rsa-sha2-*`. |
| `tcpip-forward`, `direct-tcpip`, `x11`, compression | Not auth-layer, but excluded protocol-wide: forwarding/compression belong to other layers or not at all. No auth method may request them. |

Consequences:

- No partial success (`FAILURE` boolean always 0). Single method
  means authentication either succeeds fully or fails.
- No banner: there is no `USERAUTH_BANNER` mechanism in fsh.
  Message number 53 is unassigned and MUST NOT be sent. Servers
  MUST NOT send any pre-auth or post-auth banner text as an auth
  message.

## 7. Extensibility / unknown handling

Unknown message in assigned ranges (50-79) on the control stream ->
reply `UNIMPLEMENTED`; unknown message in the 192-255 local range ->
ignore.
