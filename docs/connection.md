# fsh Connection Protocol

Service name: `fsh-connection`. Runs after transport establishment and
user authentication, multiplexed over the authenticated QUIC connection
(RFC 9000 streams; RFC 4254 channel concepts adapted to QUIC).

## 1. Framing

EVERY fsh message on ANY stream is framed as:

```
u32-BE length || u8 msg-number || payload[length-1]
```

`length` covers type byte + payload. There is no bare msg-number
framing anywhere. A sender MAY place multiple framed messages in one
QUIC stream write; a receiver MUST reassemble by the length prefix.
QUIC stream segments (STREAM frames, chunk boundaries) have no message
meaning: one DATA message NEVER equals one stream segment, and a
receiver MUST NOT treat a chunk boundary as a message boundary.

## 2. Streams and channel identifiers

- QUIC stream 0 (client-initiated bidirectional) is the control stream
  and is reserved for connection-protocol control messages. No channel
  data travels on stream 0.
- Channels are client-initiated bidirectional QUIC streams only
  (client streams 4, 8, 12, ...). Channel id is derived, never
  negotiated: `channel id = stream_id / 4` as uint32 (stream 4 = channel
  1, stream 8 = channel 2, ...). There are NO server-initiated channels
  in v0; a server MUST NOT open a channel stream and a client MUST
  reject any server-initiated channel attempt.
- All channel lifecycle messages (90-92, 96-100, 80-82) travel on the
  control stream and reference the uint32 channel id. Only DATA traffic
  (94, 95) travels on the channel's own stream, itself framed per
  Section 1.
- Channel type: only `session`. A request for any other type MUST be
  rejected with `CHANNEL_OPEN_FAILURE` (reason 3, unknown channel type).
- Flow control is QUIC stream/connection flow control (`MAX_DATA`,
  `MAX_STREAM_DATA`, RFC 9000). There is no `WINDOW_ADJUST` window
  mechanism in fsh; message 93 is reserved, MUST NOT be sent, MUST be
  treated as unknown per Section 9.

## 3. Channel lifecycle messages (control stream)

All fields use SSH wire types (RFC 4251): `byte`, `uint32`, `string`
(u32-BE length || bytes).

| #  | Name                   | Wire grammar (after framing header)        |
|----|------------------------|--------------------------------------------|
| 90 | CHANNEL_OPEN           | `string "session" || uint32 channel-id`    |
| 91 | CHANNEL_OPEN_CONFIRM   | `uint32 channel-id`                        |
| 92 | CHANNEL_OPEN_FAILURE   | `uint32 channel-id || uint32 reason || string description || string language` |
| 96 | CHANNEL_EOF            | `uint32 channel-id`                        |
| 97 | CHANNEL_CLOSE          | `uint32 channel-id`                        |

Open procedure:

1. Client opens a bidirectional QUIC stream (4, 8, 12, ...) and sends
   `CHANNEL_OPEN` on the control stream with the derived channel id.
2. Server replies on the control stream with exactly one of
   `CHANNEL_OPEN_CONFIRM` or `CHANNEL_OPEN_FAILURE`.
3. `CHANNEL_OPEN_FAILURE` reason codes follow SSH (1 administratively
   prohibited, 2 connect failed, 3 unknown channel type, 4 resource
   shortage). fsh adds no new codes. `description` is human-readable
   UTF-8, `language` is a BCP 47 tag (MAY be empty).

Channel ids MUST NOT be reused within a connection.

## 4. Data transfer (channel stream, framed)

`CHANNEL_DATA` (94) and `CHANNEL_EXTENDED_DATA` (95) travel on the
channel's own stream as framed messages per Section 1. Direction
disambiguates the standard stream:

| #  | Name                  | Direction       | Meaning | Grammar (after header) |
|----|-----------------------|-----------------|---------|------------------------|
| 94 | CHANNEL_DATA          | client -> server | stdin  | `uint32 channel-id \|\| string data` |
| 94 | CHANNEL_DATA          | server -> client | stdout | `uint32 channel-id \|\| string data` |
| 95 | CHANNEL_EXTENDED_DATA | server -> client | stderr | `uint32 channel-id \|\| uint32 type=1 \|\| string data` |

- The `channel-id` in each DATA frame MUST equal the id derived from
  the stream it travels on; a mismatch MUST cause the receiver to send
  `CHANNEL_CLOSE` for that channel.
- Extended-data type 1 is stderr. No other extended-data type is
  defined in v0; a sender MUST NOT send any other type and a receiver
  MUST reject the channel (send `CHANNEL_CLOSE`) on receipt.
- `CHANNEL_EXTENDED_DATA` in the client -> server direction is
  undefined in v0 and MUST be rejected with `CHANNEL_CLOSE`.
- Stdin, stdout, and stderr are three distinct frame types above; a
  single DATA frame carries bytes for exactly one of them. Stream
  segments MUST NOT be interpreted as message boundaries.

## 5. Shutdown reconciliation

Sender half-close (QUIC FIN) on a channel stream means EOF for that
direction. `CHANNEL_EOF` (96) is sent on the control stream, then FIN
follows on the indicated data direction. `CHANNEL_CLOSE` (97) goes on
the control stream. After both sides have sent `CHANNEL_CLOSE`, each
endpoint issues `RESET_STREAM` / `STOP_SENDING` (RFC 9000) on any
residual direction and discards all channel state; no further messages
for that channel are valid.

| Event | Who sends | On which stream | Meaning / required action |
|-------|-----------|-----------------|---------------------------|
| Client stdin end | client | control: `CHANNEL_EOF(channel-id)`; then FIN on client -> server direction of the channel stream | no more stdin; server MAY keep stdout/stderr open |
| Server stdout/stderr end | server | control: `CHANNEL_EOF(channel-id)`; then FIN on server -> client direction of the channel stream | no more output; preceded by exactly one of `exit-status` / `exit-signal` |
| QUIC FIN received | transport | channel stream direction | EOF for that direction only; equivalent to having received `CHANNEL_EOF` if the control message was lost; MUST NOT be treated as full close |
| `CHANNEL_CLOSE` | either side | control stream | "I am done with this channel"; sender MUST NOT send further messages for the channel except its own duplicate CLOSE handling |
| Both sides sent `CHANNEL_CLOSE` | both | control stream (each direction) | channel is dead; each endpoint MUST `RESET_STREAM` / `STOP_SENDING` any residual open direction, then discard state |
| Half-open leftover (FIN without EOF, or EOF without FIN) | receiver | — | receiver MUST tolerate either order; a FIN without a preceding `CHANNEL_EOF` is still EOF; an EOF without a following FIN MUST be followed by connection-idle cleanup via `CHANNEL_CLOSE` |

Normal termination order (server side): `exit-status` or `exit-signal`
(98, `want-reply=false`), then `CHANNEL_EOF`, then FIN on the
server -> client direction, then `CHANNEL_CLOSE`. Client closes its
send direction when stdin ends, and sends `CHANNEL_CLOSE` after reading
EOF and the exit notification.

## 6. Channel requests

Request framing on the control stream: 98 (`CHANNEL_REQUEST`:
`uint32 channel-id || string type-name || boolean want-reply || ...type
data`), 99 (`CHANNEL_SUCCESS`: `uint32 channel-id`), 100
(`CHANNEL_FAILURE`: `uint32 channel-id`). `want-reply` follows SSH
semantics; exit and signal notifications use `want-reply = false`.

A `session` channel carries at most one program binding (`shell`,
`exec`, or `subsystem`). A second binding request on the same channel
MUST fail with `CHANNEL_FAILURE`; implementations MAY then send
`CHANNEL_CLOSE`.

Kept requests and wire grammars (type-data after the request header):

- `shell` (`want-reply=true`): no further fields. Starts the user's
  default shell. Requires a prior `pty-req` for terminal use; without
  one the server attaches pipes.
- `exec` (`want-reply=true`): `string command`. `command` is UTF-8,
  MUST NOT contain NUL bytes, max 16384 bytes. The server executes it
  without a shell search-path interpolation; no environment passing —
  locale and caller environment are never forwarded and the server exec
  environment is fixed by policy.
- `pty-req` (`want-reply=true`):
  `string TERM || uint32 cols || uint32 rows || uint32 px-width || uint32 px-height || string modes`.
  Minimal allocation for interactive use: `TERM` 1-64 printable ASCII
  chars; `cols`/`rows` 1..1024; `px-width`/`px-height` 0..8192 (0 means
  unspecified); `modes` MUST be empty (MUST send zero length; non-empty
  MUST be rejected with `CHANNEL_FAILURE`). `pty-req` MUST precede
  `shell` when a terminal is wanted; before `exec` it requests a pty
  for that command and MAY be refused by policy; with `subsystem` it
  MUST be refused.
- `window-change` (`want-reply=false`):
  `uint32 cols || uint32 rows || uint32 px-width || uint32 px-height`
  with the same bounds as `pty-req`. Pty resize companion only; MUST be
  ignored on channels without a pty.
- `signal` (`want-reply=false`): `string signal-name`. ASCII
  uppercase, max 16 chars; defined values `HUP INT QUIT ILL TRAP ABRT
  BUS FPE KILL USR1 SEGV USR2 PIPE ALRM TERM CHLD CONT STOP TSTP URG`.
  Unknown names MUST be ignored. Delivers to the process group of the
  session (see cleanup below).
- `exit-status` (`want-reply=false`, server -> client):
  `uint32 exit-code`. Terminal state; mutually exclusive with
  `exit-signal`.
- `exit-signal` (`want-reply=false`, server -> client):
  `string signal-name || boolean core-dumped || string message || string language`.
  Terminal state; mutually exclusive with `exit-status`.

Process-cleanup semantics: the session process runs in its own process
group. `CHANNEL_CLOSE` from either side kills the process group
(equivalent to `SIGKILL` after a grace period for `exit-status` /
`exit-signal` delivery), revokes the pty, and releases the channel.
A `signal` request with `KILL` takes effect immediately on the group.

## 7. Subsystems

The `subsystem` request mechanism stays:
`subsystem` (`want-reply=true`): `string subsystem-name` (max 64 chars,
lowercase-hyphenated or `name@fqdn`). No subsystems are assigned in v0.
`fcp` (file copy) is deferred past v0: servers MUST reply
`CHANNEL_FAILURE` to any `subsystem` request in v0, and no fcp wire
format is defined by this document.

## 8. Global requests

Framing on the control stream: 80 (`GLOBAL_REQUEST`:
`string name || boolean want-reply || ...request data`), 81
(`REQUEST_SUCCESS`: no fields beyond the header for `keepalive@fsh.dev`),
82 (`REQUEST_FAILURE`). The only permitted global request in v0 is:

- `keepalive@fsh.dev` (`want-reply=true`, empty data): dead-peer
  detection. The recipient replies `REQUEST_SUCCESS` with empty data.
  All other global requests MUST fail with `REQUEST_FAILURE`. No
  forwarding or listener requests exist in v0.

## 9. Unknown-message handling

An unknown message number in an assigned range received on the control
stream MUST elicit UNIMPLEMENTED (3); an unknown message number in
192-255 MUST be ignored.

## 10. Excluded in v0

Only the `session` channel type exists. There is no TCP forwarding, no
X11, no agent forwarding, no environment passing, no flow-control
override, and no compression negotiation (QUIC handles the path; TLS
1.3 key update governs rekey). Message 93 (`WINDOW_ADJUST`) is
reserved and never sent.

Numbers used here match the shared registry: 80-82 global, 90-97
channel lifecycle, 98-100 channel requests (93 reserved, never sent).
