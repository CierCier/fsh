# fsh docs

Experimental, capability-minimal QUIC-native remote-execution protocol for fleets and edge nodes.

## Status

Experimental: the v0 protocol design is still being specified, and the
binaries in this repository (`bin/fsh`, `bin/fshd`, `bin/fcp`) are
placeholders, not working implementations. There are no conformance
tests yet. See the five protocol documents below for the current
design: `docs/architecture.md`, `docs/transport.md`,
`docs/authentication.md`, `docs/connection.md`, and `docs/numbers.md`.

## Layout

- `bin/fsh` — client
- `bin/fshd` — server daemon
- `bin/fcp` — file copy tool
- `crates/*` — shared libraries (`fsh-core`)
- `docs/` — design docs

## Protocol docs

- `docs/architecture.md` — layer architecture (transport, userauth, connection).
- `docs/transport.md` — QUIC + TLS 1.3 transport and host identity.
- `docs/authentication.md` — public-key-only user authentication.
- `docs/connection.md` — channels over QUIC streams (sessions, exec, fcp).
- `docs/numbers.md` — assigned message numbers, algorithm and service names.
