# fsh docs

FSH is an experimental, capability-minimal QUIC-native remote-execution
protocol for controlled fleets and edge nodes. This repository contains a
runnable **v0 MVP** for loopback and controlled testing; it is not a production
SSH replacement.

## Status

The MVP currently exercises QUIC v1/TLS 1.3 transport, SPKI pinning, public-key
authentication, client-initiated `session` channels, `exec`/pipe-backed
`shell`, framed stdin/stdout/stderr, exit status, and bounded channel cleanup.
Use an Ed25519 identity for the supported end-to-end path. `fcp` is deferred.

The implementation has not yet completed its security audit, FIDO/Ed448 work,
external interoperability testing, fuzzing, or reproducible benchmarking. Do
not expose it to an untrusted network or describe it as a drop-in SSH
replacement. See [`mvp.md`](mvp.md) for the exact local smoke test and the
current non-goals.

## Layout

- `bin/fsh` — client
- `bin/fshd` — server daemon
- `bin/fcp` — deferred file-copy placeholder
- `crates/fsh-core` — framing, authentication, transport, and connection code
- `docs/` — protocol and implementation documentation

## Protocol docs

- [`mvp.md`](mvp.md) — supported MVP scope and loopback smoke test
- [`architecture.md`](architecture.md) — layer architecture
- [`transport.md`](transport.md) — QUIC/TLS 1.3 transport and host identity
- [`authentication.md`](authentication.md) — public-key authentication design
- [`connection.md`](connection.md) — channels over QUIC streams
- [`numbers.md`](numbers.md) — assigned message numbers and names
