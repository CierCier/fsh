# FSH v0 MVP

This repository now contains a runnable, interoperable-in-repository MVP of
FSH v0. The MVP is intended for loopback and controlled-fleet experiments,
not production remote administration or security-sensitive deployment.

## Included in the MVP

- QUIC v1 transport with TLS 1.3 and the `fsh/1` ALPN.
- SPKI pinning with an explicit first-use `--accept-new` decision in `fsh`.
- Public-key user authentication with an OpenSSH `authorized_keys` file.
  Use an Ed25519 identity for the supported, tested path.
- Client-initiated `session` channels over independent QUIC streams.
- `exec` and pipe-backed `shell` requests with stdin, stdout, stderr, exit
  status, EOF, close, and bounded cleanup handling.
- `fsh` and `fshd` binaries plus serialized framing, authentication, and
  lifecycle regression tests.
- `fcp` remains deferred and has no v0 wire protocol.

## Local smoke test

After building the workspace, the reproducible loopback check is. It covers
TOFU pinning, Ed25519 authentication, command output, stdin, stderr, and a
non-zero remote exit status:

```sh
./scripts/mvp-smoke.sh
```

The script chooses an ephemeral UDP port, creates temporary identities, and
removes all generated state when it exits. The equivalent manual commands are
below.

The commands below require Rust, `ssh-keygen`, and a POSIX shell. Run them from
the repository root:

```sh
set -eu
TMP_DIR="$(mktemp -d)"
trap 'kill "${FSHD_PID:-}" 2>/dev/null || true; rm -rf "$TMP_DIR"' EXIT

ssh-keygen -q -t ed25519 -N '' -f "$TMP_DIR/id_ed25519"
cp "$TMP_DIR/id_ed25519.pub" "$TMP_DIR/authorized_keys"

FSHD_USER="${USER:-fsh}" \
FSHD_AUTHORIZED_KEYS="$TMP_DIR/authorized_keys" \
./target/debug/fshd \
  --listen 127.0.0.1:4433 \
  --cert "$TMP_DIR/server-cert.der" \
  --key "$TMP_DIR/server-key.der" \
  >"$TMP_DIR/fshd.log" 2>&1 &
FSHD_PID=$!

until grep -q 'listening on' "$TMP_DIR/fshd.log"; do sleep 0.05; done

FSH_USER="${USER:-fsh}" \
FSH_KNOWN_HOSTS="$TMP_DIR/known_hosts" \
./target/debug/fsh \
  --accept-new \
  --identity "$TMP_DIR/id_ed25519" \
  --port 4433 \
  127.0.0.1 -- printf '%s\n' fsh-mvp
```

The client should print `fsh-mvp` and exit successfully. Build the binaries
first if needed:

```sh
cargo build --workspace --all-targets
```

The repository lifecycle suite can be run without the daemon smoke test:

```sh
cargo test -p fsh-core --all-targets -- --test-threads=1
```

## Explicit non-goals for this pass

This MVP is not a claim of production security, complete SSH compatibility,
external interoperability, or superior performance. FIDO `sk-*` keys, Ed448,
full per-key username authorization, concurrent TOFU pin association, fuzzing,
loss/reordering interoperability, independent implementations, benchmark
artifacts, and a formal security audit remain follow-up work. Do not expose an
MVP endpoint to an untrusted network without an independent review.

The protocol design documents remain normative references for the intended v0
wire behavior; this page describes only what is currently exercised and
supported well enough to test.
