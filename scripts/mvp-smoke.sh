#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
Fshd=${FSH_MVP_FSHD:-"$ROOT_DIR/target/debug/fshd"}
Fsh=${FSH_MVP_FSH:-"$ROOT_DIR/target/debug/fsh"}
USER_NAME=${FSH_MVP_USER:-${USER:-$(id -un)}}
TMP_DIR=$(mktemp -d)
FSHD_PID=

cleanup() {
    if [ -n "${FSHD_PID:-}" ]; then
        kill "$FSHD_PID" 2>/dev/null || true
        wait "$FSHD_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if [ ! -x "$Fshd" ] || [ ! -x "$Fsh" ]; then
    cargo build --workspace --bins
fi

ssh-keygen -q -t ed25519 -N '' -f "$TMP_DIR/id_ed25519"
cp "$TMP_DIR/id_ed25519.pub" "$TMP_DIR/authorized_keys"

FSHD_USER="$USER_NAME" \
FSHD_AUTHORIZED_KEYS="$TMP_DIR/authorized_keys" \
"$Fshd" \
    --listen 127.0.0.1:0 \
    --cert "$TMP_DIR/server-cert.der" \
    --key "$TMP_DIR/server-key.der" \
    >"$TMP_DIR/fshd.log" 2>&1 &
FSHD_PID=$!

address=
for _ in $(seq 1 100); do
    address=$(sed -n 's/^fshd: listening on //p' "$TMP_DIR/fshd.log" | head -n 1)
    [ -n "$address" ] && break
    if ! kill -0 "$FSHD_PID" 2>/dev/null; then
        cat "$TMP_DIR/fshd.log" >&2
        exit 1
    fi
    sleep 0.05
done
[ -n "$address" ] || { cat "$TMP_DIR/fshd.log" >&2; exit 1; }
port=${address##*:}

run_fsh() {
    FSH_USER="$USER_NAME" \
    FSH_KNOWN_HOSTS="$TMP_DIR/known_hosts" \
    "$Fsh" \
        --accept-new \
        --identity "$TMP_DIR/id_ed25519" \
        --user "$USER_NAME" \
        --port "$port" \
        127.0.0.1 "$@"
}

output=$(run_fsh -- printf '%s\n' fsh-mvp)

[ "$output" = "fsh-mvp" ] || {
    printf 'unexpected fsh output: %s\n' "$output" >&2
    cat "$TMP_DIR/fshd.log" >&2
    exit 1
}

printf 'stdin-ok\n' | run_fsh -- cat >"$TMP_DIR/stdin.out"
[ "$(cat "$TMP_DIR/stdin.out")" = "stdin-ok" ] || {
    printf 'stdin round trip failed\n' >&2
    exit 1
}

set +e
run_fsh -- sh -c 'printf status-ok >&2; exit 7' \
    >"$TMP_DIR/status.out" 2>"$TMP_DIR/status.err"
status=$?
set -e
[ "$status" -eq 7 ] && [ ! -s "$TMP_DIR/status.out" ] &&
    [ "$(cat "$TMP_DIR/status.err")" = "status-ok" ] || {
        printf 'stderr/status round trip failed (status=%s)\n' "$status" >&2
        exit 1
    }

printf 'FSH v0 MVP smoke test passed (127.0.0.1:%s)\n' "$port"
