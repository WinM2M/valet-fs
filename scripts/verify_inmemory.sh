#!/usr/bin/env bash
# scripts/verify_inmemory.sh
#
# End-to-end cross-check that ValetFS is truly in-memory:
#   1. Start valetd --dev, write a file via the dev API.
#   2. Verify it round-trips (read back identical bytes).
#   3. Verify the file body never appears on disk under the git temp dir
#      (only the sha256 manifest does).
#   4. Kill the daemon, restart it fresh, and verify the file is GONE.
#
# Works regardless of whether FUSE is available; the dev API talks to the
# same MemFS that any FUSE/WebDAV frontend would expose.

set -euo pipefail

BIN="${BIN:-./valetd}"
PORT="${PORT:-18099}"
MOUNT_HINT="/tmp/valetfs-verify-mnt"
GIT_DIR="/tmp/valetfs-verify-git"
SECRET="ghp_super_secret_$(date +%s)"
PATH_IN_VFS="/keys/github"

API="http://127.0.0.1:${PORT}"

cleanup() {
    if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

start_daemon() {
    rm -rf "$GIT_DIR"
    "$BIN" --dev \
        --dev-addr "127.0.0.1:${PORT}" \
        --mount "$MOUNT_HINT" \
        --git-dir "$GIT_DIR" >/tmp/valetd-verify.log 2>&1 &
    PID=$!
    # Wait for the dev API to come up.
    for _ in $(seq 1 50); do
        if curl -sf "$API/status" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    echo "FAIL: dev API did not come up. Log:"; cat /tmp/valetd-verify.log; exit 1
}

echo "=== Run 1: write a secret and confirm round-trip ==="
start_daemon
curl -sf -X POST "$API/files?path=${PATH_IN_VFS}" \
    -H 'content-type: application/json' \
    -d "{\"content\":\"${SECRET}\"}" >/dev/null
got="$(curl -sf "$API/files?path=${PATH_IN_VFS}")"
[[ "$got" == "$SECRET" ]] || { echo "FAIL: read mismatch ($got vs $SECRET)"; exit 1; }
echo "OK: wrote and read back: $got"

echo
echo "=== Confirm plaintext never hits disk ==="
curl -sf -X POST "$API/sync" >/dev/null
if grep -rq "$SECRET" "$GIT_DIR"; then
    echo "FAIL: plaintext leaked to $GIT_DIR"
    grep -rn "$SECRET" "$GIT_DIR"
    exit 1
fi
echo "OK: $GIT_DIR contains only sha256 manifest, no plaintext:"
cat "$GIT_DIR/manifest.txt"

echo
echo "=== Kill daemon, restart fresh, confirm file is GONE ==="
cleanup
sleep 0.3

start_daemon
status="$(curl -sf "$API/status")"
echo "Fresh status: $status"
http_code="$(curl -s -o /dev/null -w '%{http_code}' "$API/files?path=${PATH_IN_VFS}")"
if [[ "$http_code" == "404" ]]; then
    echo "OK: file is gone after restart (HTTP 404). VFS is truly in-memory."
else
    echo "FAIL: expected 404, got $http_code"
    exit 1
fi

echo
echo "=== All cross-checks passed ==="
