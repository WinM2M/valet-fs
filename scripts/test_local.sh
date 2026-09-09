#!/usr/bin/env bash
# Automated local tests for the DO/ws control plane.
#
# Runs entirely in-process (Go test spins up the internal/hub WebSocket hub on
# localhost and drives the real daemon node + ws transport + rpc through it).
# No Cloudflare account, no wrangler, no network required.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/5] go vet"
go vet ./...

echo "[2/5] unit + integration tests (-race)"
go test -race ./internal/...

echo "[3/5] control-plane scenarios (verbose)"
go test -v ./internal/node/ -run \
  'TestPairAndPush|TestReliableRejoin|TestGraceAutoLock|TestGraceCancelOnReconnect|TestReconcileDaemonSideAdditions|TestExplicitUnmount'

echo "[4/5] signaling hub (SessionHub Durable Object)"
if command -v node >/dev/null 2>&1; then
  (cd signaling && node --experimental-strip-types worker.test.mjs)
else
  echo "  skipped: node not installed"
fi

echo "[5/5] govulncheck (reachable vulnerabilities only)"
./scripts/vulncheck.sh

echo
echo "OK: DO/ws control-plane local tests passed."
