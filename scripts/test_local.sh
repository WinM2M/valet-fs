#!/usr/bin/env bash
# Automated local tests for the DO/ws control plane.
#
# Runs entirely in-process (Go test spins up the internal/hub WebSocket hub on
# localhost and drives the real daemon node + ws transport + rpc through it).
# No Cloudflare account, no wrangler, no network required.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/6] go vet"
go vet ./...

echo "[2/6] unit + integration tests (-race)"
go test -race ./internal/... ./cmd/...

echo "[3/6] Noise IK conformance (official vectors)"
go test -v ./internal/noise/ -run TestIKMatchesOfficialVectors | grep -E '^(=== RUN|--- |ok|FAIL)'

echo "[3b/6] control-plane scenarios (verbose)"
go test -v ./internal/node/ -run \
  'TestPairAndPush|TestReliableRejoin|TestGraceAutoLock|TestGraceCancelOnReconnect|TestReconcileDaemonSideAdditions|TestExplicitUnmount'

echo "[4/6] signaling hub (SessionHub Durable Object)"
if command -v node >/dev/null 2>&1; then
  (cd signaling && node --experimental-strip-types worker.test.mjs)
else
  echo "  skipped: node not installed"
fi

echo "[5/6] govulncheck (reachable vulnerabilities only)"
./scripts/vulncheck.sh

echo "[6/6] install.sh verification (tamper fixtures)"
./scripts/install_verify_test.sh

echo
echo "OK: DO/ws control-plane local tests passed."
