#!/usr/bin/env bash
# Reachable-vulnerability gate.
#
# govulncheck exits non-zero whenever it finds anything, which would pin this
# check to "always failing" for as long as one accepted advisory exists — and a
# check that always fails is a check nobody reads. So findings are compared
# against an explicit allowlist: anything not on it fails the build, and
# everything on it had to be written down, with a reason, by a human.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
ALLOW_FILE="$ROOT_DIR/.govulncheck-allow"

if command -v govulncheck >/dev/null 2>&1; then
  GVC=govulncheck
elif [ -x "$(go env GOPATH)/bin/govulncheck" ]; then
  GVC="$(go env GOPATH)/bin/govulncheck"
else
  echo "  skipped: go install golang.org/x/vuln/cmd/govulncheck@latest"
  exit 0
fi

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT
# Exit status is deliberately ignored here; the JSON is the source of truth.
"$GVC" -format json ./... > "$OUT" 2>/dev/null || true

# A finding is reachable when its trace names a function: package- and
# module-level findings mean "present in the graph", not "called".
REACHABLE="$(python3 - "$OUT" <<'PY'
import json, sys
ids = set()
buf = ""
for chunk in open(sys.argv[1]):
    buf += chunk
dec = json.JSONDecoder()
i = 0
while i < len(buf):
    while i < len(buf) and buf[i] in " \t\r\n":
        i += 1
    if i >= len(buf):
        break
    obj, i = dec.raw_decode(buf, i)
    f = obj.get("finding")
    if not f:
        continue
    trace = f.get("trace") or []
    if trace and trace[0].get("function"):
        ids.add(f["osv"])
print("\n".join(sorted(ids)))
PY
)"

ALLOWED="$(grep -oE '^GO-[0-9]{4}-[0-9]+' "$ALLOW_FILE" 2>/dev/null || true)"

UNEXPECTED=""
for id in $REACHABLE; do
  if ! printf '%s\n' "$ALLOWED" | grep -qx "$id"; then
    UNEXPECTED="$UNEXPECTED $id"
  fi
done

for id in $REACHABLE; do
  if printf '%s\n' "$ALLOWED" | grep -qx "$id"; then
    echo "  allowed: $id (see .govulncheck-allow)"
  fi
done

if [ -n "$UNEXPECTED" ]; then
  echo
  echo "FAIL: reachable vulnerabilities not in .govulncheck-allow:$UNEXPECTED" >&2
  echo "Run '$GVC ./...' for the traces, then fix it or record why not." >&2
  exit 1
fi

echo "  no unaccepted reachable vulnerabilities"
