#!/usr/bin/env bash
# Exercises install.sh's verification against a local release fixture.
#
# Without this, the verification code is only ever exercised in production,
# where a mistake looks like a successful install of a tampered binary. Each
# case below is a way the download can be wrong; all of them must be refused.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SH="$ROOT_DIR/scripts/install.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ASSET="valetfs-linux-amd64" ;;
  aarch64|arm64) ASSET="valetfs-linux-arm64" ;;
  *) echo "unsupported arch for this test: $ARCH"; exit 0 ;;
esac

RELEASE="$WORK/release"
mkdir -p "$RELEASE" "$WORK/bin"
printf '#!/bin/sh\necho pretend-valetfs\n' > "$RELEASE/$ASSET"
( cd "$RELEASE" && sha256sum "$ASSET" > SHA256SUMS )

pass=0
fail=0

run_install() {
  env INSTALL_DIR="$WORK/bin" \
      VALETFS_VERSION="v0.0.0-test" \
      VALETFS_RELEASE_BASE="file://$RELEASE" \
      "$@" bash "$INSTALL_SH" >"$WORK/out.txt" 2>&1
}

check() {
  local name="$1" want="$2"
  shift 2
  local got=0
  run_install "$@" || got=$?
  if [ "$got" = "$want" ]; then
    echo "  ok  $name"
    pass=$((pass + 1))
  else
    echo "  FAIL $name (exit $got, want $want)"
    sed 's/^/       | /' "$WORK/out.txt" | tail -5
    fail=$((fail + 1))
  fi
}

echo "install.sh verification"

# A clean release installs.
check "an intact release installs" 0 env
if [ -x "$WORK/bin/valetfs" ]; then
  echo "  ok  the binary landed in INSTALL_DIR"
  pass=$((pass + 1))
else
  echo "  FAIL the binary did not land in INSTALL_DIR"
  fail=$((fail + 1))
fi

# The case that matters: bytes swapped after the manifest was written.
printf '#!/bin/sh\necho MALICIOUS\n' > "$RELEASE/$ASSET"
check "a tampered binary is refused" 1 env
if grep -q 'MALICIOUS' "$WORK/bin/valetfs" 2>/dev/null; then
  echo "  FAIL the tampered binary was installed anyway"
  fail=$((fail + 1))
else
  echo "  ok  the tampered binary was not installed"
  pass=$((pass + 1))
fi

# Restore, then take the manifest away: an unverifiable release is not installable.
printf '#!/bin/sh\necho pretend-valetfs\n' > "$RELEASE/$ASSET"
( cd "$RELEASE" && sha256sum "$ASSET" > SHA256SUMS )
mv "$RELEASE/SHA256SUMS" "$WORK/SHA256SUMS.away"
check "a release with no SHA256SUMS is refused" 1 env
mv "$WORK/SHA256SUMS.away" "$RELEASE/SHA256SUMS"

# An unsigned release must hard-fail in strict mode rather than warn.
check "strict mode refuses an unsigned release" 1 env VALETFS_REQUIRE_SIGNATURE=1

# A manifest listing a different file must not be accepted for this asset.
( cd "$RELEASE" && sha256sum "$ASSET" | sed "s/$ASSET/valetfs-linux-other/" > SHA256SUMS )
check "a manifest without this asset is refused" 1 env
( cd "$RELEASE" && sha256sum "$ASSET" > SHA256SUMS )

# --- signature branch -----------------------------------------------------
#
# The real keyless verification needs Sigstore and an OIDC identity, so it
# cannot run here. What can run — and is the branch that actually protects the
# user — is whether a FAILED verification stops the install. cosign is stubbed
# so both outcomes are reachable offline.
STUB="$WORK/stub"
mkdir -p "$STUB"
printf 'sig\n' > "$RELEASE/SHA256SUMS.sig"
printf 'pem\n' > "$RELEASE/SHA256SUMS.pem"

cat > "$STUB/cosign" <<'STUBEOF'
#!/bin/sh
exit 1
STUBEOF
chmod +x "$STUB/cosign"
rm -f "$WORK/bin/valetfs"
check "a failed signature check refuses the install" 1 env PATH="$STUB:$PATH"
if [ -x "$WORK/bin/valetfs" ]; then
  echo "  FAIL installed despite a failed signature check"
  fail=$((fail + 1))
else
  echo "  ok  nothing was installed after a failed signature check"
  pass=$((pass + 1))
fi

cat > "$STUB/cosign" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
chmod +x "$STUB/cosign"
check "a passing signature check allows the install" 0 env PATH="$STUB:$PATH" VALETFS_REQUIRE_SIGNATURE=1

echo
if [ "$fail" -gt 0 ]; then
  echo "install.sh verification: $pass passed, $fail FAILED"
  exit 1
fi
echo "install.sh verification: $pass/$pass 통과"
