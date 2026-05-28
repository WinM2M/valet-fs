#!/usr/bin/env bash
set -euo pipefail

REPO="winm2m/valet-fs"
BINARY_NAME="valetfs"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TMP_FILE=""

cleanup() {
  if [ -n "${TMP_FILE}" ] && [ -f "${TMP_FILE}" ]; then
    rm -f "${TMP_FILE}"
  fi
}
trap cleanup EXIT

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  if [ "${os}" != "linux" ]; then
    fail "only Linux is supported by this installer (detected: ${os})"
  fi

  case "${arch}" in
    x86_64|amd64)
      DOWNLOAD_ARCH="amd64"
      ;;
    aarch64|arm64)
      DOWNLOAD_ARCH="arm64"
      ;;
    *)
      fail "unsupported architecture: ${arch}"
      ;;
  esac

  DOWNLOAD_OS="${os}"
}

resolve_version() {
  if [ -n "${VALETFS_VERSION:-}" ]; then
    VERSION="${VALETFS_VERSION}"
    return
  fi

  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "${VERSION}" ] || fail "unable to resolve latest release tag"
}

download_binary() {
  local url
  url="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${DOWNLOAD_OS}-${DOWNLOAD_ARCH}"

  log "Downloading ${BINARY_NAME} ${VERSION} (${DOWNLOAD_OS}/${DOWNLOAD_ARCH})"
  TMP_FILE="$(mktemp)"
  curl -fL "${url}" -o "${TMP_FILE}"
  chmod +x "${TMP_FILE}"
}

install_binary() {
  local target
  target="${INSTALL_DIR}/${BINARY_NAME}"

  if [ -w "${INSTALL_DIR}" ]; then
    install -m 0755 "${TMP_FILE}" "${target}"
  elif command -v sudo >/dev/null 2>&1; then
    log "Installing to ${target} with sudo"
    sudo install -m 0755 "${TMP_FILE}" "${target}"
  else
    fail "no write permission to ${INSTALL_DIR} and sudo is not available"
  fi

  log "Installed: ${target}"
}

main() {
  require_cmd curl
  require_cmd uname
  require_cmd mktemp
  require_cmd install

  log "Detecting installation environment..."
  detect_platform
  resolve_version
  download_binary
  install_binary

  log ""
  log "Done. Try:"
  log "  ${BINARY_NAME} serve --dev"
  log "  ${BINARY_NAME} status"
}

main "$@"
