#!/usr/bin/env bash
set -euo pipefail

REPO="winm2m/valet-fs" # 이전 수정 사항 반영
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

# 1. 패키지 매니저 자동 감지
get_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt-get update -qq && apt-get install -y"
  elif command -v apk >/dev/null 2>&1; then echo "apk add --no-cache"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf install -y"
  elif command -v yum >/dev/null 2>&1; then echo "yum install -y"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman -Sy --noconfirm"
  else echo ""; fi
}

# 2. 권한(root 또는 sudo) 확인 후 실행
run_with_privilege() {
  if [ "$(id -u)" -eq 0 ]; then
    eval "$@"
  elif command -v sudo >/dev/null 2>&1; then
    eval "sudo $@"
  else
    return 1
  fi
}

# 3. 필요 명령어 확인 및 자동 설치 로직
require_cmd() {
  local cmd="$1"
  # OS에 따라 install, uname, mktemp 등은 coreutils 패키지에 포함되어 있음
  local pkg="$cmd"
  if [ "$cmd" = "install" ] || [ "$cmd" = "mktemp" ] || [ "$cmd" = "uname" ]; then
    pkg="coreutils"
  fi

  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "'$cmd' command not found. Attempting automatic installation..."
    local pm_cmd
    pm_cmd="$(get_pkg_manager)"
    
    if [ -z "$pm_cmd" ]; then
      fail "'$cmd' 가 필요하지만 지원되는 패키지 매니저를 찾을 수 없어 설치할 수 없습니다."
    fi

    log "Running: $pm_cmd $pkg"
    if ! run_with_privilege "$pm_cmd $pkg"; then
      fail "권한이 부족하여 '$pkg' 패키지를 설치할 수 없습니다. root 계정이나 sudo를 이용해 직접 설치해 주세요."
    fi
    
    if ! command -v "$cmd" >/dev/null 2>&1; then
      fail "자동 설치를 시도했으나 여전히 '$cmd' 명령어를 찾을 수 없습니다."
    fi
    log "Automatic installation for '$cmd' completed."
  fi
}

# 4. Alpine Linux 전용 런타임 호환성 패키지 자동 설치
install_alpine_runtime_deps() {
  if [ -f /etc/alpine-release ]; then
    log "Alpine Linux detected. Checking runtime compatibility packages (gcompat, fuse)..."
    local missing=""
    if ! apk info -e gcompat >/dev/null 2>&1; then missing="$missing gcompat"; fi
    if ! apk info -e fuse >/dev/null 2>&1; then missing="$missing fuse"; fi
    
    if [ -n "$missing" ]; then
      log "Installing required runtime packages:$missing"
      if ! run_with_privilege "apk add --no-cache $missing"; then
        log "Warning: failed to auto-install runtime packages. Runtime errors may occur."
      fi
    fi
  fi
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
  url="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-linux-${DOWNLOAD_ARCH}"

  log "Downloading ${BINARY_NAME} ${VERSION} (linux/${DOWNLOAD_ARCH})"
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
  install_alpine_runtime_deps
  
  resolve_version
  download_binary
  install_binary

  log ""
  log "Done. Try:"
  log "  ${BINARY_NAME} serve --dev"
  log "  ${BINARY_NAME} status"
}

main "$@"
