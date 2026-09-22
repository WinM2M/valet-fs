#!/usr/bin/env bash
# Install the ValetFS skill for Claude Code (or any agent reading ~/.claude/skills).
#
#   curl -fsSL https://winm2m.github.io/valet-fs/install-skill.sh | bash
#
# Installs to the user-global skill directory so it applies to every project on
# this machine, which is what "I gave my agent access to my vault" means.
# Override with SKILL_DIR=/path/to/.claude/skills to scope it to one project.
set -euo pipefail

REPO="winm2m/valet-fs"
REF="${REF:-main}"
SKILL_NAME="valetfs"
SKILL_DIR="${SKILL_DIR:-${CLAUDE_CONFIG_DIR:-$HOME/.claude}/skills}"
TARGET="${SKILL_DIR}/${SKILL_NAME}"
SRC_URL="https://raw.githubusercontent.com/${REPO}/${REF}/skills/${SKILL_NAME}/SKILL.md"

log()  { printf '%s\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

log "Fetching ${SKILL_NAME} skill from ${REPO}@${REF}..."
curl -fsSL "$SRC_URL" -o "$TMP" || fail "download failed: $SRC_URL"

# A truncated or error page must not overwrite a working skill.
head -n 1 "$TMP" | grep -qx -- '---' || fail "downloaded file is not a SKILL.md (missing front matter)"
grep -qx "name: ${SKILL_NAME}" "$TMP" || fail "downloaded file is not the ${SKILL_NAME} skill"

mkdir -p "$TARGET"
if [ -f "${TARGET}/SKILL.md" ]; then
  if cmp -s "$TMP" "${TARGET}/SKILL.md"; then
    log "Already up to date: ${TARGET}/SKILL.md"
    exit 0
  fi
  BACKUP="${TARGET}/SKILL.md.bak.$(date +%Y%m%d%H%M%S)"
  cp "${TARGET}/SKILL.md" "$BACKUP"
  log "Existing skill backed up to ${BACKUP}"
fi

install -m 0644 "$TMP" "${TARGET}/SKILL.md"
log "Installed ${TARGET}/SKILL.md"
log ""
log "Claude Code picks this up on its next start. From then on it checks the"
log "ValetFS vault before reading credentials from disk or the environment, and"
log "uses 'valetfs exec' to consume a secret rather than printing it."
log ""
log "There is no update channel for an installed skill: re-run this one-liner to"
log "pick up a newer one. It is idempotent and backs up what it replaces."
log ""
log "Optional, and for you rather than the agent: 'valetfs setup-claude' allows"
log "'valetfs exec', 'ls' and 'status' without a prompt each time. The agent"
log "cannot run it for you -- Claude Code blocks an agent from editing its own"
log "settings, which is the point."
