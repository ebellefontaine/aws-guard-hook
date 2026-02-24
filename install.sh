#!/usr/bin/env bash
# install.sh — User-level installer for the aws-guard Claude Code hook
#
# Installs the hook into ~/.claude/settings.json so it applies to ALL projects
# on this machine, not just this repo.
#
# Usage:
#   ./install.sh               # install to default location
#   INSTALL_DIR=~/my/dir ./install.sh
#
# Requirements: bash 4+, python3 (for JSON merging)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.claude/hooks}"
SETTINGS_FILE="${HOME}/.claude/settings.json"
HOOK_SRC="${SCRIPT_DIR}/hooks/aws_guard.py"
HOOK_DST="${INSTALL_DIR}/aws_guard.py"

# ── helpers ────────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
die()    { red "ERROR: $*" >&2; exit 1; }

# ── preflight ──────────────────────────────────────────────────────────────

[[ -f "${HOOK_SRC}" ]] || die "Hook script not found: ${HOOK_SRC}"
command -v python3 >/dev/null 2>&1 || die "python3 is required for JSON merging"

# Prefer uv for running the hook; fall back to python3.
if command -v uv >/dev/null 2>&1; then
  HOOK_CMD="uv run ${HOOK_DST}"
else
  yellow "uv not found — the hook will run with python3 instead."
  yellow "Install uv (https://docs.astral.sh/uv/) for faster hook startup."
  HOOK_CMD="python3 ${HOOK_DST}"
fi

# ── install hook script ────────────────────────────────────────────────────

mkdir -p "${INSTALL_DIR}"
cp "${HOOK_SRC}" "${HOOK_DST}"
chmod +x "${HOOK_DST}"
green "Hook script copied to: ${HOOK_DST}"

# ── merge into ~/.claude/settings.json ────────────────────────────────────

mkdir -p "${HOME}/.claude"

# Use Python to do a safe, idempotent JSON merge.
python3 - "${SETTINGS_FILE}" "${HOOK_CMD}" <<'PYEOF'
import json, sys, os, copy

settings_path = sys.argv[1]
hook_cmd      = sys.argv[2]

NEW_ENTRY = {
    "matcher": "Bash",
    "hooks": [{"type": "command", "command": hook_cmd}]
}

# Load existing settings or start fresh.
if os.path.exists(settings_path):
    with open(settings_path) as f:
        try:
            settings = json.load(f)
        except json.JSONDecodeError:
            print(f"WARNING: {settings_path} is not valid JSON — creating a backup.")
            import shutil
            shutil.copy(settings_path, settings_path + ".bak")
            settings = {}
else:
    settings = {}

hooks = settings.setdefault("hooks", {})
pre   = hooks.setdefault("PreToolUse", [])

# Check if a aws-guard entry already exists (idempotent).
for entry in pre:
    for h in entry.get("hooks", []):
        if "aws_guard.py" in h.get("command", ""):
            print("aws-guard hook is already registered in", settings_path)
            sys.exit(0)

pre.append(NEW_ENTRY)

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")

print(f"Hook registered in: {settings_path}")
PYEOF

green ""
green "Installation complete!"
green ""
green "The aws-guard hook is now active for all Claude Code projects on this machine."
green "It blocks any AWS CLI command that is not a read-only operation."
green ""
yellow "To uninstall, remove the entry from: ${SETTINGS_FILE}"
