#!/usr/bin/env bash
# Install Skill Airlock as a Claude Code skill (user level).
#   ./install.sh            install or update the skill + register the SessionStart cleanup hook
#   ./install.sh --no-hook  install without touching ~/.claude/settings.json
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/skills/skill-airlock"
DEST="${HOME}/.claude/skills/skill-airlock"
SETTINGS="${HOME}/.claude/settings.json"
HOOK_CMD="python3 \"${DEST}/airlock\" vent --expired --hook"   # quoted: survives a space in $HOME

command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

echo "Installing Skill Airlock → ${DEST}"
rm -rf "${DEST}"
mkdir -p "${DEST}"
cp -R "${SRC}/." "${DEST}/"
rm -rf "${DEST}/__pycache__"
chmod +x "${DEST}/airlock"

if [ -d "${HOME}/.local/bin" ] || mkdir -p "${HOME}/.local/bin" 2>/dev/null; then
  ln -sf "${DEST}/airlock" "${HOME}/.local/bin/airlock"
  echo "  ✓ CLI linked: ~/.local/bin/airlock"
fi

if [ "${1:-}" = "--no-hook" ]; then
  echo "  - SessionStart hook not registered (--no-hook)"
else
  # Merge one SessionStart hook into settings.json: keeps every other setting, idempotent, backs up first.
  python3 - "$SETTINGS" "$HOOK_CMD" <<'PY'
import json, os, shutil, sys, time
path, cmd = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read().strip()
        cfg = json.loads(raw) if raw else {}
    except ValueError:
        print("  ! settings.json is not valid JSON; left untouched, hook not added")
        sys.exit(0)
hooks = cfg.setdefault("hooks", {}).setdefault("SessionStart", [])
def ours(c):  # matches the quoted form and the unquoted one written by v0.1.0
    return "airlock" in c and "vent --expired" in c
if any(ours(h.get("command", "")) for e in hooks for h in e.get("hooks", [])):
    print("  ✓ SessionStart hook already registered; settings.json unchanged")
    sys.exit(0)
hooks.append({"hooks": [{"type": "command", "command": cmd}]})
existed = os.path.exists(path)
if existed:
    shutil.copy(path, f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
print("  ✓ SessionStart hook registered (removes expired temporary skills); "
      + ("previous settings backed up" if existed else "created ~/.claude/settings.json"))
PY
fi

echo "Done. First run: airlock sync   (mirrors the catalogs in ~/.skill-airlock/sources.json)"
