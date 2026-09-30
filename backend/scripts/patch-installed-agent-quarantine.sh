#!/usr/bin/env bash
set -euo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../soc-agent" && pwd)"
DEST_ROOT="/opt/soc-agent"
BACKUP_ROOT="/opt/soc-agent.backup.$(date +%Y%m%d%H%M%S)"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash backend/scripts/patch-installed-agent-quarantine.sh"
  exit 1
fi

if [[ ! -d "$DEST_ROOT" ]]; then
  echo "Installed agent not found at $DEST_ROOT"
  exit 1
fi

echo "[1/5] Stopping soc-agent service if present..."
systemctl stop soc-agent 2>/dev/null || true

echo "[2/5] Backing up installed agent files to $BACKUP_ROOT..."
mkdir -p "$BACKUP_ROOT/core" "$BACKUP_ROOT/response"
cp -f "$DEST_ROOT/core/config.py" "$BACKUP_ROOT/core/config.py" 2>/dev/null || true
cp -f "$DEST_ROOT/core/malware_responder.py" "$BACKUP_ROOT/core/malware_responder.py" 2>/dev/null || true
cp -f "$DEST_ROOT/response/quarantine.py" "$BACKUP_ROOT/response/quarantine.py" 2>/dev/null || true

echo "[3/5] Installing safe quarantine guard..."
install -m 0644 "$SRC_ROOT/core/config.py" "$DEST_ROOT/core/config.py"
install -m 0644 "$SRC_ROOT/core/malware_responder.py" "$DEST_ROOT/core/malware_responder.py"
install -m 0644 "$SRC_ROOT/response/quarantine.py" "$DEST_ROOT/response/quarantine.py"

echo "[4/5] Clearing stale bytecode..."
find "$DEST_ROOT" -type d -name __pycache__ -prune -exec rm -rf {} +

echo "[5/5] Verifying patched files..."
python3 -m py_compile \
  "$DEST_ROOT/core/config.py" \
  "$DEST_ROOT/core/malware_responder.py" \
  "$DEST_ROOT/response/quarantine.py"

echo "Done. Installed agent patched."
echo "To start it again: sudo systemctl start soc-agent"
