#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/backend/soc-agent/collectors/network.py"
DST="/opt/soc-agent/collectors/network.py"
BACKUP="/opt/soc-agent/collectors/network.py.bak.$(date +%Y%m%d%H%M%S)"

if [[ ! -f "$SRC" ]]; then
  echo "Source collector not found: $SRC" >&2
  exit 1
fi

sudo test -d /opt/soc-agent/collectors
sudo cp "$DST" "$BACKUP"
sudo cp "$SRC" "$DST"
sudo chown root:root "$DST"
sudo chmod 755 "$DST"
python3 -m py_compile "$SRC"
sudo systemctl restart soc-agent
sleep 3
sudo systemctl status soc-agent --no-pager

echo "Applied network telemetry patch."
echo "Backup: $BACKUP"
