#!/usr/bin/env bash
# Safely update an existing Linux SOC Agent from this source bundle.
# Usage: sudo bash update-installed-agent.sh [source-directory]

set -Eeuo pipefail

INSTALL_DIR="/opt/soc-agent"
SERVICE_NAME="soc-agent"
SOURCE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
BACKUP_ROOT="/var/backups/soc-agent"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_FILE="$BACKUP_ROOT/soc-agent-code-$STAMP.tar.gz"
CONFIG_BACKUP="$BACKUP_ROOT/company-config-$STAMP.json"
REPLACE_CONFIG="${SOC_AGENT_REPLACE_CONFIG:-false}"
UPDATE_VERSION="${SOC_AGENT_UPDATE_VERSION:-true}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root: sudo bash $0 [source-directory]" >&2
  exit 1
fi

if [[ ! -d "$INSTALL_DIR" || ! -f "$INSTALL_DIR/agent.py" ]]; then
  echo "ERROR: installed agent not found at $INSTALL_DIR" >&2
  exit 1
fi

for required in agent.py install-linux-location-provider.sh collectors/usb.py collectors/processes.py core/sender.py core/durable_spool.py core/config_protection.py core/device_identity.py core/suricata_parser.py requirements.txt; do
  if [[ ! -f "$SOURCE_DIR/$required" ]]; then
    echo "ERROR: update source is missing $required: $SOURCE_DIR" >&2
    exit 1
  fi
done

SOURCE_REAL="$(readlink -f "$SOURCE_DIR")"
INSTALL_REAL="$(readlink -f "$INSTALL_DIR")"
if [[ "$SOURCE_REAL" == "$INSTALL_REAL" ]]; then
  echo "ERROR: source and installed directory are identical." >&2
  echo "Extract/copy the new agent bundle elsewhere, then run:" >&2
  echo "  sudo bash update-installed-agent.sh /path/to/new/soc-agent" >&2
  exit 1
fi

mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"

echo "[1/7] Validating updated Python source..."
python3 -m py_compile \
  "$SOURCE_DIR/agent.py" \
  "$SOURCE_DIR/collectors/usb.py" \
  "$SOURCE_DIR/collectors/processes.py" \
  "$SOURCE_DIR/core/sender.py" \
  "$SOURCE_DIR/core/durable_spool.py" \
  "$SOURCE_DIR/core/suricata_parser.py"

echo "[2/7] Creating recoverable code backup: $BACKUP_FILE"
tar -C "$INSTALL_DIR" -czf "$BACKUP_FILE" \
  agent.py collectors core detectors response yara_rules requirements.txt \
  2>/dev/null
chmod 600 "$BACKUP_FILE"
if [[ -f "$INSTALL_DIR/config/company_config.json" ]]; then
  cp "$INSTALL_DIR/config/company_config.json" "$CONFIG_BACKUP"
  chmod 600 "$CONFIG_BACKUP"
fi

restore_backup() {
  local exit_code=$?
  if [[ $exit_code -eq 0 ]]; then
    return
  fi
  echo "Update failed; restoring previous agent code..." >&2
  tar -C "$INSTALL_DIR" -xzf "$BACKUP_FILE" || true
  if [[ -f "$CONFIG_BACKUP" ]]; then
    install -m 0600 "$CONFIG_BACKUP" "$INSTALL_DIR/config/company_config.json" || true
  fi
  systemctl daemon-reload || true
  systemctl restart "$SERVICE_NAME" || true
  echo "Rollback attempted from $BACKUP_FILE" >&2
  exit "$exit_code"
}
trap restore_backup ERR

echo "[3/7] Stopping $SERVICE_NAME..."
systemctl stop "$SERVICE_NAME"

echo "[4/7] Installing updated agent code (config/state are preserved)..."
install -m 0755 "$SOURCE_DIR/agent.py" "$INSTALL_DIR/agent.py"
install -m 0700 "$SOURCE_DIR/install-linux-location-provider.sh" "$INSTALL_DIR/install-linux-location-provider.sh"
install -m 0644 "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"
for directory in collectors core detectors response yara_rules; do
  mkdir -p "$INSTALL_DIR/$directory"
  cp -a "$SOURCE_DIR/$directory/." "$INSTALL_DIR/$directory/"
done
find "$INSTALL_DIR" -type d -name __pycache__ -prune -exec rm -rf {} +
"$INSTALL_DIR/install-linux-location-provider.sh"

if [[ "$REPLACE_CONFIG" == "true" ]]; then
  if [[ ! -f "$SOURCE_DIR/config/company_config.json" ]]; then
    echo "ERROR: replacement config not found: $SOURCE_DIR/config/company_config.json" >&2
    false
  fi
  mkdir -p "$INSTALL_DIR/config"
  PYTHONPATH="$SOURCE_DIR" python3 - "$SOURCE_DIR/config/company_config.json" "$INSTALL_DIR/config/company_config.json" <<'PY'
import sys
from core.config_protection import load_config, save_config
source_path, installed_path = sys.argv[1:]
save_config(installed_path, load_config(source_path))
PY
elif [[ "$UPDATE_VERSION" == "true" ]]; then
  PYTHONPATH="$SOURCE_DIR" python3 - "$SOURCE_DIR/config/company_config.json" "$INSTALL_DIR/config/company_config.json" <<'PY'
import sys
from core.config_protection import load_config, save_config
source_path, installed_path = sys.argv[1:]
source = load_config(source_path)
installed = load_config(installed_path)
version = str(source.get('agent_version') or '').strip()
if not version:
    raise SystemExit('ERROR: update source does not declare agent_version')
installed['agent_version'] = version
save_config(installed_path, installed)
PY
fi

# Explicitly preserve security-sensitive runtime data and permissions.
if [[ -f "$INSTALL_DIR/config/company_config.json" ]]; then
  chown root:root "$INSTALL_DIR/config/company_config.json"
  chmod 600 "$INSTALL_DIR/config/company_config.json"
fi

echo "[5/7] Updating Python dependencies..."
PYTHON="$INSTALL_DIR/venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  python3 -m venv "$INSTALL_DIR/venv"
fi
"$PYTHON" -m pip install -q -r "$INSTALL_DIR/requirements.txt"

echo "[6/7] Compiling installed agent..."
"$PYTHON" -m py_compile \
  "$INSTALL_DIR/agent.py" \
  "$INSTALL_DIR/collectors/usb.py" \
  "$INSTALL_DIR/collectors/processes.py" \
  "$INSTALL_DIR/core/sender.py" \
  "$INSTALL_DIR/core/durable_spool.py" \
  "$INSTALL_DIR/core/suricata_parser.py"

echo "[7/7] Restarting and verifying $SERVICE_NAME..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"
sleep 3
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
  systemctl status "$SERVICE_NAME" --no-pager -l || true
  false
fi

trap - ERR
echo "SUCCESS: SOC Agent updated and running."
echo "Backup: $BACKUP_FILE"
if [[ -f "$CONFIG_BACKUP" ]]; then
  echo "Previous config backup: $CONFIG_BACKUP"
fi
echo "Status: $(systemctl is-active "$SERVICE_NAME")"
echo "Recent USB collector logs:"
journalctl -u "$SERVICE_NAME" --since "2 minutes ago" --no-pager \
  | grep -Ei "USB monitor|USB device|collector.usb" \
  | tail -n 20 || echo "No USB event yet; plug/unplug a USB device to test."
