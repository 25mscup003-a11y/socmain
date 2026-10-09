#!/usr/bin/env bash
# Targeted network-telemetry update; preserves agent config, state and other modules.
# Run from the source bundle: sudo bash update-network-telemetry.sh
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/soc-agent"
FILES=(collectors/network.py core/network_telemetry.py)

if [[ "${1:-}" == "--check" ]]; then
  python3 - "$SOURCE_DIR" <<'PY'
import ast, pathlib, sys
root = pathlib.Path(sys.argv[1])
for relative in ('collectors/network.py', 'core/network_telemetry.py'):
    ast.parse((root / relative).read_text(), filename=relative)
print('Network telemetry source is valid.')
PY
  exit 0
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Run with sudo to update the root-owned agent at $INSTALL_DIR." >&2
  exit 1
fi
if [[ ! -f "$INSTALL_DIR/agent.py" || "$SOURCE_DIR" == "$INSTALL_DIR" ]]; then
  echo "An existing agent and a separate source bundle are required." >&2
  exit 1
fi
if ! command -v ss >/dev/null; then
  echo "Install iproute2 (the ss command) before applying TCP telemetry." >&2
  exit 1
fi
PYTHON="$INSTALL_DIR/.venv/bin/python3"
if [[ ! -x "$PYTHON" ]]; then PYTHON="$INSTALL_DIR/venv/bin/python"; fi
if [[ ! -x "$PYTHON" ]]; then
  echo "Installed agent Python environment was not found." >&2
  exit 1
fi
for relative in "${FILES[@]}"; do
  [[ -f "$SOURCE_DIR/$relative" ]] || { echo "Missing source: $relative" >&2; exit 1; }
done

mkdir -p /var/backups/soc-agent
BACKUP_DIR="$(mktemp -d /var/backups/soc-agent/network-telemetry.XXXXXXXX)"
chmod 700 "$BACKUP_DIR"
for relative in "${FILES[@]}"; do
  mkdir -p "$BACKUP_DIR/$(dirname "$relative")"
  if [[ -f "$INSTALL_DIR/$relative" ]]; then cp -a "$INSTALL_DIR/$relative" "$BACKUP_DIR/$relative"; fi
done
WAS_ACTIVE=false
if systemctl is-active --quiet soc-agent.service; then WAS_ACTIVE=true; fi

rollback() {
  local code=$?
  trap - ERR
  echo "Update failed; restoring the network modules from $BACKUP_DIR." >&2
  for relative in "${FILES[@]}"; do
    if [[ -f "$BACKUP_DIR/$relative" ]]; then
      cp -a "$BACKUP_DIR/$relative" "$INSTALL_DIR/$relative"
    else
      rm -f "$INSTALL_DIR/$relative"
    fi
  done
  if [[ "$WAS_ACTIVE" == true ]]; then systemctl restart soc-agent.service || true; fi
  exit "$code"
}
trap rollback ERR

if [[ "$WAS_ACTIVE" == true ]]; then systemctl stop soc-agent.service; fi
for relative in "${FILES[@]}"; do
  install -m 0644 "$SOURCE_DIR/$relative" "$INSTALL_DIR/$relative"
done
"$PYTHON" -m py_compile "$INSTALL_DIR/collectors/network.py" "$INSTALL_DIR/core/network_telemetry.py"
if [[ "$WAS_ACTIVE" == true ]]; then
  systemctl start soc-agent.service
  systemctl is-active --quiet soc-agent.service
fi
trap - ERR
echo "Network telemetry updated. Backup: $BACKUP_DIR"
echo "New TCP counters appear on subsequent network observations; peer DNS/Geo fills as lookups complete."
