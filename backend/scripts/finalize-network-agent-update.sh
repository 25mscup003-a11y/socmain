#!/usr/bin/env bash
# Finalize the local network change-only update with a matching integrity manifest.

set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run with sudo: sudo bash backend/scripts/finalize-network-agent-update.sh" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_DIR="$REPO_ROOT/backend/soc-agent"
INSTALL_DIR="/opt/soc-agent"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/soc-agent"
BACKUP_FILE="$BACKUP_DIR/full-before-network-finalize-$STAMP.tar.gz"
MANIFEST_FILE="$(mktemp)"

cleanup() {
  rm -f "$MANIFEST_FILE"
}
trap cleanup EXIT

echo "[1/9] Running network and sender regression tests..."
PYTHONPATH="$SOURCE_DIR" python3 -m unittest \
  "$REPO_ROOT/backend/test/test_network_change_reporting.py" \
  "$REPO_ROOT/backend/test/test_sender_transport.py" \
  "$REPO_ROOT/backend/test/test_network_sensor_normalizer.py" \
  "$REPO_ROOT/backend/test/test_suricata_parser_filter.py"

echo "[2/9] Building the package integrity manifest..."
node -e '
const fs = require("fs");
const path = require("path");
const source = process.argv[1];
const output = process.argv[2];
const builder = require(path.resolve(source, "../src/services/packageBuilder.service.js"));
const manifest = builder.getAgentIntegrityManifest();
for (const required of ["collectors/network.py", "core/config.py", "core/sender.py", "core/durable_spool.py", "core/network_sensor_normalizer.py", "core/suricata_parser.py"]) {
  if (!manifest.files[required]) throw new Error(`Manifest is missing ${required}`);
}
fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
' "$SOURCE_DIR" "$MANIFEST_FILE"

echo "[3/9] Registering the exact update manifest with the local server..."
CURRENT_PYTHON="$INSTALL_DIR/venv/bin/python"
[[ -x "$CURRENT_PYTHON" ]] || CURRENT_PYTHON="$INSTALL_DIR/.venv/bin/python3"
SYSTEM_ID="$(PYTHONPATH="$INSTALL_DIR" "$CURRENT_PYTHON" -c '
from core.config_protection import load_config
print(load_config("/opt/soc-agent/config/company_config.json").get("system_id", ""))
')"
MANIFEST_HASH="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fleetSha256"])' "$MANIFEST_FILE")"
(
  cd "$REPO_ROOT/backend"
  SYSTEM_ID="$SYSTEM_ID" MANIFEST_HASH="$MANIFEST_HASH" node -e '
require("dotenv").config();
const mongoose = require("mongoose");
(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  const result = await mongoose.connection.db.collection("systems").updateOne(
    { _id: new mongoose.Types.ObjectId(process.env.SYSTEM_ID) },
    { $set: { agentPendingIntegrityHash: process.env.MANIFEST_HASH } },
  );
  await mongoose.disconnect();
  if (result.matchedCount !== 1) throw new Error("installed system was not found");
})().catch(error => { console.error(error.message); process.exit(1); });
'
)

echo "[4/9] Stopping the running agent and taking a consistent backup..."
systemctl stop soc-agent
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
BACKUP_ITEMS=(opt/soc-agent)
[[ -e /etc/soc-agent ]] && BACKUP_ITEMS+=(etc/soc-agent)
[[ -e /etc/systemd/system/soc-agent.service ]] && BACKUP_ITEMS+=(etc/systemd/system/soc-agent.service)
tar --acls --xattrs -C / -czf "$BACKUP_FILE" "${BACKUP_ITEMS[@]}"
chmod 600 "$BACKUP_FILE"

rollback() {
  local status=$?
  trap - ERR
  echo "ERROR: finalization failed; restoring $BACKUP_FILE" >&2
  systemctl stop soc-agent 2>/dev/null || true
  tar -C / -xzf "$BACKUP_FILE" || true
  systemctl daemon-reload || true
  systemctl restart soc-agent || true
  exit "$status"
}
trap rollback ERR

echo "[5/9] Installing matching manifest and updated source..."
install -o root -g root -m 0600 "$MANIFEST_FILE" "$INSTALL_DIR/integrity_manifest.json"
SOC_AGENT_REPLACE_CONFIG=false SOC_AGENT_UPDATE_VERSION=false \
  bash "$SOURCE_DIR/update-agent-functions-linux.sh" "$SOURCE_DIR"

echo "[6/9] Restoring root-only installation permissions..."
chown -R root:root "$INSTALL_DIR"
chmod -R go-rwx "$INSTALL_DIR"

echo "[7/9] Verifying deployed files and integrity..."
for relative in collectors/network.py core/config.py core/sender.py core/durable_spool.py core/network_sensor_normalizer.py core/suricata_parser.py; do
  cmp "$SOURCE_DIR/$relative" "$INSTALL_DIR/$relative"
done

PYTHON="$INSTALL_DIR/venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="$INSTALL_DIR/.venv/bin/python3"
[[ -x "$PYTHON" ]] || { echo "ERROR: installed Python runtime not found" >&2; false; }

PYTHONPATH="$INSTALL_DIR" "$PYTHON" -c '
from core.self_protection import collect_security_report
report = collect_security_report("/opt/soc-agent")
print("Integrity:", report["integrityStatus"])
if report["integrityStatus"] != "verified":
    print("Findings:", report["findings"])
    raise SystemExit(1)
'

echo "[8/9] Restarting and checking connectivity..."
STARTED_AT="$(date '+%Y-%m-%d %H:%M:%S')"
systemctl restart soc-agent
sleep 35
systemctl is-active --quiet soc-agent
"$PYTHON" "$INSTALL_DIR/agent.py" test

echo "[9/9] Checking the new process logs..."
for _attempt in $(seq 1 18); do
  RECENT_LOGS="$(journalctl -u soc-agent --since "$STARTED_AT" --no-pager)"
  if printf '%s\n' "$RECENT_LOGS" | grep -Fq 'NET_CONNECTION_SUMMARY'; then
    break
  fi
  systemctl is-active --quiet soc-agent
  sleep 5
done
printf '%s\n' "$RECENT_LOGS" | grep -F "Network monitor started"
printf '%s\n' "$RECENT_LOGS" | grep -F "Heartbeat started"
BASELINE_COUNT="$(printf '%s\n' "$RECENT_LOGS" | grep -Fc 'NET_CONNECTION_SUMMARY' || true)"
if [[ "$BASELINE_COUNT" -lt 1 ]]; then
  echo "ERROR: startup network baseline was not delivered" >&2
  false
fi
for rule in NET_CONNECTION_SUMMARY NET_DNS_SUMMARY NET_EXPOSURE_SUMMARY NET_THREAT_INTEL_SUMMARY; do
  count="$(printf '%s\n' "$RECENT_LOGS" | grep -Fc "$rule" || true)"
  if [[ "$count" -gt 1 ]]; then
    echo "ERROR: $rule flooded during the initial unchanged/debounce window ($count sends)" >&2
    false
  fi
done
if printf '%s\n' "$RECENT_LOGS" | grep -Eq \
  'Encrypted agent payload authentication failed|Batch rejected 400|Agent tamper/analysis activity detected'; then
  echo "ERROR: a transport or integrity failure occurred after restart" >&2
  false
fi

trap - ERR
echo "SUCCESS: running agent updated, integrity verified, heartbeat/network monitor active."
echo "Backup: $BACKUP_FILE"
printf '%s\n' "$RECENT_LOGS" | tail -n 80
