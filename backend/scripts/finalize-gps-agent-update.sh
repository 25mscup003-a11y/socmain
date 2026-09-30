#!/usr/bin/env bash
# Deploy and verify the policy-gated AJNAT GPS collector without altering enrollment state.

set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run with sudo: sudo bash backend/scripts/finalize-gps-agent-update.sh" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_DIR="$REPO_ROOT/backend/soc-agent"
INSTALL_DIR="/opt/soc-agent"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/soc-agent"
BACKUP_FILE="$BACKUP_DIR/full-before-gps-update-$STAMP.tar.gz"
MANIFEST_FILE="$(mktemp)"

cleanup() { rm -f "$MANIFEST_FILE"; }
trap cleanup EXIT

echo "[1/8] Running GPS regression tests..."
PYTHONPATH="$SOURCE_DIR" python3 -m unittest \
  "$SOURCE_DIR/tests/test_gps_location.py" \
  "$SOURCE_DIR/tests/test_geo_enrichment.py"

echo "[2/8] Building and registering the exact integrity manifest..."
node -e '
const fs = require("fs");
const path = require("path");
const source = process.argv[1];
const output = process.argv[2];
const builder = require(path.resolve(source, "../src/services/packageBuilder.service.js"));
const manifest = builder.getAgentIntegrityManifest();
if (!manifest.files["core/gps_location.py"]) throw new Error("Manifest is missing core/gps_location.py");
fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
' "$SOURCE_DIR" "$MANIFEST_FILE"

CURRENT_PYTHON="$INSTALL_DIR/venv/bin/python"
[[ -x "$CURRENT_PYTHON" ]] || CURRENT_PYTHON="$INSTALL_DIR/.venv/bin/python3"
SYSTEM_ID="$(PYTHONPATH="$INSTALL_DIR" "$CURRENT_PYTHON" -c '
from core.config_protection import load_config
print(load_config("/opt/soc-agent/config/company_config.json").get("system_id", ""))
')"
MANIFEST_HASH="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fleetSha256"])' "$MANIFEST_FILE")"
PREVIOUS_PENDING_HASH="$(
  cd "$REPO_ROOT/backend"
  SYSTEM_ID="$SYSTEM_ID" node -e '
require("dotenv").config(); const mongoose = require("mongoose");
(async () => { await mongoose.connect(process.env.MONGO_URI); const system = await mongoose.connection.db.collection("systems").findOne({ _id: new mongoose.Types.ObjectId(process.env.SYSTEM_ID) }, { projection: { agentPendingIntegrityHash: 1 } }); await mongoose.disconnect(); if (!system) throw new Error("installed system was not found"); process.stdout.write(String(system.agentPendingIntegrityHash || "")); })().catch(error => { console.error(error.message); process.exit(1); });
'
)"
(
  cd "$REPO_ROOT/backend"
  SYSTEM_ID="$SYSTEM_ID" MANIFEST_HASH="$MANIFEST_HASH" node -e '
require("dotenv").config(); const mongoose = require("mongoose");
(async () => { await mongoose.connect(process.env.MONGO_URI); const result = await mongoose.connection.db.collection("systems").updateOne({ _id: new mongoose.Types.ObjectId(process.env.SYSTEM_ID) }, { $set: { agentPendingIntegrityHash: process.env.MANIFEST_HASH } }); await mongoose.disconnect(); if (result.matchedCount !== 1) throw new Error("installed system was not found"); })().catch(error => { console.error(error.message); process.exit(1); });
'
)

echo "[3/8] Stopping agent and taking a recoverable backup..."
systemctl stop soc-agent
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
tar --acls --xattrs -C / -czf "$BACKUP_FILE" opt/soc-agent
chmod 600 "$BACKUP_FILE"

rollback() {
  local status=$?
  trap - ERR
  echo "ERROR: GPS update failed; restoring $BACKUP_FILE" >&2
  systemctl stop soc-agent 2>/dev/null || true
  tar -C / -xzf "$BACKUP_FILE" || true
  systemctl restart soc-agent || true
  (
    cd "$REPO_ROOT/backend"
    SYSTEM_ID="$SYSTEM_ID" PREVIOUS_PENDING_HASH="$PREVIOUS_PENDING_HASH" node -e '
require("dotenv").config(); const mongoose = require("mongoose");
(async () => { await mongoose.connect(process.env.MONGO_URI); await mongoose.connection.db.collection("systems").updateOne({ _id: new mongoose.Types.ObjectId(process.env.SYSTEM_ID) }, { $set: { agentPendingIntegrityHash: process.env.PREVIOUS_PENDING_HASH || "" } }); await mongoose.disconnect(); })().catch(error => { console.error("WARNING: could not restore prior pending integrity hash:", error.message); process.exit(1); });
' || true
  )
  exit "$status"
}
trap rollback ERR

echo "[4/8] Installing updated code and matching manifest..."
install -o root -g root -m 0600 "$MANIFEST_FILE" "$INSTALL_DIR/integrity_manifest.json"
SOC_AGENT_REPLACE_CONFIG=false SOC_AGENT_UPDATE_VERSION=false \
  bash "$SOURCE_DIR/update-agent-functions-linux.sh" "$SOURCE_DIR"
chown -R root:root "$INSTALL_DIR"
chmod -R go-rwx "$INSTALL_DIR"

echo "[5/8] Verifying deployed GPS source and package integrity..."
cmp "$SOURCE_DIR/core/gps_location.py" "$INSTALL_DIR/core/gps_location.py"
cmp "$SOURCE_DIR/install-linux-location-provider.sh" "$INSTALL_DIR/install-linux-location-provider.sh"
PYTHON="$INSTALL_DIR/venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="$INSTALL_DIR/.venv/bin/python3"
PYTHONPATH="$INSTALL_DIR" "$PYTHON" -c '
from core.self_protection import collect_security_report
report = collect_security_report("/opt/soc-agent")
print("Integrity:", report["integrityStatus"])
for finding in report.get("findings", []):
    print(" -", finding.get("type"), finding.get("file"), finding.get("detail"))
raise SystemExit(report["integrityStatus"] != "verified")
'

echo "[6/8] Restarting the running agent..."
STARTED_AT="$(date '+%Y-%m-%d %H:%M:%S')"
systemctl restart soc-agent
sleep 5
systemctl is-active --quiet soc-agent

echo "[7/8] Waiting for heartbeat and an active GPS observation..."
RECENT_LOGS=""
for _attempt in $(seq 1 30); do
  RECENT_LOGS="$(journalctl -u soc-agent --since "$STARTED_AT" --no-pager)"
  if printf '%s\n' "$RECENT_LOGS" | grep -Fq 'Runtime config updated from server heartbeat' \
    && printf '%s\n' "$RECENT_LOGS" | grep -Fq 'GPS location collector ready (policy-gated)' \
    && printf '%s\n' "$RECENT_LOGS" | grep -Eq 'GPS observation active:|GPS_LOCATION_TELEMETRY|GEO_GPS_STATUS'; then
    break
  fi
  systemctl is-active --quiet soc-agent
  sleep 5
done
printf '%s\n' "$RECENT_LOGS" | grep -F 'Runtime config updated from server heartbeat'
printf '%s\n' "$RECENT_LOGS" | grep -F 'GPS location collector ready (policy-gated)'
printf '%s\n' "$RECENT_LOGS" | grep -E 'GPS observation active:|GPS_LOCATION_TELEMETRY|GEO_GPS_STATUS'
if printf '%s\n' "$RECENT_LOGS" | grep -Eq 'Encrypted agent payload authentication failed|Batch rejected 400|Agent tamper/analysis activity detected'; then
  echo "ERROR: transport or integrity failure after GPS deployment" >&2
  false
fi

echo "[8/8] GPS update verified (unchanged observations may remain local by design)."
trap - ERR
echo "SUCCESS: AJNAT GPS collector deployed, integrity verified, heartbeat and GPS monitoring active."
echo "Backup: $BACKUP_FILE"
