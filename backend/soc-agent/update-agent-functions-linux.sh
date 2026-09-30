#!/usr/bin/env bash
# Update only AJNAT monitoring functions on an already-enrolled Linux endpoint.
# The enrollment config and agent_version remain unchanged.
# Usage: sudo bash update-agent-functions-linux.sh [new-soc-agent-directory]

set -Eeuo pipefail

INSTALL_DIR="/opt/soc-agent"
CONFIG_FILE="$INSTALL_DIR/config/company_config.json"
SOURCE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
UPDATER="$SOURCE_DIR/update-installed-agent.sh"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root: sudo bash $0 [new-soc-agent-directory]" >&2
  exit 1
fi
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "ERROR: existing AJNAT enrollment config not found: $CONFIG_FILE" >&2
  exit 1
fi
if [[ ! -f "$UPDATER" ]]; then
  echo "ERROR: function updater not found in source bundle: $UPDATER" >&2
  exit 1
fi

CONFIG_SHA_BEFORE="$(sha256sum "$CONFIG_FILE" | awk '{print $1}')"
IDENTITY_BEFORE="$(PYTHONPATH="$SOURCE_DIR" python3 -c 'import sys; from core.config_protection import load_config; c=load_config(sys.argv[1]); print("{}|{}".format(c.get("system_id", "-"), c.get("agent_version", "-")))' "$CONFIG_FILE")"

# The underlying updater preserves config/state when this value is false.
export SOC_AGENT_REPLACE_CONFIG=false
export SOC_AGENT_UPDATE_VERSION=false
bash "$UPDATER" "$SOURCE_DIR"

CONFIG_SHA_AFTER="$(sha256sum "$CONFIG_FILE" | awk '{print $1}')"
if [[ "$CONFIG_SHA_AFTER" != "$CONFIG_SHA_BEFORE" ]]; then
  echo "ERROR: enrollment config changed unexpectedly during the function update." >&2
  exit 1
fi

echo "SUCCESS: AJNAT monitoring functions updated; release version was not changed."
echo "Identity/version: $IDENTITY_BEFORE"
