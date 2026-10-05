#!/bin/bash
# SOC Agent Uninstall Script — Linux / macOS
# Removes service, processes, and firewall rules cleanly

set -e

echo "╔══════════════════════════════════════╗"
echo "║  SOC Agent Uninstaller               ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check root
if [ "$(id -u)" != "0" ]; then
  echo "❌  This script must be run as root: sudo bash uninstall.sh"
  exit 1
fi

# Require uninstall password
PASS_FILE="/etc/soc-agent/uninstall.pass"
hash_password() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf "%s" "$1" | sha256sum | awk '{print $1}'
  else
    printf "%s" "$1" | shasum -a 256 | awk '{print $1}'
  fi
}
if [ ! -f "$PASS_FILE" ]; then
  echo "❌  Uninstall password is not configured."
  echo "    Repair/reinstall SOC Agent first, set a password, then uninstall again."
  echo "    Debian/Kali/Ubuntu: sudo dpkg --install ./soc-agent*.deb"
  exit 1
else
  if [ ! -r /dev/tty ]; then
    echo "❌  Interactive terminal required to verify the uninstall password."
    exit 1
  fi
  read -rsp "Enter uninstall password: " UNINSTALL_PASS </dev/tty; echo ""
  ENTERED_HASH="$(hash_password "$UNINSTALL_PASS")"
  SAVED_HASH="$(cat "$PASS_FILE" 2>/dev/null || true)"
  unset UNINSTALL_PASS
  if [ "$ENTERED_HASH" != "$SAVED_HASH" ]; then
    echo "❌  Incorrect uninstall password."
    exit 1
  fi
  echo "✅  Password matched. Uninstall authorized."
fi

# Confirm
read -p "This will remove SOC Agent service. Continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
  echo "Cancelled."
  exit 0
fi

# ── NOTIFY SERVER BEFORE UNINSTALLING ──
echo ""
echo "🔔 Notifying server about uninstall..."
if [ -f "/opt/soc-agent/config/company_config.json" ]; then
  HTTP_CODE=$(PYTHONPATH="/opt/soc-agent" /opt/soc-agent/venv/bin/python - <<'PY' 2>/dev/null || echo "000"
from core.config import AgentConfig
from core.secure_transport import secure_request
config = AgentConfig()
system_id = str(config.get('system_id') or '')
server_url = str(config.get('server_url') or '').rstrip('/')
if not system_id or not server_url:
    raise SystemExit('000')
payload = {'agent_key': config.get('agent_key', ''), 'reason': 'Agent uninstalled'}
response = secure_request(
    config, 'POST', f'{server_url}/api/agent/system/{system_id}/offline',
    json=payload, timeout=10,
)
print(response.status_code)
PY
  )
  if [ "$HTTP_CODE" = "200" ]; then
    echo "✅  Server notified (system marked as offline)"
  else
    echo "⚠️  Server notification may have failed (HTTP $HTTP_CODE). Continuing uninstall..."
  fi
else
  echo "⚠️  Config file not found at /opt/soc-agent/config/company_config.json. Skipping server notification."
fi

OS=$(uname -s)

if [ "$OS" = "Linux" ]; then
    echo "Step 1: Stopping SOC Agent service..."
    systemctl stop soc-agent 2>/dev/null || true
    systemctl disable soc-agent 2>/dev/null || true
    systemctl stop suricata 2>/dev/null || true
    systemctl disable soc-suricata-nfqueue.service 2>/dev/null || true
    systemctl stop soc-suricata-nfqueue.service 2>/dev/null || true
    nft delete table inet soc_suricata_ips 2>/dev/null || true
    nft delete table inet soc_country_block 2>/dev/null || true
    rm -f /var/lib/soc-agent/country-block.json
    rm -f /etc/systemd/system/soc-agent.service
    rm -f /etc/systemd/system/soc-suricata-nfqueue.service
    rm -f /etc/systemd/system/suricata.service.d/soc-inline-ips.conf
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    echo "✅  Service removed"

    echo ""
    echo "Step 2: Killing any remaining agent processes..."
    pkill -f "python3 /opt/soc-agent/agent.py" 2>/dev/null || true
    pkill -f "python3.*agent.py run" 2>/dev/null || true
    sleep 1
    echo "✅  Processes killed"

    echo ""
    echo "Step 3: Removing firewall rules (from /etc/soc-agent/firewall_rules.json)..."
    # Delete persisted firewall rules file
    rm -f /etc/soc-agent/firewall_rules.json 2>/dev/null || true
    
    # Try to remove any existing iptables rules
    # The specific rules will need to be removed individually based on what was added
    # For now, inform user
    if command -v iptables-save &>/dev/null; then
      echo "  Note: To completely reset firewall rules, run:"
      echo "    sudo iptables -F INPUT"
      echo "    sudo iptables -F OUTPUT"
      echo "    sudo iptables -F FORWARD"
    fi
    echo "✅  Firewall rules info removed (system rules may persist)"

    echo ""
    echo "Step 4: Removing installation directory..."
    read -p "Remove /opt/soc-agent? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
      rm -rf /opt/soc-agent
      rm -rf /etc/soc-agent
      echo "✅  Installation directory removed"
    else
      echo "⚠️   Keeping installation at /opt/soc-agent"
    fi

    echo ""
    echo "📁 Log files preserved at: /var/log/soc-agent/"
    echo "   Remove manually with: sudo rm -rf /var/log/soc-agent/"

elif [ "$OS" = "Darwin" ]; then
    PLIST="/Library/LaunchDaemons/com.soc.agent.plist"
    
    echo "Step 1: Stopping SOC Agent LaunchDaemon..."
    if [ -f "$PLIST" ]; then
        launchctl unload "$PLIST" 2>/dev/null || true
        rm -f "$PLIST"
        echo "✅  LaunchDaemon removed"
    else
        echo "⚠️   LaunchDaemon not found"
    fi

    echo ""
    echo "Step 2: Killing any remaining processes..."
    pkill -f "python3 /opt/soc-agent/agent.py" 2>/dev/null || true
    sleep 1
    echo "✅  Processes killed"

    echo ""
    echo "Step 3: Removing pfctl firewall rules..."
    if command -v pfctl &>/dev/null; then
      pfctl -t soc_blocklist -T flush 2>/dev/null || true
      pfctl -a com.soc.agent/country-block -F all 2>/dev/null || true
    fi
    rm -f /etc/soc-agent/firewall_rules.json 2>/dev/null || true
    rm -f "/Library/Application Support/AJNAT/state/country-block.json"
    echo "✅  pfctl rules flushed"

    echo ""
    echo "Step 4: Removing installation directory..."
    read -p "Remove /opt/soc-agent? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
      rm -rf /opt/soc-agent
      rm -rf /etc/soc-agent
      echo "✅  Installation directory removed"
    else
      echo "⚠️   Keeping installation at /opt/soc-agent"
    fi

    echo ""
    echo "📁 Logs at: /Library/Logs/SOCAgent/"

else
    echo "⚠️  Unsupported OS: $OS"
    echo "   For Windows, run: python agent.py uninstall"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  ✅  Uninstallation Complete         ║"
echo "╚══════════════════════════════════════╝"


echo ""
echo "✅  SOC Agent uninstalled successfully."
echo "   To also remove Python packages: pip3 uninstall -r requirements.txt"
