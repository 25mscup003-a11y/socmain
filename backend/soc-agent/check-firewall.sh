#!/bin/bash
# SOC Agent Firewall Test & Verification Script

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  SOC Agent Firewall Module Status Check                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

AGENT_DIR="/opt/soc-agent"
CONFIG="$AGENT_DIR/config/company_config.json"
LOG_CMD="journalctl -u soc-agent -n 50"

# Check 1: Agent status
echo "═ CHECK 1: Agent Service Status ═"
if systemctl is-active --quiet soc-agent; then
  echo "✅  Agent service is RUNNING"
else
  echo "⚠️   Agent service is NOT RUNNING"
  echo "    Start with: sudo systemctl start soc-agent"
fi
echo ""

# Check 2: Config exists
echo "═ CHECK 2: Configuration ═"
if [ -f "$CONFIG" ]; then
  echo "✅  Config file exists: $CONFIG"
  FIREWALL_ENABLED=$(PYTHONPATH="$AGENT_DIR" python3 -c "from core.config_protection import load_config; print(load_config('$CONFIG').get('firewall_enabled', True))" 2>/dev/null || echo "unknown")
  echo "   Firewall enabled: $FIREWALL_ENABLED"
else
  echo "❌  Config file NOT found: $CONFIG"
fi
echo ""

# Check 3: Firewall module file
echo "═ CHECK 3: Firewall Module File ═"
if [ -f "$AGENT_DIR/core/firewall.py" ]; then
  echo "✅  Firewall module exists"
  FIREWALL_CLASS=$(grep -c "^class FirewallModule:" "$AGENT_DIR/core/firewall.py" 2>/dev/null | tr -d '\n' || echo "0")
  if [ "$FIREWALL_CLASS" -gt 0 ] 2>/dev/null; then
    echo "   ✅ Module class found - READY"
  else
    echo "   ⚠️  Module class not found"
  fi
else
  echo "❌  Firewall module NOT found: $AGENT_DIR/core/firewall.py"
fi
echo ""

# Check 4: Command listener
echo "═ CHECK 4: Command Listener Module ═"
if [ -f "$AGENT_DIR/core/command_listener.py" ]; then
  echo "✅  Command listener module exists"
  CMD_CLASS=$(grep -c "^class CommandListener:" "$AGENT_DIR/core/command_listener.py" 2>/dev/null | tr -d '\n' || echo "0")
  if [ "$CMD_CLASS" -gt 0 ] 2>/dev/null; then
    echo "   ✅ Listener class found - READY"
  else
    echo "   ⚠️  Listener class not found"
  fi
else
  echo "❌  Command listener NOT found"
fi
echo ""

# Check 5: Persisted rules file
echo "═ CHECK 5: Persisted Firewall Rules ═"
RULES_FILE="/etc/soc-agent/firewall_rules.json"
if [ -f "$RULES_FILE" ]; then
  echo "✅  Persisted rules file exists: $RULES_FILE"
  echo "   Content:"
  cat "$RULES_FILE" | python3 -m json.tool 2>/dev/null || cat "$RULES_FILE"
else
  echo "ℹ️   No persisted rules yet (none have been created)"
fi
echo ""

# Check 6: iptables rules (Linux only)
if [ "$(uname -s)" = "Linux" ]; then
  echo "═ CHECK 6: iptables Rules ═"
  RULES_COUNT=$(sudo iptables -L -n 2>/dev/null | grep -c "DROP\|ACCEPT" || echo "0")
  if [ "$RULES_COUNT" -gt 0 ]; then
    echo "✅  Firewall rules found in iptables"
    echo "   Active rules:"
    sudo iptables -L -n 2>/dev/null | grep -E "DROP|ACCEPT" | head -5 || true
  else
    echo "ℹ️   No custom firewall rules (all default)"
  fi
  echo ""
fi

# Check 7: Recent logs
echo "═ CHECK 7: Recent Agent Logs ═"
echo "Last 10 lines involving firewall:"
$LOG_CMD 2>/dev/null | grep -i firewall | tail -10 || echo "  (No firewall logs yet)"
echo ""
echo "Last 10 lines involving command:"
$LOG_CMD 2>/dev/null | grep -i "command" | tail -10 || echo "  (No command logs yet)"
echo ""

# Check 8: Socket.IO connection
echo "═ CHECK 8: Command Listener (Socket.IO) Connection ═"
echo "Checking if command listener is connected:"
$LOG_CMD 2>/dev/null | grep -E "command.*connect|connected.*server" | tail -5 || echo "  (Not found - check if command listener is initialized)"
echo ""

# Summary
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  How to Test Firewall Rules:                             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "1. Open SOC Dashboard → Firewall page"
echo "2. Click 'Create Rule' or 'Block IP'"
echo "3. Enter an IP address (e.g., 192.168.1.100)"
echo "4. Click 'Apply'"
echo ""
echo "5. Check if rule was applied:"
echo "   Linux:   sudo iptables -L -n | grep <IP>"
echo "   macOS:   sudo pfctl -t soc_blocklist -T show"
echo "   Windows: Get-NetFirewallRule -DisplayName 'SOCBlock*'"
echo ""
echo "6. View logs in real-time:"
echo "   Linux/macOS: journalctl -u soc-agent -f"
echo "   All: python3 /opt/soc-agent/agent.py test"
echo ""
echo "7. Verify persistence after reboot:"
echo "   sudo reboot"
echo "   # After reboot:"
echo "   sudo iptables -L -n | grep <IP>"
echo ""
