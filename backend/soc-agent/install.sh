#!/bin/bash
# SOC Agent Debian/Ubuntu Installer
# Company: rru
# System:  1
# Generated: 2026-03-26T08:38:10.444Z

set -e

INSTALL_DIR="/opt/soc-agent"
SERVICE_FILE="/etc/systemd/system/soc-agent.service"
SYSTEM_PYTHON=$(which python3 || which python)
VENV_DIR="$INSTALL_DIR/venv"
PYTHON="$VENV_DIR/bin/python"

echo "═══════════════════════════════════════"
echo "  SOC Agent Installer"
echo "  Company: rru"
echo "  System:  1"
echo "═══════════════════════════════════════"

# Check root
if [ "$(id -u)" != "0" ]; then
  echo "❌  This installer must be run as root: sudo bash install.sh"
  exit 1
fi

# Uninstall password protection
PASS_DIR="/etc/soc-agent"
PASS_FILE="$PASS_DIR/uninstall.pass"
hash_password() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf "%s" "$1" | sha256sum | awk '{print $1}'
  else
    printf "%s" "$1" | shasum -a 256 | awk '{print $1}'
  fi
}
mkdir -p "$PASS_DIR"
chmod 700 "$PASS_DIR" 2>/dev/null || true
if [ -f "$PASS_FILE" ]; then
  chmod 600 "$PASS_FILE" 2>/dev/null || true
  echo "✅  Existing uninstall password kept"
else
  if [ ! -r /dev/tty ]; then
    echo "❌  Interactive terminal required to set the uninstall password."
    echo "    Run from Terminal: sudo bash install.sh"
    exit 1
  fi
  echo ""
  echo "🔐  Set uninstall password (required to remove SOC Agent later)"
  while true; do
    read -rsp "Enter uninstall password: " PASS1 </dev/tty; echo ""
    read -rsp "Confirm uninstall password: " PASS2 </dev/tty; echo ""
    if [ -z "$PASS1" ]; then
      echo "Password cannot be empty."
    elif [ "$PASS1" != "$PASS2" ]; then
      echo "Passwords do not match."
    else
      hash_password "$PASS1" > "$PASS_FILE"
      chmod 600 "$PASS_FILE"
      unset PASS1 PASS2
      echo "✅  Uninstall password saved"
      break
    fi
  done
fi

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "Installing Python 3..."
  apt-get update -qq && apt-get install -y python3 python3-pip python3-venv
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "Installing python3-venv..."
  apt-get update -qq && apt-get install -y python3-venv
fi

# Install to /opt/soc-agent
echo "📂  Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
EXISTING_CONFIG=""
if [ -f "$INSTALL_DIR/config/company_config.json" ]; then
  EXISTING_CONFIG="$(mktemp)"
  cp "$INSTALL_DIR/config/company_config.json" "$EXISTING_CONFIG"
fi
cp -r . "$INSTALL_DIR/"
if [ -n "$EXISTING_CONFIG" ] && [ -f "$EXISTING_CONFIG" ]; then
  mkdir -p "$INSTALL_DIR/config"
  cp "$EXISTING_CONFIG" "$INSTALL_DIR/config/company_config.json"
  rm -f "$EXISTING_CONFIG"
  echo "✅  Existing installed config preserved"
fi
chmod +x "$INSTALL_DIR/agent.py"
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true  # Make all helper scripts executable (check-firewall.sh, uninstall.sh, etc)
# Root-only installation: users cannot list, read, edit, or execute agent files.
chown -R root:root "$INSTALL_DIR"
find "$INSTALL_DIR" -type d -exec chmod 700 {} +
find "$INSTALL_DIR" -type f -exec chmod 600 {} +
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true

if [ -x "$INSTALL_DIR/install-linux-advanced-telemetry.sh" ]; then
  "$INSTALL_DIR/install-linux-advanced-telemetry.sh" || true
fi
if [ -x "$INSTALL_DIR/install-linux-location-provider.sh" ]; then
  "$INSTALL_DIR/install-linux-location-provider.sh"
fi

# Install Python dependencies
echo "📦  Installing Python dependencies in isolated venv..."
"$SYSTEM_PYTHON" -m venv "$VENV_DIR"
"$PYTHON" -m pip install -q --upgrade pip setuptools wheel
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
  "$PYTHON" -m pip install -q -r "$INSTALL_DIR/requirements.txt" || {
    echo "⚠️  Full requirements install failed; installing critical dependencies individually..."
    "$PYTHON" -m pip install -q requests "urllib3<2" psutil watchdog cryptography pyudev "python-socketio[client]" websocket-client pynput || true
    "$PYTHON" -m pip install -q yara-python || echo "⚠️  yara-python install failed (optional — YARA scanning disabled)"
  }
else
  "$PYTHON" -m pip install -q requests "urllib3<2" psutil watchdog cryptography pyudev "python-socketio[client]" websocket-client pynput || true
  "$PYTHON" -m pip install -q yara-python || echo "⚠️  yara-python install failed (optional — YARA scanning disabled)"
fi

# Raise Linux inotify watch limit so real-time file monitoring can watch broad trees.
if [ "$(uname -s)" = "Linux" ]; then
  SYSCTL_FILE="/etc/sysctl.d/99-soc-agent-inotify.conf"
  echo "fs.inotify.max_user_watches=1048576" > "$SYSCTL_FILE"
  echo "fs.inotify.max_user_instances=1024" >> "$SYSCTL_FILE"
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
fi

# Keep the downloaded/bundled config. The dashboard package already includes
# config/company_config.json with the correct company, system, and agent key.
mkdir -p "$INSTALL_DIR/config"
if [ -f "$INSTALL_DIR/config/company_config.json" ]; then
  chown root:root "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
  chmod 600 "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
  python3 - "$INSTALL_DIR/config/company_config.json" <<'PY' || true
import json, sys
path = sys.argv[1]
try:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    data.setdefault('ids_ips_capabilities_enabled', True)
    data.setdefault('network_ids_sensors_enabled', True)
    data.setdefault('suricata_eve_path', '/var/log/suricata/eve.json')
    data.setdefault('zeek_log_paths', [
        f'{root}/{name}.log'
        for root in ('/opt/zeek/logs/current', '/var/log/zeek/current')
        for name in ('conn', 'dns', 'http', 'ssl', 'files', 'notice', 'weird', 'x509')
    ])
    data.setdefault('ids_sensor_mirror_to_agent_alerts', False)
    data.setdefault('ids_packet_sensor_required', [
        'SYN Scan', 'FIN Scan', 'NULL Scan', 'XMAS Scan', 'ACK Scan',
        'ICMP Flood', 'Network Packets',
    ])
    data.setdefault('ids_ips_attack_types', [
        'SQL Injection', 'Blind SQL Injection', 'XSS', 'CSRF',
        'Command Injection', 'Remote Code Execution (RCE)', 'File Upload Attack',
        'Path Traversal', 'Directory Traversal', 'Local File Inclusion (LFI)',
        'Remote File Inclusion (RFI)', 'XXE Attack', 'SSRF', 'SSTI',
        'Port Scan', 'SYN Scan', 'FIN Scan', 'NULL Scan', 'XMAS Scan', 'ACK Scan',
        'UDP Scan', 'Ping Sweep', 'Host Discovery', 'Service Enumeration',
        'Banner Grabbing', 'Brute Force', 'Password Spraying',
        'Credential Stuffing', 'Login Flood', 'Multiple Failed Login Attempts',
        'Privilege Escalation Attempts', 'Ransomware', 'Botnet Traffic',
        'Malicious IP Detection', 'IOC Matching', 'CVE Exploit Detection',
        'Known Exploit Detection', 'Signature Match', 'Zero-Day Behavior Detection',
    ])
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
except Exception:
    pass
PY
  echo "✅  Config installed: $INSTALL_DIR/config/company_config.json"
else
  echo "⚠️  Config file missing: $INSTALL_DIR/config/company_config.json"
  echo "    Download the agent from SOC Dashboard so company_config.json is auto-filled."
fi

EXPECTED_ROLE=$(python3 -c "import json; d=json.load(open('$INSTALL_DIR/config/company_config.json')); print((d.get('expected_device_role') or d.get('agent_type') or 'system').lower())" 2>/dev/null || echo 'system')
ACTUAL_ROLE="system"
if [ "$(uname -s)" = "Linux" ]; then
  CHASSIS=$(cat /sys/class/dmi/id/chassis_type 2>/dev/null || true)
  TARGET=$(systemctl get-default 2>/dev/null || true)
  if echo " 11 12 17 23 28 29 30 31 32 " | grep -q " $CHASSIS "; then
    ACTUAL_ROLE="server"
  elif [ "$TARGET" = "multi-user.target" ] && ! command -v gnome-shell >/dev/null 2>&1 && ! command -v startplasma-x11 >/dev/null 2>&1 && ! command -v startxfce4 >/dev/null 2>&1; then
    ACTUAL_ROLE="server"
  fi
fi
if [ "$EXPECTED_ROLE" = "server" ] || [ "$EXPECTED_ROLE" = "system" ]; then
  if [ "$EXPECTED_ROLE" != "$ACTUAL_ROLE" ]; then
    echo "❌  Agent type mismatch: this package is for $EXPECTED_ROLE, but this machine looks like $ACTUAL_ROLE."
    echo "    Download the correct agent from SOC Dashboard."
    exit 1
  fi
fi

# Auto-install/enroll bundled Velociraptor client when present.
install_velociraptor_client() {
  if command -v velociraptor_client >/dev/null 2>&1 || command -v velociraptor >/dev/null 2>&1; then
    echo "✅  Velociraptor client already installed"
    systemctl enable velociraptor_client >/dev/null 2>&1 || true
    systemctl restart velociraptor_client >/dev/null 2>&1 || true
    systemctl enable velociraptor >/dev/null 2>&1 || true
    systemctl restart velociraptor >/dev/null 2>&1 || true
    return 0
  fi

  BUNDLE_DIR="$INSTALL_DIR/velociraptor"
  if command -v dpkg >/dev/null 2>&1 && ls "$BUNDLE_DIR"/*.deb >/dev/null 2>&1; then
    echo "📦  Installing bundled Velociraptor client (.deb)..."
    dpkg -i "$BUNDLE_DIR"/*.deb >/dev/null 2>&1 || {
      apt-get update -qq >/dev/null 2>&1 || true
      apt-get install -f -y >/dev/null 2>&1 || true
      dpkg -i "$BUNDLE_DIR"/*.deb >/dev/null 2>&1 || true
    }
  elif command -v rpm >/dev/null 2>&1 && ls "$BUNDLE_DIR"/*.rpm >/dev/null 2>&1; then
    echo "📦  Installing bundled Velociraptor client (.rpm)..."
    rpm -Uvh --replacepkgs "$BUNDLE_DIR"/*.rpm >/dev/null 2>&1 || true
  elif ls "$BUNDLE_DIR"/velociraptor_client_* >/dev/null 2>&1; then
    echo "📦  Installing bundled Velociraptor client binary..."
    install -m 755 "$(ls "$BUNDLE_DIR"/velociraptor_client_* | head -n1)" /usr/local/bin/velociraptor_client
  else
    echo "ℹ️  Velociraptor client bundle not found; skipping auto-install"
    return 0
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable velociraptor_client >/dev/null 2>&1 || true
  systemctl restart velociraptor_client >/dev/null 2>&1 || true
  systemctl enable velociraptor >/dev/null 2>&1 || true
  systemctl restart velociraptor >/dev/null 2>&1 || true
}
install_velociraptor_client || true

# Install and configure the bundled Suricata inline IPS before the agent starts.
# Zeek remains an additional passive sensor. Set
# SOC_INSTALL_NETWORK_SENSORS=false to opt out on endpoints that must not sniff
# network traffic.
install_network_sensors() {
  if [ "${SOC_INSTALL_NETWORK_SENSORS:-true}" = "false" ]; then
    echo "ℹ️  Suricata inline IPS/Zeek auto-install explicitly disabled"
    return 0
  fi

  IDS_INSTALLER="$INSTALL_DIR/install-ids-sensors.sh"
  if [ ! -f "$IDS_INSTALLER" ]; then
    echo "❌  Suricata inline IPS installer missing"
    return 1
  fi

  echo "🔍  Installing and configuring Suricata NFQUEUE inline IPS and Zeek..."
  chmod +x "$IDS_INSTALLER" 2>/dev/null || true
  SOC_SURICATA_MODE=ips bash "$IDS_INSTALLER"
  echo "✅  Suricata inline IPS and Zeek sensor setup complete"
}
install_network_sensors

# Create systemd service
# IMPORTANT: use unquoted heredoc so $PYTHON and $INSTALL_DIR expand correctly
cat > "$SERVICE_FILE" << SERVICE
[Unit]
Description=SOC Security Agent — rru/1
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/agent.py run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable soc-agent
systemctl restart soc-agent

echo ""
echo "✅  SOC Agent installed and started!"
echo "    Status:  systemctl status soc-agent"
echo "    Logs:    journalctl -u soc-agent -f"
echo "    Test:    python3 $INSTALL_DIR/agent.py test"
