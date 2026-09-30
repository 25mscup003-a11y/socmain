#!/bin/bash
# Required Suricata inline IPS and optional Zeek sensor installer for SOC Agent.
# Linux packets are queued through nftables/NFQUEUE so Suricata drop/reject
# rules enforce verdicts before traffic reaches the protected endpoint.

set -e

# Resolve companion files before the source builder changes directories.  Also
# include the source-install prefix in PATH because sudo commonly replaces the
# caller's PATH and would otherwise miss an already installed /opt/zeek binary.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ZEEK_PREFIX="${SOC_ZEEK_PREFIX:-/opt/zeek}"
export PATH="$ZEEK_PREFIX/bin:$PATH"

echo "SOC Agent IDS Sensor Installer"
echo "Installs Suricata and Zeek when available from OS repositories."
echo "If the OS Zeek package is incompatible, Zeek can be built from source."
echo ""

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root: sudo bash install-ids-sensors.sh"
  exit 1
fi

detect_ids_interfaces() {
  if [ -n "${SOC_IDS_INTERFACES:-}" ]; then
    echo "$SOC_IDS_INTERFACES" | tr ',' ' '
    return
  fi
  if [ -n "${SOC_IDS_INTERFACE:-}" ]; then
    echo "$SOC_IDS_INTERFACE"
    return
  fi

  ip -br link 2>/dev/null | awk '
    $1 !~ /^(lo|docker|br-|veth|virbr|tunl|sit|ip6tnl)/ &&
    $2 ~ /^(UP|UNKNOWN)$/ &&
    $0 ~ /LOWER_UP/ {
      print $1
    }
  '
}

IFACES="$(detect_ids_interfaces)"
if [ -z "$IFACES" ]; then
  IFACES="$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')"
fi
if [ -z "$IFACES" ]; then
  IFACES="eth0"
fi
IFACE="$(echo "$IFACES" | awk '{print $1}')"
ZEEK_SKIPPED_INCOMPATIBLE=0
ZEEK_SOURCE_ATTEMPTED=0

apt_install_if_available() {
  for pkg in "$@"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" || true
    fi
  done
}

install_zeek_from_source() {
  if command -v zeek >/dev/null 2>&1; then
    return 0
  fi

  # Kali rolling can expose an old Zeek package with impossible libc deps.
  # Source install avoids downgrading libc and keeps Zeek under /opt/zeek.
  local version="${SOC_ZEEK_SOURCE_VERSION:-7.0.0}"
  local prefix="${SOC_ZEEK_PREFIX:-/opt/zeek}"
  local workdir="${SOC_ZEEK_BUILD_DIR:-/usr/local/src/soc-zeek-build}"
  local url="${SOC_ZEEK_SOURCE_URL:-https://download.zeek.org/zeek-${version}.tar.gz}"
  ZEEK_SOURCE_ATTEMPTED=1

  echo "INFO: Installing Zeek from source ${version} into ${prefix}"
  echo "      This can take 20-40 minutes on small systems."

  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential cmake make gcc g++ flex bison swig curl ca-certificates \
    libpcap-dev libssl-dev python3-dev zlib1g-dev libmaxminddb-dev libsqlite3-dev \
    libzstd-dev libbroker-dev libkrb5-dev libgeoip-dev || true

  # Zeek's binpac build checks for BIND/ISC development headers on some
  # Debian/Kali releases. Package names differ by OS release, so install
  # whichever exists instead of failing on missing packages.
  apt_install_if_available bind9-dev libbind-dev libbind-export-dev libisc-dev libdns-dev

  mkdir -p "$workdir"
  cd "$workdir"
  rm -rf "zeek-${version}" "zeek-${version}.tar.gz"

  if ! curl -fL "$url" -o "zeek-${version}.tar.gz"; then
    echo "WARN: Could not download Zeek source from $url"
    echo "      Try: SOC_ZEEK_SOURCE_VERSION=7.0.0 sudo -E bash install-ids-sensors.sh"
    return 1
  fi

  tar -xzf "zeek-${version}.tar.gz"
  cd "zeek-${version}"

  # Zeek 7.0 bundles an older paraglob release which relied on transitive
  # stdint includes. GCC 15 no longer exposes uint8_t/uint64_t that way.
  # Patch both public headers so Kali/Debian rolling builds remain portable.
  for paraglob_header in \
    auxil/paraglob/include/paraglob/serializer.h \
    auxil/paraglob/include/paraglob/paraglob.h; do
    if [[ -f "$paraglob_header" ]] && ! grep -q '^#include <cstdint>' "$paraglob_header"; then
      sed -i '/^#define PARAGLOB.*_H$/a #include <cstdint>' "$paraglob_header"
    fi
  done

  # Zeek 7's BIND probe uses an unprototyped function pointer. GCC 15/C23
  # rejects that probe even though libresolv and its symbols are present.
  # Keep the link check, but call res_mkquery with its declared signature.
  while IFS= read -r bind_probe; do
    sed -i 's/int (\*p)() = res_mkquery;/return res_mkquery(0, 0, 0, 0, 0, 0, 0, 0, 0);/' "$bind_probe"
  done < <(find . -path '*/cmake/FindBIND.cmake' -type f)

  # Current Kali Node/V8 headers require C++20 and are incompatible with the
  # Zeek 7.0 zeekjs plugin. JavaScript is optional and not used by IDS logs.
  local configure_args=(--prefix="$prefix" --disable-javascript)
  if ! ./configure "${configure_args[@]}"; then
    echo "WARN: Zeek configure failed. Cleaning build cache and retrying once..."
    make distclean >/dev/null 2>&1 || true
    rm -rf build CMakeCache.txt CMakeFiles
    if ! ./configure "${configure_args[@]}"; then
      echo "ERROR: Zeek configure failed after retry."
      return 1
    fi
  fi
  # Avoid exhausting RAM on endpoints with many CPUs. Override when desired.
  local build_jobs="${SOC_ZEEK_BUILD_JOBS:-2}"
  if ! [[ "$build_jobs" =~ ^[1-9][0-9]*$ ]]; then
    build_jobs=2
  fi
  if ! make -j"$build_jobs"; then
    echo "ERROR: Zeek compilation failed."
    return 1
  fi
  if ! make install; then
    echo "ERROR: Zeek installation failed."
    return 1
  fi

  if [ ! -x "$prefix/bin/zeek" ] || [ ! -x "$prefix/bin/zeekctl" ]; then
    echo "ERROR: Zeek build finished without the expected binaries in $prefix/bin."
    return 1
  fi

  ln -sf "$prefix/bin/zeek" /usr/local/bin/zeek
  ln -sf "$prefix/bin/zeekctl" /usr/local/bin/zeekctl

  mkdir -p "$prefix/logs" /var/log/zeek
  if [ -f "$prefix/etc/node.cfg" ]; then
    sed -i "s/^interface=.*/interface=$IFACE/" "$prefix/etc/node.cfg" 2>/dev/null || true
  fi

  cat >/etc/systemd/system/zeek.service <<EOF
[Unit]
Description=Zeek Network Security Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$prefix/bin/zeekctl deploy
ExecStop=$prefix/bin/zeekctl stop
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable zeek >/dev/null 2>&1 || true
  systemctl restart zeek >/dev/null 2>&1 || true
  echo "OK: Zeek source install complete on interface $IFACE"
}

install_debian() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y suricata || true

  # Some rolling Kali/Debian repos expose an old Zeek build that depends on
  # libc6 < 2.38. Never downgrade libc for Zeek; Suricata is the primary IDS.
  if apt-cache show zeek 2>/dev/null | grep -q 'Depends:.*libc6 (<< 2.38)'; then
    ZEEK_SKIPPED_INCOMPATIBLE=1
    echo "WARN: Zeek repo package is incompatible with this libc."
    if [ "${SOC_INSTALL_ZEEK_FROM_SOURCE:-auto}" != "false" ]; then
      install_zeek_from_source || true
    else
      echo "OK: Zeek source install disabled by SOC_INSTALL_ZEEK_FROM_SOURCE=false."
      echo "    Suricata remains the primary packet IDS sensor."
    fi
  else
    DEBIAN_FRONTEND=noninteractive apt-get install -y zeek || install_zeek_from_source || true
  fi
}

install_rhel() {
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y epel-release || true
    dnf install -y suricata zeek || true
  else
    yum install -y epel-release || true
    yum install -y suricata zeek || true
  fi
}

configure_suricata_interface() {
  local yaml="/etc/suricata/suricata.yaml"

  if [ -f /etc/default/suricata ]; then
    sed -i "s/^LISTENMODE=.*/LISTENMODE=af-packet/" /etc/default/suricata 2>/dev/null || true
    sed -i "s/^IFACE=.*/IFACE=$IFACE/" /etc/default/suricata 2>/dev/null || true
  fi

  if [ -f "$yaml" ]; then
    cp "$yaml" "${yaml}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    awk -v ifaces="$IFACES" '
      BEGIN { split(ifaces, iface_arr, /[[:space:]]+/); in_af = 0; inserted = 0 }
      /^af-packet:/ {
        print
        for (i in iface_arr) {
          iface = iface_arr[i]
          if (iface == "") continue
          print "  - interface: " iface
          print "    cluster-id: " (90 + i)
          print "    cluster-type: cluster_flow"
          print "    defrag: yes"
          print "    use-mmap: yes"
          print "    tpacket-v3: yes"
        }
        in_af = 1
        inserted = 1
        next
      }
      in_af && /^[^[:space:]]/ && $0 !~ /^af-packet:/ { in_af = 0 }
      in_af { next }
      { print }
    ' "$yaml" > "${yaml}.tmp" && mv "${yaml}.tmp" "$yaml"
    echo "OK: Suricata af-packet interfaces set to: $IFACES"
  fi
}

# Enable Suricata as an inline IPS by default. NFQUEUE
# receives packets from nftables and Suricata returns the accept/drop verdict;
# af-packet by itself is detection-only and cannot prevent traffic.
configure_suricata_ips() {
  local yaml="/etc/suricata/suricata.yaml"
  local queue="${SOC_SURICATA_NFQUEUE:-0}"
  # Protect every active physical NIC so wired and wireless connections are
  # covered together. Explicit interface settings remain available for a
  # gateway that intentionally protects a smaller set of interfaces.
  local configured_ifaces
  local -a ips_ifaces=()
  local iface
  configured_ifaces="${SOC_SURICATA_IPS_INTERFACES:-${SOC_SURICATA_IPS_INTERFACE:-$IFACES}}"
  configured_ifaces="$(echo "$configured_ifaces" | tr ',' ' ')"
  if [ -z "$configured_ifaces" ]; then
    configured_ifaces="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
  fi
  for iface in $configured_ifaces; do
    if [[ ! "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
      echo "ERROR: invalid IPS interface name '$iface'"
      return 1
    elif ip link show "$iface" >/dev/null 2>&1; then
      ips_ifaces+=("$iface")
    else
      echo "WARN: IPS interface '$iface' does not exist; skipping it"
    fi
  done
  local override_dir="/etc/systemd/system/suricata.service.d"

  if [ "${SOC_SURICATA_MODE:-ips}" != "ips" ]; then
    return 0
  fi
  if ! command -v nft >/dev/null 2>&1; then
    echo "ERROR: SOC_SURICATA_MODE=ips requires nftables (nft command not found)"
    return 1
  fi
  if ! command -v suricata >/dev/null 2>&1; then
    echo "ERROR: SOC_SURICATA_MODE=ips requires Suricata"
    return 1
  fi
  if ! [[ "$queue" =~ ^[0-9]+$ ]]; then
    echo "ERROR: SOC_SURICATA_NFQUEUE must be a numeric queue number"
    return 1
  fi
  if [ "${#ips_ifaces[@]}" -eq 0 ]; then
    echo "ERROR: could not find an active interface for inline IPS"
    return 1
  fi

  # Keep a restore point before replacing the SOC-managed queue table.
  mkdir -p /etc/soc-agent
  nft list ruleset > /etc/soc-agent/nftables-before-suricata-ips.rules
  local queue_script="/etc/soc-agent/configure-suricata-nfqueue.sh"
  cat > "$queue_script" <<EOF
#!/bin/bash
set -e
QUEUE=$queue
nft list table inet soc_suricata_ips >/dev/null 2>&1 && nft delete table inet soc_suricata_ips || true
nft add table inet soc_suricata_ips
nft add chain inet soc_suricata_ips input '{ type filter hook input priority filter; policy accept; }'
nft add chain inet soc_suricata_ips output '{ type filter hook output priority filter; policy accept; }'
EOF
  for iface in "${ips_ifaces[@]}"; do
    printf 'nft add rule inet soc_suricata_ips input iifname "%s" queue num "$QUEUE" bypass\n' "$iface" >> "$queue_script"
    printf 'nft add rule inet soc_suricata_ips output oifname "%s" queue num "$QUEUE" bypass\n' "$iface" >> "$queue_script"
  done
  chmod 700 "$queue_script"

  cat > /etc/systemd/system/soc-suricata-nfqueue.service <<EOF
[Unit]
Description=AJNAT Suricata NFQUEUE rules
Wants=network-online.target
After=network-online.target
Before=suricata.service

[Service]
Type=oneshot
ExecStart=$queue_script
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  mkdir -p "$override_dir"
  cat > "$override_dir/soc-inline-ips.conf" <<EOF
[Unit]
Requires=soc-suricata-nfqueue.service
After=soc-suricata-nfqueue.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q $queue -c $yaml --pidfile /var/run/suricata/suricata.pid
EOF

  # Suricata's NFQUEUE CLI flag is `-q`, not `--nfq` (including v8).
  suricata -T -q "$queue" -c "$yaml"
  systemctl daemon-reload
  systemctl enable soc-suricata-nfqueue.service
  systemctl restart soc-suricata-nfqueue.service
  systemctl enable suricata
  systemctl restart suricata
  systemctl is-active --quiet suricata
  systemctl show suricata -p ExecStart --value | grep -Eq -- '(^|[[:space:]])-q([[:space:]]|$)'
  nft list table inet soc_suricata_ips >/dev/null
  update_agent_inline_config
  echo "OK: Suricata inline IPS enabled (NFQUEUE=$queue, interfaces=${ips_ifaces[*]})"
}

update_agent_inline_config() {
  local config_path="${SOC_AGENT_CONFIG:-$SCRIPT_DIR/config/company_config.json}"
  local python_bin
  python_bin="$(command -v python3 || command -v python || true)"
  if [ -z "$python_bin" ] || [ ! -f "$config_path" ]; then
    echo "WARN: Agent config not found; inline status will be reported after config is available"
    return 0
  fi
  PYTHONPATH="$SCRIPT_DIR" "$python_bin" - "$config_path" <<'PY'
import sys
from core.config_protection import load_config, save_config

path = sys.argv[1]
config = load_config(path)
config.update({
    'packet_sensor_provider': 'suricata-nfqueue',
    'packet_ids_mode': 'suricata-nfqueue-inline',
    'ips_enforcement_mode': 'suricata-inline-nfqueue+native-firewall',
    'inline_packet_verdict': True,
    'suricata_config': '/etc/suricata/suricata.yaml',
    'suricata_soc_rules': '/etc/suricata/rules/soc-managed.rules',
    'suricata_executable': '/usr/bin/suricata',
    'waf_enabled': True,
    'waf_direct_block_enabled': True,
    'waf_direct_block_threshold': 'medium',
})
save_config(path, config)
PY
}

if [ "${1:-}" = "--inline-ips" ]; then
  if ! command -v suricata >/dev/null 2>&1; then
    echo "ERROR: Suricata is not installed"
    exit 1
  fi
  export SOC_SURICATA_MODE=ips
  configure_suricata_ips
  exit 0
fi


configure_zeek_monitoring() {
  local prefix="${SOC_ZEEK_PREFIX:-/opt/zeek}"
  local node_cfg=""
  for candidate in "$prefix/etc/node.cfg" /usr/local/zeek/etc/node.cfg /etc/zeek/node.cfg /opt/zeek/etc/node.cfg; do
    if [ -f "$candidate" ]; then
      node_cfg="$candidate"
      break
    fi
  done

  mkdir -p "$prefix/logs" /var/log/zeek

  # ZeekControl owns logs/current and creates it as a symlink when Zeek starts.
  # Clean up the empty placeholder directory made by older installer versions,
  # but never remove a directory containing real log data.
  if [ -d "$prefix/logs/current" ] && [ ! -L "$prefix/logs/current" ]; then
    find "$prefix/logs/current" -maxdepth 1 -type f \
      \( -name conn.log -o -name notice.log \) -empty -delete
    rmdir "$prefix/logs/current" 2>/dev/null || true
  fi

  if [ -n "$node_cfg" ]; then
    sed -i "s/^interface=.*/interface=$IFACE/" "$node_cfg" 2>/dev/null || true
  fi

  local local_zeek=""
  for candidate in "$prefix/share/zeek/site/local.zeek" /usr/local/zeek/share/zeek/site/local.zeek /opt/zeek/share/zeek/site/local.zeek; do
    if [ -f "$candidate" ]; then
      local_zeek="$candidate"
      break
    fi
  done
  if [ -n "$local_zeek" ]; then
    local zeek_share="${local_zeek%%/site/local.zeek}"
    local policy_load policy_file
    for policy_load in \
      policy/protocols/conn/known-hosts \
      policy/protocols/conn/known-services \
      policy/misc/scan; do
      policy_file="$zeek_share/$policy_load.zeek"
      if [ -f "$policy_file" ] || [ -f "$zeek_share/$policy_load/__load__.zeek" ]; then
        grep -Fqx "@load $policy_load" "$local_zeek" 2>/dev/null || echo "@load $policy_load" >> "$local_zeek"
      else
        # Remove stale lines previously added by this installer when a policy
        # is unavailable in the installed Zeek release.
        sed -i "\\|^@load $policy_load$|d" "$local_zeek"
      fi
    done
  fi

  # Older agents generated Python-style boolean literals, which Zeek rejects.
  # Repair only generated SOC boolean declarations, leaving user scripts alone.
  local managed_zeek="$(dirname "${local_zeek:-$prefix/share/zeek/site/local.zeek}")/soc-managed.zeek"
  if [ -f "$managed_zeek" ]; then
    sed -Ei '/^const (dns_tunnel|c2|beacon|exfil|tls|file)_enabled = / { s/ = true([[:space:]]*&redef;)/ = T\1/; s/ = false([[:space:]]*&redef;)/ = F\1/; }' "$managed_zeek"
    grep -q '^@load policy/protocols/ssl/validate-certs$' "$managed_zeek" || \
      sed -i '/^@load base\/frameworks\/notice$/a @load policy/protocols/ssl/validate-certs' "$managed_zeek"
    for required_load in \
      base/frameworks/files base/protocols/conn base/protocols/dns base/protocols/ssl; do
      grep -q "^@load $required_load$" "$managed_zeek" || \
        sed -i "/^@load base\\/frameworks\\/notice$/a @load $required_load" "$managed_zeek"
    done
    sed -i 's/rec\$mime_type in { "application\/x-dosexec", "application\/x-executable" }/(rec\$mime_type == "application\/x-dosexec" || rec\$mime_type == "application\/x-executable")/' "$managed_zeek"
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable zeek >/dev/null 2>&1 || true
  systemctl restart zeek >/dev/null 2>&1 || zeekctl deploy >/dev/null 2>&1 || true
  echo "OK: Zeek monitoring configured on interface $IFACE"
}

if command -v apt-get >/dev/null 2>&1; then
  install_debian
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  install_rhel
else
  echo "WARN: unsupported package manager. Install Suricata/Zeek manually."
fi

mkdir -p /var/log/suricata /var/log/zeek/current

if command -v suricata >/dev/null 2>&1; then
  configure_suricata_interface
  configure_suricata_ips
  # Install/update the community ruleset for broad CVE, malware, botnet and
  # protocol signature coverage. Failure is non-fatal so offline installs keep
  # the bundled AJNAT managed rules.
  if command -v suricata-update >/dev/null 2>&1; then
    suricata-update || echo "WARN: Suricata community rule update failed; bundled AJNAT rules remain active"
    cat >/etc/systemd/system/soc-suricata-rules-update.service <<'EOF'
[Unit]
Description=Update and validate Suricata threat rules
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/suricata-update
ExecStart=/usr/bin/suricata -T -c /etc/suricata/suricata.yaml
ExecStartPost=/bin/systemctl reload suricata
EOF
    cat >/etc/systemd/system/soc-suricata-rules-update.timer <<'EOF'
[Unit]
Description=Daily Suricata threat-rule update

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now soc-suricata-rules-update.timer >/dev/null 2>&1 || true
  fi
  suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1 || echo "WARN: Suricata config test failed; check /etc/suricata/suricata.yaml"
  systemctl enable suricata >/dev/null 2>&1 || true
  systemctl restart suricata >/dev/null 2>&1 || true
  echo "OK: Suricata enabled on interfaces: $IFACES"
else
  if [ "${SOC_SURICATA_MODE:-ips}" = "ips" ]; then
    echo "ERROR: Suricata installation failed; inline IPS is required"
    exit 1
  fi
  echo "WARN: Suricata not installed"
fi

if command -v zeek >/dev/null 2>&1; then
  configure_zeek_monitoring
  systemctl enable zeek >/dev/null 2>&1 || true
  systemctl restart zeek >/dev/null 2>&1 || true
  echo "OK: Zeek installed/enabled where supported"
elif [ "$ZEEK_SKIPPED_INCOMPATIBLE" = "1" ]; then
  if [ "$ZEEK_SOURCE_ATTEMPTED" = "1" ]; then
    echo "WARN: Zeek source install did not complete. Collector will skip Zeek logs."
  else
    echo "OK: Zeek not installed because repository package is incompatible. Collector will skip Zeek logs."
  fi
else
  echo "WARN: Zeek not installed"
fi

# Re-detect interfaces after boot, cable/Wi-Fi changes, and VPN transitions.
# Suricata follows all active physical interfaces; standalone Zeek follows the
# primary/default-route interface because one standalone node captures one NIC.
install -m 0755 "$SCRIPT_DIR/sync-ids-interfaces.sh" /usr/local/sbin/soc-ids-interface-sync
cat >/etc/systemd/system/soc-ids-interface-sync.service <<'EOF'
[Unit]
Description=Synchronize IDS sensors with active network interfaces
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/soc-ids-interface-sync
EOF

cat >/etc/systemd/system/soc-ids-interface-sync.timer <<'EOF'
[Unit]
Description=Periodically detect active IDS network interfaces

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now soc-ids-interface-sync.timer >/dev/null 2>&1 || true
systemctl start soc-ids-interface-sync.service >/dev/null 2>&1 || true


echo ""
echo "Agent collector watches:"
echo "  Suricata: /var/log/suricata/eve.json"
echo "  Zeek    : /opt/zeek/logs/current/*.log or /var/log/zeek/current/*.log"
echo ""
echo "Restart SOC Agent after installing sensors:"
echo "  sudo systemctl restart soc-agent"
