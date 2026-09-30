#!/bin/bash
# Repair Suricata packet capture when eve.json only shows event_type=stats.

set -e

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root: sudo bash fix-suricata-interface.sh"
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
  echo "ERROR: could not detect active interface. Run: sudo SOC_IDS_INTERFACES='wlan0 eth0' bash fix-suricata-interface.sh"
  exit 1
fi
IFACE="$(echo "$IFACES" | awk '{print $1}')"

YAML="/etc/suricata/suricata.yaml"
if [ ! -f "$YAML" ]; then
  echo "ERROR: $YAML not found. Is Suricata installed?"
  exit 1
fi

echo "Active IDS interfaces: $IFACES"

if [ -f /etc/default/suricata ]; then
  sed -i "s/^LISTENMODE=.*/LISTENMODE=af-packet/" /etc/default/suricata 2>/dev/null || true
  sed -i "s/^IFACE=.*/IFACE=$IFACE/" /etc/default/suricata 2>/dev/null || true
fi

cp "$YAML" "${YAML}.bak.$(date +%Y%m%d%H%M%S)"
awk -v ifaces="$IFACES" '
  BEGIN { in_af = 0; inserted = 0; split(ifaces, iface_arr, /[[:space:]]+/) }
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
' "$YAML" > "${YAML}.tmp"
mv "${YAML}.tmp" "$YAML"

echo "Testing Suricata config..."
suricata -T -c "$YAML" >/tmp/suricata-config-test.log 2>&1 || {
  echo "ERROR: Suricata config test failed:"
  tail -80 /tmp/suricata-config-test.log
  exit 1
}

systemctl restart suricata
sleep 5
systemctl is-active --quiet suricata || {
  echo "ERROR: Suricata did not start"
  systemctl status suricata --no-pager -l | sed -n '1,100p'
  exit 1
}

echo "OK: Suricata restarted on interfaces: $IFACES"
echo ""
echo "Verify packet capture:"
echo "  sudo tail -f /var/log/suricata/eve.json"
echo ""
echo "If you still only see stats, generate normal traffic in another terminal:"
echo "  curl -I http://example.com"
echo ""
echo "Current af-packet config:"
grep -n "af-packet:\|interface:" "$YAML" | head -20
