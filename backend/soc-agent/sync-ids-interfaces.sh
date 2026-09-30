#!/bin/bash
# Keep IDS sensors bound to the currently active physical network interfaces.

set -u

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root"
  exit 1
fi

detect_interfaces() {
  ip -br link 2>/dev/null | awk '
    $1 !~ /^(lo|docker|br-|veth|virbr|tunl|sit|ip6tnl)/ &&
    $2 ~ /^(UP|UNKNOWN)$/ &&
    $0 ~ /LOWER_UP/ { print $1 }
  '
}

IFACES="$(detect_interfaces | sort -u | xargs)"
[ -n "$IFACES" ] || exit 0

PRIMARY="$(ip route 2>/dev/null | awk '/^default/ { print $5; exit }')"
case " $IFACES " in
  *" $PRIMARY "*) ;;
  *) PRIMARY="$(printf '%s\n' "$IFACES" | awk '{ print $1 }')" ;;
esac

STATE_FILE=/run/soc-ids-interfaces.state
NEXT_STATE="interfaces=$IFACES primary=$PRIMARY"
if [ -r "$STATE_FILE" ] && [ "$(cat "$STATE_FILE")" = "$NEXT_STATE" ]; then
  exit 0
fi

AGENT_ROOT="${SOC_AGENT_ROOT:-/opt/soc-agent}"
if command -v suricata >/dev/null 2>&1 && [ -x "$AGENT_ROOT/fix-suricata-interface.sh" ]; then
  SOC_IDS_INTERFACES="$IFACES" "$AGENT_ROOT/fix-suricata-interface.sh"
fi

ZEEK_CFG=""
for candidate in /opt/zeek/etc/node.cfg /usr/local/zeek/etc/node.cfg /etc/zeek/node.cfg; do
  if [ -f "$candidate" ]; then ZEEK_CFG="$candidate"; break; fi
done
if command -v zeek >/dev/null 2>&1 && [ -n "$ZEEK_CFG" ]; then
  sed -i "s/^interface=.*/interface=$PRIMARY/" "$ZEEK_CFG"
  systemctl restart zeek >/dev/null 2>&1 || zeekctl deploy >/dev/null 2>&1 || true
fi

printf '%s\n' "$NEXT_STATE" > "$STATE_FILE"
logger -t soc-ids-interface-sync "IDS interfaces updated: $IFACES (Zeek primary: $PRIMARY)"
