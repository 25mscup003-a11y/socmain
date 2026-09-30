#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-3001}"
SID=9900001
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULT_FILE="$ROOT_DIR/backend/waf-inline-test-result.txt"
RULE_FILE="/etc/suricata/rules/soc-managed.rules"
EVE_FILE="/var/log/suricata/eve.json"
BACKUP_FILE=""

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo bash backend/scripts/verify-waf-inline-3001.sh" >&2
  exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "Port must be between 1 and 65535" >&2
  exit 1
fi

cleanup() {
  local status=$?
  if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]]; then
    cp "$BACKUP_FILE" "$RULE_FILE"
    rm -f "$BACKUP_FILE"
    systemctl restart suricata || true
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

if ! curl --connect-timeout 3 --max-time 5 -fsS -o /dev/null "http://127.0.0.1:${PORT}/"; then
  echo "Port ${PORT} is not serving HTTP. Start the local test server first." >&2
  exit 1
fi

BACKUP_FILE="$(mktemp "${RULE_FILE}.ajnat-test.XXXXXX")"
cp "$RULE_FILE" "$BACKUP_FILE"
sed -i "/sid:${SID};/d" "$RULE_FILE"
printf 'drop http any any -> any %s (msg:"AJNAT controlled WAF inline test"; flow:to_server,established; http.request_header; content:"X-Ajnat-Waf-Test|3a| block"; nocase; sid:%s; rev:1;)\n' "$PORT" "$SID" >> "$RULE_FILE"

if ! suricata -T -c /etc/suricata/suricata.yaml >/tmp/ajnat-suricata-test.out 2>&1; then
  cat /tmp/ajnat-suricata-test.out >&2
  exit 1
fi

systemctl restart suricata
systemctl is-active --quiet suricata

baseline_code="$(curl --connect-timeout 3 --max-time 5 -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/")"
set +e
test_code="$(curl --connect-timeout 3 --max-time 5 -sS -o /dev/null -w '%{http_code}' -H 'X-Ajnat-Waf-Test: block' "http://127.0.0.1:${PORT}/")"
test_exit=$?
set -e
alert_line="$(tail -n 400 "$EVE_FILE" 2>/dev/null | grep "\"signature_id\":${SID}" | tail -n 1 || true)"

verdict="FAIL"
if [[ "$baseline_code" == "200" && "$test_code" != "200" && "$test_exit" -ne 0 && -n "$alert_line" ]]; then
  verdict="PASS"
fi

{
  printf 'timestamp=%s\n' "$(date --iso-8601=seconds)"
  printf 'port=%s\n' "$PORT"
  printf 'baseline_http=%s\n' "$baseline_code"
  printf 'test_http=%s\n' "$test_code"
  printf 'test_curl_exit=%s\n' "$test_exit"
  printf 'suricata_alert=%s\n' "$([[ -n "$alert_line" ]] && echo present || echo absent)"
  printf 'verdict=%s\n' "$verdict"
} > "$RESULT_FILE"

if [[ -n "${SUDO_USER:-}" ]]; then
  chown "$SUDO_USER" "$RESULT_FILE"
fi

cat "$RESULT_FILE"
[[ "$verdict" == "PASS" ]]