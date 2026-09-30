#!/usr/bin/env bash
set -u

STATUS_DIR="/var/lib/soc-agent"
STATUS_FILE="$STATUS_DIR/advanced-process-telemetry.json"
RULE_FILE="/etc/audit/rules.d/ajn-process.rules"
mkdir -p "$STATUS_DIR"

AUDIT_AVAILABLE=false
AUDIT_CONFIGURED=false
if command -v auditctl >/dev/null 2>&1; then
  AUDIT_AVAILABLE=true
  mkdir -p /etc/audit/rules.d
  {
    echo '# AJNAT process injection and persistence evidence'
    echo '-a always,exit -F arch=b64 -S ptrace -S process_vm_writev -k ajnat_process_injection'
    if [ "$(uname -m)" = "x86_64" ]; then
      echo '-a always,exit -F arch=b32 -S ptrace -S process_vm_writev -k ajnat_process_injection'
    fi
    [ -d /etc/systemd/system ] && echo '-w /etc/systemd/system -p wa -k ajnat_service_persistence'
    [ -d /etc/cron.d ] && echo '-w /etc/cron.d -p wa -k ajnat_scheduled_task'
    [ -d /etc/cron.daily ] && echo '-w /etc/cron.daily -p wa -k ajnat_scheduled_task'
    [ -e /etc/rc.local ] && echo '-w /etc/rc.local -p wa -k ajnat_startup_persistence'
  } > "$RULE_FILE"
  chmod 600 "$RULE_FILE"
  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 && AUDIT_CONFIGURED=true
  else
    auditctl -R "$RULE_FILE" >/dev/null 2>&1 && AUDIT_CONFIGURED=true
  fi
fi

cat > "$STATUS_FILE" <<EOF
{"platform":"Linux","linuxAuditAvailable":$AUDIT_AVAILABLE,"linuxAuditConfigured":$AUDIT_CONFIGURED,"configuredAt":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
chmod 600 "$STATUS_FILE"

if [ "$AUDIT_CONFIGURED" = true ]; then
  echo 'AJNAT Linux audit rules loaded.'
else
  echo 'WARNING: auditd is unavailable or rules could not be loaded; /proc monitoring remains active but kernel syscall coverage is degraded.' >&2
fi
