"""Deterministic insider-risk tagging for real endpoint telemetry.

This module does not invent incidents.  It adds capability 16 to events that
already contain concrete endpoint evidence, allowing the backend to correlate
the same event across its original capability and Insider Threat Detection.
"""

from __future__ import annotations


_SIGNALS = {
    'AUTH_ROOT_LOGIN': 'privileged_access',
    'AUTH_SUDO': 'privileged_access',
    'AUTH_GROUP_CHANGE': 'privilege_change',
    'AUTH_ADMIN_RIGHTS': 'privilege_change',
    'AUTH_USER_CREATED': 'account_change',
    'AUTH_USER_DELETED': 'account_change',
    'EDR_PRIV_ESC': 'privilege_escalation',
    'EDR_GROUP_MOD': 'privilege_change',
    'PROC_PRIVILEGED_COMMAND': 'privileged_access',
    'PROC_PRIVILEGE_ESCALATION': 'privilege_escalation',
    'PROC_SECURITY_TOOL_TAMPER': 'defense_evasion',
    'PROC_SECURITY_TOOL_TERMINATED': 'defense_evasion',
    'PROC_SECURITY_LOG_CLEARED': 'log_tampering',
    'PROC_ARCHIVE_STAGING': 'archive_staging',
    'SCRIPT_CREDENTIAL_ACCESS': 'credential_access',
    'SCRIPT_DATA_EXFILTRATION': 'data_exfiltration',
    'SCRIPT_MASS_FILE_OPERATION': 'destructive_file_activity',
    'NET_OUTBOUND_TRANSFER_ANOMALY': 'data_exfiltration',
    'NET_EXFIL': 'data_exfiltration',
    'NET_LATERAL_MOVEMENT_PATTERN': 'lateral_movement',
    'SCRIPT_REMOTE_EXECUTION': 'lateral_movement',
    'WIN_PSEXEC': 'lateral_movement',
    'USB_SENSITIVE_FILE_COPIED': 'removable_media_exfiltration',
    'USB_POLICY_BLOCKED': 'removable_media_policy_violation',
    'USB_POLICY_VIOLATION': 'removable_media_policy_violation',
    'FILE_SENSITIVE': 'sensitive_file_activity',
    'GEO_IMPOSSIBLE_TRAVEL': 'identity_anomaly',
}

_RISK_BY_SEVERITY = {'low': 25, 'medium': 50, 'high': 75, 'critical': 95}


def _signal_type(alert: dict) -> str:
    rule_id = str(alert.get('rule_id') or alert.get('ruleId') or '').upper()
    if rule_id in _SIGNALS:
        return _SIGNALS[rule_id]
    if rule_id.startswith('TIME_') and (
        alert.get('after_hours') is True
        or alert.get('weekend') is True
        or any(token in rule_id for token in ('AFTER_HOURS', 'OFF_HOURS', 'WEEKEND', 'UNUSUAL_TIME'))
    ):
        return 'after_hours_activity'
    sensitivity = str(alert.get('sensitivity_type') or alert.get('sensitivityType') or '').lower()
    file_action = str(alert.get('file_action') or alert.get('fileAction') or '').lower()
    if sensitivity in {'sensitive', 'restricted', 'confidential'} and file_action:
        return 'sensitive_file_activity'
    return ''


def tag_insider_threat(alert: dict) -> dict:
    """Tag a proven endpoint event for capability 16 and retain its origin."""
    if not isinstance(alert, dict):
        return alert
    signal_type = _signal_type(alert)
    if not signal_type:
        return alert

    capability_ids = set()
    for value in alert.get('capabilityIds') or alert.get('capability_ids') or []:
        try:
            capability_ids.add(int(value))
        except (TypeError, ValueError):
            continue
    for key in ('capabilityId', 'capability_id'):
        try:
            value = int(alert.get(key))
            if value:
                capability_ids.add(value)
        except (TypeError, ValueError):
            pass
    capability_ids.add(16)
    alert['capabilityIds'] = sorted(capability_ids)
    if not alert.get('capabilityId') and not alert.get('capability_id'):
        alert['capabilityId'] = 16

    alert.setdefault('risk_score', _RISK_BY_SEVERITY.get(str(alert.get('severity') or '').lower(), 50))
    raw = alert.get('raw') if isinstance(alert.get('raw'), dict) else {}
    alert['raw'] = {
        **raw,
        'insider_signal_type': signal_type,
        'insider_evidence_rule': str(alert.get('rule_id') or alert.get('ruleId') or ''),
    }
    return alert

