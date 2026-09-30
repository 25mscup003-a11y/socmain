"""Cross-collector time anomaly correlation for AJNAT capability 22.

This detector runs at the sender boundary so process, file, network, USB and
system collectors use the same company policy without duplicating collectors.
It emits only contextual findings; a routine low-risk event outside business
hours is retained as source telemetry but is not automatically an anomaly.
"""

import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 fallback
    ZoneInfo = None


_SENSITIVE_PATTERNS = (
    ('FILE_ENCRYPTION', r'ransom|encrypt|mass[_ -]?(?:rename|modif)|bulk[_ -]?(?:delete|modif)'),
    ('PRIVILEGE_ACTIVITY', r'privilege|escalat|sudo|administrator|\broot\b|credential|lsass'),
    ('SCRIPT_EXECUTION', r'powershell|cmd\.exe|script|wscript|cscript|lolbin|encodedcommand'),
    ('DATA_TRANSFER', r'exfil|large[_ -]?(?:upload|download)|data[_ -]?transfer|upload burst|download burst'),
    ('SECURITY_CONTROL_CHANGE', r'antivirus.*(?:disable|stop)|edr.*(?:disable|stop)|firewall.*change|policy.*change|log.*clear'),
    ('CONFIGURATION_CHANGE', r'registry|config(?:uration)?.*change|software.*install|patch|service.*(?:change|stop|delete)'),
    ('SCHEDULE_DEVIATION', r'scheduled task|cron|backup|database access'),
    ('REMOTE_ACTIVITY', r'rdp|remote desktop|ssh|vpn|lateral movement'),
    ('NETWORK_BURST', r'dns.*burst|api.*burst|connection.*spike|network.*spike'),
    ('USB_ACTIVITY', r'usb|removable'),
)

_LIVE_RULES = {
    'PROC_INVENTORY_SUMMARY', 'NET_CONNECTION_SUMMARY', 'NET_EXPOSURE_SUMMARY',
    'NET_DNS_SUMMARY', 'WEB_TRAFFIC_SUMMARY', 'WEB_BROWSER_ACTIVITY_SUMMARY',
    'WAF_AGENT_STATUS', 'GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS',
}


def _int(value, default, minimum=None, maximum=None):
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = int(default)
    if minimum is not None:
        result = max(minimum, result)
    if maximum is not None:
        result = min(maximum, result)
    return result


def _event_datetime(alert):
    value = alert.get('timestamp') or alert.get('event_time') or alert.get('eventTime')
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone()
        except (TypeError, ValueError):
            pass
    return datetime.now().astimezone()


def _outside_hours(when, start_hour, end_hour):
    hour = when.hour
    if start_hour == end_hour:
        return False
    if start_hour < end_hour:
        return not (start_hour <= hour < end_hour)
    return end_hour <= hour < start_hour


def _first(alert, *keys):
    raw = alert.get('raw') if isinstance(alert.get('raw'), dict) else {}
    for key in keys:
        value = alert.get(key)
        if value not in (None, ''):
            return value
        value = raw.get(key)
        if value not in (None, ''):
            return value
    return ''


class TimeAnomalyDetector:
    def __init__(self, config, state=None):
        self.config = config
        self._hours = defaultdict(lambda: [0] * 24)
        self._samples = defaultdict(int)
        self._last_alert = {}
        self._lock = threading.Lock()
        self._state = state
        self._updates = 0
        if state and hasattr(state, 'get_time_baseline'):
            for key, value in (state.get_time_baseline() or {}).items():
                hours = value.get('hours') if isinstance(value, dict) else None
                if isinstance(hours, list) and len(hours) == 24:
                    self._hours[str(key)] = [_int(count, 0, 0) for count in hours]
                    self._samples[str(key)] = _int(value.get('total'), sum(self._hours[str(key)]), 0)

    def _persist_baseline(self):
        if not self._state or not hasattr(self._state, 'set_time_baseline'):
            return
        with self._lock:
            self._updates += 1
            if self._updates % 100:
                return
            keys = sorted(self._samples, key=self._samples.get, reverse=True)[:2000]
            snapshot = {key: {'hours': list(self._hours[key]), 'total': self._samples[key]} for key in keys}
        self._state.set_time_baseline(snapshot)

    def _exception(self, alert, when):
        username = str(_first(alert, 'username', 'user', 'file_user', 'process_user')).lower()
        host = str(_first(alert, 'hostname', 'host') or self.config.get('system_name') or '').lower()
        process = str(_first(alert, 'process_name', 'processName', 'process', 'exe')).lower()
        ip = str(_first(alert, 'src_ip', 'srcip', 'source_ip')).lower()
        now_utc = datetime.now(timezone.utc)
        for item in self.config.get('time_anomaly_exceptions', []) or []:
            if not isinstance(item, dict):
                continue
            expiry_value = item.get('expires_at') or item.get('expiresAt')
            if expiry_value:
                try:
                    expiry = datetime.fromisoformat(str(expiry_value).replace('Z', '+00:00'))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry <= now_utc:
                        continue
                except (TypeError, ValueError):
                    continue
            kind = str(item.get('type') or '').lower()
            value = str(item.get('value') or '').strip().lower()
            if not value:
                continue
            if kind in ('user', 'service_account') and value == username:
                return True
            if kind == 'host' and value == host:
                return True
            if kind == 'process' and (value == process or value in process):
                return True
            if kind == 'ip' and value == ip:
                return True
            if kind == 'maintenance_window':
                match = re.fullmatch(r'([01]?\d|2[0-3]):?([0-5]\d)?-([01]?\d|2[0-3]):?([0-5]\d)?', value)
                if match:
                    start = int(match.group(1)) * 60 + int(match.group(2) or 0)
                    end = int(match.group(3)) * 60 + int(match.group(4) or 0)
                    minute = when.hour * 60 + when.minute
                    if start == end or (start < end and start <= minute < end) or (start > end and (minute >= start or minute < end)):
                        return True
        return False

    def _all_rules_bypassed(self):
        if not self.config.get('time_anomaly_bypass_active', False):
            return False
        expiry_value = self.config.get('time_anomaly_bypass_until')
        if not expiry_value:
            return False
        try:
            expiry = datetime.fromisoformat(str(expiry_value).replace('Z', '+00:00'))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return expiry > datetime.now(timezone.utc)
        except (TypeError, ValueError):
            return False

    def analyze(self, alert):
        if not self.config.get('time_anomaly_enabled', True) or self._all_rules_bypassed():
            return []
        rule_id = str(_first(alert, 'rule_id', 'ruleId')).upper()
        source = str(_first(alert, 'source', 'source_tag', 'log_source')).lower()
        capability_ids = [alert.get('capabilityId'), *(alert.get('capabilityIds') or [])]
        if source == 'time_anomaly' or rule_id.startswith('TIME_') or 22 in [int(value) for value in capability_ids if str(value).isdigit()]:
            return []
        if rule_id in _LIVE_RULES or alert.get('memory_metric_type') or alert.get('memoryMetricType'):
            return []

        when = _event_datetime(alert)
        timezone_name = str(self.config.get('time_anomaly_timezone') or 'endpoint-local').strip()
        if timezone_name.lower() != 'endpoint-local' and ZoneInfo:
            try:
                when = when.astimezone(ZoneInfo(timezone_name))
            except (KeyError, ValueError):
                pass
        start_hour = _int(self.config.get('working_hours_start'), 8, 0, 23)
        end_hour = _int(self.config.get('working_hours_end'), 20, 0, 23)
        weekend_days = {_int(day, -1) for day in (self.config.get('time_anomaly_weekend_days', [5, 6]) or [])}
        weekend = when.weekday() in weekend_days and self.config.get('time_anomaly_weekends', True)
        holiday = when.date().isoformat() in {str(day) for day in (self.config.get('time_anomaly_holidays', []) or [])}
        outside = _outside_hours(when, start_hour, end_hour)

        entity = str(_first(alert, 'username', 'user', 'hostname', 'host') or self.config.get('system_name') or 'endpoint')
        signature = f'{entity}:{rule_id or source or "event"}'[:400]
        with self._lock:
            prior_total = self._samples[signature]
            prior_hour = self._hours[signature][when.hour]
            self._samples[signature] += 1
            self._hours[signature][when.hour] += 1
        self._persist_baseline()
        if (not outside and not weekend and not holiday) or self._exception(alert, when):
            return []

        text = ' '.join(str(value or '') for value in (
            rule_id, alert.get('eventType'), alert.get('event_type'), alert.get('category'),
            alert.get('description'), alert.get('process_name'), alert.get('file_action'),
        )).lower()
        match = next(((name, pattern) for name, pattern in _SENSITIVE_PATTERNS if re.search(pattern, text)), None)
        severity = str(alert.get('severity') or 'low').lower()
        if severity not in ('high', 'critical') and not match:
            return []

        frequency = round((prior_hour / prior_total) * 100, 2) if prior_total else 0.0
        minimum_samples = _int(self.config.get('time_baseline_minimum_samples'), 20, 1, 10000)
        confidence = min(100, round((prior_total / minimum_samples) * 100))
        risk = 15 + (10 if weekend else 0) + (15 if holiday else 0)
        risk += {'low': 0, 'medium': 10, 'high': 25, 'critical': 40}.get(severity, 10)
        if match:
            risk += 20
        if re.search(r'privilege|sudo|administrator|\broot\b|system account', text):
            risk += 15
        if prior_total >= minimum_samples and frequency < 5:
            risk += 15
        risk = min(100, risk)
        threshold = _int(self.config.get('time_anomaly_risk_threshold'), 45, 0, 100)
        if risk < threshold:
            return []

        kind = match[0] if match else 'HIGH_RISK_ACTIVITY'
        cooldown = _int(self.config.get('time_anomaly_cooldown_seconds'), 3600, 300, 604800)
        dedup_key = f'{kind}:{signature}'
        now = time.time()
        with self._lock:
            if now - self._last_alert.get(dedup_key, 0) < cooldown:
                return []
            self._last_alert[dedup_key] = now

        period = 'configured holiday' if holiday else ('weekend' if weekend else 'outside configured business hours')
        ids = sorted({22, *[int(value) for value in capability_ids if str(value).isdigit()]})
        return [{
            'rule_id': f'TIME_{kind}',
            'capabilityId': 22,
            'capabilityIds': ids,
            'category': 'edr',
            'source': 'time_anomaly',
            'severity': 'critical' if risk >= 81 else 'high' if risk >= 61 else 'medium' if risk >= 41 else 'low',
            'risk_score': risk,
            'eventType': kind.replace('_', ' ').title(),
            'description': f'{rule_id or "Security activity"} occurred during {period}',
            'username': _first(alert, 'username', 'user', 'file_user', 'process_user'),
            'src_ip': _first(alert, 'src_ip', 'srcip', 'source_ip'),
            'process_name': _first(alert, 'process_name', 'processName', 'process'),
            'file_path': _first(alert, 'file_path', 'filePath'),
            'timestamp': when.astimezone(timezone.utc).isoformat(),
            'actual_time': when.isoformat(),
            'expected_time': f'{start_hour:02d}:00-{end_hour:02d}:00',
            'time_window': period.title(),
            'baseline_diff': f'Historical frequency {frequency}%',
            'baseline_confidence': confidence,
            'related_events': [alert.get('event_id')] if alert.get('event_id') else [],
            'raw': {
                'source_event': rule_id,
                'source_category': alert.get('category'),
                'local_hour': when.hour,
                'weekday': when.weekday(),
                'after_hours': outside,
                'weekend': weekend,
                'holiday': holiday,
                'historical_frequency': frequency,
                'baseline_confidence': confidence,
                'actual_time': when.isoformat(),
                'expected_time': f'{start_hour:02d}:00-{end_hour:02d}:00',
                'time_window': period.title(),
            },
            'raw_log': str(alert.get('raw_log') or alert.get('description') or '')[:500],
        }]
