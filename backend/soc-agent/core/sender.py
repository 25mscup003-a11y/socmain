"""
Alert Sender v2.0 — priority queue, VT intelligence, health monitoring.

MASTER RULES (from SOC Agent v2.0 spec):
  1. INSTALL_TIME baseline — drop events before install
  2. VT = 0 → CLEAN, severity=LOW, NEVER malware
  3. VT 1-5 → SUSPICIOUS, severity=MEDIUM
  4. VT > 5 → MALWARE, severity=HIGH/CRITICAL
  5. Priority queue: CRITICAL > HIGH > MEDIUM > LOW
  6. NEVER drop CRITICAL; drop LOW first on queue pressure
  7. Queue overflow → mark LOW/MEDIUM as UNDER_OBSERVATION
  8. System health: stop LOW logging on memory/CPU overload

Field mapping (agent → backend Alert model):
  rule_id      → type / rule_id
  category     → eventCategory  (malware/network/file/system/edr/usb)
  severity     → severity
  raw_log      → full_log
  src_ip       → srcip
  dst_port     → port
  file_hash    → fileHash
  file_path    → filePath
  file_action  → fileAction
  malware_type → malwareType
  virustotal   → forwarded raw; backend saves vtScore/vtDetections/etc.
"""

import logging
import threading
import time
import os
import platform
import random
import uuid
import gzip
import json
import re
import psutil  # optional — graceful degradation if not installed
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from queue import PriorityQueue, Empty, Full
from typing import Optional, Dict, Any, List

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import psutil as _psutil_mod
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from .state import StateManager
from .config import AgentConfig
from .security import signed_headers
from .durable_spool import DurableSpool
from .secure_transport import secure_request

try:
    from .geo_enrichment import GeoEnrichment
except Exception:
    GeoEnrichment = None

try:
    from .time_anomaly import TimeAnomalyDetector
except Exception:
    TimeAnomalyDetector = None

try:
    from .insider_threat import tag_insider_threat
except Exception:
    tag_insider_threat = None

logger = logging.getLogger('soc-agent.sender')

# ── Constants ─────────────────────────────────────────────────────────────────
STALE_HOURS        = 24
SEND_TIMEOUT       = 15
BATCH_SIZE         = 20
RATE_WINDOW        = 60          # same rule+key suppressed for 60s
QUEUE_MAX          = 10000       # max buffered alerts (configurable)
QUEUE_HIGH         = int(QUEUE_MAX * 0.80)   # 80% → drop LOW
QUEUE_CRITICAL     = int(QUEUE_MAX * 0.95)   # 95% → drop HIGH too
BACKOFF_MAX        = 60
HEALTH_CHECK_SECS  = 30          # check CPU/RAM this often

# Priority weights (lower number = higher priority in PriorityQueue)
SEV_PRIORITY = {
    'critical': 0,
    'high':     1,
    'medium':   2,
    'low':      3,
}

# VT intelligence thresholds (MASTER RULE)
VT_THRESHOLD_MALWARE     = 5   # > 5 detections → MALWARE
VT_THRESHOLD_SUSPICIOUS  = 1   # 1-5 detections → SUSPICIOUS
# 0 detections → CLEAN / LOW / NOT malware (non-negotiable)

# Patch inventory is emitted as one or more batches belonging to a single
# snapshot.  These records are live endpoint state and every batch is needed
# to reconstruct the snapshot, so normal alert throttling/deduplication must
# never discard them.
PATCH_INVENTORY_LIVE_RULES = frozenset({
    'PATCH_INVENTORY_SENSOR_HEALTH',
    'PATCH_INVENTORY_SENSOR_ERROR',
    'PATCH_SOFTWARE_INVENTORY',
    'PATCH_INSTALLED_UPDATES',
    'PATCH_PENDING_UPDATES',
})

_SENSITIVE_ARGUMENTS = re.compile(
    r'(?i)(--?(?:password|passwd|pwd|token|api[_-]?key|secret|client[_-]?secret|'
    r'access[_-]?key|session|cookie|authorization)(?:\s+|=))([^\s"\']+|"[^"]*"|\'[^\']*\')'
)
_BEARER_TOKEN = re.compile(r'(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+')


def _redact_command_line(value):
    """Redact common credentials while retaining useful process context."""
    if value is None:
        return None
    text = str(value)[:8000]
    text = _SENSITIVE_ARGUMENTS.sub(r'\1[REDACTED]', text)
    return _BEARER_TOKEN.sub(r'\1[REDACTED]', text)


def _redact_sensitive_payload(value, key=''):
    """Bound and redact nested raw telemetry before it leaves the endpoint."""
    sensitive_keys = {
        'password', 'passwd', 'pwd', 'token', 'access_token', 'refresh_token',
        'api_key', 'apikey', 'secret', 'client_secret', 'authorization',
        'cookie', 'session_cookie', 'private_key',
    }
    normalized_key = str(key).lower().replace('-', '_')
    if normalized_key in sensitive_keys:
        return '[REDACTED]'
    if isinstance(value, dict):
        return {str(k)[:128]: _redact_sensitive_payload(v, k) for k, v in list(value.items())[:256]}
    if isinstance(value, (list, tuple)):
        return [_redact_sensitive_payload(item, key) for item in list(value)[:256]]
    if isinstance(value, str):
        if normalized_key in {'cmdline', 'command_line', 'commandline', 'parent_cmdline', 'script_content'}:
            return _redact_command_line(value)
        return _redact_command_line(value[:16000])
    return value


def _encode_transport_body(payload: dict, gzip_min_bytes: int = 1024):
    body = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    if len(body) >= max(0, int(gzip_min_bytes)):
        body = gzip.compress(body)
        headers['Content-Encoding'] = 'gzip'
    return body, headers


def _vt_verdict_and_severity(detections: int) -> tuple:
    """
    Convert VT detection count to (verdict, severity, is_malware).
    STRICT: 0 = CLEAN, never malware.
    """
    if detections == 0:
        return 'clean', 'low', False
    elif detections <= VT_THRESHOLD_MALWARE:
        return 'suspicious', 'medium', False
    else:
        return 'malicious', 'high', True


class AlertSender:
    def __init__(self, config: AgentConfig, state: StateManager):
        self.config = config
        self.state  = state

        # Priority queue: items are (priority_int, timestamp, alert_dict)
        # Lower priority_int = processed first (CRITICAL first)
        self._q: PriorityQueue = PriorityQueue(maxsize=QUEUE_MAX)
        self._q_counter = 0   # tie-breaker for equal priority (FIFO within tier)
        self._q_lock    = threading.Lock()
        self._queued_ids = set()

        default_spool = os.path.join(os.path.dirname(__file__), '..', 'config', 'sender_spool.sqlite3')
        spool_path = os.getenv('SOC_AGENT_SPOOL_PATH') or config.get('sender_spool_path') or default_spool
        spool_key = config.get('storage_encryption_key')
        if not spool_key:
            raise RuntimeError('server-issued AES-256 storage key is unavailable')
        self._spool = DurableSpool(
            spool_path,
            config.get('sender_max_attempts', 20),
            encryption_key=spool_key,
        )
        live_state_id = config.get('system_id') or config.get('agent_key') or 'local'
        self._inventory_coalesce_key = 'live-process-inventory:{}'.format(live_state_id)
        self._waf_status_coalesce_key = 'live-waf-status:{}'.format(live_state_id)
        self._exposure_coalesce_key = 'live-port-exposure:{}'.format(live_state_id)
        self._network_snapshot_coalesce_key = 'live-network-snapshot:{}'.format(live_state_id)
        self._dns_summary_coalesce_key = 'live-dns-summary:{}'.format(live_state_id)
        self._web_summary_coalesce_key = 'live-web-summary:{}'.format(live_state_id)
        self._browser_summary_coalesce_key = 'live-browser-summary:{}'.format(live_state_id)
        self._gps_location_coalesce_key = 'live-gps-location:{}'.format(live_state_id)
        collapsed = self._spool.collapse_rule('PROC_INVENTORY_SUMMARY', self._inventory_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending process inventory snapshots', collapsed)
        collapsed = self._spool.collapse_rule('WAF_AGENT_STATUS', self._waf_status_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending WAF status snapshots', collapsed)
        collapsed = self._spool.collapse_rule('NET_EXPOSURE_SUMMARY', self._exposure_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending port exposure snapshots', collapsed)
        collapsed = self._spool.collapse_rule('NET_CONNECTION_SUMMARY', self._network_snapshot_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending network snapshots', collapsed)
        collapsed = self._spool.collapse_rule('NET_DNS_SUMMARY', self._dns_summary_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending DNS summaries', collapsed)
        collapsed = self._spool.collapse_rule('WEB_TRAFFIC_SUMMARY', self._web_summary_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending web summaries', collapsed)
        collapsed = self._spool.collapse_rule('WEB_BROWSER_ACTIVITY_SUMMARY', self._browser_summary_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending browser summaries', collapsed)
        collapsed = self._spool.collapse_rule('GPS_LOCATION_TELEMETRY', self._gps_location_coalesce_key)
        if collapsed:
            logger.info('Coalesced %d obsolete pending GPS locations', collapsed)

        self._worker  = threading.Thread(target=self._loop,   daemon=True, name='sender')
        self._health  = threading.Thread(target=self._health_loop, daemon=True, name='sender-health')
        self._vt      = None
        self._geo     = GeoEnrichment(config=config) if GeoEnrichment and config.get('geo_enrichment_enabled', True) else None
        self._time_anomaly = TimeAnomalyDetector(config, state=state) if TimeAnomalyDetector else None

        # Health state
        self._overload    = False   # True when CPU/RAM overloaded
        self._dropped_cnt = 0

        # Per-key rate limiting
        self._rate_map:  Dict[str, float] = {}
        self._rate_lock  = threading.Lock()

        self._init_vt()

    def _init_vt(self):
        key = self.config.get('virustotal_api_key', '')
        if key:
            try:
                import importlib
                mod = importlib.import_module('detectors.virustotal')
                # Support both class names for compat
                cls = getattr(mod, 'VirusTotalScanner', None) or getattr(mod, 'VTScanner', None)
                if cls:
                    self._vt = cls(key)
                    logger.info('VirusTotal enrichment enabled (strict VT rules active)')
            except Exception as e:
                logger.warning('VT init: %s', e)

    def start(self):
        self._refill_from_spool()
        self._worker.start()
        self._health.start()

    # ── Health monitoring ─────────────────────────────────────────────────────
    def _health_loop(self):
        """Monitor CPU/RAM. On overload stop logging LOW events."""
        while True:
            try:
                if HAS_PSUTIL:
                    cpu = _psutil_mod.cpu_percent(interval=1)
                    mem = _psutil_mod.virtual_memory().percent
                    qsz = self._q.qsize()
                    self._overload = (cpu > 85 or mem > 90 or qsz > QUEUE_HIGH)
                    if self._overload:
                        logger.warning(
                            '[HEALTH] Overload detected — CPU=%.0f%% MEM=%.0f%% '
                            'Q=%d/%d → suppressing LOW events',
                            cpu, mem, qsz, QUEUE_MAX,
                        )
            except Exception:
                pass
            time.sleep(HEALTH_CHECK_SECS)

    def get_health(self) -> dict:
        qsz = self._q.qsize()
        return {
            'queue_size':     qsz,
            'queue_max':      QUEUE_MAX,
            'queue_pct':      round(qsz / QUEUE_MAX * 100, 1),
            'overload':       self._overload,
            'dropped_total':  self._dropped_cnt,
            'durable_spool':  self._spool.counts(),
            'counters':       self.state.get_counters(),
        }

    # ── Rate limiting ─────────────────────────────────────────────────────────
    def _rate_key(self, alert: dict) -> str:
        rule  = alert.get('rule_id', '')
        fpath = alert.get('file_path', '') or alert.get('file_name', '')
        ip    = alert.get('src_ip', '')
        if 14 in (alert.get('capabilityIds') or alert.get('capability_ids') or []):
            ip = f'{ip}>{alert.get("dst_ip", "")}:{alert.get("dst_port", "")}'
        if 13 in (alert.get('capabilityIds') or alert.get('capability_ids') or []):
            ip = f'{alert.get("username", "")}@{ip}:{alert.get("session_id", "")}'
        dev   = alert.get('device', '')
        loc   = fpath or ip or dev or alert.get('description', '')[:60]
        return f'{rule}::{loc}'

    def _is_rate_limited(self, alert: dict) -> bool:
        """60-second per-key dedup. CRITICAL alerts bypass rate limit."""
        if alert.get('rule_id') == 'PROC_INVENTORY_SUMMARY':
            return False
        if alert.get('severity') == 'critical':
            return False
        key = self._rate_key(alert)
        now = time.monotonic()
        with self._rate_lock:
            last = self._rate_map.get(key, 0)
            if now - last < RATE_WINDOW:
                return True
            self._rate_map[key] = now
            if len(self._rate_map) > 2000:
                cutoff = now - RATE_WINDOW * 2
                self._rate_map = {k: v for k, v in self._rate_map.items()
                                  if v > cutoff}
        return False

    # ── VT Intelligence check (applied before enqueue) ───────────────────────
    def _apply_vt_rules(self, alert: dict) -> dict:
        """
        Apply MASTER VT RULES to re-classify alert based on VT data.
        VT = 0 → CLEAN, severity=LOW, category='file' (NOT malware).
        Called after VT enrichment in enqueue, before queuing.
        """
        vt = alert.get('virustotal') or {}
        detections = vt.get('malicious', 0) + vt.get('suspicious', 0)
        verdict, new_sev, is_malware = _vt_verdict_and_severity(detections)

        if vt:  # VT data available — enforce strict rules
            if not is_malware:
                # VT says clean/low — downgrade from malware to file event
                if alert.get('category') == 'malware' and detections == 0:
                    alert['category'] = 'file'
                    alert['severity'] = 'low'
                    alert['_vt_override'] = True
                    logger.debug(
                        'VT=0 override: %s → NOT malware (LOW)',
                        alert.get('rule_id')
                    )
                else:
                    alert['severity'] = new_sev
            else:
                # VT confirms malware
                alert['severity'] = new_sev
                alert['category'] = 'malware'
                self.state.count_malware()

            alert['vt_verdict_local'] = verdict

        else:
            # No VT data
            if alert.get('category') == 'malware' and not alert.get('file_hash'):
                # No VT, no hash, no behavior anomaly confirmed → OBSERVATION
                alert['_under_observation'] = True
                alert['description'] = (
                    alert.get('description', '') +
                    ' [UNDER OBSERVATION — VT data unavailable]'
                )
                alert['severity'] = min(
                    alert.get('severity', 'medium'),
                    'medium',
                    key=lambda s: SEV_PRIORITY.get(s, 99),
                )

        return alert

    # ── Enqueue ───────────────────────────────────────────────────────────────
    def send_alert(self, alert: dict):
        """Compatibility wrapper for detector modules that call send_alert."""
        return self.enqueue(alert)

    def _event_is_after_effective_install(self, event_ts: Optional[str]) -> bool:
        """Honor local install_time plus server-provided FIM start date."""
        if not self.state.event_is_after_install(event_ts):
            return False
        server_start = (
            self.config.get('fim_start_at', '')
            or self.config.get('file_monitor_start_at', '')
        )
        if not event_ts or not server_start:
            return True
        try:
            raw_event = event_ts[:-1] + '+00:00' if str(event_ts).endswith('Z') else str(event_ts)
            raw_start = server_start[:-1] + '+00:00' if str(server_start).endswith('Z') else str(server_start)
            event_dt = datetime.fromisoformat(raw_event)
            start_dt = datetime.fromisoformat(raw_start)
            if event_dt.tzinfo is None:
                event_dt = event_dt.replace(tzinfo=timezone.utc)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            return event_dt >= start_dt
        except Exception:
            return True

    def enqueue(self, alert: dict) -> bool:
        """
        Gate:
          1. INSTALL_TIME baseline check → drop pre-install events
          2. Stale drop (> 24h old)
          3. Rate limit (60s per key)
          4. Dedup (24h fingerprint)
          5. VT rules applied
          6. Queue pressure management (priority-aware)
          7. Counters updated

        Return True once persisted to the retry spool, False if rejected.
        """
        alert.setdefault('event_id', uuid.uuid4().hex)

        if tag_insider_threat:
            alert = tag_insider_threat(alert)

        if self._time_anomaly:
            try:
                for finding in self._time_anomaly.analyze(alert):
                    self.enqueue(finding)
            except Exception as e:
                logger.debug('[TimeAnomaly] alert analysis skipped: %s', e)

        if self._geo and not str(alert.get('ruleId') or alert.get('rule_id') or '').startswith('GEO_'):
            try:
                findings = self._geo.analyze(alert)
                for finding in findings:
                    if finding.get('systemLogoutRequested'):
                        try:
                            from .session_response import logout_user
                            result = logout_user(finding.get('username'))
                            finding['containmentStatus'] = 'logged_out'
                            finding['policyActionStatus'] = 'enforced'
                            finding['action_taken'] = 'System Logout'
                            finding['raw'] = {**(finding.get('raw') or {}), 'sessionResponse': result}
                            finding['description'] = f"{finding.get('description', '')} [OS USER LOGGED OUT]"
                        except Exception as logout_err:
                            finding['containmentStatus'] = 'logout_failed'
                            finding['policyActionStatus'] = 'failed'
                            finding['raw'] = {**(finding.get('raw') or {}), 'logoutError': str(logout_err)}
                    elif finding.get('geoFenceLockRequested'):
                        try:
                            from response.isolate import isolate
                            isolate(self.config.get('server_url'))
                            finding['containmentStatus'] = 'isolated'
                            finding['policyActionStatus'] = 'enforced'
                            finding['blocked'] = True
                            finding['action_taken'] = 'Blocked'
                            finding['description'] = f"{finding.get('description', '')} [SYSTEM LOCKED]"
                        except Exception as lock_err:
                            finding['raw'] = {**(finding.get('raw') or {}), 'lockError': str(lock_err)}
                            finding['containmentStatus'] = 'isolation_failed'
                            finding['policyActionStatus'] = 'failed'
                    elif finding.get('ipBlockRequested'):
                        try:
                            import ipaddress
                            from . import fw_backend
                            source_ip = finding.get('srcip') or finding.get('src_ip')
                            address = ipaddress.ip_address(str(source_ip))
                            if not address.is_global:
                                raise ValueError('only a public source IP can be blocked by geolocation policy')
                            if not fw_backend.block_ip(str(address), direction='both', comment='geolocation-policy'):
                                raise RuntimeError('host firewall rejected the geolocation IP block')
                            finding['containmentStatus'] = 'blocked'
                            finding['policyActionStatus'] = 'enforced'
                            finding['blocked'] = True
                            finding['action_taken'] = 'Blocked'
                            finding['description'] = f"{finding.get('description', '')} [SOURCE IP BLOCKED]"
                        except Exception as block_err:
                            finding['raw'] = {**(finding.get('raw') or {}), 'ipBlockError': str(block_err)}
                            finding['containmentStatus'] = 'block_failed'
                            finding['policyActionStatus'] = 'failed'
                    elif finding.get('policyTriggered'):
                        action = str(finding.get('policyAction') or '').upper()
                        finding['policyActionStatus'] = 'allowed' if action == 'ALLOW & AUDIT' else 'logged'
                        if action == 'ALLOW & AUDIT':
                            finding['containmentStatus'] = 'allowed'
                            finding['action_taken'] = 'Allowed'
                    self.enqueue(finding)
            except Exception as e:
                logger.debug('[GeoEnrich] alert analysis skipped: %s', e)

        # ── 1. Install-time baseline ──────────────────────────────────────────
        ts = alert.get('timestamp')
        if not self._event_is_after_effective_install(ts):
            logger.debug('Pre-install event dropped: %s @ %s', alert.get('rule_id'), ts)
            return False

        # ── 2. Stale drop ─────────────────────────────────────────────────────
        if ts:
            try:
                t  = ts[:-1] + '+00:00' if ts.endswith('Z') else ts
                dt = datetime.fromisoformat(t)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt < datetime.now(timezone.utc) - timedelta(hours=STALE_HOURS):
                    logger.debug('Stale drop: %s', alert.get('rule_id'))
                    return False
            except Exception:
                pass

        # ── 3. Rate limit ─────────────────────────────────────────────────────
        realtime_inventory = alert.get('rule_id') == 'PROC_INVENTORY_SUMMARY'
        realtime_waf_status = alert.get('rule_id') == 'WAF_AGENT_STATUS'
        realtime_exposure = alert.get('rule_id') == 'NET_EXPOSURE_SUMMARY'
        realtime_network_snapshot = alert.get('rule_id') == 'NET_CONNECTION_SUMMARY'
        change_only_network_summary = (
            alert.get('rule_id') in {
                'NET_CONNECTION_SUMMARY', 'NET_DNS_SUMMARY',
                'NET_EXPOSURE_SUMMARY', 'NET_THREAT_INTEL_SUMMARY',
            }
            and isinstance(alert.get('raw'), dict)
            and alert['raw'].get('reporting_mode') == 'on_change'
        )
        realtime_dns_summary = alert.get('rule_id') == 'NET_DNS_SUMMARY'
        realtime_web_summary = alert.get('rule_id') == 'WEB_TRAFFIC_SUMMARY'
        realtime_browser_summary = alert.get('rule_id') == 'WEB_BROWSER_ACTIVITY_SUMMARY'
        realtime_api_request = alert.get('rule_id') == 'API_CALL_TELEMETRY'
        realtime_gps_location = alert.get('rule_id') in ('GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS')
        # Kernel inventory can span several events. Bypass rate/dedup/pressure
        # for every batch, but deliberately do not coalesce those batches.
        realtime_kernel_inventory = alert.get('rule_id') == 'KERNEL_INVENTORY_SNAPSHOT'
        # Patch inventory also spans multiple batches. Every batch must reach
        # the backend; coalescing is intentionally disabled for these rules.
        realtime_patch_inventory = alert.get('rule_id') in PATCH_INVENTORY_LIVE_RULES
        live_status = (realtime_inventory or realtime_waf_status or realtime_exposure
                       or realtime_network_snapshot or realtime_dns_summary or realtime_web_summary
                       or realtime_browser_summary or realtime_api_request or realtime_gps_location
                       or realtime_kernel_inventory or realtime_patch_inventory
                       or change_only_network_summary)

        if not live_status and self._is_rate_limited(alert):
            logger.debug('Rate-limited: %s', self._rate_key(alert))
            return False

        # ── 4. Dedup ──────────────────────────────────────────────────────────
        if not live_status and self.state.is_duplicate(
            alert.get('rule_id', ''),
            alert.get('description', ''),
            alert.get('raw_log', ''),
            alert.get('src_ip', ''),
        ):
            logger.debug('Dup drop: %s', alert.get('rule_id'))
            return False

        if not live_status:
            self.state.mark_sent(
                alert.get('rule_id', ''),
                alert.get('description', ''),
                alert.get('raw_log', ''),
                alert.get('src_ip', ''),
            )

        # ── 5. VT rules ───────────────────────────────────────────────────────
        alert = self._apply_vt_rules(alert)

        # ── 6. Queue pressure ─────────────────────────────────────────────────
        sev   = alert.get('severity', 'medium')
        pri   = SEV_PRIORITY.get(sev, 2)
        qsize = self._q.qsize()

        # System overload → only HIGH/CRITICAL
        if not live_status and self._overload and sev in ('low', 'medium'):
            logger.debug('Overload suppress [%s]: %s', sev, alert.get('rule_id'))
            self.state.count_dropped()
            self._dropped_cnt += 1
            return False

        if qsize >= QUEUE_CRITICAL:
            # Extreme pressure → only CRITICAL survives
            if not live_status and sev != 'critical':
                alert['_under_observation'] = True
                logger.warning(
                    'Queue critical [%d/%d] — %s marked UNDER_OBSERVATION: %s',
                    qsize, QUEUE_MAX, sev, alert.get('rule_id'),
                )
                self.state.count_dropped()
                self._dropped_cnt += 1
                return False
        elif qsize >= QUEUE_HIGH:
            # High pressure → drop LOW (CRITICAL/HIGH always go in)
            if not live_status and sev == 'low':
                logger.debug('Pressure drop LOW [%d/%d]: %s', qsize, QUEUE_MAX,
                             alert.get('rule_id'))
                self.state.count_dropped()
                self._dropped_cnt += 1
                return False

        # Update counters
        cat = alert.get('category', '')
        if cat == 'file':     self.state.count_file_event()
        elif cat == 'usb':    self.state.count_usb_event()
        elif cat == 'edr':    self.state.count_edr_event()
        elif cat == 'malware': self.state.count_malware()

        # ── 7. Enqueue with priority ──────────────────────────────────────────
        seq = self._next_sequence()

        try:
            coalesce_key = (
                # State changes include closure evidence. Retain each change
                # during outages instead of replacing it with a later snapshot.
                '' if change_only_network_summary
                else self._inventory_coalesce_key if realtime_inventory
                else self._waf_status_coalesce_key if realtime_waf_status
                else self._exposure_coalesce_key if realtime_exposure
                else self._network_snapshot_coalesce_key if realtime_network_snapshot
                else self._dns_summary_coalesce_key if realtime_dns_summary
                else self._web_summary_coalesce_key if realtime_web_summary
                else self._browser_summary_coalesce_key if realtime_browser_summary
                else self._gps_location_coalesce_key if realtime_gps_location
                else ''
            )
            self._spool.put(alert, coalesce_key=coalesce_key)
            # Inventory and WAF heartbeats are mutable live state, not audit
            # events. Deliver the latest snapshot ahead of an old alert backlog.
            delivery_priority = 0 if live_status else pri
            self._queue_for_delivery(alert, delivery_priority, seq)
            return True
        except Exception as exc:
            logger.error('Durable spool rejected event_id=%s: %s', alert.get('event_id'), exc)
            self.state.count_dropped()
            self._dropped_cnt += 1
            return False

    def _next_sequence(self) -> int:
        """Return a process-unique FIFO tiebreaker for PriorityQueue entries."""
        with self._q_lock:
            self._q_counter += 1
            return self._q_counter

    def _queue_for_delivery(self, alert: dict, priority=None, sequence=None) -> bool:
        event_id = str(alert.get('event_id') or '')
        if sequence is None:
            sequence = self._next_sequence()
        with self._q_lock:
            if event_id in self._queued_ids:
                return False
            self._queued_ids.add(event_id)
        try:
            self._q.put_nowait((
                SEV_PRIORITY.get(alert.get('severity', 'medium'), 2) if priority is None else priority,
                sequence,
                alert,
            ))
            return True
        except Full:
            with self._q_lock:
                self._queued_ids.discard(event_id)
            return False

    def _refill_from_spool(self):
        available = max(0, QUEUE_MAX - self._q.qsize())
        if not available:
            return 0
        added = 0
        for alert in self._spool.due(min(available, BATCH_SIZE * 10)):
            if self._queue_for_delivery(alert):
                added += 1
        return added

    # ── VT enrichment (async, respects rate limits) ───────────────────────────
    def _enrich(self, alert: dict) -> dict:
        """VT scan in worker thread. Re-applies VT rules after scan result."""
        if not self._vt:
            return alert
        # Skip enrichment under queue pressure — prioritize throughput
        if self._q.qsize() > QUEUE_HIGH // 2:
            return alert

        cat = alert.get('category', '')
        r   = None
        try:
            if cat in ('malware', 'file', 'usb'):
                h = alert.get('file_hash')
                p = alert.get('file_path')
                if h:
                    r = self._vt.scan_hash(h, p or '')
                elif p:
                    r = self._vt.scan_file(p)
        except Exception as e:
            logger.debug('VT enrich error: %s', e)

        if r:
            alert['virustotal'] = r
            detections = r.get('malicious', 0) + r.get('suspicious', 0)
            verdict, new_sev, is_malware = _vt_verdict_and_severity(detections)

            # RE-APPLY VT rules with fresh data
            if detections == 0:
                # STRICT: VT=0 → NOT malware
                if alert.get('category') == 'malware':
                    alert['category'] = 'file'
                    logger.info(
                        'VT=0 STRICT: downgraded %s from malware → file [CLEAN]',
                        alert.get('rule_id')
                    )
                alert['severity'] = 'low'
            else:
                alert['severity'] = new_sev
                if is_malware:
                    alert['category'] = 'malware'
                    self.state.count_malware()

            logger.info(
                'VT %s: %s/%s engines (%s) → %s',
                alert.get('rule_id'),
                r.get('malicious', 0) + r.get('suspicious', 0),
                r.get('total_engines', '?'),
                r.get('verdict'),
                alert.get('severity'),
            )

        return alert

    # ── Build backend payload ─────────────────────────────────────────────────
    def _build_payload(self, alert: dict) -> dict:
        cfg = self.config
        p: Dict[str, Any] = {
            'agent_key':     cfg.get('agent_key', ''),
            'event_id':      alert.get('event_id'),
            'company_id':    cfg.get('company_id', ''),
            'department_id': cfg.get('department_id', ''),
            'system_id':     cfg.get('system_id', ''),
            'system_name':   cfg.get('system_name', 'unknown'),
            'endpointId':     alert.get('endpointId') or alert.get('endpoint_id') or cfg.get('system_id', ''),
            'hostname':       alert.get('hostname') or cfg.get('hostname') or cfg.get('system_name', 'unknown'),
            'osType':         alert.get('osType') or alert.get('os_type') or platform.system(),
            'agentVersion':   cfg.get('agent_version', ''),
            'capabilityId':   alert.get('capabilityId') or alert.get('capability_id'),
            'capabilityIds':  alert.get('capabilityIds') or alert.get('capability_ids'),
            'subCategory':    alert.get('subCategory') or alert.get('sub_category'),
            'eventType':      alert.get('eventType') or alert.get('event_type'),
            'module':         alert.get('module'),
            'source_type':    alert.get('source_type'),
            'event_category': alert.get('event_category'),
            'type':           alert.get('type'),
            'attackType':     alert.get('attackType') or alert.get('attack_type'),
            'signatureName':  alert.get('signatureName') or alert.get('signature_name'),
            'riskScore':      alert.get('riskScore') or alert.get('risk_score'),
            # UEBA metadata and privacy-safe aggregate input rates. No key
            # values, text, cursor coordinates, clipboard or screen content.
            'behaviorCategory': alert.get('behaviorCategory') or alert.get('behavior_category'),
            'entityType': alert.get('entityType') or alert.get('entity_type'),
            'entityId': alert.get('entityId') or alert.get('entity_id'),
            'behaviorScore': alert.get('behaviorScore') if 'behaviorScore' in alert else alert.get('behavior_score'),
            'baselineScore': alert.get('baselineScore') if 'baselineScore' in alert else alert.get('baseline_score'),
            'peerDeviationScore': alert.get('peerDeviationScore') if 'peerDeviationScore' in alert else alert.get('peer_deviation_score'),
            'uebaConfidence': alert.get('uebaConfidence') if 'uebaConfidence' in alert else alert.get('ueba_confidence'),
            'uebaRiskFactors': alert.get('uebaRiskFactors') or alert.get('ueba_risk_factors'),
            'baselineWindowDays': alert.get('baselineWindowDays') if 'baselineWindowDays' in alert else alert.get('baseline_window_days'),
            'inputMonitoringAvailable': alert.get('inputMonitoringAvailable') if 'inputMonitoringAvailable' in alert else alert.get('input_monitoring_available'),
            'inputPrivacyMode': alert.get('inputPrivacyMode') or alert.get('input_privacy_mode'),
            'inputKeyboardEvents': alert.get('inputKeyboardEvents') if 'inputKeyboardEvents' in alert else alert.get('input_keyboard_events'),
            'inputMouseEvents': alert.get('inputMouseEvents') if 'inputMouseEvents' in alert else alert.get('input_mouse_events'),
            'inputClickCount': alert.get('inputClickCount') if 'inputClickCount' in alert else alert.get('input_click_count'),
            'inputScrollCount': alert.get('inputScrollCount') if 'inputScrollCount' in alert else alert.get('input_scroll_count'),
            'inputKeyboardRate': alert.get('inputKeyboardRate') if 'inputKeyboardRate' in alert else alert.get('input_keyboard_rate'),
            'inputMouseRate': alert.get('inputMouseRate') if 'inputMouseRate' in alert else alert.get('input_mouse_rate'),
            'inputActivityPercent': alert.get('inputActivityPercent') if 'inputActivityPercent' in alert else alert.get('input_activity_percent'),
            'inputProfileStatus': alert.get('inputProfileStatus') or alert.get('input_profile_status'),
            'inputBaselineDays': alert.get('inputBaselineDays') if 'inputBaselineDays' in alert else alert.get('input_baseline_days'),
            'inputIdentityConfidence': alert.get('inputIdentityConfidence') if 'inputIdentityConfidence' in alert else alert.get('input_identity_confidence'),
            'inputProfileMismatch': alert.get('inputProfileMismatch') if 'inputProfileMismatch' in alert else alert.get('input_profile_mismatch'),
            'inputProfileMismatchFeatures': alert.get('inputProfileMismatchFeatures') or alert.get('input_profile_mismatch_features'),
            'inputProfileDeviation': alert.get('inputProfileDeviation') or alert.get('input_profile_deviation'),
            'inputUserSource': alert.get('inputUserSource') or alert.get('input_user_source'),
            'inputUserVerified': alert.get('inputUserVerified') if 'inputUserVerified' in alert else alert.get('input_user_verified'),
            'inputSessionCount': alert.get('inputSessionCount') if 'inputSessionCount' in alert else alert.get('input_session_count'),
            'insiderSignalType': alert.get('insiderSignalType') or alert.get('insider_signal_type')
                or (alert.get('raw', {}).get('insider_signal_type') if isinstance(alert.get('raw'), dict) else None),
            # Email capability metadata. Endpoint collection deliberately has
            # less message-level detail than an authorized mail API connector.
            'emailSender':    alert.get('emailSender') or alert.get('email_sender') or alert.get('sender'),
            'emailRecipient': alert.get('emailRecipient') or alert.get('email_recipient') or alert.get('recipient'),
            'emailSubject':   alert.get('emailSubject') or alert.get('email_subject') or alert.get('subject'),
            'emailDirection': alert.get('emailDirection') or alert.get('email_direction'),
            'emailMessageId': alert.get('emailMessageId') or alert.get('email_message_id') or alert.get('message_id'),
            'emailAuth':      alert.get('emailAuth') or alert.get('email_auth'),
            'mailboxEventType': alert.get('mailboxEventType') or alert.get('mailbox_event_type'),
            'attachmentMimeType': alert.get('attachmentMimeType') or alert.get('attachment_mime_type') or alert.get('mime_type'),
            'attachmentSize': alert.get('attachmentSize') or alert.get('attachment_size'),
            # Lateral movement and remote-session evidence.
            'lateralVector': alert.get('lateralVector') or alert.get('lateral_vector') or alert.get('vector'),
            'sourceHost': alert.get('sourceHost') or alert.get('source_host') or alert.get('src_host'),
            'destinationHost': alert.get('destinationHost') or alert.get('destination_host') or alert.get('dst_host'),
            'authProtocol': alert.get('authProtocol') or alert.get('auth_protocol') or alert.get('auth_method'),
            'shareName': alert.get('shareName') or alert.get('share_name') or alert.get('share'),
            'sessionState': alert.get('sessionState') or alert.get('session_state'),
            'windowsEventId': alert.get('windowsEventId') or alert.get('windows_event_id'),
            'attackPathId': alert.get('attackPathId') or alert.get('attack_path_id'),
            'relatedEventIds': alert.get('relatedEventIds') or alert.get('related_event_ids'),
            # Credential security and identity evidence. Never contains secrets.
            'credentialEventType': alert.get('credentialEventType') or alert.get('credential_event_type'),
            'authType': alert.get('authType') or alert.get('auth_type') or alert.get('auth_method')
                or (alert.get('raw', {}).get('auth_method') if isinstance(alert.get('raw'), dict) else None),
            'userAction': alert.get('userAction') or alert.get('user_action')
                or (alert.get('raw', {}).get('auth_action') if isinstance(alert.get('raw'), dict) else None),
            'authResult': alert.get('authResult') or alert.get('auth_result'),
            'failureReason': alert.get('failureReason') or alert.get('failure_reason'),
            'sessionId': alert.get('sessionId') or alert.get('session_id'),
            'deviceId': alert.get('deviceId') or alert.get('device_id'),
            'mfaStatus': alert.get('mfaStatus') or alert.get('mfa_status'),
            'identityProvider': alert.get('identityProvider') or alert.get('identity_provider'),
            'privilegeLevel': alert.get('privilegeLevel') or alert.get('privilege_level'),
            'logonType': alert.get('logonType') or alert.get('logon_type')
                or (alert.get('raw', {}).get('logon_type') if isinstance(alert.get('raw'), dict) else None),
            'groupName': alert.get('groupName') or alert.get('group_name') or alert.get('group'),
            'targetUser': alert.get('targetUser') or alert.get('target_user'),
            'endpointType': alert.get('endpointType') or alert.get('endpoint_type')
                or (alert.get('raw', {}).get('host_type') if isinstance(alert.get('raw'), dict) else None),
            'credentialTarget': alert.get('credentialTarget') or alert.get('credential_target'),
            'tokenType': alert.get('tokenType') or alert.get('token_type'),
            # Data-security/DLP evidence. Values are metadata and classifications;
            # matched content and clipboard/file bodies are never transmitted.
            'dataEventType': alert.get('dataEventType') or alert.get('data_event_type'),
            'dataClassification': alert.get('dataClassification') or alert.get('data_classification'),
            'dlpPattern': alert.get('dlpPattern') or alert.get('dlp_pattern'),
            'dlpMatchCount': alert.get('dlpMatchCount') or alert.get('dlp_match_count'),
            'transferChannel': alert.get('transferChannel') or alert.get('transfer_channel'),
            'destinationDomain': alert.get('destinationDomain') or alert.get('destination_domain'),
            'transferProtocol': alert.get('transferProtocol') or alert.get('transfer_protocol'),
            'status':         alert.get('status'),
            'sourcePath':     alert.get('sourcePath') or alert.get('source_path'),
            'keyPath':        alert.get('keyPath') or alert.get('key_path') or alert.get('registry_key'),
            'oldValue':       alert.get('oldValue') or alert.get('old_value'),
            'newValue':       alert.get('newValue') or alert.get('new_value'),
            # Capability 6 normalized registry/configuration evidence.
            'configurationCategory': alert.get('configurationCategory') or alert.get('configuration_category'),
            'configurationOperation': alert.get('configurationOperation') or alert.get('configuration_operation'),
            'configurationObject': alert.get('configurationObject') or alert.get('configuration_object'),
            'configurationPlatform': alert.get('configurationPlatform') or alert.get('configuration_platform'),
            'configurationBaselineStatus': alert.get('configurationBaselineStatus') or alert.get('configuration_baseline_status'),
            'configurationPolicyViolation': alert.get('configurationPolicyViolation') if 'configurationPolicyViolation' in alert else alert.get('configuration_policy_violation'),
            'configurationRiskFactors': alert.get('configurationRiskFactors') or alert.get('configuration_risk_factors'),
            'registryHive': alert.get('registryHive') or alert.get('registry_hive'),
            'registryValueName': alert.get('registryValueName') or alert.get('registry_value_name') or alert.get('value_name'),
            'registryValueType': alert.get('registryValueType') or alert.get('registry_value_type') or alert.get('value_type'),
            'processAttribution': alert.get('processAttribution') or alert.get('process_attribution'),
            'persistenceType': alert.get('persistenceType') or alert.get('persistence_type'),
            'persistenceLocation': alert.get('persistenceLocation') or alert.get('persistence_location'),
            'persistenceKey': alert.get('persistenceKey') or alert.get('persistence_key'),
            'persistenceValue': alert.get('persistenceValue') or alert.get('persistence_value'),
            'persistenceTrigger': alert.get('persistenceTrigger') or alert.get('persistence_trigger'),
            'persistenceAction': alert.get('persistenceAction') or alert.get('persistence_action'),
            'oldHash':        alert.get('oldHash') or alert.get('old_hash') or alert.get('previous_hash'),
            'newHash':        alert.get('newHash') or alert.get('new_hash'),
            'old_hash':       alert.get('old_hash') or alert.get('oldHash') or alert.get('previous_hash'),
            'new_hash':       alert.get('new_hash') or alert.get('newHash'),
            'hash_algorithm': alert.get('hash_algorithm') or alert.get('hashAlgorithm'),
            'hash':           alert.get('hash') or alert.get('sha256'),
            'recommendedAction': alert.get('recommendedAction') or alert.get('recommended_action'),
            'mitreId':        alert.get('mitreId') or alert.get('mitre_id'),
            'technique':      alert.get('technique'),
            'mitreTactic':    alert.get('mitreTactic') or alert.get('mitre_tactic'),
            'mitreTechniques': alert.get('mitreTechniques') or alert.get('mitre_techniques'),
            'rule_id':       alert.get('rule_id', ''),
            'category':      alert.get('category', 'other'),
            'severity':      alert.get('severity', 'medium'),
            'description':   alert.get('description', ''),
            'source':        alert.get('log_source', '') or alert.get('source', ''),
            'raw_log':       _redact_command_line(alert.get('raw_log', '')),
            'raw':           _redact_sensitive_payload(alert.get('raw')),
            'timestamp':     alert.get('timestamp') or datetime.now(timezone.utc).isoformat(),
            # Network
            'src_ip':   alert.get('src_ip') or alert.get('source_ip'),
            'dst_ip':   alert.get('dst_ip') or alert.get('dest_ip'),
            'destinationIps': alert.get('destinationIps') or alert.get('destination_ips'),
            'src_port': alert.get('src_port'),
            'dst_port': alert.get('dst_port'),
            'packet_count': alert.get('packet_count'),
            'action':   alert.get('action'),
            'agentIP':  alert.get('agent_ip') or alert.get('agentIP'),
            'detectedPorts': alert.get('detected_ports') or alert.get('detectedPorts'),
            'monitoredServices': alert.get('monitored_services') or alert.get('monitoredServices'),
            'wafIntercept': alert.get('waf_intercept') if 'waf_intercept' in alert else alert.get('wafIntercept'),
            'requestPath': alert.get('requestPath') or alert.get('request_path') or alert.get('path'),
            'method': alert.get('method'),
            'matched': alert.get('matched'),
            'statusCode': alert.get('statusCode') or alert.get('status_code'),
            'backendService': alert.get('backendService') or alert.get('backend_service'),
            'backendError': alert.get('backendError') or alert.get('backend_error'),
            'sensor':   alert.get('sensor'),
            'protocol': alert.get('protocol'),
            'domain': alert.get('domain') or alert.get('query') or alert.get('dns_query'),
            'url': alert.get('url') or alert.get('target_url'),
            'httpMethod': alert.get('httpMethod') or alert.get('http_method') or alert.get('request_method'),
            'responseTime': alert.get('responseTime') or alert.get('response_time') or alert.get('query_time'),
            'requestSize': alert.get('requestSize') or alert.get('request_size'),
            'responseSize': alert.get('responseSize') or alert.get('response_size'),
            'browser': alert.get('browser'),
            'userAgent': alert.get('userAgent') or alert.get('user_agent'),
            'referrer': alert.get('referrer') or alert.get('referer'),
            'tlsVersion': alert.get('tlsVersion') or alert.get('tls_version'),
            'certificateInfo': alert.get('certificateInfo') or alert.get('certificate_info'),
            'resolver': alert.get('resolver') or alert.get('dns_server'),
            'queryTime': alert.get('queryTime') or alert.get('query_time'),
            'queryType': alert.get('queryType') or alert.get('query_type'),
            'responseCode': alert.get('responseCode') or alert.get('response_code'),
            'responseType': alert.get('responseType') or alert.get('response_type'),
            'responseIp': alert.get('responseIp') or alert.get('response_ip') or alert.get('answer_ip'),
            'expectedIp': alert.get('expectedIp') or alert.get('expected_ip') or alert.get('known_good_ip'),
            # Native device-location evidence. Preserve numeric zeroes because
            # latitude/longitude 0 are valid coordinates.
            'gpsLat': alert.get('gpsLat') if 'gpsLat' in alert else alert.get('gps_lat'),
            'gpsLon': alert.get('gpsLon') if 'gpsLon' in alert else alert.get('gps_lon'),
            'gpsAccuracyMeters': alert.get('gpsAccuracyMeters') if 'gpsAccuracyMeters' in alert else alert.get('gps_accuracy_meters'),
            'gpsAltitudeMeters': alert.get('gpsAltitudeMeters') if 'gpsAltitudeMeters' in alert else alert.get('gps_altitude_meters'),
            'gpsProvider': alert.get('gpsProvider') or alert.get('gps_provider'),
            'gpsStatus': alert.get('gpsStatus') or alert.get('gps_status'),
            'gpsReason': alert.get('gpsReason') or alert.get('gps_reason'),
            'gpsObservedAt': alert.get('gpsObservedAt') or alert.get('gps_observed_at'),
            'detectionType': alert.get('detectionType') or alert.get('detection_type') or alert.get('eventType') or alert.get('event_type'),
            'detectionEvidence': alert.get('detectionEvidence') or alert.get('detection_evidence') or alert.get('evidence'),
            'detectionReason': alert.get('detectionReason') or alert.get('detection_reason') or alert.get('reason'),
            'sinkholeIp': alert.get('sinkholeIp') or alert.get('sinkhole_ip'),
            'threatCategory': alert.get('threatCategory') or alert.get('threat_category'),
            'iocMatched': alert.get('iocMatched') if 'iocMatched' in alert else alert.get('ioc_matched'),
            'reputationScore': alert.get('reputationScore') or alert.get('reputation_score'),
            'confidenceScore': alert.get('confidenceScore') or alert.get('confidence_score'),
            'connectionCount': alert.get('connectionCount') or alert.get('connection_count'),
            'retryCount': alert.get('retryCount') or alert.get('retry_count'),
            'averageInterval': alert.get('averageInterval') or alert.get('average_interval'),
            'medianInterval': alert.get('medianInterval') or alert.get('median_interval'),
            'jitterSeconds': alert.get('jitterSeconds') or alert.get('jitter_seconds'),
            'intervalConsistency': alert.get('intervalConsistency') or alert.get('interval_consistency'),
            'periodicityScore': alert.get('periodicityScore') or alert.get('periodicity_score'),
            'observationSeconds': alert.get('observationSeconds') or alert.get('observation_seconds'),
            'bytesSent': alert.get('bytesSent') or alert.get('bytes_sent'),
            'bytesReceived': alert.get('bytesReceived') or alert.get('bytes_received'),
            'connectionId': alert.get('connectionId') or alert.get('connection_id'),
            'connectionState': alert.get('connectionState') or alert.get('connection_state') or alert.get('state'),
            'connectionStartTime': alert.get('connectionStartTime') or alert.get('connection_start_time') or alert.get('start_time'),
            'connectionEndTime': alert.get('connectionEndTime') or alert.get('connection_end_time') or alert.get('end_time'),
            'connectionDuration': alert.get('connectionDuration') or alert.get('connection_duration') or alert.get('duration'),
            'networkInterface': alert.get('networkInterface') or alert.get('network_interface') or alert.get('interface'),
            'networkAdapter': alert.get('networkAdapter') or alert.get('network_adapter'),
            'ipVersion': alert.get('ipVersion') or alert.get('ip_version'),
            'ttl': alert.get('ttl') or alert.get('new_ttl'),
            'previousTtl': alert.get('previousTtl') or alert.get('previous_ttl') or alert.get('old_ttl'),
            'blocked':  alert.get('blocked', False),
            'inbound':  alert.get('inbound'),
            # File
            'file_path':     alert.get('file_path'),
            'file_name':     alert.get('file_name'),
            'file_hash':     alert.get('file_hash'),
            'file_hash_md5': alert.get('file_hash_md5'),
            'file_action':   alert.get('file_action'),
            'file_user':     alert.get('file_user'),
            'module_type':   alert.get('module_type') or alert.get('moduleType'),
            'fim_module':    alert.get('fim_module') or alert.get('fimModule'),
            'change_type':   alert.get('change_type') or alert.get('changeType'),
            'old_permission': alert.get('old_permission') or alert.get('oldPermission'),
            'new_permission': alert.get('new_permission') or alert.get('newPermission'),
            'permission_risk': alert.get('permission_risk') or alert.get('permissionRisk'),
            'changed_by_user': alert.get('changed_by_user') or alert.get('changedByUser'),
            'old_owner':     alert.get('old_owner') or alert.get('oldOwner'),
            'new_owner':     alert.get('new_owner') or alert.get('newOwner'),
            'old_group':     alert.get('old_group') or alert.get('oldGroup'),
            'new_group':     alert.get('new_group') or alert.get('newGroup'),
            'sensitivity_type': alert.get('sensitivity_type') or alert.get('sensitivityType'),
            'file_size':       alert.get('file_size') or alert.get('fileSize'),
            'bytes_transferred': alert.get('bytes_transferred') or alert.get('bytesTransferred'),
            'accessed_by_user': alert.get('accessed_by_user') or alert.get('accessedByUser'),
            'permission_status': alert.get('permission_status') or alert.get('permissionStatus'),
            'extension_changed': alert.get('extension_changed') if 'extension_changed' in alert else alert.get('extensionChanged'),
            'mass_rename_count': alert.get('mass_rename_count') or alert.get('massRenameCount'),
            'encryption_indicator': alert.get('encryption_indicator') if 'encryption_indicator' in alert else alert.get('encryptionIndicator'),
            'entropy': alert.get('entropy'),
            'affectedFiles': alert.get('affectedFiles') or alert.get('affected_files'),
            'affectedDirectory': alert.get('affectedDirectory') or alert.get('affected_directory'),
            'extension': alert.get('extension'),
            'encryptionSpeed': alert.get('encryptionSpeed') or alert.get('encryption_speed'),
            'modifiedFilesPerSecond': alert.get('modifiedFilesPerSecond') or alert.get('modified_files_per_second'),
            'deletedFilesPerSecond': alert.get('deletedFilesPerSecond') or alert.get('deleted_files_per_second'),
            'renamedFilesPerSecond': alert.get('renamedFilesPerSecond') or alert.get('renamed_files_per_second'),
            # Malware
            'malware_type': alert.get('malware_type'),
            'quarantined':  alert.get('quarantined', False),
            'yara_rules':   alert.get('yara_rules'),
            # Process / EDR
            'process_name':        alert.get('process_name') or alert.get('processName'),
            'pid':                 alert.get('pid'),
            'parent_pid':          alert.get('parent_pid') or alert.get('parentPid'),
            'parent_process_name': alert.get('parent_process_name') or alert.get('parentProcessName'),
            'parent_cmdline':      _redact_command_line(alert.get('parent_cmdline') or alert.get('parentCommandLine')),
            'parent_username':     alert.get('parent_username') or alert.get('parentUsername'),
            'process_cmdline':     _redact_command_line(alert.get('process_cmdline') or alert.get('processCmdline') or alert.get('cmdline')),
            'process_exe':         alert.get('process_exe') or alert.get('processExe') or alert.get('exe'),
            'source_process_name': alert.get('source_process_name') or alert.get('sourceProcessName'),
            'source_pid':          alert.get('source_pid') or alert.get('sourcePid'),
            'target_process_name': alert.get('target_process_name') or alert.get('targetProcessName'),
            'target_pid':          alert.get('target_pid') or alert.get('targetPid'),
            'granted_access':      alert.get('granted_access') or alert.get('grantedAccess'),
            'call_trace':          alert.get('call_trace') or alert.get('callTrace'),
            'memory_protection':   alert.get('memory_protection') or alert.get('memoryProtection') or alert.get('protection'),
            'risk_score':          alert.get('risk_score') or alert.get('riskScore'),
            'matched_patterns':    alert.get('matched_patterns') or alert.get('matchedPatterns'),
            'is_network':          alert.get('is_network') or alert.get('isNetwork'),
            'is_persistence':      alert.get('is_persistence') or alert.get('isPersistence'),
            'cpu_percent':         alert.get('cpu_percent'),
            'memory_percent':      alert.get('memory_percent'),
            'memory_mb':           alert.get('memory_mb'),
            'memory_metric_type':  alert.get('memory_metric_type'),
            'memory_total_bytes':  alert.get('memory_total_bytes'),
            'memory_used_bytes':   alert.get('memory_used_bytes'),
            'memory_available_bytes': alert.get('memory_available_bytes'),
            'commit_charge_bytes': alert.get('commit_charge_bytes'),
            'memory_pressure':     alert.get('memory_pressure'),
            'swap_total_bytes':    alert.get('swap_total_bytes'),
            'swap_used_bytes':     alert.get('swap_used_bytes'),
            'swap_percent':        alert.get('swap_percent'),
            'page_faults':         alert.get('page_faults'),
            'major_page_faults':   alert.get('major_page_faults'),
            'paging_rate':         alert.get('paging_rate'),
            'oom_events':          alert.get('oom_events'),
            'container_memory_bytes': alert.get('container_memory_bytes'),
            'container_memory_limit_bytes': alert.get('container_memory_limit_bytes'),
            'container_oom_events': alert.get('container_oom_events'),
            'process_rss_bytes':   alert.get('process_rss_bytes'),
            'virtual_memory_bytes': alert.get('virtual_memory_bytes'),
            'private_working_set_bytes': alert.get('private_working_set_bytes'),
            'shared_memory_bytes': alert.get('shared_memory_bytes'),
            'peak_memory_bytes':   alert.get('peak_memory_bytes'),
            'memory_growth_bytes': alert.get('memory_growth_bytes'),
            'memory_growth_percent': alert.get('memory_growth_percent'),
            'memory_allocation_rate': alert.get('memory_allocation_rate'),
            'thread_count':        alert.get('thread_count'),
            'handle_count':        alert.get('handle_count'),
            'crash_count':         alert.get('crash_count'),
            'restart_count':       alert.get('restart_count'),
            'executable_region_count': alert.get('executable_region_count'),
            'rwx_region_count':    alert.get('rwx_region_count'),
            'detection_rule_id':  alert.get('detection_rule_id') or alert.get('detectionRuleId'),
            'confidence_score':    alert.get('confidenceScore') or alert.get('confidence_score'),
            'actionable':          alert.get('actionable'),
            'is_simulated':        alert.get('is_simulated', False),
            'disk_read_bytes':     alert.get('disk_read_bytes'),
            'disk_write_bytes':    alert.get('disk_write_bytes'),
            'disk_read_bytes_per_second': alert.get('disk_read_bytes_per_second'),
            'disk_write_bytes_per_second': alert.get('disk_write_bytes_per_second'),
            'network_connection_count': alert.get('network_connection_count'),
            'external_connection_count': alert.get('external_connection_count'),
            'remote_addresses':    alert.get('remote_addresses'),
            'unique_remote_ip_count': alert.get('unique_remote_ip_count'),
            'unique_remote_port_count': alert.get('unique_remote_port_count'),
            'private_remote_ip_count': alert.get('private_remote_ip_count'),
            'process_classifications': alert.get('process_classifications'),
            'executable_sha256':   alert.get('executable_sha256'),
            'signature_status':    alert.get('signature_status'),
            'trust_status':        alert.get('trust_status'),
            'publisher':           alert.get('publisher'),
            'package_owner':       alert.get('package_owner'),
            'package_verification_status': alert.get('package_verification_status'),
            'cmdline':             _redact_command_line(alert.get('cmdline')),
            'exe':                 alert.get('exe'),
            'process_status':      alert.get('process_status'),
            'process_create_time': alert.get('process_create_time'),
            'process_end_time':    alert.get('process_end_time') or alert.get('end_time'),
            'process_exit_code':   alert.get('process_exit_code') if 'process_exit_code' in alert else alert.get('exit_code'),
            'integrity_level':     alert.get('integrity_level'),
            'process_file_company': alert.get('process_file_company') or alert.get('company'),
            'process_file_version': alert.get('process_file_version') or alert.get('version'),
            'executable_md5':      alert.get('executable_md5') or alert.get('file_hash_md5'),
            'user_domain':         alert.get('user_domain') or alert.get('endpoint_domain'),
            'process_count':       alert.get('process_count'),
            'username':            alert.get('username'),
            'user_action':         alert.get('user_action'),
            # Source tag (lolbins / ransomware / auto_response)
            'source_tag':          alert.get('source'),
            # USB
            'device':       alert.get('device'),
            'device_name':  alert.get('device_name'),
            'mount_path':   alert.get('mount_path'),
            'vendor':       alert.get('vendor'),
            'serial_number': alert.get('serial_number'),
            'vid':          alert.get('vid'),
            'product_id':   alert.get('product_id'),
            'device_type':  alert.get('device_type'),
            'file_size':    alert.get('file_size'),
            'bytes_transferred': alert.get('bytes_transferred'),
            'policy_name':  alert.get('policy_name'),
            'action_taken': alert.get('action_taken'),
            'policy_id':    alert.get('policy_id'),
            'policy_rule_type': alert.get('policy_rule_type'),
            'driver_name':  alert.get('driver_name'),
            'sensitivity_type': alert.get('sensitivity_type'),
            'enforcement_status': alert.get('enforcement_status'),
            'enforcement_error': alert.get('enforcement_error'),
            # VT
            'virustotal':   alert.get('virustotal'),
            # Meta flags
            'under_observation': alert.get('_under_observation', False),
            'vt_override':       alert.get('_vt_override', False),
        }
        return {k: v for k, v in p.items() if v is not None and v != ''}

    # ── Send batch ────────────────────────────────────────────────────────────
    def _send_batch(self, alerts: list) -> bool:
        if not HAS_REQUESTS:
            logger.error('requests not installed — pip3 install requests')
            return False

        base = (self.config.get('server_url') or
                'http://{}:{}'.format(
                    self.config.get('server_ip', 'localhost'),
                    self.config.get('server_port', 5000)))
        # Try batch endpoint first (≥2 alerts)
        if len(alerts) > 1:
            try:
                payloads = [self._build_payload(a) for a in alerts]
                batch_payload = {'alerts': payloads}
                r = secure_request(self.config, 'POST',
                    base.rstrip('/') + '/api/alerts/batch',
                    json=batch_payload,
                    headers=signed_headers(self.config, batch_payload),
                    timeout=SEND_TIMEOUT,
                )
                if r.status_code in (200, 201, 202):
                    logger.info('✓ Batch [%d alerts]', len(alerts))
                    return True
                if r.status_code == 404:
                    pass   # batch endpoint not available
                else:
                    logger.warning('Batch rejected %s: %s', r.status_code, r.text[:120])
                    return False
            except requests.RequestException as e:
                logger.warning('Batch send failed: %s', e)
                return False

        # Single-alert fallback
        ok = True
        for alert in alerts:
            payload = self._build_payload(alert)
            try:
                r = secure_request(self.config, 'POST',
                    base.rstrip('/') + '/api/alerts',
                    json=payload,
                    headers=signed_headers(self.config, payload),
                    timeout=SEND_TIMEOUT,
                )
                if r.status_code in (200, 201, 202):
                    logger.info('✓ [%s][%s] %s',
                        payload.get('severity', '?'),
                        payload.get('category', '?'),
                        payload.get('rule_id', '?'))
                else:
                    logger.warning('Rejected %s: %s', r.status_code, r.text[:120])
                    ok = False
            except requests.RequestException as e:
                logger.warning('Send failed: %s', e)
                ok = False
        return ok

    def report_response_result(self, response_id: str, command_id: str, ok: bool,
                               result: str, duration_ms: int = 0, exit_code=None) -> bool:
        """Report a signed, structured automated-response result to the SOC API."""
        if not HAS_REQUESTS or not response_id or not command_id:
            return False
        base = (self.config.get('server_url') or 'http://{}:{}'.format(
            self.config.get('server_ip', 'localhost'), self.config.get('server_port', 5000)))
        payload = {
            'agent_key': self.config.get('agent_key', ''),
            'responseId': response_id,
            'commandId': command_id,
            'ok': bool(ok),
            'result': str(result or '')[:2000],
            'durationMs': max(0, int(duration_ms or 0)),
        }
        if exit_code is not None:
            payload['exitCode'] = exit_code
        try:
            response = secure_request(self.config, 'POST',
                base.rstrip('/') + '/api/agent/response-result', json=payload,
                headers=signed_headers(self.config, payload), timeout=SEND_TIMEOUT,
            )
            if response.status_code in (200, 201, 202):
                return True
            logger.warning('Response result rejected %s: %s', response.status_code, response.text[:120])
        except requests.RequestException as exc:
            logger.warning('Response result delivery failed: %s', exc)
        return False

    def report_response_status(self, response_id: str, command_id: str, status: str) -> bool:
        if not HAS_REQUESTS or status not in ('acknowledged', 'executing'):
            return False
        base = (self.config.get('server_url') or 'http://{}:{}'.format(
            self.config.get('server_ip', 'localhost'), self.config.get('server_port', 5000)))
        payload = {'agent_key': self.config.get('agent_key', ''), 'responseId': response_id, 'commandId': command_id, 'status': status}
        try:
            response = secure_request(self.config, 'POST', base.rstrip('/') + '/api/agent/response-status', json=payload, headers=signed_headers(self.config, payload), timeout=SEND_TIMEOUT)
            return response.status_code in (200, 201, 202)
        except requests.RequestException:
            return False

    # ── Worker loop (priority-ordered processing) ─────────────────────────────
    def _record_failed(self, alerts: list, delay_seconds: float, error='delivery failed'):
        """Persist bounded retry state; exhausted events move to the local DLQ."""
        for alert in alerts:
            result = self._spool.fail(alert.get('event_id'), error, delay_seconds)
            if result == 'dead_letter':
                logger.error('Event moved to durable DLQ event_id=%s', alert.get('event_id'))

    def _loop(self):
        backoff = 1
        while True:
            batch: List[dict] = []
            try:
                # Block until at least one item (priority, seq, alert)
                pri, seq, first = self._q.get(timeout=2)
                batch.append(first)
                # Drain up to BATCH_SIZE - 1 more (non-blocking)
                while len(batch) < BATCH_SIZE:
                    try:
                        _, _, alert = self._q.get_nowait()
                        batch.append(alert)
                    except Empty:
                        break
            except Empty:
                self._refill_from_spool()
                continue

            with self._q_lock:
                for alert in batch:
                    self._queued_ids.discard(str(alert.get('event_id') or ''))

            # Enrich
            enriched: List[dict] = []
            # A large retry spool must drain through the backend instead of
            # re-running slow external VT lookups for every historical file
            # event. New live events resume normal enrichment once healthy.
            spool_pending = self._spool.counts().get('pending', 0)
            skip_external_enrichment = spool_pending > 1000
            for a in batch:
                try:
                    enriched.append(a if skip_external_enrichment else self._enrich(a))
                except Exception as e:
                    logger.error('Enrich error: %s', e)
                    enriched.append(a)

            # Send
            try:
                ok = self._send_batch(enriched)
                backoff = 1 if ok else min(backoff * 2, BACKOFF_MAX)
                if ok:
                    self._spool.acknowledge(a.get('event_id') for a in enriched)
                else:
                    self._record_failed(enriched, backoff)
                    time.sleep(backoff + random.uniform(0, min(1.0, backoff * 0.25)))
            except Exception as e:
                logger.error('Sender error: %s', e, exc_info=True)
                if enriched:
                    self._record_failed(enriched, backoff, str(e))
                time.sleep(min(backoff, BACKOFF_MAX))
                backoff = min(backoff * 2, BACKOFF_MAX)

            self._refill_from_spool()
            self.state.maybe_cleanup()
