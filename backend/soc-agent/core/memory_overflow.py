"""Defensive memory telemetry and overflow detection (capability 29).

The collector uses psutil, procfs/cgroup counters and operating-system logs.  It
never reads process memory and never captures dumps.  Optional telemetry sources
are best-effort so an unavailable provider cannot stop the agent.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
import time
from fnmatch import fnmatch
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import psutil
    HAS_PSUTIL = True
except Exception:  # pragma: no cover - optional on minimal installations
    psutil = None
    HAS_PSUTIL = False

CAPABILITY_ID = 29
MIB = 1024 * 1024

DEFAULTS = {
    'memory_collection_interval_seconds': 30,
    'memory_high_usage_threshold': 90.0,
    'memory_high_usage_duration_seconds': 300,
    'memory_spike_percent_threshold': 25.0,
    'memory_spike_window_seconds': 60,
    'memory_leak_window_minutes': 30,
    'memory_leak_min_samples': 10,
    'memory_leak_growth_percent': 30.0,
    'memory_alert_cooldown_seconds': 300,
    'memory_process_sample_limit': 75,
    'memory_process_metric_top_n': 10,
    'memory_crash_correlation_enabled': True,
}

EVENT_RULE_IDS = {
    'spike': 'MEM-002',
    'leak': 'MEM-003',
    'repeated_memory_crash': 'MEM-005',
    'oom_kill': 'MEM-011',
    'exhaustion': 'MEM-011',
    'stack_overflow': 'MEM-014',
    'stack_smash': 'MEM-014',
    'heap_overflow': 'MEM-014',
    'heap_corruption': 'MEM-014',
    'segmentation_fault': 'MEM-014',
    'access_violation': 'MEM-014',
    'out_of_bounds': 'MEM-014',
    'dep_violation': 'MEM-014',
}

CRASH_PATTERNS = [
    (re.compile(r'out of memory|oom-kill|killed process .* total-vm', re.I), 'oom_kill', 'critical', 'T1499'),
    (re.compile(r'segfault at|SIGSEGV|segmentation fault', re.I), 'segmentation_fault', 'high', 'T1203'),
    (re.compile(r'access violation|0xc0000005', re.I), 'access_violation', 'high', 'T1203'),
    (re.compile(r'SIGABRT|Aborted \(core dumped\)', re.I), 'application_crash', 'medium', 'T1203'),
    (re.compile(r'stack smashing detected|stack overflow|0xc00000fd', re.I), 'stack_overflow', 'critical', 'T1203'),
    (re.compile(r'heap corruption|heap-buffer-overflow|heap overflow|0xc0000374', re.I), 'heap_corruption', 'critical', 'T1203'),
    (re.compile(r'general protection fault|\bgpf\b', re.I), 'out_of_bounds', 'critical', 'T1203'),
    (re.compile(r'nx violation|exec-shield|DEP violation', re.I), 'dep_violation', 'critical', 'T1203'),
    (re.compile(r'AddressSanitizer|ASAN:', re.I), 'out_of_bounds', 'critical', 'T1203'),
]

LOG_PATHS = {
    'linux': ['/var/log/syslog', '/var/log/kern.log', '/var/log/messages'],
    'darwin': ['/var/log/system.log'],
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_number(value, default, minimum, maximum, cast=float):
    try:
        return max(minimum, min(maximum, cast(value)))
    except (TypeError, ValueError):
        return default


def severity_from_risk(risk_score: int) -> str:
    score = max(0, min(100, int(risk_score or 0)))
    if score >= 90:
        return 'critical'
    if score >= 70:
        return 'high'
    if score >= 40:
        return 'medium'
    return 'low'


def calculate_risk_score(finding: Dict) -> int:
    """Deterministic 0-100 risk scoring for normalized memory findings."""
    configured = finding.get('configured_risk_score')
    base = int(configured) if configured is not None else {
        'critical': 91, 'high': 70, 'medium': 40, 'low': 1,
    }.get(str(finding.get('severity') or 'high').lower(), 40)
    confidence = _bounded_number(finding.get('confidence'), 80, 0, 100, float)
    score = base + round(max(0.0, confidence - 50.0) * 0.125)
    target = str(finding.get('target_process') or finding.get('process') or '').lower()
    if target in {'lsass.exe', 'winlogon.exe', 'csrss.exe', 'securityhealthservice.exe'}:
        score += 10
    event_type = str(finding.get('type') or '').lower()
    if any(token in event_type for token in ('rwx', 'injection', 'remote_thread', 'hollowing', 'tampering')):
        score += 8
    score += min(5, max(0, int(finding.get('crash_count') or 1) - 1))
    if finding.get('allowlisted'):
        score -= 50
    if finding.get('maintenance_window'):
        score -= 25
    return max(0, min(100, int(score)))


class MemoryOverflowDetector:
    """Collects bounded metrics and produces correlation-ready detections."""

    def __init__(self, config=None):
        self.config = config
        self.os_type = platform.system().lower()
        self._log_pos: Dict[str, int] = {}
        self._history: Dict[Tuple[int, float], Deque[Tuple[float, int]]] = defaultdict(deque)
        self._last_alert: Dict[str, float] = {}
        self._high_since: Optional[float] = None
        self._crash_history: Dict[str, Deque[float]] = defaultdict(deque)
        self._findings: List[Dict] = []
        self._last_vmstat: Optional[Tuple[float, Dict[str, int]]] = None

    def _cfg(self, key):
        value = None
        try:
            value = self.config.get(key) if self.config is not None else None
        except Exception:
            value = None
        if value in (None, ''):
            env_name = key.upper()
            value = os.getenv(env_name, DEFAULTS[key])
        default = DEFAULTS[key]
        if isinstance(default, bool):
            if isinstance(value, str):
                normalized = value.strip().lower()
                if normalized in {'1', 'true', 'yes', 'on'}:
                    return True
                if normalized in {'0', 'false', 'no', 'off'}:
                    return False
                return default
            return bool(value)
        if isinstance(default, int):
            return int(_bounded_number(value, default, 1, 86400, int))
        return float(_bounded_number(value, default, 0.0, 100000.0, float))

    @property
    def collection_interval_seconds(self):
        return self._cfg('memory_collection_interval_seconds')

    def _cooldown_allows(self, key: str, now: float) -> bool:
        cooldown = self._cfg('memory_alert_cooldown_seconds')
        if now - self._last_alert.get(key, 0) < cooldown:
            return False
        self._last_alert[key] = now
        return True

    def _rule_allows(self, finding: Dict) -> bool:
        rule_id = EVENT_RULE_IDS.get(str(finding.get('type') or '').lower())
        finding['detection_rule_id'] = rule_id
        try:
            rules = self.config.get('memory_detection_rules', []) if self.config is not None else []
        except Exception:
            rules = []
        if not isinstance(rules, list) or not rules or not rule_id:
            return True
        rule = next((item for item in rules if item.get('rule_id') == rule_id), None)
        if not rule:
            return True
        if rule.get('enabled') is False:
            return False
        os_scope = [str(item).lower() for item in (rule.get('operating_systems') or [])]
        if os_scope and self.os_type not in os_scope:
            return False
        process = str(finding.get('process') or finding.get('exe') or '').lower()
        patterns = list(rule.get('process_exclusions') or []) + list(rule.get('allowlist') or [])
        if process and any(fnmatch(process, str(pattern).lower()) for pattern in patterns):
            return False
        now = datetime.now(timezone.utc)
        for window in rule.get('maintenance_windows') or []:
            try:
                starts = datetime.fromisoformat(str(window.get('starts_at') or window.get('startsAt')).replace('Z', '+00:00'))
                ends = datetime.fromisoformat(str(window.get('ends_at') or window.get('endsAt')).replace('Z', '+00:00'))
                if starts <= now <= ends:
                    return False
            except (AttributeError, TypeError, ValueError):
                continue
        if rule.get('severity'):
            finding['severity'] = rule['severity']
        if rule.get('confidence') is not None:
            finding['confidence'] = rule['confidence']
        if rule.get('risk_score') is not None:
            finding['configured_risk_score'] = rule['risk_score']
        return True

    def _read_new(self, path: str) -> List[str]:
        try:
            size = os.path.getsize(path)
            previous = self._log_pos.get(path, size)
            if size < previous:
                previous = 0
            with open(path, 'r', errors='replace') as stream:
                stream.seek(previous)
                lines = stream.readlines()
                self._log_pos[path] = stream.tell()
            return lines[-500:]
        except (FileNotFoundError, PermissionError, OSError):
            return []

    def _windows_recent_events(self) -> List[str]:
        if self.os_type != 'windows':
            return []
        query = "*[System[(EventID=1000 or EventID=1001 or EventID=2004) and TimeCreated[timediff(@SystemTime) <= 90000]]]"
        try:
            result = subprocess.run(
                ['wevtutil', 'qe', 'Application', f'/q:{query}', '/f:text', '/c:40', '/rd:true'],
                capture_output=True, text=True, timeout=5, check=False,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            return result.stdout.splitlines() if result.returncode == 0 else []
        except (OSError, subprocess.SubprocessError):
            return []

    def scan_logs(self) -> List[Dict]:
        """Scan newly appended OS logs for defensive crash/OOM metadata."""
        lines: List[str] = []
        for path in LOG_PATHS.get(self.os_type, []):
            lines.extend(self._read_new(path))
        lines.extend(self._windows_recent_events())

        findings: List[Dict] = []
        now = time.time()
        for line in lines:
            for pattern, event_type, severity, mitre in CRASH_PATTERNS:
                if not pattern.search(line):
                    continue
                proc_match = re.search(r'\b([\w.\-]+)\[(\d+)\]', line)
                if not proc_match:
                    proc_match = re.search(r'(?:Faulting application name|process)[:= ]+([\w.\-]+).*?(?:PID|pid)[:= ]*(\d+)', line, re.I)
                name = proc_match.group(1) if proc_match else 'unknown'
                pid = int(proc_match.group(2)) if proc_match else None
                crash_key = f'{name}:{event_type}'
                recent = self._crash_history[crash_key]
                recent.append(now)
                while recent and now - recent[0] > 600:
                    recent.popleft()
                repeated = bool(self._cfg('memory_crash_correlation_enabled')) and len(recent) >= 3
                finding_type = 'repeated_memory_crash' if repeated and event_type != 'oom_kill' else event_type
                key = f'log:{finding_type}:{name}'
                if not self._cooldown_allows(key, now):
                    break
                findings.append({
                    'type': finding_type, 'process': name, 'pid': pid,
                    'crash_count': len(recent), 'severity': 'critical' if repeated else severity,
                    'confidence': 90 if repeated else 82, 'mitre': mitre,
                    'description': f'Memory event [{finding_type}] in {name}' + (f' (PID {pid})' if pid else ''),
                    'evidence': {'log_excerpt': line.strip()[:500], 'source': 'os_log'},
                })
                break
        return findings

    @staticmethod
    def _linux_vmstat() -> Dict[str, int]:
        values: Dict[str, int] = {}
        try:
            with open('/proc/vmstat', 'r', encoding='utf-8', errors='replace') as stream:
                for line in stream:
                    key, _, value = line.partition(' ')
                    if key in {'pgfault', 'pgmajfault', 'pgpgin', 'pgpgout', 'oom_kill'}:
                        values[key] = int(value.strip())
        except (FileNotFoundError, PermissionError, OSError, ValueError):
            pass
        return values

    @staticmethod
    def _linux_cgroup() -> Dict[str, Optional[int]]:
        result = {'container_memory_bytes': None, 'container_memory_limit_bytes': None, 'container_oom_events': None}
        candidates = [
            ('/sys/fs/cgroup/memory.current', 'container_memory_bytes'),
            ('/sys/fs/cgroup/memory.max', 'container_memory_limit_bytes'),
        ]
        for path, key in candidates:
            try:
                value = open(path, 'r', encoding='utf-8').read().strip()
                result[key] = None if value == 'max' else int(value)
            except (FileNotFoundError, PermissionError, OSError, ValueError):
                pass
        try:
            events = open('/sys/fs/cgroup/memory.events', 'r', encoding='utf-8').read()
            match = re.search(r'^oom_kill\s+(\d+)$', events, re.M)
            if match:
                result['container_oom_events'] = int(match.group(1))
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return result

    def collect_host_metric(self) -> Optional[Dict]:
        if not HAS_PSUTIL:
            return None
        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            counters = self._linux_vmstat() if self.os_type == 'linux' else {}
            cgroup = self._linux_cgroup() if self.os_type == 'linux' else {}
            now = time.time()
            paging_rate = None
            if self._last_vmstat and counters:
                previous_at, previous = self._last_vmstat
                elapsed = max(0.001, now - previous_at)
                paging_delta = max(0, counters.get('pgpgin', 0) - previous.get('pgpgin', 0))
                paging_delta += max(0, counters.get('pgpgout', 0) - previous.get('pgpgout', 0))
                paging_rate = round(paging_delta / elapsed, 2)
            if counters:
                self._last_vmstat = (now, counters)
            return {
                'rule_id': 'MEM_HOST_METRIC', 'capabilityId': CAPABILITY_ID,
                'category': 'memory', 'subCategory': 'Memory Metrics',
                'eventType': 'memory.metric', 'severity': 'low', 'riskScore': 0,
                'confidenceScore': 100, 'actionable': False, 'user_action': 'memory_metric',
                'description': f'Host memory metric: RAM {vm.percent:.1f}%, swap {swap.percent:.1f}%',
                'memory_metric_type': 'host', 'memory_total_bytes': vm.total,
                'memory_used_bytes': vm.used, 'memory_available_bytes': vm.available,
                'memory_percent': round(vm.percent, 2), 'swap_total_bytes': swap.total,
                'swap_used_bytes': swap.used, 'swap_percent': round(swap.percent, 2),
                'commit_charge_bytes': vm.used + swap.used,
                'memory_pressure': round(vm.percent, 2),
                'page_faults': counters.get('pgfault'), 'major_page_faults': counters.get('pgmajfault'),
                'paging_rate': paging_rate, 'oom_events': counters.get('oom_kill'),
                **cgroup, 'source': 'memory_overflow_detector', 'timestamp': _utc_now(),
            }
        except Exception as exc:
            logger.debug('[MemOverflow] host metrics unavailable: %s', exc)
            return None

    def scan_processes(self) -> List[Dict]:
        """Rolling spike/leak/high-pressure analysis using process metadata only."""
        if not HAS_PSUTIL:
            return []
        findings: List[Dict] = []
        now = time.time()
        window = self._cfg('memory_leak_window_minutes') * 60
        spike_window = self._cfg('memory_spike_window_seconds')
        min_samples = self._cfg('memory_leak_min_samples')
        leak_growth = self._cfg('memory_leak_growth_percent')
        sample_limit = self._cfg('memory_process_sample_limit')
        processes = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'cmdline', 'create_time', 'memory_info', 'memory_percent', 'cpu_percent', 'num_threads']):
            try:
                info = proc.info
                memory = info.get('memory_info')
                if memory is not None:
                    processes.append((memory.rss, proc, info, memory))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        processes.sort(key=lambda item: item[0], reverse=True)

        live_keys = set()
        for rss, proc, info, memory in processes[:sample_limit]:
            try:
                pid = int(info['pid'])
                key = (pid, float(info.get('create_time') or 0))
                live_keys.add(key)
                history = self._history[key]
                history.append((now, rss))
                while history and now - history[0][0] > window:
                    history.popleft()
                if len(history) < 2:
                    continue
                baseline = min(value for _, value in history)
                growth_bytes = rss - history[0][1]
                growth_pct = (growth_bytes / max(history[0][1], 1)) * 100
                recent = [(ts, value) for ts, value in history if now - ts <= spike_window]
                spike_pct = 0.0
                if len(recent) >= 2:
                    spike_pct = ((recent[-1][1] - recent[0][1]) / max(recent[0][1], 1)) * 100
                name = info.get('name') or 'unknown'
                common = {
                    'process': name, 'pid': pid, 'parent_pid': info.get('ppid'),
                    'username': info.get('username') or '', 'exe': info.get('exe') or '',
                    'memory_mb': round(rss / MIB, 2), 'memory_percent': round(float(info.get('memory_percent') or 0), 2),
                    'memory_growth_bytes': growth_bytes, 'memory_growth_percent': round(growth_pct, 2),
                }
                if spike_pct >= self._cfg('memory_spike_percent_threshold') and self._cooldown_allows(f'spike:{key}', now):
                    findings.append({**common, 'type': 'spike', 'severity': 'high', 'confidence': 82,
                                     'mitre': 'T1203', 'description': f'Sudden memory spike in {name} (PID {pid}): {spike_pct:.1f}% within {spike_window}s'})

                values = [value for _, value in history]
                upward_steps = sum(1 for left, right in zip(values, values[1:]) if right >= left)
                consistent = upward_steps >= max(1, int((len(values) - 1) * 0.8))
                if len(history) >= min_samples and growth_pct >= leak_growth and consistent and self._cooldown_allows(f'leak:{key}', now):
                    findings.append({**common, 'type': 'leak', 'severity': 'high', 'confidence': 86,
                                     'mitre': 'T1499', 'sample_count': len(history),
                                     'description': f'Probable memory leak in {name} (PID {pid}): sustained {growth_pct:.1f}% growth across {len(history)} samples'})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:
                logger.debug('[MemOverflow] process analysis skipped: %s', exc)
        for stale in set(self._history) - live_keys:
            self._history.pop(stale, None)
        return findings

    def collect_process_metrics(self) -> List[Dict]:
        if not HAS_PSUTIL:
            return []
        rows = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'create_time', 'memory_info', 'memory_percent', 'cpu_percent', 'num_threads']):
            try:
                info = proc.info
                memory = info.get('memory_info')
                if memory is None:
                    continue
                rows.append((memory.rss, {
                    'rule_id': 'MEM_PROCESS_METRIC', 'capabilityId': CAPABILITY_ID,
                    'category': 'memory', 'subCategory': 'Process Memory Metrics',
                    'eventType': 'memory.metric', 'severity': 'low', 'riskScore': 0,
                    'confidenceScore': 100, 'actionable': False, 'user_action': 'memory_metric',
                    'description': f'Process memory metric: {info.get("name") or "unknown"} (PID {info["pid"]}) {memory.rss / MIB:.1f} MiB',
                    'memory_metric_type': 'process', 'process_name': info.get('name') or 'unknown',
                    'pid': info['pid'], 'parent_pid': info.get('ppid'), 'username': info.get('username') or '',
                    'process_exe': info.get('exe') or '', 'process_create_time': info.get('create_time'),
                    'memory_percent': round(float(info.get('memory_percent') or 0), 2),
                    'memory_mb': round(memory.rss / MIB, 2), 'process_rss_bytes': memory.rss,
                    'virtual_memory_bytes': getattr(memory, 'vms', None),
                    'shared_memory_bytes': getattr(memory, 'shared', None),
                    'peak_memory_bytes': getattr(memory, 'peak_wset', None),
                    'thread_count': info.get('num_threads'), 'cpu_percent': info.get('cpu_percent'),
                    'source': 'memory_overflow_detector', 'timestamp': _utc_now(),
                }))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        rows.sort(key=lambda item: item[0], reverse=True)
        selected = [payload for _, payload in rows[:self._cfg('memory_process_metric_top_n')]]
        for payload in selected:
            try:
                proc = psutil.Process(payload['pid'])
                payload['process_cmdline'] = ' '.join(proc.cmdline())[:4000]
                if hasattr(proc, 'num_handles'):
                    payload['handle_count'] = proc.num_handles()
                full = proc.memory_full_info()
                payload['private_working_set_bytes'] = getattr(full, 'uss', None) or getattr(full, 'private', None)
                key = (payload['pid'], float(payload.get('process_create_time') or 0))
                history = self._history.get(key)
                if history and len(history) >= 2:
                    elapsed = max(0.001, history[-1][0] - history[-2][0])
                    payload['memory_allocation_rate'] = round((history[-1][1] - history[-2][1]) / elapsed, 2)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
        return selected

    def _host_pressure_findings(self, metric: Optional[Dict]) -> List[Dict]:
        if not metric:
            return []
        now = time.time()
        used = float(metric.get('memory_percent') or 0)
        threshold = self._cfg('memory_high_usage_threshold')
        if used < threshold:
            self._high_since = None
            return []
        if self._high_since is None:
            self._high_since = now
            return []
        duration = now - self._high_since
        if duration < self._cfg('memory_high_usage_duration_seconds') or not self._cooldown_allows('host-pressure', now):
            return []
        return [{
            'type': 'exhaustion', 'severity': 'critical' if used >= 98 else 'high',
            'confidence': 95, 'mitre': 'T1499', 'memory_percent': used,
            'description': f'Sustained host memory pressure: {used:.1f}% for {int(duration)} seconds',
            'evidence': {'duration_seconds': int(duration), 'threshold_percent': threshold},
        }]

    @staticmethod
    def _alert_payload(finding: Dict) -> Dict:
        event_type = str(finding.get('type') or 'overflow')
        risk_score = calculate_risk_score(finding)
        severity = severity_from_risk(risk_score)
        return {
            # Preserve the established identifier consumed by existing alerts and
            # dashboards, and attach the configurable MEM-* rule separately.
            'rule_id': f'MEMORY_OVERFLOW_{event_type.upper()}',
            'detection_rule_id': finding.get('detection_rule_id') or EVENT_RULE_IDS.get(event_type),
            'capabilityId': CAPABILITY_ID,
            'capabilityIds': [5, CAPABILITY_ID], 'category': 'memory',
            'subCategory': 'Memory Overflow Detection', 'eventType': f'memory.{event_type}',
            'severity': severity, 'confidenceScore': finding.get('confidence', 80),
            'riskScore': risk_score,
            'description': finding['description'], 'user_action': 'memory_overflow_detected',
            'mitreId': finding.get('mitre', 'T1203'), 'technique': 'Exploitation for Client Execution',
            'process_name': finding.get('process'), 'pid': finding.get('pid'),
            'parent_pid': finding.get('parent_pid'), 'username': finding.get('username'),
            'process_exe': finding.get('exe'), 'memory_percent': finding.get('memory_percent'),
            'memory_mb': finding.get('memory_mb'), 'memory_growth_bytes': finding.get('memory_growth_bytes'),
            'memory_growth_percent': finding.get('memory_growth_percent'),
            'crash_count': finding.get('crash_count'), 'detectionEvidence': finding.get('evidence'),
            'source': 'memory_overflow_detector',
            'recommendedAction': 'Review the process tree and executable trust, preserve limited forensic metadata, then contain through the approved response workflow if confirmed.',
            'raw': finding, 'timestamp': _utc_now(),
        }

    def run_and_report(self, sender=None) -> List[Dict]:
        host_metric = self.collect_host_metric()
        findings = [
            finding for finding in (
                self.scan_logs() + self.scan_processes() + self._host_pressure_findings(host_metric)
            ) if self._rule_allows(finding)
        ]
        self._findings.extend(findings)
        self._findings = self._findings[-500:]

        if sender:
            for finding in findings:
                try:
                    sender.send_alert(self._alert_payload(finding))
                except Exception as exc:
                    logger.error('[MemOverflow] detection send error: %s', exc)
            for metric in ([host_metric] if host_metric else []) + self.collect_process_metrics():
                try:
                    sender.send_alert(metric)
                except Exception as exc:
                    logger.error('[MemOverflow] metric send error: %s', exc)
        if findings:
            logger.warning('[MemOverflow] %d memory detections produced', len(findings))
        return findings

    def recent(self, limit: int = 50) -> List[Dict]:
        return self._findings[-limit:]


OverflowDetector = MemoryOverflowDetector
Detector = MemoryOverflowDetector
