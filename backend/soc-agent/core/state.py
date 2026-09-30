"""
StateManager — tracks:
  1. Sent alert fingerprints (24h dedup window)
  2. Windows event log cursors (last RecordNumber per channel)
  3. File tail positions (bytes read per log file)
  4. INSTALL_TIME baseline — only events >= install_time are processed
  5. Event counters: file_events, usb_events, edr_events, malware_count
  6. Auto-cleanup: deletes agent log files older than 90 days

MASTER RULE:
  Any event with timestamp < install_time is IGNORED (old system data).
  install_time is set ONCE on first install and NEVER reset on restart.
  Only reset_baseline() / CLI command can reset it.
"""

from typing import Optional, List, Dict, Any

import os
import json
import time
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta

from .secure_file import load_json, save_json

logger = logging.getLogger('soc-agent.state')

STATE_FILE = Path(os.path.join(os.path.dirname(__file__), '..', 'config', 'agent_state.json'))
DEDUP_WINDOW_HOURS        = 24
CLEANUP_INTERVAL_SECONDS  = 86400   # run cleanup once per day
LOG_RETENTION_DAYS        = 90


def _log_dirs() -> List[Path]:
    import platform
    system = platform.system()
    if system == 'Linux':
        return [Path('/var/log/soc-agent')]
    elif system == 'Windows':
        return [Path(os.environ.get('ProgramData', 'C:\\ProgramData')) / 'SOCAgent' / 'logs']
    else:  # macOS
        return [Path('/Library/Logs/SOCAgent')]


class StateManager:
    def __init__(self, encryption_key: str = ''):
        self._lock = threading.Lock()
        self._encryption_key = encryption_key
        self._state: Dict[str, Any] = {
            'fingerprints':  {},   # hash -> ISO timestamp
            'win_cursors':   {},   # channel -> last RecordNumber
            'file_positions': {},  # file_path -> byte offset
            'time_baseline': {},   # entity/rule -> hourly behavioral counts
            'input_behavior_baseline': {},  # encrypted 30-day aggregate input profile
            'gps_location_state': None,  # last uploaded change-only GPS state

            # ── Baseline tracking (INSTALL_TIME) ──────────────────────────────
            # Once set, NEVER overwritten on restart.
            # reset_baseline() is the only way to clear it.
            'install_time': None,  # ISO UTC string or None

            # ── Event counters (only incremented for >= install_time events) ──
            'counters': {
                'file_events':   0,
                'usb_events':    0,
                'edr_events':    0,
                'malware_count': 0,
                'dropped_alerts': 0,
            },
        }
        self._last_cleanup = 0.0
        self._load()

        # Ensure install_time is set if missing (first run after upgrade)
        if not self._state.get('install_time'):
            self._set_install_time_now()

    # ─── Persistence ─────────────────────────────────────────────────────────
    def _load(self):
        try:
            if STATE_FILE.exists():
                loaded = load_json(
                    STATE_FILE, self._encryption_key, 'agent-state', {}
                )
                # Merge loaded state — preserve install_time if already set
                for k, v in loaded.items():
                    self._state[k] = v
                # Ensure counters sub-dict always has all keys
                for key in ('file_events', 'usb_events', 'edr_events',
                            'malware_count', 'dropped_alerts'):
                    self._state.setdefault('counters', {})[key] = \
                        self._state['counters'].get(key, 0)
                self._purge_expired_fingerprints()
                logger.info('State loaded — install_time=%s', self._state.get('install_time'))
        except Exception as e:
            logger.warning('State load error: %s', e)

    def _save(self):
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            save_json(
                STATE_FILE, self._state, self._encryption_key, 'agent-state'
            )
        except Exception as e:
            logger.debug('State save error: %s', e)

    def _purge_expired_fingerprints(self):
        cutoff = (datetime.now(timezone.utc) -
                  timedelta(hours=DEDUP_WINDOW_HOURS)).isoformat()
        expired = [k for k, v in self._state['fingerprints'].items() if v < cutoff]
        for k in expired:
            del self._state['fingerprints'][k]

    # ─── Install-time baseline ────────────────────────────────────────────────
    def _set_install_time_now(self):
        """Called once on very first run. Never called again on restarts."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._state['install_time'] = now
        self._save()
        logger.info('INSTALL_TIME set: %s', now)

    @property
    def install_time(self) -> Optional[datetime]:
        """Return install_time as timezone-aware datetime, or None."""
        raw = self._state.get('install_time')
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def event_is_after_install(self, event_ts: Optional[str]) -> bool:
        """
        MASTER RULE: Return True only if this event happened >= install_time.
        If event_ts is missing/unparseable → allow (benefit of doubt).
        If install_time is not set → allow all.
        """
        install = self.install_time
        if install is None:
            return True  # baseline not set → allow
        if not event_ts:
            return True  # no timestamp on event → allow

        try:
            t = event_ts
            if t.endswith('Z'):
                t = t[:-1] + '+00:00'
            dt = datetime.fromisoformat(t)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt >= install
        except Exception:
            return True  # unparseable → allow

    def reset_baseline(self):
        """
        CLI command: reset_baseline.
        Clears install_time and counters so the agent starts fresh.
        Should only be called explicitly — NEVER on restart.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._state['install_time'] = now
            self._state['time_baseline'] = {}
            self._state['input_behavior_baseline'] = {}
            self._state['counters'] = {
                'file_events': 0, 'usb_events': 0,
                'edr_events': 0, 'malware_count': 0, 'dropped_alerts': 0,
            }
        self._save()
        logger.warning('BASELINE RESET — new install_time: %s', now)

    def gps_location_state(self):
        """Return the restart-safe state of the last queued GPS observation."""
        with self._lock:
            value = self._state.get('gps_location_state')
            return list(value) if isinstance(value, (list, tuple)) else None

    def set_gps_location_state(self, value):
        """Persist GPS change detection state so a restart cannot resend it."""
        with self._lock:
            self._state['gps_location_state'] = list(value) if value is not None else None
        self._save()

    # ─── Event counters ───────────────────────────────────────────────────────
    def _inc(self, key: str, amount: int = 1):
        with self._lock:
            self._state['counters'][key] = self._state['counters'].get(key, 0) + amount
        # Don't save on every counter increment — too frequent; state saves
        # happen on dedup mark_sent and periodically in maybe_cleanup.

    def count_file_event(self):   self._inc('file_events')
    def count_usb_event(self):    self._inc('usb_events')
    def count_edr_event(self):    self._inc('edr_events')
    def count_malware(self):      self._inc('malware_count')
    def count_dropped(self):      self._inc('dropped_alerts')

    def get_counters(self) -> dict:
        with self._lock:
            return dict(self._state['counters'])

    # ─── Dedup / fingerprint API ──────────────────────────────────────────────
    def _make_fingerprint(self, rule_id: str, description: str,
                          log_line: str, src_ip: str = '') -> str:
        raw = f'{rule_id}|{description[:80]}|{log_line[:120]}|{src_ip}'
        return hashlib.md5(raw.encode()).hexdigest()

    def is_duplicate(self, rule_id: str, description: str,
                     log_line: str, src_ip: str = '') -> bool:
        """Returns True if this exact alert was sent within the last 24 hours."""
        fp = self._make_fingerprint(rule_id, description, log_line, src_ip)
        with self._lock:
            sent_at = self._state['fingerprints'].get(fp)
            if not sent_at:
                return False
            cutoff = (datetime.now(timezone.utc) -
                      timedelta(hours=DEDUP_WINDOW_HOURS)).isoformat()
            return sent_at > cutoff

    def mark_sent(self, rule_id: str, description: str,
                  log_line: str, src_ip: str = ''):
        """Record that this alert was sent now."""
        fp = self._make_fingerprint(rule_id, description, log_line, src_ip)
        with self._lock:
            self._state['fingerprints'][fp] = datetime.now(timezone.utc).isoformat()
        self._save()

    # ─── Windows cursor API ───────────────────────────────────────────────────
    def get_win_cursor(self, channel: str) -> Optional[int]:
        return self._state['win_cursors'].get(channel)

    def set_win_cursor(self, channel: str, record_number: int):
        with self._lock:
            self._state['win_cursors'][channel] = record_number
        self._save()

    # ─── File position API ────────────────────────────────────────────────────
    def get_file_position(self, path: str) -> int:
        return self._state['file_positions'].get(path, -1)

    def set_file_position(self, path: str, pos: int):
        with self._lock:
            self._state['file_positions'][path] = pos
        self._save()

    # ─── Time-based behavioral baseline ─────────────────────────────────────
    def get_time_baseline(self) -> dict:
        with self._lock:
            baseline = self._state.get('time_baseline') or {}
            return json.loads(json.dumps(baseline))

    def set_time_baseline(self, baseline: dict):
        if not isinstance(baseline, dict):
            return
        # Bound the encrypted state file even on very large multi-user servers.
        ordered = sorted(
            baseline.items(),
            key=lambda item: int((item[1] or {}).get('total', 0)),
            reverse=True,
        )[:2000]
        with self._lock:
            self._state['time_baseline'] = dict(ordered)
        self._save()

    # ─── Privacy-safe input behavior baseline ───────────────────────────────
    def get_input_behavior_baseline(self) -> dict:
        with self._lock:
            baseline = self._state.get('input_behavior_baseline') or {}
            return json.loads(json.dumps(baseline))

    def set_input_behavior_baseline(self, baseline: dict):
        if not isinstance(baseline, dict):
            return
        days = baseline.get('days') if isinstance(baseline.get('days'), dict) else {}
        baseline = {
            'started_at': baseline.get('started_at'),
            'days': dict(sorted(days.items())[-30:]),
        }
        with self._lock:
            self._state['input_behavior_baseline'] = baseline
        self._save()

    # ─── 90-day log cleanup ───────────────────────────────────────────────────
    def maybe_cleanup(self):
        now = time.time()
        if now - self._last_cleanup < CLEANUP_INTERVAL_SECONDS:
            return
        self._last_cleanup = now
        # Persist counters during cleanup
        self._save()
        cutoff = now - (LOG_RETENTION_DAYS * 86400)
        deleted = 0
        for log_dir in _log_dirs():
            if not log_dir.exists():
                continue
            for f in log_dir.iterdir():
                if f.is_file() and f.name != 'agent.log':
                    try:
                        if f.stat().st_mtime < cutoff:
                            f.unlink()
                            deleted += 1
                    except OSError:
                        pass
        if deleted:
            logger.info('90-day cleanup: removed %d old log files', deleted)
