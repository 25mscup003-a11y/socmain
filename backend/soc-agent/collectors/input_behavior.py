"""Privacy-safe keyboard and mouse activity-rate telemetry for UEBA.

The collector counts input events and calculates aggregate rates only. It never
stores or transmits key values, typed text, cursor coordinates, window titles,
clipboard data, screenshots, or application content.
"""
import logging
import math
import glob
import os
import select
import statistics
import struct
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

logger = logging.getLogger('soc-agent.collector.input-behavior')

_NON_INTERACTIVE_USERS = {
    '', 'system', 'local service', 'network service', 'localsystem',
    'root', 'daemon', 'nobody', 'www-data', 'sshd', 'messagebus',
}


def _utc():
    return datetime.now(timezone.utc).isoformat()


class Collector:
    def __init__(self, sender, config=None, state=None):
        self._sender = sender
        self._config = config or {}
        self._state = state
        self._lock = threading.Lock()
        self._keys = 0
        self._moves = 0
        self._distance = 0.0
        self._clicks = 0
        self._scrolls = 0
        self._last_position = None
        self._last_input_at = 0.0
        self._active_seconds = 0
        self._idle_seconds = 0
        self._keyboard_history = deque(maxlen=60)
        self._mouse_history = deque(maxlen=60)
        self._high_activity_streak = 0
        self._identity_mismatch_streak = 0
        self._last_anomaly_at = 0.0
        self._profile = self._load_profile()
        self._listeners = []
        self._thread = threading.Thread(target=self._loop, daemon=True, name='input-behavior')

    def start(self):
        if self._config.get('input_behavior_monitoring_enabled', True) is False:
            return
        available, reason = self._start_listeners()
        if available:
            self._emit_status(True, '')
            self._thread.start()
            return
        logger.warning('Privacy-safe input activity sensor unavailable: %s; retrying automatically', reason)
        self._emit_status(False, reason)
        self._thread = threading.Thread(target=self._retry_until_available, daemon=True, name='input-behavior-retry')
        self._thread.start()

    def _start_listeners(self):
        try:
            from pynput import keyboard, mouse
            key_listener = keyboard.Listener(on_press=self._on_key)
            mouse_listener = mouse.Listener(on_move=self._on_move, on_click=self._on_click, on_scroll=self._on_scroll)
            self._listeners = [key_listener, mouse_listener]
            for listener in self._listeners:
                listener.daemon = True
                listener.start()
            return True, ''
        except Exception as exc:
            self._listeners = []
            if sys.platform.startswith('linux'):
                available, linux_reason = self._start_linux_input_listener()
                if available:
                    logger.info('Using Linux evdev input-rate sensor because pynput is unavailable')
                    return True, ''
                return False, f'{type(exc).__name__}; {linux_reason}'
            return False, type(exc).__name__

    def _start_linux_input_listener(self):
        """Count Linux evdev activity without requiring an X/Wayland session.

        Only event counts and relative movement distance are retained. Key
        codes, button identities, device paths and pointer positions are never
        emitted or persisted.
        """
        devices = []
        for path in sorted(glob.glob('/dev/input/event*')):
            try:
                devices.append(open(path, 'rb', buffering=0))
            except OSError:
                continue
        if not devices:
            return False, 'Linux input devices are not readable'
        self._listeners = devices
        listener = threading.Thread(
            target=self._linux_input_loop,
            args=(devices,),
            daemon=True,
            name='input-behavior-evdev',
        )
        listener.start()
        return True, ''

    def _linux_input_loop(self, devices):
        event_struct = struct.Struct('@llHHi')
        active_devices = list(devices)
        while active_devices:
            try:
                readable, _, _ = select.select(active_devices, [], [], 5)
            except (OSError, ValueError):
                return
            for device in readable:
                try:
                    packet = os.read(device.fileno(), event_struct.size * 64)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    active_devices.remove(device)
                    continue
                for offset in range(0, len(packet) - event_struct.size + 1, event_struct.size):
                    _, _, event_type, code, value = event_struct.unpack_from(packet, offset)
                    self._record_linux_input_event(event_type, code, value)

    def _record_linux_input_event(self, event_type, code, value):
        with self._lock:
            # EV_KEY press. Linux mouse buttons occupy BTN_* codes from 0x110;
            # the concrete key/button code is discarded immediately.
            if event_type == 0x01 and value == 1:
                if 0x110 <= code <= 0x11f:
                    self._clicks += 1
                else:
                    self._keys += 1
                self._last_input_at = time.monotonic()
            # EV_REL X/Y movement and wheel activity.
            elif event_type == 0x02 and code in (0x00, 0x01):
                self._moves += 1
                self._distance += abs(float(value))
                self._last_input_at = time.monotonic()
            elif event_type == 0x02 and code in (0x06, 0x08):
                self._scrolls += abs(int(value))
                self._last_input_at = time.monotonic()

    def _retry_until_available(self):
        retry_seconds = max(30, min(600, int(self._config.get('input_behavior_retry_seconds', 60))))
        while True:
            time.sleep(retry_seconds)
            available, reason = self._start_listeners()
            if available:
                logger.info('Privacy-safe input activity sensor is now available')
                self._emit_status(True, '')
                self._loop()
                return
            logger.debug('Input activity sensor still unavailable: %s', reason)

    def _on_key(self, _key):
        # The key object is intentionally ignored and never retained.
        with self._lock:
            self._keys += 1
            self._last_input_at = time.monotonic()

    def _on_move(self, x, y):
        # Coordinates exist only long enough to calculate distance and are
        # never emitted or written to disk.
        with self._lock:
            if self._last_position is not None:
                self._distance += math.hypot(float(x) - self._last_position[0], float(y) - self._last_position[1])
            self._last_position = (float(x), float(y))
            self._moves += 1
            self._last_input_at = time.monotonic()

    def _on_click(self, _x, _y, _button, pressed):
        if not pressed:
            return
        with self._lock:
            self._clicks += 1
            self._last_input_at = time.monotonic()

    def _on_scroll(self, _x, _y, _dx, _dy):
        with self._lock:
            self._scrolls += 1
            self._last_input_at = time.monotonic()

    def _emit_status(self, available, reason):
        self._sender.enqueue({
            'capabilityId': 11, 'capabilityIds': [11], 'category': 'edr', 'subCategory': 'ueba',
            'source': 'input_behavior', 'eventType': 'input_behavior_status',
            'rule_id': 'UEBA_INPUT_ACTIVITY_STATUS', 'severity': 'low', 'risk_score': 10,
            'behavior_category': 'Endpoint Behavior', 'entity_type': 'endpoint',
            'input_monitoring_available': bool(available), 'input_privacy_mode': 'aggregate_counts_only',
            'description': 'Privacy-safe mouse and keyboard activity-rate monitoring is active' if available else 'Privacy-safe input activity monitoring is unavailable on this session',
            'failure_reason': str(reason or '')[:120], 'timestamp': _utc(),
        })

    def _load_profile(self):
        if self._state and hasattr(self._state, 'get_input_behavior_baseline'):
            profile = self._state.get_input_behavior_baseline()
        else:
            profile = {}
        if not isinstance(profile, dict):
            profile = {}
        profile.setdefault('started_at', _utc())
        profile.setdefault('days', {})
        return profile

    def _save_profile(self):
        if self._state and hasattr(self._state, 'set_input_behavior_baseline'):
            self._state.set_input_behavior_baseline(self._profile)

    @staticmethod
    def _interactive_user():
        """Return one unambiguous interactive session user.

        The agent commonly runs as SYSTEM/root, so the process owner is never
        accepted as the person at the keyboard. Multiple signed-in users are
        deliberately treated as ambiguous and cannot trigger auto-lock.
        """
        try:
            import psutil
            users = {
                str(session.name or '').strip()
                for session in psutil.users()
                if str(session.name or '').strip().lower() not in _NON_INTERACTIVE_USERS
            }
        except Exception:
            users = set()
        if len(users) != 1:
            return '', 'ambiguous_session' if users else 'no_interactive_session', False, len(users)
        return next(iter(users)), 'psutil_interactive_session', True, 1

    @staticmethod
    def _daily_average(entry, key):
        return float(entry.get(key, 0)) / max(1, int(entry.get('samples', 0)))

    def _evaluate_profile(self, values):
        """Train for 30 distinct days, then flag multi-feature deviation.

        The model receives aggregate rates only and cannot identify a person;
        a mismatch means that interactive verification is recommended.
        """
        today = datetime.now(timezone.utc).date().isoformat()
        days = self._profile.setdefault('days', {})
        baseline_entries = list(days.values())
        observed_days = len(days)
        fields = ('keyboard_rate', 'mouse_rate', 'click_rate', 'activity_percent')
        deviation = {}
        mismatch_features = []
        if observed_days >= 30:
            for field in fields:
                samples = [self._daily_average(entry, field) for entry in baseline_entries if int(entry.get('samples', 0)) > 0]
                if len(samples) < 20:
                    continue
                mean = statistics.mean(samples)
                spread = statistics.pstdev(samples)
                floor = {'keyboard_rate': 12.0, 'mouse_rate': 100.0, 'click_rate': 5.0, 'activity_percent': 8.0}[field]
                z_score = abs(float(values.get(field, 0)) - mean) / max(spread, abs(mean) * 0.15, floor)
                deviation[field] = round(z_score, 2)
                if z_score >= 3.0:
                    mismatch_features.append(field)
        mismatch_now = len(mismatch_features) >= 2
        self._identity_mismatch_streak = self._identity_mismatch_streak + 1 if mismatch_now else 0
        mismatch = observed_days >= 30 and self._identity_mismatch_streak >= 2
        avg_deviation = statistics.mean(deviation.values()) if deviation else 0
        similarity = max(0, min(100, round(100 - min(avg_deviation, 6) * 14))) if observed_days >= 30 else 0

        entry = days.setdefault(today, {'samples': 0})
        entry['samples'] = int(entry.get('samples', 0)) + 1
        for field in fields:
            entry[field] = float(entry.get(field, 0)) + float(values.get(field, 0))
        self._profile['days'] = dict(sorted(days.items())[-30:])
        self._save_profile()
        learned_days = len(self._profile['days'])
        return {
            'status': 'verification_active' if learned_days >= 30 else 'learning',
            'baseline_days': learned_days,
            'identity_confidence': similarity,
            'profile_mismatch': mismatch,
            'mismatch_features': mismatch_features,
            'deviation': deviation,
        }

    def _snapshot(self, elapsed):
        with self._lock:
            values = {
                'keys': self._keys, 'moves': self._moves, 'distance': self._distance,
                'clicks': self._clicks, 'scrolls': self._scrolls,
                'active_seconds': self._active_seconds, 'idle_seconds': self._idle_seconds,
            }
            self._keys = self._moves = self._clicks = self._scrolls = 0
            self._distance = 0.0
            self._active_seconds = self._idle_seconds = 0
        minutes = max(elapsed / 60.0, 1 / 60.0)
        values['keyboard_rate'] = round(values['keys'] / minutes, 2)
        values['mouse_rate'] = round(values['distance'] / max(elapsed, 1.0), 2)
        values['click_rate'] = round(values['clicks'] / minutes, 2)
        values['activity_percent'] = round((values['active_seconds'] / max(values['active_seconds'] + values['idle_seconds'], 1)) * 100, 2)
        return values

    def _emit(self, values, anomaly=False, profile=None):
        profile = profile or {}
        identity_mismatch = bool(profile.get('profile_mismatch'))
        username, user_source, user_verified, session_count = self._interactive_user()
        risk = 85 if identity_mismatch else 75 if anomaly else 10
        rule_id = 'UEBA_INPUT_PROFILE_MISMATCH' if identity_mismatch else 'UEBA_INPUT_AUTOMATION_ANOMALY' if anomaly else 'UEBA_INPUT_ACTIVITY_SUMMARY'
        self._sender.enqueue({
            'capabilityId': 11, 'capabilityIds': [11], 'category': 'edr', 'subCategory': 'ueba',
            'source': 'input_behavior', 'eventType': 'input_profile_mismatch' if identity_mismatch else 'input_behavior_anomaly' if anomaly else 'input_behavior_summary',
            'rule_id': rule_id, 'severity': 'high' if anomaly or identity_mismatch else 'low', 'risk_score': risk,
            'behavior_category': 'User Behavior', 'entity_type': 'endpoint',
            'behavior_score': risk, 'ueba_confidence': 80 if anomaly else 70,
            'ueba_risk_factors': ['behavioral_profile_mismatch', *(profile.get('mismatch_features') or [])] if identity_mismatch else ['input_rate_deviation'] if anomaly else ['privacy_safe_input_activity'],
            'baseline_window_days': 30, 'input_monitoring_available': True,
            'input_privacy_mode': 'aggregate_counts_only',
            'input_profile_status': profile.get('status', 'learning'),
            'input_baseline_days': int(profile.get('baseline_days') or 0),
            'input_identity_confidence': float(profile.get('identity_confidence') or 0),
            'input_profile_mismatch': identity_mismatch,
            'input_profile_mismatch_features': list(profile.get('mismatch_features') or [])[:4],
            'input_profile_deviation': dict(profile.get('deviation') or {}),
            'username': username or None,
            'entity_id': username or None,
            'input_user_source': user_source,
            'input_user_verified': bool(user_verified),
            'input_session_count': int(session_count),
            'input_keyboard_events': values['keys'], 'input_mouse_events': values['moves'],
            'input_click_count': values['clicks'], 'input_scroll_count': values['scrolls'],
            'input_keyboard_rate': values['keyboard_rate'], 'input_mouse_rate': values['mouse_rate'],
            'input_activity_percent': values['activity_percent'],
            'description': 'Aggregate input behavior differs from the learned 30-day profile; interactive user verification is recommended, not automatic identity denial' if identity_mismatch else 'Unusually high aggregate keyboard/mouse activity rate detected' if anomaly else 'Privacy-safe keyboard and mouse activity-rate summary',
            'timestamp': _utc(),
        })

    def _loop(self):
        sample_interval = max(1, min(10, int(self._config.get('input_behavior_sample_interval_seconds', 1))))
        # Publish one aggregate sample per minute for the live dashboard. This
        # contains counts/rates only; no key values or pointer coordinates.
        keyboard_threshold = max(30, int(self._config.get('input_keyboard_rate_threshold', 240)))
        mouse_threshold = max(100, int(self._config.get('input_mouse_rate_threshold', 2500)))
        cooldown = max(300, int(self._config.get('input_behavior_anomaly_cooldown_seconds', 1800)))
        window_started = time.monotonic()
        report_started = window_started
        report_totals = {'keys': 0, 'moves': 0, 'distance': 0.0, 'clicks': 0, 'scrolls': 0, 'active_seconds': 0, 'idle_seconds': 0}
        while True:
            time.sleep(sample_interval)
            now = time.monotonic()
            with self._lock:
                if self._last_input_at and now - self._last_input_at <= 5:
                    self._active_seconds += sample_interval
                else:
                    self._idle_seconds += sample_interval
            if now - window_started < 60:
                continue
            values = self._snapshot(now - window_started)
            window_started = now
            for key in report_totals:
                report_totals[key] += values[key]
            self._keyboard_history.append(values['keyboard_rate'])
            self._mouse_history.append(values['mouse_rate'])
            high = values['keyboard_rate'] >= keyboard_threshold or values['mouse_rate'] >= mouse_threshold or values['click_rate'] >= 120
            self._high_activity_streak = self._high_activity_streak + 1 if high else 0
            if self._high_activity_streak >= 2 and now - self._last_anomaly_at >= cooldown:
                self._last_anomaly_at = now
                self._emit(values, anomaly=True)
            # Heartbeat policy updates mutate the shared runtime config after
            # collectors have started. Read this value for every completed
            # window so a live cadence change applies without restarting the
            # endpoint service.
            # This is live dashboard telemetry, so never let a stale persisted
            # policy stretch reporting beyond the privacy-safe one-minute
            # aggregate window.
            report_interval = 60
            if now - report_started >= report_interval:
                elapsed = max(now - report_started, 1.0)
                report = dict(report_totals)
                report['keyboard_rate'] = round(report['keys'] / (elapsed / 60.0), 2)
                report['mouse_rate'] = round(report['distance'] / elapsed, 2)
                report['click_rate'] = round(report['clicks'] / (elapsed / 60.0), 2)
                report['activity_percent'] = round((report['active_seconds'] / max(report['active_seconds'] + report['idle_seconds'], 1)) * 100, 2)
                profile = self._evaluate_profile(report)
                self._emit(report, anomaly=bool(profile.get('profile_mismatch')), profile=profile)
                report_totals = {key: 0.0 if key == 'distance' else 0 for key in report_totals}
                report_started = now
