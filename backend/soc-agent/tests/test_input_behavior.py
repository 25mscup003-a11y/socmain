import importlib.util
import os
import sys
import types
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(ROOT, 'collectors', 'input_behavior.py')
spec = importlib.util.spec_from_file_location('input_behavior_collector', MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class State:
    def __init__(self, profile):
        self.profile = profile

    def get_input_behavior_baseline(self):
        return self.profile

    def set_input_behavior_baseline(self, profile):
        self.profile = profile


class InputBehaviorTests(unittest.TestCase):
    def test_emits_rates_without_keys_text_or_coordinates(self):
        sender = Sender()
        collector = module.Collector(sender, {})
        collector._on_key(object())
        collector._on_key(object())
        collector._on_move(100, 200)
        collector._on_move(103, 204)
        collector._on_click(103, 204, object(), True)
        collector._on_scroll(103, 204, 0, 1)
        collector._active_seconds = 30
        collector._idle_seconds = 30
        values = collector._snapshot(60)
        collector._emit(values)
        event = sender.events[-1]
        self.assertEqual(event['capabilityId'], 11)
        self.assertEqual(event['input_keyboard_events'], 2)
        self.assertEqual(event['input_click_count'], 1)
        self.assertEqual(event['input_scroll_count'], 1)
        self.assertEqual(event['input_activity_percent'], 50)
        encoded = repr(event).lower()
        self.assertNotIn('cursor_x', encoded)
        self.assertNotIn('cursor_y', encoded)
        self.assertNotIn('key_value', encoded)
        self.assertNotIn('typed_text', encoded)

    def test_disabled_policy_does_not_start_sensor(self):
        sender = Sender()
        collector = module.Collector(sender, {'input_behavior_monitoring_enabled': False})
        collector.start()
        self.assertEqual(sender.events, [])

    def test_linux_input_fallback_counts_rates_without_retaining_key_codes(self):
        collector = module.Collector(Sender(), {})
        collector._record_linux_input_event(0x01, 30, 1)
        collector._record_linux_input_event(0x01, 0x110, 1)
        collector._record_linux_input_event(0x02, 0x00, -12)
        collector._record_linux_input_event(0x02, 0x01, 5)
        collector._record_linux_input_event(0x02, 0x08, -1)
        values = collector._snapshot(60)
        self.assertEqual(values['keys'], 1)
        self.assertEqual(values['clicks'], 1)
        self.assertEqual(values['moves'], 2)
        self.assertEqual(values['distance'], 17)
        self.assertEqual(values['scrolls'], 1)
        self.assertEqual(values['keyboard_rate'], 1)
        self.assertGreater(values['mouse_rate'], 0)

    def test_only_one_non_service_interactive_user_is_verified(self):
        fake_psutil = types.SimpleNamespace(users=lambda: [types.SimpleNamespace(name='alice')])
        with mock.patch.dict(sys.modules, {'psutil': fake_psutil}):
            username, source, verified, count = module.Collector._interactive_user()
        self.assertEqual(username, 'alice')
        self.assertEqual(source, 'psutil_interactive_session')
        self.assertTrue(verified)
        self.assertEqual(count, 1)

    def test_service_or_ambiguous_sessions_cannot_be_verified(self):
        fake_psutil = types.SimpleNamespace(users=lambda: [
            types.SimpleNamespace(name='SYSTEM'), types.SimpleNamespace(name='alice'), types.SimpleNamespace(name='bob'),
        ])
        with mock.patch.dict(sys.modules, {'psutil': fake_psutil}):
            username, source, verified, count = module.Collector._interactive_user()
        self.assertEqual(username, '')
        self.assertEqual(source, 'ambiguous_session')
        self.assertFalse(verified)
        self.assertEqual(count, 2)

    def test_profile_requests_verification_only_after_30_learned_days(self):
        days = {}
        today = datetime.now(timezone.utc).date()
        for offset in range(1, 31):
            days[(today - timedelta(days=offset)).isoformat()] = {
                'samples': 1, 'keyboard_rate': 50, 'mouse_rate': 100,
                'click_rate': 10, 'activity_percent': 50,
            }
        collector = module.Collector(Sender(), {}, State({'started_at': 'test', 'days': days}))
        unusual = {'keyboard_rate': 400, 'mouse_rate': 1400, 'click_rate': 10, 'activity_percent': 50}
        first = collector._evaluate_profile(unusual)
        second = collector._evaluate_profile(unusual)
        self.assertEqual(first['status'], 'verification_active')
        self.assertFalse(first['profile_mismatch'])
        self.assertTrue(second['profile_mismatch'])
        self.assertGreaterEqual(len(second['mismatch_features']), 2)


if __name__ == '__main__':
    unittest.main()
