import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from core.gps_location import (
    GPSLocationCollector,
    geoclue_command,
    parse_geoclue_location,
    parse_gpsd_tpv,
    parse_windows_location,
)


class GPSLocationTests(unittest.TestCase):
    def test_disabled_policy_never_collects_or_emits(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': False})
        self.assertFalse(collector.enabled)
        self.assertIsNone(collector.run_and_report())

    def test_windows_location_json_parser_preserves_zero_coordinates(self):
        location = parse_windows_location(
            '{"latitude":0,"longitude":0,"altitude":15.5,"accuracy":8,"timestamp":"2026-08-30T10:00:00Z"}'
        )
        self.assertEqual(location['latitude'], 0)
        self.assertEqual(location['longitude'], 0)
        self.assertEqual(location['accuracyMeters'], 8)

    def test_linux_geoclue_parser(self):
        location = parse_geoclue_location(
            'Latitude: 28.6139\nLongitude: 77.2090\nAccuracy: 12 m\nAltitude: 216 m\n'
        )
        self.assertAlmostEqual(location['latitude'], 28.6139)
        self.assertAlmostEqual(location['longitude'], 77.2090)
        self.assertEqual(location['accuracyMeters'], 12)

    def test_linux_geoclue_parser_selects_best_accuracy_from_live_updates(self):
        location = parse_geoclue_location(
            'Latitude: 28.6000\nLongitude: 77.2000\nAccuracy: 25000 m\n'
            'Latitude: 28.6139\nLongitude: 77.2090\nAccuracy: 32 m\n'
        )
        self.assertAlmostEqual(location['latitude'], 28.6139)
        self.assertAlmostEqual(location['longitude'], 77.2090)
        self.assertEqual(location['accuracyMeters'], 32)

    def test_linux_geoclue_parser_prefers_latest_location_when_accuracy_ties(self):
        location = parse_geoclue_location(
            'Latitude: 26.4652\nLongitude: 80.3497\nAccuracy: 25000 m\n'
            'Latitude: 26.8393\nLongitude: 80.9231\nAccuracy: 25000 m\n'
        )
        self.assertAlmostEqual(location['latitude'], 26.8393)
        self.assertAlmostEqual(location['longitude'], 80.9231)
        self.assertEqual(location['accuracyMeters'], 25000)

    def test_linux_gpsd_parser_uses_real_gnss_error_radius(self):
        location = parse_gpsd_tpv({
            'class': 'TPV', 'mode': 3, 'lat': 28.6139, 'lon': 77.2090,
            'altHAE': 216.4, 'epx': 4.5, 'epy': 7.25,
            'time': '2026-09-07T00:00:00Z',
        })
        self.assertEqual(location['accuracyMeters'], 7.25)
        self.assertEqual(location['altitudeMeters'], 216.4)

    def test_linux_prefers_local_hardware_gnss_over_geoclue(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        collector._collect_gpsd = lambda: {
            'status': 'available', 'provider': 'gpsd-gnss',
            'latitude': 28.6139, 'longitude': 77.2090, 'accuracyMeters': 4,
        }
        collector._geoclue_executable = lambda: self.fail('GeoClue should not run after a GNSS fix')
        result = collector._collect_linux()
        self.assertEqual(result['provider'], 'gpsd-gnss')
        self.assertEqual(result['accuracyMeters'], 4)

    def test_root_agent_uses_the_desktop_users_geoclue_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            user_runtime = runtime / '1000'
            user_runtime.mkdir()
            (user_runtime / 'bus').touch()
            with patch('core.gps_location.os.geteuid', return_value=0), \
                    patch('core.gps_location.shutil.which', return_value='/usr/sbin/runuser'), \
                    patch('core.gps_location.pwd.getpwuid', return_value=SimpleNamespace(pw_name='desktop-user')):
                command = geoclue_command('/usr/libexec/geoclue-2.0/demos/where-am-i', runtime)
        self.assertEqual(command[:5], ['/usr/sbin/runuser', '-u', 'desktop-user', '--', 'env'])
        self.assertIn('XDG_RUNTIME_DIR={}'.format(user_runtime), command)
        self.assertIn('DBUS_SESSION_BUS_ADDRESS=unix:path={}'.format(user_runtime / 'bus'), command)
        self.assertEqual(command[-3:], [
            '/usr/libexec/geoclue-2.0/demos/where-am-i',
            '--accuracy-level=8', '--timeout=20',
        ])

    def test_desktop_user_requests_exact_geoclue_accuracy(self):
        with patch('core.gps_location.os.geteuid', return_value=1000):
            command = geoclue_command('/usr/libexec/geoclue-2.0/demos/where-am-i')
        self.assertEqual(command, [
            '/usr/libexec/geoclue-2.0/demos/where-am-i',
            '--accuracy-level=8', '--timeout=20',
        ])

    def test_accuracy_policy_prevents_inaccurate_position_from_being_enforced(self):
        collector = GPSLocationCollector({
            'gps_tracking_enabled': True,
            'gps_required_accuracy_meters': 50,
        })
        collector._collect_linux = lambda: {
            'status': 'available', 'provider': 'geoclue', 'latitude': 28.6,
            'longitude': 77.2, 'accuracyMeters': 250,
        }
        original = __import__('platform').system
        try:
            __import__('platform').system = lambda: 'Linux'
            result = collector.collect()
        finally:
            __import__('platform').system = original
        self.assertEqual(result['status'], 'inaccurate')
        event = collector.event_for(result)
        self.assertEqual(event['ruleId'], 'GEO_GPS_STATUS')
        self.assertEqual(event['gpsStatus'], 'inaccurate')
        self.assertEqual(event['gpsLat'], 28.6)
        self.assertEqual(event['gpsLon'], 77.2)
        self.assertEqual(event['gpsCoordinateQuality'], 'approximate')

    def test_unchanged_inaccurate_position_is_kept_local_after_first_report(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        result = {
            'status': 'inaccurate', 'provider': 'geoclue',
            'latitude': 26.8393, 'longitude': 80.9231,
            'accuracyMeters': 25000,
        }
        self.assertIsNotNone(collector.event_for(result))
        self.assertIsNone(collector.event_for({**result, 'timestamp': '2026-09-07T01:00:00Z'}))

    def test_coarse_geoclue_coordinate_changes_remain_local(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        original = {
            'status': 'inaccurate', 'provider': 'geoclue',
            'latitude': 26.8393, 'longitude': 80.9231,
            'accuracyMeters': 25000,
        }
        changed = {**original, 'latitude': 26.8493}
        self.assertIsNotNone(collector.event_for(original))
        self.assertIsNone(collector.event_for(changed))

    def test_accurate_fix_after_inaccurate_state_is_reported(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        inaccurate = {
            'status': 'inaccurate', 'provider': 'geoclue',
            'latitude': 26.8393, 'longitude': 80.9231, 'accuracyMeters': 25000,
        }
        available = {**inaccurate, 'status': 'available', 'accuracyMeters': 20}
        self.assertIsNotNone(collector.event_for(inaccurate))
        event = collector.event_for(available)
        self.assertIsNotNone(event)
        self.assertEqual(event['ruleId'], 'GPS_LOCATION_TELEMETRY')
        self.assertEqual(event['gpsLat'], 26.8393)

    def test_small_provider_jitter_is_monitored_locally(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        original = {
            'status': 'available', 'provider': 'gpsd-gnss',
            'latitude': 26.83931, 'longitude': 80.92311,
            'accuracyMeters': 9,
        }
        jitter = {**original, 'latitude': 26.83932, 'longitude': 80.92312, 'accuracyMeters': 10}
        self.assertIsNotNone(collector.event_for(original))
        self.assertIsNone(collector.event_for(jitter))

    def test_accuracy_only_change_does_not_resend_same_position(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        original = {
            'status': 'available', 'provider': 'gpsd-gnss',
            'latitude': 26.83931, 'longitude': 80.92311,
            'accuracyMeters': 9,
        }
        self.assertIsNotNone(collector.event_for(original))
        self.assertIsNone(collector.event_for({**original, 'accuracyMeters': 24}))

    def test_changed_position_is_reported(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        original = {
            'status': 'available', 'provider': 'gpsd-gnss',
            'latitude': 26.83931, 'longitude': 80.92311,
            'accuracyMeters': 9,
        }
        moved = {**original, 'latitude': 26.84031}
        self.assertIsNotNone(collector.event_for(original))
        self.assertIsNotNone(collector.event_for(moved))

    def test_last_gps_state_survives_collector_restart(self):
        class MemoryState:
            value = None

            def gps_location_state(self):
                return self.value

            def set_gps_location_state(self, value):
                self.value = list(value)

        state = MemoryState()
        location = {
            'status': 'available', 'provider': 'windows-location-services',
            'latitude': 28.6139, 'longitude': 77.209, 'accuracyMeters': 9,
        }
        self.assertIsNotNone(GPSLocationCollector({'gps_tracking_enabled': True}, state=state).event_for(location))
        self.assertIsNone(GPSLocationCollector({'gps_tracking_enabled': True}, state=state).event_for(location))

    def test_unchanged_restart_state_still_logs_active_monitoring_once(self):
        class MemoryState:
            def gps_location_state(self):
                return ['inaccurate', 'geoclue', None, None, '', '', 0, '']

            def set_gps_location_state(self, _value):
                pass

        collector = GPSLocationCollector({'gps_tracking_enabled': True}, state=MemoryState())
        collector.collect = lambda: {
            'status': 'inaccurate', 'provider': 'geoclue',
            'latitude': 25.3167, 'longitude': 83.0104,
            'accuracyMeters': 25000,
        }
        with self.assertLogs('soc-agent.gps-location', level='INFO') as captured:
            self.assertIsNone(collector.run_and_report())
        self.assertTrue(any(
            'GPS observation active:' in message and 'suppressed_unchanged_state' in message
            for message in captured.output
        ))

    def test_policy_change_reports_current_state_without_gps_movement(self):
        class MemoryState:
            value = None

            def gps_location_state(self):
                return self.value

            def set_gps_location_state(self, value):
                self.value = list(value)

        state = MemoryState()
        location = {
            'status': 'available', 'provider': 'gpsd-gnss',
            'latitude': 28.6139, 'longitude': 77.209, 'accuracyMeters': 9,
        }
        first = GPSLocationCollector({
            'gps_tracking_enabled': True, 'gps_policy_id': 'policy-1',
            'gps_policy_version': 1, 'gps_policy_action': 'LOG & MONITOR',
        }, state=state)
        self.assertIsNotNone(first.event_for(location))
        changed = GPSLocationCollector({
            'gps_tracking_enabled': True, 'gps_policy_id': 'policy-1',
            'gps_policy_version': 2, 'gps_policy_action': 'ALERT & NOTIFY SOC',
        }, state=state)
        event = changed.event_for(location)
        self.assertIsNotNone(event)
        self.assertEqual(event['policyAction'], 'ALERT & NOTIFY SOC')

    def test_allow_policy_records_allowed_action_status(self):
        collector = GPSLocationCollector({
            'gps_tracking_enabled': True,
            'gps_policy_action': 'ALLOW & AUDIT',
        })
        event = collector.event_for({
            'status': 'available', 'provider': 'test-provider',
            'latitude': 28.6139, 'longitude': 77.209,
            'accuracyMeters': 10, 'timestamp': '2026-09-08T00:00:00Z',
        })
        self.assertEqual(event['policyActionStatus'], 'allowed')

    def test_accuracy_policy_cannot_be_relaxed_beyond_fifty_metres(self):
        collector = GPSLocationCollector({
            'gps_tracking_enabled': True,
            'gps_required_accuracy_meters': 50000,
        })
        self.assertEqual(collector.required_accuracy_meters, 50)

    def test_available_position_is_live_capability_23_telemetry(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        event = collector.event_for({
            'status': 'available', 'provider': 'windows-location-services',
            'latitude': 28.6139, 'longitude': 77.209, 'accuracyMeters': 9,
            'timestamp': '2026-08-30T10:00:00Z',
        })
        self.assertEqual(event['ruleId'], 'GPS_LOCATION_TELEMETRY')
        self.assertEqual(event['capabilityId'], 23)
        self.assertEqual(event['gpsLat'], 28.6139)
        self.assertEqual(event['geoLon'], 77.209)

    def test_forensic_context_populates_every_forensic_panel_tab(self):
        collector = GPSLocationCollector({
            'gps_tracking_enabled': True,
            'geolocation_forensics_enabled': True,
            'system_id': 'system-23',
            'agent_version': '2.0.0',
            'gps_policy_id': 'policy-23',
            'gps_policy_name': 'Office GPS',
            'gps_policy_category': 'Device GPS Tracking',
            'gps_policy_action': 'LOG & MONITOR',
            'geo_fence_latitude': 28.6139,
            'geo_fence_longitude': 77.209,
            'geo_fence_radius_meters': 50,
        })
        event = collector.event_for({
            'status': 'available', 'provider': 'gpsd-gnss',
            'latitude': 28.6139, 'longitude': 77.209,
            'accuracyMeters': 8, 'timestamp': '2026-09-08T00:00:00Z',
        })
        context = event['raw']['geoForensics']
        self.assertEqual(set(context), {
            'schemaVersion', 'evidenceOrigin', 'overview', 'network', 'travel',
            'authentication', 'endpoint', 'data', 'mitre', 'policy', 'timeline', 'actions',
        })
        self.assertEqual(context['endpoint']['systemId'], 'system-23')
        self.assertTrue(context['travel']['policyEligible'])
        self.assertTrue(context['travel']['insideAllowedRadius'])
        self.assertFalse(context['data']['exfiltrationObserved'])
        self.assertEqual(context['policy']['policyId'], 'policy-23')

    def test_forensic_context_remains_policy_gated(self):
        event = GPSLocationCollector({'gps_tracking_enabled': True}).event_for({
            'status': 'sensor_unavailable', 'provider': 'gpsd-gnss', 'reason': 'no fix',
        })
        self.assertNotIn('raw', event)

    def test_macos_uses_corelocation_provider(self):
        collector = GPSLocationCollector({'gps_tracking_enabled': True})
        with patch('core.gps_location.platform.system', return_value='Darwin'), \
                patch('core.gps_location.collect_macos_corelocation', return_value={
                    'status': 'available', 'provider': 'macos-corelocation',
                    'latitude': 28.6139, 'longitude': 77.209, 'accuracyMeters': 15,
                }):
            result = collector.collect()
        self.assertEqual(result['status'], 'available')
        self.assertEqual(result['provider'], 'macos-corelocation')


if __name__ == '__main__':
    unittest.main()
