import os
import sys
import unittest
from unittest.mock import patch


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from core.geo_enrichment import GeoEnrichment, _distance_meters


class GeolocationEnrichmentTests(unittest.TestCase):
    def test_haversine_distance_is_realistic(self):
        # Delhi to London is roughly 6,700 km.
        distance_km = _distance_meters(28.6139, 77.2090, 51.5074, -0.1278) / 1000
        self.assertGreater(distance_km, 6500)
        self.assertLess(distance_km, 7000)

    def test_impossible_travel_uses_configured_speed_and_distance(self):
        detector = GeoEnrichment({
            'geolocation_policies': [{
                'id': 'travel', 'name': 'Travel rule', 'category': 'Impossible Travel',
                'severity': 'Critical', 'action': 'ALERT & NOTIFY SOC', 'conditions': {},
            }],
            'geo_max_travel_speed_kmh': 900,
            'geo_min_travel_distance_km': 500,
        })
        first = {
            'username': 'analyst@example.test', 'geoCountry': 'India', 'geoCountryCode': 'IN',
            'geoCity': 'Delhi', 'geoLat': 28.6139, 'geoLon': 77.2090,
            'timestamp': '2026-08-30T10:00:00Z',
        }
        second = {
            'username': 'analyst@example.test', 'geoCountry': 'United Kingdom', 'geoCountryCode': 'GB',
            'geoCity': 'London', 'geoLat': 51.5074, 'geoLon': -0.1278,
            'timestamp': '2026-08-30T10:10:00Z',
        }
        self.assertFalse(any(row['ruleId'] == 'GEO_IMPOSSIBLE_TRAVEL' for row in detector.analyze(first)))
        finding = next(row for row in detector.analyze(second) if row['ruleId'] == 'GEO_IMPOSSIBLE_TRAVEL')
        self.assertEqual(finding['capabilityId'], 23)
        self.assertGreater(finding['riskScore'], 80)
        self.assertGreater(finding['raw']['distanceKm'], 6500)
        self.assertGreater(finding['raw']['requiredSpeedKmh'], 900)

    def test_no_policy_means_no_anomaly_action(self):
        detector = GeoEnrichment({'geolocation_policies': []})
        alert = {'username': 'user', 'geoCountry': 'Test', 'geoCountryCode': 'ZZ'}
        self.assertEqual(detector.analyze(alert), [])

    def test_device_gps_drives_configured_radius_violation(self):
        detector = GeoEnrichment({
            'geolocation_policies': [{
                'id': 'location', 'name': 'Office radius', 'category': 'Location-Based',
                'severity': 'High', 'action': 'LOG & MONITOR', 'conditions': {},
            }],
            'geo_fence_enabled': True,
            'geo_fence_latitude': 28.6139,
            'geo_fence_longitude': 77.2090,
            'geo_fence_radius_meters': 100,
        })
        findings = detector.analyze({
            'ruleId': 'GPS_LOCATION_TELEMETRY',
            'gpsLat': 28.6200,
            'gpsLon': 77.2090,
            'gpsAccuracyMeters': 10,
        })
        violation = next(item for item in findings if item['ruleId'] == 'GEO_FENCE_RADIUS_VIOLATION')
        self.assertGreater(violation['geoFenceDistanceMeters'], 100)
        self.assertEqual(violation['gpsAccuracyMeters'], 10)
        self.assertEqual(violation['policyCategory'], 'Location-Based')
        self.assertEqual(violation['policyAction'], 'LOG & MONITOR')

    def test_inaccurate_gps_never_falls_back_to_ip_coordinates_for_geofence(self):
        detector = GeoEnrichment({
            'geolocation_policies': [{
                'id': 'location', 'name': 'Office radius', 'category': 'Location-Based',
                'severity': 'High', 'action': 'LOG & MONITOR', 'conditions': {},
            }],
            'geo_fence_enabled': True,
            'geo_fence_latitude': 28.6139,
            'geo_fence_longitude': 77.2090,
            'geo_fence_radius_meters': 100,
            'gps_required_accuracy_meters': 50,
        })
        findings = detector.analyze({
            'ruleId': 'GPS_LOCATION_TELEMETRY',
            'gpsLat': 28.6200,
            'gpsLon': 77.2090,
            'gpsAccuracyMeters': 51,
            'gpsStatus': 'available',
            'geoLat': 51.5074,
            'geoLon': -0.1278,
        })
        self.assertFalse(any(item['ruleId'] == 'GEO_FENCE_RADIUS_VIOLATION' for item in findings))

    def test_unrelated_policy_does_not_authorize_proxy_detection(self):
        detector = GeoEnrichment({
            'geolocation_policies': [{
                'id': 'gps', 'name': 'GPS tracking', 'category': 'Device GPS Tracking',
                'severity': 'Low', 'action': 'LOG & MONITOR', 'conditions': {},
            }],
        })
        findings = detector.analyze({
            'username': 'analyst', 'geoCountry': 'India', 'geoCountryCode': 'IN',
            'geoProxy': True, 'srcip': '203.0.113.10',
        })
        self.assertEqual(findings, [])

    def test_country_policy_binds_action_and_block_request(self):
        detector = GeoEnrichment({
            'geolocation_policies': [{
                'id': 'country-1', 'name': 'Country block', 'category': 'Country-Based',
                'severity': 'Critical', 'action': 'BLOCK & IP BAN',
                'conditions': {'countries': ['ZZ'], 'riskCutoff': 70},
            }],
            'high_risk_geo_countries': ['ZZ'],
        })
        # Keep this policy/action unit test independent of the public Geo-IP
        # service; a live lookup must not overwrite the fixture country.
        with patch('core.geo_enrichment.lookup_ip', return_value=None):
            findings = detector.analyze({
                'username': 'analyst', 'geoCountry': 'Test', 'geoCountryCode': 'ZZ',
                'srcip': '8.8.8.8',
            })
        finding = next(item for item in findings if item['ruleId'] == 'GEO_HIGH_RISK_COUNTRY')
        self.assertEqual(finding['policyId'], 'country-1')
        self.assertEqual(finding['policyCategory'], 'Country-Based')
        self.assertEqual(finding['policyAction'], 'BLOCK & IP BAN')
        self.assertTrue(finding['ipBlockRequested'])


if __name__ == '__main__':
    unittest.main()
