import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import core.dns_sinkhole as dns_module
from core.dns_sinkhole import DNSSinkhole


class DnsSinkholeConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.hosts = Path(self.tempdir.name) / 'hosts'
        self.dnsmasq = Path(self.tempdir.name) / 'soc4-sinkhole.conf'
        self.hosts.write_text('127.0.0.1 localhost\n', encoding='utf-8')
        self.hosts_patch = patch.dict(dns_module.HOSTS_PATHS, {'linux': str(self.hosts)})
        self.dnsmasq_patch = patch.object(dns_module, 'DNSMASQ_CONF', str(self.dnsmasq))
        self.platform_patch = patch('core.dns_sinkhole.platform.system', return_value='Linux')
        self.hosts_patch.start()
        self.dnsmasq_patch.start()
        self.platform_patch.start()

    def tearDown(self):
        self.platform_patch.stop()
        self.dnsmasq_patch.stop()
        self.hosts_patch.stop()
        self.tempdir.cleanup()

    def test_configuration_applies_blocklist_and_allowlist(self):
        sinkhole = DNSSinkhole(config={})
        result = sinkhole.configure({
            'dns_sinkhole_enabled': True,
            'dns_sinkhole_ip': '127.0.0.2',
            'dns_sinkhole_enforcement_mode': 'both',
            'dns_sinkhole_telemetry_enabled': True,
            'dns_sinkhole_report_interval_seconds': 120,
            'dns_sinkhole_sync_blocklist': True,
            'dns_sinkhole_policy_version': 4,
        }, blocklist=['bad.example', 'safe.example'], allowlist=['safe.example'])

        self.assertEqual(result['policy_version'], 4)
        self.assertEqual(sinkhole.list_sinkholed(), ['bad.example'])
        self.assertIn('127.0.0.2 bad.example # SOC4-SINKHOLE', self.hosts.read_text())
        self.assertIn('address=/bad.example/127.0.0.2', self.dnsmasq.read_text())
        self.assertNotIn('safe.example', self.hosts.read_text())

    def test_disabling_policy_removes_managed_entries(self):
        sinkhole = DNSSinkhole(config={})
        sinkhole.sinkhole('bad.example')
        sinkhole.configure({
            'dns_sinkhole_enabled': False,
            'dns_sinkhole_ip': '0.0.0.0',
            'dns_sinkhole_enforcement_mode': 'both',
            'dns_sinkhole_telemetry_enabled': False,
            'dns_sinkhole_report_interval_seconds': 300,
            'dns_sinkhole_sync_blocklist': True,
        }, blocklist=['bad.example'])

        self.assertEqual(sinkhole.list_sinkholed(), [])
        self.assertNotIn('bad.example', self.hosts.read_text())

    def test_configuration_rejects_invalid_ip(self):
        sinkhole = DNSSinkhole(config={})
        with self.assertRaises(ValueError):
            sinkhole.configure({'dns_sinkhole_ip': 'not-an-ip'})

    def test_rule_specific_sinkhole_ip_overrides_global_destination(self):
        sinkhole = DNSSinkhole(config={})
        result = sinkhole.configure({
            'dns_sinkhole_enabled': True,
            'dns_sinkhole_ip': '127.0.0.2',
            'dns_sinkhole_enforcement_mode': 'both',
            'dns_sinkhole_sync_blocklist': True,
        }, blocklist=['bad.example', 'c2.example'], sinkhole_targets={
            'c2.example': '10.20.30.40',
        })

        self.assertEqual(result['total_sinkholed'], 2)
        hosts = self.hosts.read_text()
        dnsmasq = self.dnsmasq.read_text()
        self.assertIn('127.0.0.2 bad.example # SOC4-SINKHOLE', hosts)
        self.assertIn('10.20.30.40 c2.example # SOC4-SINKHOLE', hosts)
        self.assertIn('address=/c2.example/10.20.30.40', dnsmasq)

    def test_direct_rule_replaces_previous_sinkhole_ip(self):
        sinkhole = DNSSinkhole(config={})
        sinkhole.sinkhole('bad.example', sinkhole_ip='10.0.0.10')
        result = sinkhole.sinkhole('bad.example', sinkhole_ip='10.0.0.20')

        self.assertTrue(result['success'])
        self.assertEqual(result['sinkhole_ip'], '10.0.0.20')
        hosts = self.hosts.read_text()
        self.assertIn('10.0.0.20 bad.example # SOC4-SINKHOLE', hosts)
        self.assertNotIn('10.0.0.10 bad.example', hosts)

    def test_rule_specific_sinkhole_rejects_invalid_safe_server_ip(self):
        sinkhole = DNSSinkhole(config={})
        result = sinkhole.sinkhole('bad.example', sinkhole_ip='999.10.10.10')

        self.assertFalse(result['success'])
        self.assertNotIn('bad.example', self.hosts.read_text())


if __name__ == '__main__':
    unittest.main()
