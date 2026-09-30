import unittest
from unittest.mock import patch

from core.ips import IPSModule


class Sender:
    def enqueue(self, _event):
        pass


class IpsWhitelistTests(unittest.TestCase):
    def setUp(self):
        self.ips = IPSModule(Sender(), {'ips_whitelist': []})
        self.ips.set_dashboard_whitelist([
            {'type': 'cidr', 'value': '203.0.113.0/24'},
            {'type': 'domain', 'value': 'trusted.example'},
        ])

    def test_dashboard_cidr_and_domain_are_enforced(self):
        self.assertTrue(self.ips.is_whitelisted('203.0.113.42'))
        self.assertFalse(self.ips.is_whitelisted('203.0.114.42'))
        self.assertTrue(self.ips.is_whitelisted('api.trusted.example', 'domain'))
        self.assertFalse(self.ips.is_whitelisted('nottrusted.example', 'domain'))

    @patch('core.ips.fw_backend.block_ip')
    def test_whitelisted_ip_never_reaches_firewall(self, block_ip):
        self.assertFalse(self.ips.block_ip('203.0.113.42'))
        block_ip.assert_not_called()


if __name__ == '__main__':
    unittest.main()
