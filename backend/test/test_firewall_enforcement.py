import unittest
from unittest.mock import mock_open, patch

from core import firewall
from core.command_listener import CommandListener


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class FirewallEnforcementTests(unittest.TestCase):
    def test_protocol_only_rule_uses_protocol_without_undefined_port(self):
        class FakeFirewall:
            def __init__(self):
                self.protocols = []

            def block_protocol(self, protocol, reason=''):
                self.protocols.append((protocol, reason))
                return True

        listener = CommandListener.__new__(CommandListener)
        listener._firewall = FakeFirewall()
        listener._ips = None
        listener._sender = Sender()
        result = listener._apply_firewall_rule({
            'ruleName': 'ICMP guard',
            'action': 'block',
            'conditions': {'protocol': 'icmp'},
        })
        self.assertIn('block_protocol(icmp)=ok', result)
        self.assertEqual(listener._firewall.protocols[0][0], 'icmp')

    def test_agent_ack_reports_only_real_firewall_success(self):
        self.assertTrue(CommandListener._firewall_result_ok('block_ip(203.0.113.10,dir=both)=✓'))
        self.assertTrue(CommandListener._firewall_result_ok('ips.block_ip(203.0.113.10)=ok'))
        self.assertFalse(CommandListener._firewall_result_ok('block_ip(203.0.113.10,dir=both)=✗'))
        self.assertFalse(CommandListener._firewall_result_ok('IPS block failed for 203.0.113.10'))
        self.assertFalse(CommandListener._firewall_result_ok('no actionable conditions'))

    @patch.object(firewall.os.path, 'exists', return_value=False)
    def test_linux_application_block_fails_closed_without_killing_process(self, _exists):
        sender = Sender()
        module = firewall.FirewallModule(sender)
        with patch.object(firewall, 'SYSTEM', 'Linux'):
            self.assertFalse(module.block_application('browser', persist=False))
        self.assertIn('not supported', sender.events[-1]['description'])

    @patch.object(firewall.subprocess, 'run')
    def test_domain_resolution_includes_ipv4_and_ipv6(self, run):
        def result(command, **_kwargs):
            record_type = command[2] if command[:2] == ['dig', '+short'] else ''
            stdout = '151.101.2.132\n' if record_type == 'A' else '2a04:4e42::644\n'
            return type('Result', (), {'returncode': 0, 'stdout': stdout})()

        run.side_effect = result

        self.assertEqual(
            firewall._resolve_domain('bugcrowd.com'),
            ['151.101.2.132', '2a04:4e42::644'],
        )

    @patch.object(firewall.subprocess, 'run')
    @patch.object(firewall, '_resolve_domain', return_value=[])
    def test_existing_hosts_entry_is_reported_as_enforced(self, _resolve, _run):
        sender = Sender()
        with patch.object(firewall.os.path, 'exists', return_value=False):
            module = firewall.FirewallModule(sender)
        hosts = (
            '0.0.0.0 example.com\n:: example.com\n'
            '0.0.0.0 www.example.com\n:: www.example.com\n'
        )
        with patch.object(firewall, 'SYSTEM', 'Linux'), \
                patch.object(firewall.os.path, 'exists', return_value=True), \
                patch('builtins.open', mock_open(read_data=hosts)):
            result = module.block_domain('example.com', persist=False)

        self.assertTrue(result['ok'])
        self.assertTrue(result['hosts_blocked'])


if __name__ == '__main__':
    unittest.main()
