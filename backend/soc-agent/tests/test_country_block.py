import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.country_block import CountryBlockEnforcer, compile_networks, nft_script, pf_script, apply_firewall


def policy(direction='both', revision='a' * 64):
    return {'revision': revision, 'rules': [{'id': 'one', 'countryCode': 'IN', 'direction': direction}],
            'networks': {'IN': {'ipv4': ['8.8.8.0/24'], 'ipv6': ['2606:4700::/32']}}}


class CountryBlockTests(unittest.TestCase):
    def test_inbound_and_outbound_match_the_correct_remote_address_for_both_families(self):
        inbound = compile_networks(policy('inbound'))
        self.assertEqual(inbound['in4'], ['8.8.8.0/24'])
        self.assertEqual(inbound['out4'], [])
        self.assertEqual(inbound['out6'], [])
        outbound = compile_networks(policy('outbound'))
        self.assertEqual(outbound['in6'], [])
        self.assertEqual(outbound['out6'], ['2606:4700::/32'])
        script = nft_script(compile_networks(policy()), True)
        self.assertIn('ip saddr @in4 counter drop', script)
        self.assertIn('ip6 daddr @out6 counter drop', script)
        self.assertIn('delete table inet soc_country_block', script)
        self.assertNotIn('flush ruleset', script)

    def test_overlapping_rules_remain_blocked_until_the_last_matching_rule_is_removed(self):
        data = policy('inbound')
        data['rules'].append({'id': 'two', 'countryCode': 'IN', 'direction': 'both'})
        self.assertEqual(compile_networks(data)['in4'], ['8.8.8.0/24'])
        data['rules'].pop(0)
        self.assertEqual(compile_networks(data)['in4'], ['8.8.8.0/24'])
        data['rules'] = []
        self.assertEqual(nft_script(compile_networks(data), True), 'delete table inet soc_country_block\n')

    def test_management_address_is_excluded_without_allowing_the_rest_of_the_country(self):
        address = ipaddress.ip_address('8.8.8.8')
        groups = compile_networks(policy(), [address])
        for key in ('in4', 'out4'):
            networks = [ipaddress.ip_network(value) for value in groups[key]]
            self.assertFalse(any(address in network for network in networks))
            self.assertTrue(any(ipaddress.ip_address('8.8.8.9') in network for network in networks))

    def test_rejects_partial_or_unsafe_feeds_before_touching_firewall(self):
        for invalid in ['0.0.0.0/0', '127.0.0.0/8', '10.0.0.0/8', '8.8.8.0/24;drop']:
            data = policy()
            data['networks']['IN']['ipv4'] = [invalid]
            with self.assertRaises(ValueError):
                compile_networks(data)
        data = policy()
        data['networks']['IN']['ipv6'] = []
        with self.assertRaises(ValueError):
            compile_networks(data)

    @patch('core.country_block.platform.system', return_value='Linux')
    @patch('core.country_block.fw_backend._have', return_value=True)
    @patch('core.country_block.fw_backend._run')
    def test_linux_replacement_is_one_atomic_transaction_and_surfaces_errors(self, run, *_):
        run.side_effect = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=1, stderr='permission denied')]
        with self.assertRaisesRegex(RuntimeError, 'permission denied'):
            apply_firewall(compile_networks(policy()))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0], ['nft', '-f', '-'])
        self.assertIn('delete table inet soc_country_block\ntable inet soc_country_block', run.call_args.kwargs['stdin'])

    def test_macos_rules_express_direction_separately(self):
        self.assertIn('block drop in quick from <in4> to any', pf_script(compile_networks(policy('inbound'))))
        self.assertNotIn('block drop out', pf_script(compile_networks(policy('inbound'))))
        self.assertIn('block drop out quick from any to <out6>', pf_script(compile_networks(policy('outbound'))))

    @patch('core.country_block.platform.system', return_value='Windows')
    @patch('core.country_block.fw_backend._run')
    def test_windows_failure_is_reported_and_staging_cleanup_preserves_old_rules(self, run, *_):
        import base64
        run.return_value = SimpleNamespace(returncode=1, stderr='firewall disabled')
        with self.assertRaisesRegex(RuntimeError, 'firewall disabled'):
            apply_firewall(compile_networks(policy()))
        script = base64.b64decode(run.call_args.args[0][-1]).decode('utf-16le')
        self.assertTrue(script.startswith("$ErrorActionPreference = 'Stop'"))
        self.assertIn('foreach ($name in $created)', script)
        self.assertIn("$_.Group -eq 'AJNAT Country Block'", script)
        self.assertIn("'Inbound'", script)
        self.assertIn("'Outbound'", script)

    def test_failed_download_retains_the_applied_revision_and_cached_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            enforcer = CountryBlockEnforcer({'country_block_state_path': str(Path(directory) / 'state.json')})
            previous = policy(revision='b' * 64)
            enforcer._save(previous)
            enforcer._status['appliedRevision'] = previous['revision']
            enforcer._desired = policy()
            with patch.object(enforcer, '_download', side_effect=RuntimeError('feed unavailable')), patch('core.country_block.apply_firewall') as apply:
                enforcer._sync(policy())
            apply.assert_not_called()
            self.assertEqual(enforcer.status()['state'], 'error')
            self.assertEqual(enforcer.status()['appliedRevision'], previous['revision'])
            self.assertEqual(json.loads(enforcer.path.read_text())['policy'], previous)

    def test_failed_firewall_replacement_retains_last_successful_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            enforcer = CountryBlockEnforcer({'country_block_state_path': str(Path(directory) / 'state.json')})
            previous = policy(revision='b' * 64)
            enforcer._save(previous)
            enforcer._desired = policy()
            with patch('core.country_block.management_addresses', return_value=set()), patch('core.country_block.apply_firewall', side_effect=RuntimeError('failed')):
                enforcer._sync(policy(), cached=policy())
            self.assertEqual(json.loads(enforcer.path.read_text())['policy'], previous)

    def test_empty_policy_removes_blocks_without_needing_the_country_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            enforcer = CountryBlockEnforcer({'country_block_state_path': str(Path(directory) / 'state.json')})
            empty = {'revision': 'c' * 64, 'rules': []}
            enforcer._desired = empty
            with patch.object(enforcer, '_download') as download, patch('core.country_block.apply_firewall') as apply:
                enforcer._sync(empty)
            download.assert_not_called()
            self.assertFalse(any(apply.call_args.args[0].values()))
            self.assertEqual(enforcer.status()['appliedRevision'], empty['revision'])

    def test_superseded_download_never_installs_a_stale_rule(self):
        enforcer = CountryBlockEnforcer({})
        enforcer._desired = {'revision': 'b' * 64, 'rules': []}
        with patch('core.country_block.management_addresses', return_value=set()), patch('core.country_block.apply_firewall') as apply:
            enforcer._sync(policy(), cached=policy())
        apply.assert_not_called()


if __name__ == '__main__':
    unittest.main()
