import os
import sys
import unittest


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from core.waf import Module, _sanitize_request_target


class Sender:
    def __init__(self):
        self.alerts = []

    def enqueue(self, alert):
        self.alerts.append(alert)


class ApiMonitoringTests(unittest.TestCase):
    def test_sensitive_query_values_are_redacted(self):
        target = _sanitize_request_target('/api/login?user=alice&access_token=secret&password=pwd')
        self.assertIn('user=alice', target)
        self.assertNotIn('secret', target)
        self.assertNotIn('pwd', target)
        self.assertEqual(target.count('%5BREDACTED%5D'), 2)

    def test_proxy_request_is_sent_as_capability_20_telemetry(self):
        sender = Sender()
        module = Module(sender, config={
            'company_id': 'company-1', 'department_id': 'dept-1', 'system_id': 'system-1',
        })
        module.on_request({
            'src_ip': '198.51.100.20', 'path': '/v1/orders', 'method': 'POST',
            'status_code': 201, 'request_size': 120, 'response_size': 480,
            'response_time_ms': 18.25, 'target_port': 8080,
        })
        event = sender.alerts[-1]
        self.assertEqual(event['capabilityId'], 20)
        self.assertEqual(event['rule_id'], 'API_CALL_TELEMETRY')
        self.assertEqual(event['requestPath'], '/v1/orders')
        self.assertEqual(event['statusCode'], 201)
        self.assertEqual(event['responseTime'], 18.25)
        self.assertEqual(event['dst_port'], 8080)


if __name__ == '__main__':
    unittest.main()
