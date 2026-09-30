import json
import os
import socket
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from collectors.file_monitor import _file_state
from collectors.network import _get_connections, _get_listeners
from collectors.processes import ProcessCollector


class CountingPsutil:
    class AccessDenied(Exception):
        pass

    class NoSuchProcess(Exception):
        pass

    def __init__(self, rows=None):
        self.rows = rows or []
        self.socket_calls = 0
        self.process_calls = 0

    def net_connections(self, kind='inet'):
        self.socket_calls += 1
        return self.rows

    def Process(self, pid):
        self.process_calls += 1
        return FakeProcess(pid)


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid

    def exe(self): return ''
    def name(self): return 'worker'
    def username(self): return 'service'
    def cmdline(self): return ['worker']
    def ppid(self): return 1
    def parent(self): return None
    def create_time(self): return 123.0


def socket_row(remote=True):
    return SimpleNamespace(
        type=socket.SOCK_STREAM,
        status='ESTABLISHED' if remote else 'LISTEN',
        family=socket.AF_INET,
        pid=77,
        laddr=SimpleNamespace(ip='10.0.0.2', port=5000),
        raddr=SimpleNamespace(ip='8.8.8.8', port=443) if remote else None,
    )


class LoadOptimizationTests(unittest.TestCase):
    def test_unchanged_file_reuses_hashes(self):
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b'agent-load-test')
            handle.flush()
            with patch('collectors.file_monitor._sha256', return_value='sha') as sha, \
                    patch('collectors.file_monitor._md5', return_value='md5') as md5:
                first = _file_state(handle.name)
                second = _file_state(handle.name, previous=first)
            self.assertEqual(second['sha256'], 'sha')
            self.assertEqual(second['md5'], 'md5')
            self.assertEqual(sha.call_count, 1)
            self.assertEqual(md5.call_count, 1)

    def test_process_socket_snapshot_is_cached(self):
        fake = CountingPsutil([SimpleNamespace(
            pid=41, raddr=SimpleNamespace(ip='8.8.8.8', port=443)
        )])
        collector = ProcessCollector(SimpleNamespace(enqueue=lambda event: None), config={
            'process_connection_snapshot_interval_seconds': 60,
        })
        collector._cached_connection_snapshot(fake, 100.0)
        collector._cached_connection_snapshot(fake, 120.0)
        self.assertEqual(fake.socket_calls, 1)

    def test_network_views_share_one_socket_snapshot_and_process_cache(self):
        fake = CountingPsutil([socket_row(True), socket_row(False)])
        rows = fake.net_connections(kind='inet')
        cache = {}
        connections = _get_connections(rows, cache, fake, {})
        listeners = _get_listeners(rows, cache, fake, {})
        self.assertEqual(fake.socket_calls, 1)
        self.assertEqual(fake.process_calls, 1)
        self.assertEqual(len(connections), 1)
        self.assertEqual(len(listeners), 1)

    def test_company_config_uses_low_load_intervals(self):
        path = os.path.join(AGENT_DIR, 'config', 'company_config.json')
        with open(path, encoding='utf-8') as handle:
            config = json.load(handle)
        self.assertGreaterEqual(config['process_poll_interval_seconds'], 30)
        self.assertGreaterEqual(config['process_inventory_interval_seconds'], 60)
        self.assertGreaterEqual(config['file_monitor_poll_interval_seconds'], 60)
        self.assertGreaterEqual(config['network_poll_interval_seconds'], 20)
        self.assertFalse(config['file_monitor_md5_enabled'])


if __name__ == '__main__':
    unittest.main()
