import tempfile
import unittest
from pathlib import Path

from core.durable_spool import DurableSpool


class DurableSpoolTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'spool.sqlite3'
        self.key = 'a' * 64

    def tearDown(self):
        self.temp.cleanup()

    def test_pending_survives_reopen_and_acknowledges(self):
        spool = DurableSpool(self.path, encryption_key=self.key)
        self.assertTrue(spool.put({'event_id': 'evt-1', 'severity': 'high'}))
        self.assertFalse(spool.put({'event_id': 'evt-1', 'severity': 'high'}))
        spool.close()

        reopened = DurableSpool(self.path, encryption_key=self.key)
        self.assertEqual([item['event_id'] for item in reopened.due()], ['evt-1'])
        self.assertEqual(reopened.acknowledge(['evt-1']), 1)
        self.assertEqual(reopened.counts(), {'pending': 0, 'dead_letter': 0})
        reopened.close()

    def test_exhausted_retry_moves_event_to_dead_letter(self):
        spool = DurableSpool(self.path, max_attempts=2, encryption_key=self.key)
        spool.put({'event_id': 'evt-2', 'severity': 'critical'})
        self.assertEqual(spool.fail('evt-2', 'offline', 0), 'pending')
        self.assertEqual(spool.fail('evt-2', 'offline', 0), 'dead_letter')
        self.assertEqual(spool.counts(), {'pending': 0, 'dead_letter': 1})
        spool.close()

    def test_payload_is_aes256_encrypted_at_rest(self):
        import sqlite3

        spool = DurableSpool(self.path, encryption_key=self.key)
        spool.put({'event_id': 'evt-secret', 'description': 'sensitive telemetry'})
        with sqlite3.connect(self.path) as db:
            stored = db.execute('SELECT payload FROM pending_events').fetchone()[0]
        self.assertTrue(stored.startswith('enc:v1:'))
        self.assertNotIn('sensitive telemetry', stored)
        self.assertEqual(spool.due()[0]['description'], 'sensitive telemetry')
        spool.close()


if __name__ == '__main__':
    unittest.main()
