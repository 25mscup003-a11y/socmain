import unittest
from unittest import mock

from collectors.usb import USBCollector


class FakeSender:
    def enqueue(self, _event):
        return None


class USBCollectorLifecycleTest(unittest.TestCase):
    def test_mount_watcher_is_deduplicated_until_worker_exits(self):
        collector = USBCollector(FakeSender())
        collector._scan_mount = mock.Mock()
        collector._watch_mount = mock.Mock()

        with mock.patch('collectors.usb.threading.Thread') as thread:
            worker = mock.Mock()
            thread.return_value = worker

            self.assertTrue(collector._start_mount_watch('/media/test-usb', 'USB', 'analyst'))
            self.assertFalse(collector._start_mount_watch('/media/test-usb', 'USB', 'analyst'))
            worker.start.assert_called_once()

            target = thread.call_args.kwargs['target']
            target()

        self.assertNotIn('/media/test-usb', collector._watched_mounts)


if __name__ == '__main__':
    unittest.main()
