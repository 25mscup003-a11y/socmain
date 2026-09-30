import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'soc-agent'))

from core.session_response import logout_user


class GeographySessionResponseTests(unittest.TestCase):
    @patch('core.session_response.subprocess.run')
    @patch('core.session_response.platform.system', return_value='Windows')
    def test_windows_logout_uses_allowlisted_command_without_shell(self, _system, run):
        run.return_value = Mock(returncode=0, stdout='', stderr='')
        result = logout_user('alice')
        self.assertTrue(result['ok'])
        run.assert_called_once_with(
            ['shutdown.exe', '/l', '/f'], capture_output=True, text=True,
            timeout=15, check=False,
        )

    @patch('core.session_response.subprocess.run')
    @patch('core.session_response.platform.system', return_value='Linux')
    def test_linux_logout_targets_only_valid_named_user(self, _system, run):
        run.return_value = Mock(returncode=0, stdout='', stderr='')
        logout_user('alice')
        self.assertEqual(run.call_args.args[0], ['loginctl', 'terminate-user', 'alice'])

    @patch('core.session_response.subprocess.run')
    @patch('core.session_response.pwd.getpwnam')
    @patch('core.session_response.platform.system', return_value='Darwin')
    def test_macos_logout_closes_only_selected_gui_session(self, _system, getpwnam, run):
        getpwnam.return_value = Mock(pw_name='alice', pw_uid=501)
        run.return_value = Mock(returncode=0, stdout='', stderr='')
        result = logout_user('alice')
        self.assertTrue(result['ok'])
        self.assertEqual(run.call_args.args[0], ['/bin/launchctl', 'bootout', 'gui/501'])

    def test_unsafe_or_service_accounts_are_refused(self):
        with self.assertRaises(ValueError):
            logout_user('alice; reboot')
        with patch('core.session_response.platform.system', return_value='Linux'):
            with self.assertRaises(RuntimeError):
                logout_user('root')


if __name__ == '__main__':
    unittest.main()
