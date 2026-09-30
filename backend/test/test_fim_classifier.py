import unittest

from collectors.file_monitor import _fim_module


class FimClassifierTest(unittest.TestCase):
    def test_permission_words_in_filename_do_not_create_permission_events(self):
        path = '/app/node_modules/pkg/aclPermissionTypes.js'
        module = _fim_module(path, 'created', 'File created: aclPermissionTypes.js')
        self.assertEqual(module, 'sensitive')
        self.assertNotEqual(module, 'permission')

    def test_explicit_permission_delta_is_classified(self):
        self.assertEqual(_fim_module('/etc/passwd', 'permission_changed', 'File permission changed', {
            'old_permission': '0644', 'new_permission': '0777',
        }), 'permission')

    def test_explicit_ownership_delta_is_classified(self):
        self.assertEqual(_fim_module('/srv/app', 'ownership_changed', 'File ownership changed', {
            'old_owner': 'root', 'new_owner': 'app',
        }), 'ownership')


if __name__ == '__main__':
    unittest.main()
