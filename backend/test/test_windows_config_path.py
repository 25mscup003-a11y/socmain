import importlib.util
import os
import pathlib
import unittest
from unittest import mock


CONFIG_MODULE = pathlib.Path(__file__).parents[1] / 'soc-agent' / 'core' / 'config.py'


def load_config_module():
    spec = importlib.util.spec_from_file_location('soc_agent_config_path_test', CONFIG_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsConfigPathTest(unittest.TestCase):
    def test_installed_windows_agent_uses_programdata_without_env_override(self):
        with mock.patch.dict(os.environ, {
            'ProgramData': r'C:\ProgramData',
            'AJNAT_DATA_DIR': r'C:\ProgramData\AJNAT',
        }, clear=False), mock.patch('platform.system', return_value='Windows'), \
                mock.patch.object(pathlib.Path, 'exists', return_value=True):
            module = load_config_module()
            self.assertEqual(
                module.CONFIG_PATH,
                pathlib.Path(r'C:\ProgramData\AJNAT\config\company_config.json'),
            )


if __name__ == '__main__':
    unittest.main()
