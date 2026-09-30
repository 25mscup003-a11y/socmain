import importlib.util
import pathlib
import unittest


AGENT_PATH = pathlib.Path(__file__).parents[1] / 'soc-agent' / 'agent.py'
SPEC = importlib.util.spec_from_file_location('soc_agent_main', AGENT_PATH)
AGENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AGENT)


class AgentStartupTest(unittest.TestCase):
    def test_storage_key_retries_without_insecure_fallback(self):
        calls = []
        sleeps = []

        def fetcher(_config):
            calls.append(True)
            if len(calls) < 3:
                raise RuntimeError('temporary 503')
            return 'server-key'

        result = AGENT._fetch_storage_key_with_retry(
            {}, fetcher=fetcher, sleeper=sleeps.append, max_attempts=3
        )

        self.assertEqual(result, 'server-key')
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, [5, 10])


if __name__ == '__main__':
    unittest.main()
