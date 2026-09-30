import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / 'soc-agent' / 'collectors' / 'network.py'
SPEC = importlib.util.spec_from_file_location('soc_agent_network_collector', MODULE_PATH)
NETWORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NETWORK)


def listener(ip='0.0.0.0', port=8080, protocol='tcp', process='python'):
    return {
        'local_ip': ip,
        'local_port': port,
        'protocol': protocol,
        'process_name': process,
    }


def test_empty_allowlist_is_inventory_only():
    verdict = NETWORK.evaluate_port_policy(listener(), {'port_policy_enabled': True})
    assert verdict == {
        'violation': False,
        'reason': 'allowlist_not_configured',
        'exposed': True,
    }


def test_loopback_listener_is_exempt_by_default():
    config = {'port_policy_enabled': True, 'allowed_listening_ports': [443]}
    verdict = NETWORK.evaluate_port_policy(listener(ip='127.0.0.1'), config)
    assert verdict['violation'] is False
    assert verdict['reason'] == 'loopback_exempt'


def test_unapproved_exposed_port_is_violation():
    config = {'port_policy_enabled': True, 'allowed_listening_ports': ['tcp/443']}
    verdict = NETWORK.evaluate_port_policy(listener(port=8080), config)
    assert verdict['violation'] is True
    assert verdict['reason'] == 'port_not_allowed'


def test_port_can_be_limited_to_expected_process():
    config = {
        'port_policy_enabled': True,
        'allowed_listening_ports': ['tcp/443'],
        'allowed_port_processes': {'tcp/443': ['nginx']},
    }
    assert NETWORK.evaluate_port_policy(listener(port=443, process='nginx'), config)['violation'] is False
    verdict = NETWORK.evaluate_port_policy(listener(port=443, process='python'), config)
    assert verdict['violation'] is True
    assert verdict['reason'] == 'process_not_allowed'


def test_protocol_specific_allowlist_does_not_allow_udp():
    config = {'port_policy_enabled': True, 'allowed_listening_ports': ['tcp/53']}
    verdict = NETWORK.evaluate_port_policy(listener(port=53, protocol='udp'), config)
    assert verdict['violation'] is True


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class Firewall:
    def __init__(self):
        self.calls = []

    def close_port(self, port, protocol, direction='both'):
        self.calls.append((port, protocol, direction))
        return True


def test_block_mode_enforces_once_and_reports_owner():
    sender = Sender()
    firewall = Firewall()
    collector = NETWORK.NetworkCollector(sender, config={
        'port_policy_enabled': True,
        'port_policy_mode': 'block',
        'allowed_listening_ports': ['tcp/443'],
    })
    collector.set_firewall(firewall)
    exposed = listener(port=8080, process='python')
    exposed.update({'pid': 42, 'executable': '/usr/bin/python3', 'username': 'app'})

    collector._enforce_port_policy([exposed])
    collector._enforce_port_policy([exposed])

    assert firewall.calls == [(8080, 'tcp', 'in')]
    assert len(sender.events) == 1
    assert sender.events[0]['blocked'] is True
    assert sender.events[0]['pid'] == 42


def test_audit_mode_never_calls_firewall():
    sender = Sender()
    firewall = Firewall()
    collector = NETWORK.NetworkCollector(sender, config={
        'port_policy_enabled': True,
        'port_policy_mode': 'audit',
        'allowed_listening_ports': [443],
    })
    collector.set_firewall(firewall)
    collector._enforce_port_policy([listener(port=8080)])

    assert firewall.calls == []
    assert sender.events[0]['blocked'] is False
