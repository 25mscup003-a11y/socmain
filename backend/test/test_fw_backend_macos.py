import sys
from pathlib import Path
from types import SimpleNamespace

AGENT_ROOT = Path(__file__).resolve().parents[1] / 'soc-agent'
sys.path.insert(0, str(AGENT_ROOT))

from core import fw_backend


def _mac_backend(monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(fw_backend, 'SYSTEM', 'Darwin')
    monkeypatch.setattr(fw_backend, 'MACOS_PF_ANCHOR_FILE', tmp_path / 'com.soc.agent')
    monkeypatch.setattr(fw_backend, 'MACOS_PF_ISOLATION_FILE', tmp_path / 'com.soc.agent.isolation')
    monkeypatch.setattr(fw_backend, '_have', lambda binary: binary == 'pfctl')

    def run(command, timeout=10, stdin=None):
        commands.append((command, stdin))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(fw_backend, '_run', run)
    return commands


def test_macos_port_and_protocol_rules_are_persistent_and_removable(monkeypatch, tmp_path):
    commands = _mac_backend(monkeypatch, tmp_path)

    assert fw_backend.block_port(443, 'tcp', 'both') is True
    assert fw_backend.block_protocol('udp', 'out') is True
    rules = (tmp_path / 'com.soc.agent').read_text()
    assert 'socport_tcp_443_in' in rules
    assert 'socport_tcp_443_out' in rules
    assert 'socproto_udp_out' in rules

    assert fw_backend.unblock_port(443, 'tcp', 'both') is True
    assert fw_backend.unblock_protocol('udp', 'out') is True
    rules = (tmp_path / 'com.soc.agent').read_text()
    assert 'socport_tcp_443' not in rules
    assert 'socproto_udp_out' not in rules
    assert any(command[:3] == ['pfctl', '-a', 'com.soc.agent'] for command, _ in commands)


def test_macos_isolation_preserves_management_and_restore_clears_anchor(monkeypatch, tmp_path):
    commands = _mac_backend(monkeypatch, tmp_path)

    fw_backend.isolate('203.0.113.20', 443)
    rules = (tmp_path / 'com.soc.agent.isolation').read_text()
    assert 'pass quick on lo0 all' in rules
    assert 'to 203.0.113.20 port = 443 keep state' in rules
    assert 'block drop quick all' in rules

    fw_backend.restore()
    assert (tmp_path / 'com.soc.agent.isolation').read_text() == '# AJNAT isolation inactive\n'
    assert any(command[:3] == ['pfctl', '-a', 'com.soc.agent/isolation'] for command, _ in commands)
