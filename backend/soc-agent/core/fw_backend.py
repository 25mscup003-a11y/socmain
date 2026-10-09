"""
core/fw_backend.py — On-host firewall enforcement backend.

Replaces the pfSense/OPNsense IPS webhook: every block / unblock / isolate
action is applied on THIS host's own firewall. No network appliance involved.

Backend selection:
  Linux   : UFW      — when `ufw` is installed AND active
            nftables — otherwise (direct `nft` rules in dedicated tables)
  Windows : Windows Defender Firewall (netsh advfirewall)
  macOS   : pfctl (AJNAT-owned IP, port, protocol and isolation anchors)

nftables layout (Linux 'nft' path):
  table inet soc_agent      → IP / port / protocol blocks (named sets + chains)
  table inet soc_isolation  → full network isolation (added on isolate, dropped on restore)

macOS PF layout:
  com.soc.agent             → persistent IP/port/protocol rules
  com.soc.agent/isolation   → reversible full isolation preserving management
"""
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

logger = logging.getLogger('soc-agent.fw')
SYSTEM = platform.system()

SOC_TABLE = 'soc_agent'
ISO_TABLE = 'soc_isolation'
NAT_TABLE = 'soc_nat'
SURICATA_TABLE = 'soc_suricata_ips'
MACOS_PF_ANCHOR = 'com.soc.agent'
MACOS_PF_TABLE = 'soc_blocklist'
MACOS_PF_ANCHOR_FILE = Path('/etc/pf.anchors/com.soc.agent')
MACOS_PF_ISOLATION_ANCHOR = 'com.soc.agent/isolation'
MACOS_PF_ISOLATION_FILE = Path('/etc/pf.anchors/com.soc.agent.isolation')

_soc_table_ready = False
_nat_table_ready = False
_mac_pf_lock = threading.Lock()


def _run(cmd, timeout=10, stdin=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, input=stdin)
    except Exception as e:                       # noqa: BLE001
        logger.debug('cmd failed %s: %s', cmd, e)

        class _R:
            returncode = 1
            stdout = ''
            stderr = str(e)
        return _R()


def _have(binary):
    return shutil.which(binary) is not None


def _is_v6(ip):
    return ':' in ip


def _mac_pf_write(path, content):
    """Atomically replace an AJNAT-owned PF anchor and keep it root-only."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _mac_pf_update_rule(tag, rule=None):
    """Add/remove one tagged rule without replacing the IP block table."""
    if SYSTEM != 'Darwin' or not _have('pfctl'):
        return False
    marker = f'# {tag}'
    with _mac_pf_lock:
        path = Path(MACOS_PF_ANCHOR_FILE)
        original = path.read_text(encoding='utf-8') if path.exists() else (
            f'table <{MACOS_PF_TABLE}> persist\n'
            f'block drop quick from <{MACOS_PF_TABLE}> to any\n'
            f'block drop quick from any to <{MACOS_PF_TABLE}>\n'
        )
        lines = [line for line in original.splitlines() if marker not in line]
        if rule:
            lines.append(f'{rule} {marker}')
        updated = '\n'.join(lines).rstrip() + '\n'
        try:
            _mac_pf_write(path, updated)
        except OSError as exc:
            logger.error('pfctl: could not update %s: %s', path, exc)
            return False
        result = _run(['pfctl', '-a', MACOS_PF_ANCHOR, '-f', str(path)])
        if result.returncode == 0:
            return True
        logger.error('pfctl: could not reload %s: %s', MACOS_PF_ANCHOR, result.stderr)
        try:
            _mac_pf_write(path, original)
            _run(['pfctl', '-a', MACOS_PF_ANCHOR, '-f', str(path)])
        except OSError:
            pass
        return False


# ── backend detection ─────────────────────────────────────────────────────────
def _ufw_active():
    if not _have('ufw'):
        return False
    r = _run(['ufw', 'status'])
    return r.returncode == 0 and 'Status: active' in (r.stdout or '')


def linux_backend():
    """'ufw' | 'nft' | None — which Linux firewall we'll drive."""
    if _ufw_active():
        return 'ufw'
    if _have('nft'):
        return 'nft'
    return None


def backend_name():
    if SYSTEM == 'Linux':
        return linux_backend() or 'none'
    if SYSTEM == 'Windows':
        return 'netsh' if _have('netsh') else 'none'
    if SYSTEM == 'Darwin':
        return 'pfctl' if _have('pfctl') else 'none'
    return 'none'


def ensure_suricata_nfqueue_ports(ports, queue_num=0):
    """Queue inbound TCP traffic for real listening ports to Suricata.

    The dedicated table is fully agent-owned and rebuilt idempotently. The
    nftables ``bypass`` flag keeps services reachable if Suricata is stopped.
    """
    if SYSTEM != 'Linux' or not _have('nft'):
        return False
    safe_ports = sorted({int(p) for p in (ports or []) if str(p).isdigit() and 1 <= int(p) <= 65535})
    try:
        queue_num = max(0, int(queue_num))
    except (TypeError, ValueError):
        queue_num = 0
    _run(['nft', 'delete', 'table', 'inet', SURICATA_TABLE])
    if not safe_ports:
        return True
    port_set = ', '.join(str(port) for port in safe_ports)
    script = (
        f'table inet {SURICATA_TABLE} {{\n'
        '  chain input { type filter hook input priority 0; policy accept;\n'
        f'    tcp dport {{ {port_set} }} queue num {queue_num} bypass comment "AJNAT WAF direct inspection"\n'
        '  }\n'
        '}\n'
    )
    result = _run(['nft', '-f', '-'], stdin=script)
    if result.returncode != 0:
        logger.error('nft: could not configure Suricata NFQUEUE ports: %s', result.stderr)
        return False
    logger.info('Suricata NFQUEUE %d monitoring TCP ports: %s', queue_num, safe_ports)
    return True


# ── nftables helpers (soc_agent table) ─────────────────────────────────────────
def _ensure_soc_table():
    global _soc_table_ready
    if _soc_table_ready:
        return True
    if _run(['nft', 'list', 'table', 'inet', SOC_TABLE]).returncode == 0:
        _soc_table_ready = True
        return True
    script = (
        f'table inet {SOC_TABLE} {{\n'
        '  set blk_in4  { type ipv4_addr; flags interval; }\n'
        '  set blk_out4 { type ipv4_addr; flags interval; }\n'
        '  set blk_in6  { type ipv6_addr; flags interval; }\n'
        '  set blk_out6 { type ipv6_addr; flags interval; }\n'
        '  chain input  { type filter hook input  priority -10; policy accept;\n'
        '    ip saddr @blk_in4 drop\n'
        '    ip6 saddr @blk_in6 drop\n'
        '  }\n'
        '  chain output { type filter hook output priority -10; policy accept;\n'
        '    ip daddr @blk_out4 drop\n'
        '    ip6 daddr @blk_out6 drop\n'
        '  }\n'
        '}\n'
    )
    r = _run(['nft', '-f', '-'], stdin=script)
    if r.returncode == 0:
        _soc_table_ready = True
        return True
    logger.error('nft: could not create %s table: %s', SOC_TABLE, r.stderr)
    return False


def _nft_set_element(op, set_name, ip):
    r = _run(['nft', op, 'element', 'inet', SOC_TABLE, set_name, '{', ip, '}'])
    txt = (r.stderr or '').lower()
    # adding an existing / deleting an absent element is not a real failure
    return r.returncode == 0 or (op == 'add' and 'file exists' in txt) or (op == 'delete' and 'no such file or directory' in txt)


def _nft_add_rule(chain, expr, tag):
    return _run(['nft', 'add', 'rule', 'inet', SOC_TABLE, chain,
                 *expr, 'drop', 'comment', tag]).returncode == 0


def _nft_del_by_comment(chain, tag):
    r = _run(['nft', '-a', 'list', 'chain', 'inet', SOC_TABLE, chain])
    removed = False
    for line in (r.stdout or '').splitlines():
        if tag in line and 'handle' in line:
            handle = line.rsplit('handle', 1)[-1].strip()
            if handle.isdigit():
                _run(['nft', 'delete', 'rule', 'inet', SOC_TABLE, chain, 'handle', handle])
                removed = True
    return removed


# ═══════════════════════════════════════════════════════════════════════════════
# IP blocking
# ═══════════════════════════════════════════════════════════════════════════════
def block_ip(ip, direction='both', comment='soc-agent'):
    ip = (ip or '').strip()
    if not ip:
        return False
    d = _norm_dir(direction)

    if SYSTEM == 'Linux':
        be = linux_backend()
        if be == 'ufw':
            ok = True
            if d in ('in', 'both'):
                r = _run(['ufw', 'insert', '1', 'deny', 'from', ip])
                ok = _ufw_ok(r) and ok
            if d in ('out', 'both'):
                r = _run(['ufw', 'deny', 'out', 'to', ip])
                ok = _ufw_ok(r) and ok
            return ok
        if be == 'nft':
            if not _ensure_soc_table():
                return False
            fam = '6' if _is_v6(ip) else '4'
            ok = True
            if d in ('in', 'both'):
                ok = _nft_set_element('add', f'blk_in{fam}', ip) and ok
            if d in ('out', 'both'):
                ok = _nft_set_element('add', f'blk_out{fam}', ip) and ok
            return ok
        logger.warning('No Linux firewall backend (ufw/nft) available to block %s', ip)
        return False

    if SYSTEM == 'Windows':
        ok = True
        if d in ('in', 'both'):
            ok = _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name=SOCBlock_IN_{ip}', 'dir=in', 'action=block',
                       f'remoteip={ip}']).returncode == 0 and ok
        if d in ('out', 'both'):
            ok = _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name=SOCBlock_OUT_{ip}', 'dir=out', 'action=block',
                       f'remoteip={ip}']).returncode == 0 and ok
        return ok

    if SYSTEM == 'Darwin':
        return _run([
            'pfctl', '-a', MACOS_PF_ANCHOR, '-t', MACOS_PF_TABLE,
            '-T', 'add', ip,
        ]).returncode == 0

    return False


def unblock_ip(ip, direction='both'):
    ip = (ip or '').strip()
    if not ip:
        return False
    d = _norm_dir(direction)

    if SYSTEM == 'Linux':
        be = linux_backend()
        if be == 'ufw':
            ok = True
            if d in ('in', 'both'):
                result = _run(['ufw', 'delete', 'deny', 'from', ip])
                ok = (result.returncode == 0 or 'non-existent rule' in (result.stdout + result.stderr).lower()) and ok
            if d in ('out', 'both'):
                result = _run(['ufw', 'delete', 'deny', 'out', 'to', ip])
                ok = (result.returncode == 0 or 'non-existent rule' in (result.stdout + result.stderr).lower()) and ok
            return ok
        if be == 'nft':
            result = _run(['nft', 'list', 'table', 'inet', SOC_TABLE])
            if result.returncode != 0:
                return 'no such file or directory' in (result.stderr or '').lower()
            fam = '6' if _is_v6(ip) else '4'
            ok = True
            if d in ('in', 'both'):
                ok = _nft_set_element('delete', f'blk_in{fam}', ip) and ok
            if d in ('out', 'both'):
                ok = _nft_set_element('delete', f'blk_out{fam}', ip) and ok
            return ok
        return False

    if SYSTEM == 'Windows':
        ok = True
        for name in (f'SOCBlock_IN_{ip}', f'SOCBlock_OUT_{ip}', f'SOCBlock_{ip}'):
            result = _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}'])
            ok = (result.returncode == 0 or 'no rules match' in (result.stdout or '').lower()) and ok
        return ok

    if SYSTEM == 'Darwin':
        return _run([
            'pfctl', '-a', MACOS_PF_ANCHOR, '-t', MACOS_PF_TABLE,
            '-T', 'delete', ip,
        ]).returncode == 0

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Port blocking
# ═══════════════════════════════════════════════════════════════════════════════
def block_port(port, proto='tcp', direction='in'):
    proto = (proto or 'tcp').lower()
    d = _norm_dir(direction)
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    if proto not in ('tcp', 'udp') or not 1 <= port <= 65535:
        return False

    if SYSTEM == 'Linux':
        be = linux_backend()
        if be == 'ufw':
            ok = True
            if d in ('in', 'both'):
                ok = _ufw_ok(_run(['ufw', 'deny', f'{port}/{proto}'])) and ok
            if d in ('out', 'both'):
                ok = _ufw_ok(_run(['ufw', 'deny', 'out', f'{port}/{proto}'])) and ok
            return ok
        if be == 'nft':
            if not _ensure_soc_table():
                return False
            ok = True
            if d in ('in', 'both'):
                ok = _nft_add_rule('input', [proto, 'dport', str(port)],
                                   f'socport_{proto}_{port}_in') and ok
            if d in ('out', 'both'):
                ok = _nft_add_rule('output', [proto, 'dport', str(port)],
                                   f'socport_{proto}_{port}_out') and ok
            return ok
        return False

    if SYSTEM == 'Windows':
        return _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     f'name=SOCClose_{port}_{proto}', 'dir=in', 'action=block',
                     f'protocol={proto}', f'localport={port}']).returncode == 0
    if SYSTEM == 'Darwin':
        directions = ('in', 'out') if d == 'both' else (d,)
        ok = True
        for item in directions:
            ok = _mac_pf_update_rule(
                f'socport_{proto}_{port}_{item}',
                f'block drop quick {item} proto {proto} to any port = {port}',
            ) and ok
        return ok
    return False


def unblock_port(port, proto='tcp', direction='both'):
    proto = (proto or 'tcp').lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    if proto not in ('tcp', 'udp') or not 1 <= port <= 65535:
        return False
    d = _norm_dir(direction)

    if SYSTEM == 'Linux':
        be = linux_backend()
        if be == 'ufw':
            _run(['ufw', 'delete', 'deny', f'{port}/{proto}'])
            _run(['ufw', 'delete', 'deny', 'out', f'{port}/{proto}'])
            return True
        if be == 'nft':
            if _run(['nft', 'list', 'table', 'inet', SOC_TABLE]).returncode != 0:
                return True
            _nft_del_by_comment('input', f'socport_{proto}_{port}_in')
            _nft_del_by_comment('output', f'socport_{proto}_{port}_out')
            return True
        return False

    if SYSTEM == 'Windows':
        _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
              f'name=SOCClose_{port}_{proto}'])
        return True
    if SYSTEM == 'Darwin':
        directions = ('in', 'out') if d == 'both' else (d,)
        ok = True
        for item in directions:
            ok = _mac_pf_update_rule(f'socport_{proto}_{port}_{item}') and ok
        return ok
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Protocol blocking
# ═══════════════════════════════════════════════════════════════════════════════
def block_protocol(proto, direction='both'):
    proto = (proto or '').lower()
    if proto not in ('tcp', 'udp', 'icmp'):
        return False
    d = _norm_dir(direction)

    if SYSTEM == 'Linux':
        be = linux_backend()
        if be == 'ufw':
            ok = True
            if d in ('in', 'both'):
                ok = _ufw_ok(_run(['ufw', 'deny', 'proto', proto, 'from', 'any', 'to', 'any'])) and ok
            if d in ('out', 'both'):
                ok = _ufw_ok(_run(['ufw', 'deny', 'out', 'proto', proto, 'from', 'any', 'to', 'any'])) and ok
            return ok
        if be == 'nft':
            if not _ensure_soc_table():
                return False
            ok = True
            if d in ('in', 'both'):
                ok = _nft_add_rule('input', ['meta', 'l4proto', proto],
                                   f'socproto_{proto}_in') and ok
            if d in ('out', 'both'):
                ok = _nft_add_rule('output', ['meta', 'l4proto', proto],
                                   f'socproto_{proto}_out') and ok
            return ok
        return False

    if SYSTEM == 'Windows':
        ok = True
        if d in ('in', 'both'):
            ok = _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name=SOCBlock_Proto_IN_{proto}', 'dir=in', 'action=block',
                       f'protocol={proto}']).returncode == 0 and ok
        if d in ('out', 'both'):
            ok = _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name=SOCBlock_Proto_OUT_{proto}', 'dir=out', 'action=block',
                       f'protocol={proto}']).returncode == 0 and ok
        return ok
    if SYSTEM == 'Darwin':
        directions = ('in', 'out') if d == 'both' else (d,)
        ok = True
        for item in directions:
            ok = _mac_pf_update_rule(
                f'socproto_{proto}_{item}',
                f'block drop quick {item} proto {proto} from any to any',
            ) and ok
        return ok
    return False


def unblock_protocol(proto, direction='both'):
    proto = (proto or '').lower()
    if proto not in ('tcp', 'udp', 'icmp'):
        return False
    d = _norm_dir(direction)

    if SYSTEM == 'Linux':
        be = linux_backend()
        if be == 'ufw':
            _run(['ufw', 'delete', 'deny', 'proto', proto, 'from', 'any', 'to', 'any'])
            _run(['ufw', 'delete', 'deny', 'out', 'proto', proto, 'from', 'any', 'to', 'any'])
            return True
        if be == 'nft':
            if _run(['nft', 'list', 'table', 'inet', SOC_TABLE]).returncode != 0:
                return True
            _nft_del_by_comment('input', f'socproto_{proto}_in')
            _nft_del_by_comment('output', f'socproto_{proto}_out')
            return True
        return False

    if SYSTEM == 'Windows':
        for name in (f'SOCBlock_Proto_IN_{proto}', f'SOCBlock_Proto_OUT_{proto}',
                     f'SOCBlock_Proto_{proto}'):
            _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}'])
        return True
    if SYSTEM == 'Darwin':
        directions = ('in', 'out') if d == 'both' else (d,)
        ok = True
        for item in directions:
            ok = _mac_pf_update_rule(f'socproto_{proto}_{item}') and ok
        return ok
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Full network isolation (preserves SOC management + loopback)
# ═══════════════════════════════════════════════════════════════════════════════
def isolate(mgmt_ip, mgmt_port):
    if SYSTEM == 'Linux':
        if not _have('nft'):
            raise RuntimeError('nftables (nft) required for isolation')
        current = _run(['nft', 'list', 'table', 'inet', ISO_TABLE])
        if current.returncode != 0 and 'no such file or directory' not in (current.stderr or '').lower():
            raise RuntimeError(f'Cannot inspect current isolation: {current.stderr}')
        # nft commits the entire batch atomically: a failed replacement leaves
        # the previous isolation intact instead of briefly restoring traffic.
        replacement = f'delete table inet {ISO_TABLE}\n' if current.returncode == 0 else ''
        saddr = 'ip6 saddr' if _is_v6(mgmt_ip) else 'ip saddr'
        daddr = 'ip6 daddr' if _is_v6(mgmt_ip) else 'ip daddr'
        script = (
            f'table inet {ISO_TABLE} {{\n'
            '  chain input  { type filter hook input  priority -150; policy accept;\n'
            '    iif lo accept\n'
            f'    {saddr} {mgmt_ip} tcp sport {mgmt_port} accept\n'
            '    drop\n'
            '  }\n'
            '  chain output { type filter hook output priority -150; policy accept;\n'
            '    oif lo accept\n'
            f'    {daddr} {mgmt_ip} tcp dport {mgmt_port} accept\n'
            '    drop\n'
            '  }\n'
            '}\n'
        )
        r = _run(['nft', '-f', '-'], stdin=replacement + script)
        if r.returncode != 0:
            raise RuntimeError(f'nft isolation failed: {r.stderr}')
        return

    if SYSTEM == 'Windows':
        from core.windows_isolation import isolation_script
        result = _run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                       isolation_script(mgmt_ip, mgmt_port)], timeout=90)
        if result.returncode != 0 or 'AJNAT isolation confirmed' not in result.stdout:
            raise RuntimeError(f'Windows isolation failed: {result.stderr or result.stdout}')
        return

    if SYSTEM == 'Darwin':
        family = 'inet6' if _is_v6(mgmt_ip) else 'inet'
        rules = (
            '# Generated by AJNAT. Do not edit.\n'
            'pass quick on lo0 all\n'
            f'pass out quick {family} proto tcp to {mgmt_ip} port = {int(mgmt_port)} keep state\n'
            f'pass in quick {family} proto tcp from {mgmt_ip} port = {int(mgmt_port)} keep state\n'
            'block drop quick all\n'
        )
        with _mac_pf_lock:
            _mac_pf_write(MACOS_PF_ISOLATION_FILE, rules)
            result = _run(['pfctl', '-a', MACOS_PF_ISOLATION_ANCHOR, '-f', str(MACOS_PF_ISOLATION_FILE)])
        if result.returncode != 0:
            raise RuntimeError(f'pf isolation failed: {result.stderr}')
        return

    raise RuntimeError(f'network isolation is unsupported on {SYSTEM}')


def restore():
    if SYSTEM == 'Linux':
        if not _have('nft'):
            raise RuntimeError('nftables (nft) required to verify removal of isolation')
        result = _run(['nft', 'delete', 'table', 'inet', ISO_TABLE])
        if result.returncode != 0 and 'No such file or directory' not in result.stderr:
            raise RuntimeError(f'nft reconnect failed: {result.stderr}')
        return
    if SYSTEM == 'Windows':
        from core.windows_isolation import restoration_script
        result = _run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                       restoration_script()], timeout=90)
        if result.returncode != 0 or 'AJNAT reconnect confirmed' not in result.stdout:
            raise RuntimeError(f'Windows reconnect failed: {result.stderr or result.stdout}')
        return
    if SYSTEM == 'Darwin':
        with _mac_pf_lock:
            _mac_pf_write(MACOS_PF_ISOLATION_FILE, '# AJNAT isolation inactive\n')
            result = _run(['pfctl', '-a', MACOS_PF_ISOLATION_ANCHOR, '-f', str(MACOS_PF_ISOLATION_FILE)])
        if result.returncode != 0:
            raise RuntimeError(f'pf reconnect failed: {result.stderr}')
        return
    raise RuntimeError(f'network reconnect is unsupported on {SYSTEM}')


# ═══════════════════════════════════════════════════════════════════════════════
# WAF transparent-proxy REDIRECT (nftables nat) — optional, off by default
# ═══════════════════════════════════════════════════════════════════════════════
def _ensure_nat_table():
    global _nat_table_ready
    if _nat_table_ready:
        return True
    if _run(['nft', 'list', 'table', 'ip', NAT_TABLE]).returncode == 0:
        _nat_table_ready = True
        return True
    script = (
        f'table ip {NAT_TABLE} {{\n'
        '  chain prerouting { type nat hook prerouting priority -100; policy accept; }\n'
        '}\n'
    )
    r = _run(['nft', '-f', '-'], stdin=script)
    if r.returncode == 0:
        _nat_table_ready = True
        return True
    logger.error('nft: could not create %s nat table: %s', NAT_TABLE, r.stderr)
    return False


def redirect_port(orig, waf):
    """Transparently redirect inbound TCP :orig → local WAF proxy :waf (nftables)."""
    if SYSTEM != 'Linux' or not _have('nft'):
        return False
    if not _ensure_nat_table():
        return False
    return _run(['nft', 'add', 'rule', 'ip', NAT_TABLE, 'prerouting',
                 'tcp', 'dport', str(orig), 'redirect', 'to', f':{waf}',
                 'comment', f'socwaf_{orig}']).returncode == 0


def remove_redirect(orig):
    if SYSTEM != 'Linux' or not _have('nft'):
        return False
    if _run(['nft', 'list', 'table', 'ip', NAT_TABLE]).returncode != 0:
        return True
    r = _run(['nft', '-a', 'list', 'chain', 'ip', NAT_TABLE, 'prerouting'])
    for line in (r.stdout or '').splitlines():
        if f'socwaf_{orig}' in line and 'handle' in line:
            handle = line.rsplit('handle', 1)[-1].strip()
            if handle.isdigit():
                _run(['nft', 'delete', 'rule', 'ip', NAT_TABLE, 'prerouting', 'handle', handle])
    return True


# ── small helpers ───────────────────────────────────────────────────────────────
def _norm_dir(direction):
    d = (direction or 'both').lower().strip()
    if d in ('in', 'inbound'):
        return 'in'
    if d in ('out', 'outbound'):
        return 'out'
    return 'both'


def _ufw_ok(r):
    txt = (r.stdout or '') + (r.stderr or '')
    return r.returncode == 0 or 'existing' in txt.lower() or 'skipping' in txt.lower()
