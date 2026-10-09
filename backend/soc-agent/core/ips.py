"""
IPS Module v4.0 — Intrusion Prevention System
On-host blocking via the local firewall (UFW / nftables / Windows Defender).

Features:
  - Auto-block IPs detected by IDS, WAF, EDR, log rules
  - Block / unblock on THIS host via core.fw_backend
      Linux   → UFW (if active) else nftables
      Windows → Windows Defender Firewall (netsh)
      macOS   → pfctl
  - Whitelist check before any block action (loopback, DNS resolvers, etc.)
  - Report all block/unblock actions to the SOC dashboard

NOTE: the pfSense / OPNsense IPS-webhook backend has been removed — every
block is now enforced locally on the endpoint itself.
"""

import logging
import threading
import ipaddress

from . import fw_backend

import platform
SYSTEM = platform.system()
logger = logging.getLogger('soc-agent.ips')

# IPs that should NEVER be blocked (loopback, common DNS resolvers, etc.)
WHITELIST = {
    '127.0.0.1', '::1', '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '9.9.9.11', '149.112.112.112', '149.112.112.11',
    '0.0.0.0',
}


class IPSModule:
    def __init__(self, sender, config=None):
        self._sender  = sender
        self._config  = config or {}
        self._blocked = set()
        self._lock    = threading.Lock()
        self._auto_block = self._config.get('ips_auto_block', True)
        self._company_id = self._config.get('company_id', '')
        # Extra never-block IPs from config (e.g. the DNS resolvers in use)
        self._whitelist = set(WHITELIST) | set(self._config.get('ips_whitelist', []))
        self._dashboard_whitelist = []
        logger.info('IPS v4.0: local enforcement via %s backend',
                    fw_backend.backend_name())

    # ── public API ─────────────────────────────────────────────────────────────
    def block_ip(self, ip: str, reason: str = 'auto-block',
                 port: int = None, protocol: str = None,
                 threat_level: str = None, payload: str = None,
                 attack_type: str = None, authorized_by_backend: bool = False) -> bool:
        """Block an IP on the local host firewall. Returns True on success."""
        ip = (ip or '').strip()
        if not ip or self.is_whitelisted(ip, 'ip'):
            logger.debug('IPS: skipping whitelisted IP %s', ip)
            return False
        if self._is_private(ip):
            logger.debug('IPS: skipping private IP %s', ip)
            return False
        if not authorized_by_backend:
            from .network_verification import verify_network_action
            if not verify_network_action(self._config, ip, 'block_ip'):
                logger.info('IPS auto-block deferred for %s: backend threat checks did not authorize it', ip)
                return False

        with self._lock:
            if ip in self._blocked:
                return True   # already blocked

        try:
            ok = fw_backend.block_ip(ip, direction='both', comment=reason)
            if ok:
                with self._lock:
                    self._blocked.add(ip)
                logger.warning('IPS BLOCKED: %s (%s attack_type=%s) via %s',
                               ip, reason, attack_type or '-', fw_backend.backend_name())
                self._sender.enqueue({
                    'rule_id':     'IPS_AUTO_BLOCK',
                    'category':    'network',
                    'severity':    threat_level or 'high',
                    'description': f'IPS v4.0 auto-blocked IP: {ip} — {reason}',
                    'raw_log':     (
                        f'ips_block ip={ip} reason={reason} '
                        f'port={port} proto={protocol} attack={attack_type or "-"} '
                        f'backend={fw_backend.backend_name()}'
                    ),
                    'src_ip':      ip,
                    'blocked':     True,
                    'attackType':  attack_type or '',
                    'company_id':  self._company_id,
                })
            else:
                logger.error('IPS: local firewall failed to block %s', ip)
            return ok
        except Exception as e:                       # noqa: BLE001
            logger.error('IPS block %s failed: %s', ip, e)
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove a block rule for an IP from the local host firewall."""
        ip = (ip or '').strip()
        if not ip:
            return False
        try:
            ok = fw_backend.unblock_ip(ip, direction='both')
            if ok:
                with self._lock:
                    self._blocked.discard(ip)
                logger.info('IPS UNBLOCKED: %s', ip)
                self._sender.enqueue({
                    'rule_id':     'IPS_UNBLOCK',
                    'category':    'network',
                    'severity':    'low',
                    'description': f'IPS v4.0 unblocked IP: {ip}',
                    'raw_log':     f'ips_unblock ip={ip} backend={fw_backend.backend_name()}',
                    'src_ip':      ip,
                    'blocked':     False,
                })
            return ok
        except Exception as e:                       # noqa: BLE001
            logger.error('IPS unblock %s failed: %s', ip, e)
            return False

    def analyze_and_block(self, payload: str, src_ip: str, reason: str = '') -> bool:
        """Attack classification previously ran on the IPS webhook server, which
        has been removed. Local detectors (WAF, IDS, EDR) now classify attacks
        and call block_ip() directly, so this is a no-op kept for API stability.
        """
        return False

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Return True unless *ip* is a routable public address.

        Endpoint auto-blocking must never ban local infrastructure such as the
        default gateway, IPv6 link-local peers (``fe80::/10``), multicast, or
        loopback addresses.  ``ipaddress`` covers IPv4 and IPv6 consistently,
        including reserved ranges that prefix matching used to miss.
        """
        try:
            # IPv6 link-local addresses can include an interface zone ID.
            address = ipaddress.ip_address(str(ip).split('%', 1)[0])
            return not address.is_global
        except ValueError:
            # Invalid addresses must not reach a firewall command.
            return True

    def get_blocked_list(self):
        with self._lock:
            return list(self._blocked)

    @staticmethod
    def _normalize_domain(value: str) -> str:
        value = (value or '').strip().lower()
        for prefix in ('http://', 'https://'):
            if value.startswith(prefix):
                value = value[len(prefix):]
        return value.split('/', 1)[0].split(':', 1)[0].lstrip('*.').rstrip('.')

    def is_whitelisted(self, value: str, target_type: str = 'ip') -> bool:
        value = (value or '').strip()
        if not value:
            return False
        if target_type == 'domain':
            host = self._normalize_domain(value)
            return any(
                entry.get('type') == 'domain' and (
                    host == self._normalize_domain(entry.get('value', '')) or
                    host.endswith('.' + self._normalize_domain(entry.get('value', '')))
                )
                for entry in self._dashboard_whitelist
            )
        if value in self._whitelist:
            return True
        try:
            address = ipaddress.ip_address(value.split('%', 1)[0])
        except ValueError:
            return False
        for entry in self._dashboard_whitelist:
            kind = entry.get('type', 'ip')
            candidate = str(entry.get('value', '')).strip()
            try:
                if kind == 'cidr' and address in ipaddress.ip_network(candidate, strict=False):
                    return True
                if kind == 'ip' and address == ipaddress.ip_address(candidate):
                    return True
            except ValueError:
                continue
        return False

    def set_dashboard_whitelist(self, entries) -> int:
        normalized = []
        for entry in entries or []:
            if isinstance(entry, str):
                entry = {'value': entry, 'type': 'ip'}
            value = str(entry.get('value', '')).strip()
            kind = str(entry.get('type', 'ip')).lower()
            if value and kind in ('ip', 'cidr', 'domain'):
                normalized.append({'value': value, 'type': kind})
        with self._lock:
            self._dashboard_whitelist = normalized
            blocked_snapshot = list(self._blocked)
        for blocked_ip in blocked_snapshot:
            if self.is_whitelisted(blocked_ip, 'ip'):
                self.unblock_ip(blocked_ip)
        logger.info('IPS dashboard whitelist synchronized: %d entries', len(normalized))
        return len(normalized)

    def update_dashboard_whitelist(self, action: str, value: str, kind: str = 'ip') -> int:
        value = str(value or '').strip()
        kind = str(kind or 'ip').lower()
        with self._lock:
            self._dashboard_whitelist = [
                entry for entry in self._dashboard_whitelist
                if not (entry.get('value') == value and entry.get('type') == kind)
            ]
            if action == 'add' and value and kind in ('ip', 'cidr', 'domain'):
                self._dashboard_whitelist.append({'value': value, 'type': kind})
            count = len(self._dashboard_whitelist)
            blocked_snapshot = list(self._blocked)
        if action == 'add' and kind in ('ip', 'cidr'):
            for blocked_ip in blocked_snapshot:
                if self.is_whitelisted(blocked_ip, 'ip'):
                    self.unblock_ip(blocked_ip)
        return count


# Backwards-compat: some loaders import the class as `Module`.
Module = IPSModule
