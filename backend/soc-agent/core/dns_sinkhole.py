"""
core/dns_sinkhole.py
DNS Sinkhole — redirect malicious domains to 0.0.0.0
Writes sinkhole entries to /etc/hosts (Linux/macOS) or Windows hosts file.
Also supports dnsmasq address= directives.

MITRE ATT&CK: T1071.004, T1568 (defensive countermeasure)
"""

import os
import platform
import logging
import re
import time
import ipaddress
from typing import Set, List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

SINKHOLE_IP   = '0.0.0.0'
SINKHOLE_MARK = '# SOC4-SINKHOLE'

HOSTS_PATHS = {
    'linux':   '/etc/hosts',
    'darwin':  '/etc/hosts',
    'windows': r'C:\Windows\System32\drivers\etc\hosts',
}

DNSMASQ_CONF = '/etc/dnsmasq.d/soc4-sinkhole.conf'

# Log of sinkholed domains
SINKHOLE_LOG: List[Dict] = []


class DNSSinkhole:
    """Manages a DNS sinkhole by maintaining the system hosts file."""

    def __init__(self, config=None):
        self.config    = config
        self.os_type   = platform.system().lower()
        self._sinkholed: Set[str] = set()
        self._sinkhole_ips: Dict[str, str] = {}
        self._report_cursor = len(SINKHOLE_LOG)
        self._status_reported = False
        self.enabled = bool(self._config_value('dns_sinkhole_enabled', True))
        self.sinkhole_ip = str(self._config_value('dns_sinkhole_ip', SINKHOLE_IP))
        self.enforcement_mode = str(self._config_value('dns_sinkhole_enforcement_mode', 'both'))
        self.telemetry_enabled = bool(self._config_value('dns_sinkhole_telemetry_enabled', True))
        self.report_interval_seconds = int(self._config_value('dns_sinkhole_report_interval_seconds', 300))
        self.sync_blocklist = bool(self._config_value('dns_sinkhole_sync_blocklist', True))
        self.policy_version = int(self._config_value('dns_sinkhole_policy_version', 0))
        self.default_severity = str(self._config_value('dns_sinkhole_default_severity', 'high'))
        self._load_existing()

    def _config_value(self, key: str, default=None):
        if hasattr(self.config, 'get'):
            return self.config.get(key, default)
        return default

    def _hosts_path(self) -> str:
        return HOSTS_PATHS.get(self.os_type, '/etc/hosts')

    def _load_existing(self):
        """Read current hosts file and collect already-sinkholed domains."""
        try:
            with open(self._hosts_path(), 'r', errors='replace') as f:
                for line in f:
                    if SINKHOLE_MARK in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            self._sinkholed.add(parts[1])
                            self._sinkhole_ips[parts[1]] = parts[0]
        except (FileNotFoundError, PermissionError):
            pass

    def _write_hosts(self, domain: str, add: bool = True, sinkhole_ip: Optional[str] = None):
        """Add or remove a sinkhole entry in /etc/hosts."""
        path = self._hosts_path()
        try:
            with open(path, 'r', errors='replace') as f:
                lines = f.readlines()

            target_ip = sinkhole_ip or self.sinkhole_ip
            entry = f'{target_ip} {domain} {SINKHOLE_MARK}\n'

            if add:
                # Remove existing entry first (avoid duplicates)
                lines = [l for l in lines if not self._is_managed_domain_line(l, domain)]
                lines.append(entry)
                logger.info(f'[DNSSinkhole] Sinkholed: {domain} → {target_ip}')
            else:
                lines = [l for l in lines if not self._is_managed_domain_line(l, domain)]
                logger.info(f'[DNSSinkhole] Removed sinkhole for: {domain}')

            with open(path, 'w') as f:
                f.writelines(lines)
        except PermissionError:
            logger.error('[DNSSinkhole] Permission denied — run as root/Administrator')
        except Exception as e:
            logger.error(f'[DNSSinkhole] Hosts file error: {e}')

    @staticmethod
    def _is_managed_domain_line(line: str, domain: str) -> bool:
        if SINKHOLE_MARK not in line:
            return False
        values = line.split('#', 1)[0].split()
        return domain in values[1:]

    def _write_dnsmasq(self, domain: str, add: bool = True, sinkhole_ip: Optional[str] = None):
        """Write/remove dnsmasq address directive for the domain."""
        if self.os_type != 'linux':
            return
        try:
            conf_path = Path(DNSMASQ_CONF)
            conf_path.parent.mkdir(parents=True, exist_ok=True)
            existing = conf_path.read_text() if conf_path.exists() else ''
            target_ip = sinkhole_ip or self.sinkhole_ip
            entry = f'address=/{domain}/{target_ip}\n'

            if add:
                if entry not in existing:
                    with open(conf_path, 'a') as f:
                        f.write(entry)
            else:
                lines = [l for l in existing.splitlines(keepends=True)
                         if f'address=/{domain}/' not in l]
                with open(conf_path, 'w') as f:
                    f.writelines(lines)
        except Exception as e:
            logger.warning(f'[DNSSinkhole] dnsmasq write error: {e}')

    # ─── Public API ──────────────────────────────────────────────────────────
    def sinkhole(self, domain: str, reason: str = 'manual',
                 severity: str = 'high', sinkhole_ip: Optional[str] = None) -> dict:
        """Add a domain to the sinkhole."""
        domain = domain.lower().strip().rstrip('.')
        if not domain or re.search(r'[^a-z0-9.\-]', domain):
            return {'success': False, 'error': 'Invalid domain'}
        if not self.enabled:
            return {'success': False, 'error': 'DNS sinkhole is disabled'}
        target_ip = str(sinkhole_ip or self.sinkhole_ip).strip()
        try:
            if ipaddress.ip_address(target_ip).version != 4:
                raise ValueError('IPv4 required')
        except ValueError:
            return {'success': False, 'error': 'Invalid sinkhole IPv4 address'}

        if domain in self._sinkholed and self._sinkhole_ips.get(domain) != target_ip:
            self._write_hosts(domain, add=False)
            self._write_dnsmasq(domain, add=False)

        if self.enforcement_mode in ('hosts', 'both'):
            self._write_hosts(domain, add=True, sinkhole_ip=target_ip)
        if self.enforcement_mode in ('dnsmasq', 'both'):
            self._write_dnsmasq(domain, add=True, sinkhole_ip=target_ip)
        self._sinkholed.add(domain)
        self._sinkhole_ips[domain] = target_ip

        entry = {
            'domain':   domain,
            'ip':       target_ip,
            'reason':   reason,
            'severity': severity,
            'ts':       time.time(),
            'action':   'sinkholed',
        }
        SINKHOLE_LOG.append(entry)
        return {'success': True, 'domain': domain, 'sinkhole_ip': target_ip}

    def unsinkhole(self, domain: str) -> dict:
        """Remove a domain from the sinkhole."""
        domain = domain.lower().strip()
        self._write_hosts(domain, add=False)
        self._write_dnsmasq(domain, add=False)
        self._sinkholed.discard(domain)
        self._sinkhole_ips.pop(domain, None)
        SINKHOLE_LOG.append({
            'domain': domain, 'action': 'removed', 'ts': time.time(),
        })
        return {'success': True, 'domain': domain}

    def is_sinkholed(self, domain: str) -> bool:
        return domain.lower() in self._sinkholed

    def list_sinkholed(self) -> List[str]:
        return sorted(self._sinkholed)

    def get_log(self, limit: int = 100) -> List[Dict]:
        return SINKHOLE_LOG[-limit:]

    def bulk_sinkhole(self, domains: List[str],
                      reason: str = 'threat_intel') -> dict:
        """Sinkhole a list of domains at once."""
        results = []
        for d in domains:
            r = self.sinkhole(d, reason=reason)
            results.append({'domain': d, 'success': r.get('success', False)})
        return {
            'sinkholed': sum(1 for r in results if r['success']),
            'failed':    sum(1 for r in results if not r['success']),
            'results':   results,
        }

    def stats(self) -> dict:
        return {
            'enabled': self.enabled,
            'total_sinkholed': len(self._sinkholed),
            'log_entries':     len(SINKHOLE_LOG),
            'sinkhole_ip':     self.sinkhole_ip,
            'enforcement_mode': self.enforcement_mode,
            'telemetry_enabled': self.telemetry_enabled,
            'report_interval_seconds': self.report_interval_seconds,
            'policy_version': self.policy_version,
            'default_severity': self.default_severity,
            'hosts_file':      self._hosts_path(),
            'dnsmasq_conf':    DNSMASQ_CONF,
        }

    def configure(self, settings: dict, blocklist=None, allowlist=None, sinkhole_targets=None) -> dict:
        """Validate, persist, and immediately apply a server-authorized policy."""
        settings = settings if isinstance(settings, dict) else {}
        ip_value = str(settings.get('dns_sinkhole_ip', self.sinkhole_ip)).strip()
        try:
            if ipaddress.ip_address(ip_value).version != 4:
                raise ValueError('IPv4 required')
        except ValueError as exc:
            raise ValueError('invalid DNS sinkhole IPv4 address') from exc

        mode = str(settings.get('dns_sinkhole_enforcement_mode', self.enforcement_mode)).lower()
        if mode not in {'hosts', 'dnsmasq', 'both'}:
            raise ValueError('invalid DNS sinkhole enforcement mode')
        interval = int(settings.get('dns_sinkhole_report_interval_seconds', self.report_interval_seconds))
        if interval < 60 or interval > 3600:
            raise ValueError('DNS sinkhole report interval must be between 60 and 3600 seconds')

        allowed = {str(value).lower().strip().rstrip('.') for value in (allowlist or []) if value}
        configured_targets = sinkhole_targets if isinstance(sinkhole_targets, dict) else {}
        desired_ips = {}
        for value in (blocklist or []):
            domain = str(value).lower().strip().rstrip('.')
            if not domain or domain in allowed:
                continue
            target_ip = str(configured_targets.get(domain) or ip_value).strip()
            try:
                if ipaddress.ip_address(target_ip).version != 4:
                    raise ValueError('IPv4 required')
            except ValueError as exc:
                raise ValueError(f'invalid sinkhole IPv4 address for {domain}') from exc
            desired_ips[domain] = target_ip

        previous_domains = set(self._sinkholed)
        previous_ips = dict(self._sinkhole_ips)
        previous_mode = self.enforcement_mode
        self.enabled = settings.get('dns_sinkhole_enabled', self.enabled) is True
        self.sinkhole_ip = ip_value
        self.enforcement_mode = mode
        self.telemetry_enabled = settings.get('dns_sinkhole_telemetry_enabled', self.telemetry_enabled) is True
        self.report_interval_seconds = interval
        self.sync_blocklist = settings.get('dns_sinkhole_sync_blocklist', self.sync_blocklist) is True
        self.policy_version = max(0, int(settings.get('dns_sinkhole_policy_version', self.policy_version)))
        default_severity = str(settings.get('dns_sinkhole_default_severity', self.default_severity)).lower()
        if default_severity not in {'low', 'medium', 'high', 'critical'}:
            raise ValueError('invalid DNS sinkhole default severity')
        self.default_severity = default_severity

        persisted = {
            'dns_sinkhole_enabled': self.enabled,
            'dns_sinkhole_ip': self.sinkhole_ip,
            'dns_sinkhole_enforcement_mode': self.enforcement_mode,
            'dns_sinkhole_telemetry_enabled': self.telemetry_enabled,
            'dns_sinkhole_report_interval_seconds': self.report_interval_seconds,
            'dns_sinkhole_sync_blocklist': self.sync_blocklist,
            'dns_sinkhole_policy_version': self.policy_version,
            'dns_sinkhole_default_severity': self.default_severity,
            'dns_sinkhole_builtin_rule_ids': list(settings.get('dns_sinkhole_builtin_rule_ids') or []),
            'dns_anomaly_detection_enabled': settings.get('dns_anomaly_detection_enabled', True) is True,
            'dns_anomaly_threshold': max(25, min(100, int(settings.get('dns_anomaly_threshold', 45)))),
            'dns_anomaly_cooldown_seconds': max(60, min(86400, int(settings.get('dns_anomaly_cooldown_seconds', 1800)))),
            'dns_beacon_detection_enabled': settings.get('dns_beacon_detection_enabled', True) is True,
            'dns_beacon_alert_threshold': max(25, min(100, int(settings.get('dns_beacon_alert_threshold', 55)))),
            'beacon_min_connections': max(4, min(100, int(settings.get('beacon_min_connections', 6)))),
            'beacon_consistency_threshold': max(40, min(100, int(settings.get('beacon_consistency_threshold', 75)))),
            'beacon_alert_cooldown_seconds': max(60, min(86400, int(settings.get('beacon_alert_cooldown_seconds', 1800)))),
        }
        if hasattr(self.config, 'update_runtime'):
            self.config.update_runtime(persisted, persist=True)
        elif isinstance(self.config, dict):
            self.config.update(persisted)

        if not self.enabled or not self.sync_blocklist:
            desired_ips = {}
        desired = set(desired_ips)
        for domain in previous_domains - desired:
            self.unsinkhole(domain)
        for domain in desired:
            target_changed = previous_ips.get(domain) != desired_ips[domain]
            if domain in previous_domains and (target_changed or previous_mode != self.enforcement_mode):
                self.unsinkhole(domain)
            if domain not in previous_domains or target_changed or previous_mode != self.enforcement_mode:
                self.sinkhole(domain, reason='dashboard_policy', severity=self.default_severity, sinkhole_ip=desired_ips[domain])
        self._status_reported = False
        return {'success': True, **self.stats()}

    def run_and_report(self, sender=None) -> List[Dict]:
        """Report real sinkhole policy changes and a single startup status event.

        A policy addition is deliberately not called a "hit": query-hit telemetry
        must come from a DNS sensor. This keeps dashboard counts factual.
        """
        events = list(SINKHOLE_LOG[self._report_cursor:])
        self._report_cursor = len(SINKHOLE_LOG)
        if not self._status_reported:
            events.insert(0, {
                'action': 'status',
                'severity': 'low',
                'total_sinkholed': len(self._sinkholed),
                'sinkhole_ip': SINKHOLE_IP,
                'ts': time.time(),
            })
            self._status_reported = True

        if sender and self.telemetry_enabled:
            for event in events:
                action = event.get('action', 'status')
                domain = event.get('domain')
                is_block = action == 'sinkholed'
                description = (
                    f'DNS sinkhole policy added for {domain}' if is_block
                    else f'DNS sinkhole policy removed for {domain}' if action == 'removed'
                    else f'DNS sinkhole active with {len(self._sinkholed)} managed domains'
                )
                sender.send_alert({
                    'rule_id': f'DNS_SINKHOLE_{action.upper()}',
                    'capabilityId': 31,
                    'category': 'network',
                    'subCategory': 'dns-sinkhole',
                    'eventType': 'sinkhole_policy_change' if action != 'status' else 'sinkhole_status',
                    'severity': event.get('severity', 'high' if is_block else 'low'),
                    'description': description,
                    'domain': domain,
                    'sinkholeIp': event.get('ip') or event.get('sinkhole_ip') or self.sinkhole_ip,
                    'threatCategory': event.get('reason'),
                    'blocked': is_block,
                    'user_action': f'dns_sinkhole_{action}',
                    'source': 'dns_sinkhole',
                    'mitreId': 'T1071.004',
                    'riskScore': 80 if is_block else 20,
                    'recommendedAction': 'Review the domain policy and correlate with DNS query telemetry.',
                    'raw': {**event, **self.stats()},
                })
        return events


# Singleton
_sinkhole: Optional[DNSSinkhole] = None

def get_sinkhole(config=None) -> DNSSinkhole:
    global _sinkhole
    if _sinkhole is None:
        _sinkhole = DNSSinkhole(config)
    return _sinkhole
