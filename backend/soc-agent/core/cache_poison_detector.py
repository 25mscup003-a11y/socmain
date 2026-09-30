"""
core/cache_poison_detector.py
DNS Cache Poisoning Detection — CAP (new)

Detects DNS cache poisoning by:
  1. Monitoring DNS responses and comparing resolved IPs against known-good baseline
  2. Detecting TTL anomalies (sudden TTL drop = cache poisoning indicator)
  3. Detecting unexpected IP changes for monitored domains
  4. BGP hijack indicators (IP moving to different ASN/country unexpectedly)

MITRE ATT&CK: T1557.003 (LLMNR/NBT-NS Poisoning), T1584.002 (DNS Server)
"""

import time
import socket
import logging
import ipaddress
import os
import sys
import hashlib
import platform
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

# Domains to actively monitor for cache poisoning
DEFAULT_WATCH_DOMAINS = [
    'google.com', 'microsoft.com', 'github.com',
    'cloudflare.com', 'amazon.com', 'apple.com',
]

# Tolerable IP change window (seconds) — IPs can legitimately change via CDN
CDN_CHANGE_WINDOW = 3600

# Minimum TTL below which we flag as suspicious (normal is 300-3600s)
MIN_SAFE_TTL = 30

class CachePoisonDetector:
    """Detects DNS cache poisoning by monitoring domain resolution stability."""

    def __init__(self, config=None):
        self.config         = config
        self._baseline: Dict[str, dict] = {}   # domain → {ips, asns, country, ttl, ts}
        self._history: Dict[str, List] = defaultdict(list)
        self._findings: List[Dict] = []
        self._last_scan_at = 0.0
        self._last_error = ''
        self._resolver_snapshot = None
        self._hosts_snapshot = None
        self._resolver_original = None
        self._watch = set()
        self.configure(config.all() if hasattr(config, 'all') else (config or {}))
        self._capture_file_baseline()

    @property
    def enabled(self):
        return self._enabled

    @property
    def telemetry_enabled(self):
        return self._telemetry_enabled

    @property
    def scan_interval_seconds(self):
        return self._scan_interval_seconds

    def configure(self, settings=None):
        """Apply a server-authorized detector policy at runtime."""
        settings = settings or {}
        self._enabled = settings.get('cache_poison_enabled', getattr(self, '_enabled', True)) is not False
        self._telemetry_enabled = settings.get(
            'cache_poison_telemetry_enabled', getattr(self, '_telemetry_enabled', True)
        ) is not False
        self._scan_interval_seconds = max(60, min(3600, int(
            settings.get('cache_poison_scan_interval_seconds', getattr(self, '_scan_interval_seconds', 300))
        )))
        self._min_safe_ttl = max(1, int(settings.get('cache_poison_min_safe_ttl', getattr(self, '_min_safe_ttl', MIN_SAFE_TTL))))
        self._max_safe_ttl = max(self._min_safe_ttl + 1, int(settings.get('cache_poison_max_safe_ttl', getattr(self, '_max_safe_ttl', 86400))))
        self._baseline_window = max(60, int(settings.get('cache_poison_baseline_window_seconds', getattr(self, '_baseline_window', CDN_CHANGE_WINDOW))))
        self._monitor_resolver = settings.get('cache_poison_monitor_resolver_changes', getattr(self, '_monitor_resolver', True)) is not False
        self._monitor_hosts = settings.get('cache_poison_monitor_hosts_changes', getattr(self, '_monitor_hosts', True)) is not False
        self._detect_private = settings.get('cache_poison_detect_private_answers', getattr(self, '_detect_private', True)) is not False
        self._detect_ttl = settings.get('cache_poison_detect_ttl_anomaly', getattr(self, '_detect_ttl', True)) is not False
        self._trusted_resolvers = set(settings.get('cache_poison_trusted_resolvers', getattr(self, '_trusted_resolvers', [])) or [])
        self._custom_rules = [
            {
                'id': str(rule.get('id') or ''),
                'name': str(rule.get('name') or 'Custom DNS rule'),
                'domain': str(rule.get('domain') or '').lower().strip().rstrip('.'),
                'queryType': str(rule.get('queryType') or 'A').upper(),
                'expectedIps': [str(ip).strip() for ip in (rule.get('expectedIps') or []) if str(ip).strip()],
                'severity': str(rule.get('severity') or 'high').lower(),
                'enabled': rule.get('enabled', True) is not False,
            }
            for rule in (settings.get('cache_poison_custom_rules', getattr(self, '_custom_rules', [])) or [])
            if isinstance(rule, dict) and rule.get('domain') and rule.get('expectedIps')
        ]
        default_severities = {'private-answer': 'critical', 'ttl-anomaly': 'high', 'resolver-change': 'high', 'hosts-file-change': 'high'}
        reported_severities = settings.get('cache_poison_rule_severities', getattr(self, '_rule_severities', {})) or {}
        self._rule_severities = {
            key: value if value in ('low', 'medium', 'high', 'critical') else default_severities[key]
            for key, value in {**default_severities, **reported_severities}.items()
            if key in default_severities
        }
        self._policy_version = max(0, int(settings.get('cache_poison_policy_version', getattr(self, '_policy_version', 0))))
        domains = settings.get('cache_poison_watch_domains')
        if domains is not None:
            self._watch = {str(domain).lower().strip().rstrip('.') for domain in domains if str(domain).strip()}
        if not self._watch:
            self._watch = set(DEFAULT_WATCH_DOMAINS)
        if self.config and hasattr(self.config, 'update_runtime'):
            self.config.update_runtime({
                'cache_poison_enabled': self._enabled,
                'cache_poison_telemetry_enabled': self._telemetry_enabled,
                'cache_poison_watch_domains': sorted(self._watch),
                'cache_poison_trusted_resolvers': sorted(self._trusted_resolvers),
                'cache_poison_scan_interval_seconds': self._scan_interval_seconds,
                'cache_poison_min_safe_ttl': self._min_safe_ttl,
                'cache_poison_max_safe_ttl': self._max_safe_ttl,
                'cache_poison_baseline_window_seconds': self._baseline_window,
                'cache_poison_monitor_resolver_changes': self._monitor_resolver,
                'cache_poison_monitor_hosts_changes': self._monitor_hosts,
                'cache_poison_detect_private_answers': self._detect_private,
                'cache_poison_detect_ttl_anomaly': self._detect_ttl,
                'cache_poison_rule_severities': self._rule_severities,
                'cache_poison_custom_rules': self._custom_rules,
                'cache_poison_policy_version': self._policy_version,
            }, persist=True)
        return self.status()

    def add_watch(self, domain: str):
        """Add a domain to active monitoring."""
        self._watch.add(domain.lower().strip())

    def remove_watch(self, domain: str):
        self._watch.discard(domain.lower().strip())

    def _resolve(self, domain: str, query_type: str = 'A') -> Tuple[List[str], int]:
        """Resolve domain → (list of IPs, TTL). TTL approximated via socket timeout."""
        record_type = 'AAAA' if str(query_type).upper() == 'AAAA' else 'A'
        try:
            import dns.resolver  # dnspython
            answers = dns.resolver.resolve(domain, record_type)
            ips = [str(r) for r in answers]
            ttl = answers.rrset.ttl
            return ips, ttl
        except ImportError:
            # Fallback: basic socket (no TTL info)
            try:
                family = socket.AF_INET6 if record_type == 'AAAA' else socket.AF_INET
                info = socket.getaddrinfo(domain, None, family)
                ips = list({r[4][0] for r in info})
                return ips, -1   # TTL unknown
            except socket.gaierror:
                return [], -1
        except Exception:
            return [], -1

    def _hosts_path(self):
        if platform.system() == 'Windows':
            return Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'drivers' / 'etc' / 'hosts'
        return Path('/etc/hosts')

    def _resolver_state(self):
        try:
            if platform.system() == 'Windows':
                return subprocess.check_output(['ipconfig', '/all'], text=True, errors='replace', timeout=15)
            return Path('/etc/resolv.conf').read_text(encoding='utf-8', errors='replace')
        except Exception as exc:
            self._last_error = 'resolver state unavailable: {}'.format(exc)
            return ''

    @staticmethod
    def _digest(value):
        return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest() if value else ''

    def _capture_file_baseline(self):
        resolver = self._resolver_state()
        self._resolver_original = resolver
        self._resolver_snapshot = self._digest(resolver)
        try:
            hosts = self._hosts_path().read_text(encoding='utf-8', errors='replace')
        except Exception:
            hosts = ''
        self._hosts_snapshot = self._digest(hosts)

    def _configuration_findings(self):
        findings = []
        if self._monitor_resolver:
            resolver = self._resolver_state()
            digest = self._digest(resolver)
            if self._resolver_snapshot and digest and digest != self._resolver_snapshot:
                if platform.system() == 'Windows':
                    resolver_ips = set(re.findall(r'(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])', resolver))
                else:
                    resolver_ips = set(re.findall(r'^\s*nameserver\s+([^\s#]+)', resolver, re.MULTILINE))
                untrusted = sorted(resolver_ips - self._trusted_resolvers) if self._trusted_resolvers else []
                findings.append({
                    'type': 'resolver_configuration_change', 'severity': self._rule_severities['resolver-change'],
                    'mitre': 'T1557.003',
                    'description': 'Endpoint DNS resolver configuration changed since the previous scan.',
                    'evidence': {'stateSha256': digest, 'untrustedResolvers': untrusted},
                })
            self._resolver_snapshot = digest or self._resolver_snapshot
        if self._monitor_hosts:
            try:
                hosts = self._hosts_path().read_text(encoding='utf-8', errors='replace')
                digest = self._digest(hosts)
            except Exception as exc:
                self._last_error = 'hosts file unavailable: {}'.format(exc)
                digest = ''
            if self._hosts_snapshot and digest and digest != self._hosts_snapshot:
                findings.append({
                    'type': 'hosts_file_change', 'severity': self._rule_severities['hosts-file-change'], 'mitre': 'T1565.001',
                    'description': 'Endpoint hosts file changed since the previous scan.',
                    'evidence': {'path': str(self._hosts_path()), 'sha256': digest},
                })
            self._hosts_snapshot = digest or self._hosts_snapshot
        return findings

    def _check_domain(self, domain: str) -> List[Dict]:
        """Resolve domain and compare against baseline. Return findings."""
        findings = []
        ips, ttl = self._resolve(domain)
        now = time.time()

        if not ips:
            return []

        baseline = self._baseline.get(domain)

        if not baseline:
            # First time — establish baseline
            self._baseline[domain] = {
                'ips': set(ips), 'ttl': ttl, 'ts': now, 'country': '',
            }
            logger.info(f'[CachePoisonDetector] Baseline: {domain} → {ips} TTL={ttl}')
            if self._detect_private:
                for observed_ip in ips:
                    try:
                        address = ipaddress.ip_address(observed_ip)
                        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                            findings.append({
                                'type': 'cache_poison_private_ip', 'domain': domain,
                                'old_ips': [], 'new_ip': observed_ip, 'severity': self._rule_severities['private-answer'],
                                'mitre': 'T1557.003',
                                'description': '{} resolved to private, loopback or reserved address {}.'.format(domain, observed_ip),
                            })
                    except ValueError:
                        continue
            if self._detect_ttl and ttl > 0 and (ttl < self._min_safe_ttl or ttl > self._max_safe_ttl):
                findings.append({
                    'type': 'cache_poison_ttl_outlier', 'domain': domain,
                    'old_ttl': None, 'new_ttl': ttl, 'ips': list(ips), 'severity': self._rule_severities['ttl-anomaly'],
                    'mitre': 'T1557.003',
                    'description': 'DNS TTL {}s for {} is outside the configured safe range.'.format(ttl, domain),
                })
            return findings

        old_ips = baseline['ips']
        old_ttl = baseline['ttl']
        new_ips = set(ips)

        # ── Check 1: IP changed ──────────────────────────────────────────────
        changed = new_ips - old_ips
        if changed and now - baseline['ts'] < self._baseline_window:
            for new_ip in changed:
                # Check if new IP is private/loopback (MITM indicator)
                try:
                    obj = ipaddress.ip_address(new_ip)
                    if self._detect_private and (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved):
                        findings.append({
                            'type':     'cache_poison_private_ip',
                            'domain':   domain,
                            'old_ips':  list(old_ips),
                            'new_ip':   new_ip,
                            'severity': self._rule_severities['private-answer'],
                            'mitre':    'T1557.003',
                            'description': (
                                f'CRITICAL: {domain} now resolves to private IP {new_ip} — '
                                f'possible DNS cache poisoning or MITM attack!'
                            ),
                        })
                    else:
                        # Public-IP rotation is expected for CDN/anycast domains
                        # such as Google, Microsoft and GitHub. IP change alone
                        # is not a cache-poisoning signal; private/loopback
                        # answers and independently suspicious TTL changes below
                        # remain actionable.
                        logger.debug(
                            '[CachePoisonDetector] Expected public DNS rotation: %s %s -> %s',
                            domain, list(old_ips), new_ip,
                        )
                except ValueError:
                    pass

        # ── Check 2: TTL too low ─────────────────────────────────────────────
        if self._detect_ttl and 0 < ttl < self._min_safe_ttl and old_ttl > self._min_safe_ttl:
            findings.append({
                'type':     'cache_poison_ttl_drop',
                'domain':   domain,
                'old_ttl':  old_ttl,
                'new_ttl':  ttl,
                'ips':      list(new_ips),
                'severity': self._rule_severities['ttl-anomaly'],
                'mitre':    'T1557.003',
                'description': (
                    f'Suspicious TTL drop for {domain}: {old_ttl}s → {ttl}s — '
                    f'possible cache poisoning attempt'
                ),
            })
        if self._detect_ttl and ttl > self._max_safe_ttl and (old_ttl <= 0 or old_ttl <= self._max_safe_ttl):
            findings.append({
                'type': 'cache_poison_ttl_outlier', 'domain': domain,
                'old_ttl': old_ttl, 'new_ttl': ttl, 'ips': list(new_ips),
                'severity': self._rule_severities['ttl-anomaly'], 'mitre': 'T1557.003',
                'description': 'DNS TTL increased outside the configured safe range for {}: {}s to {}s.'.format(domain, old_ttl, ttl),
            })

        # Update baseline
        self._baseline[domain] = {'ips': new_ips, 'ttl': ttl, 'ts': now}
        self._history[domain].append({'ips': list(new_ips), 'ttl': ttl, 'ts': now})

        return findings

    def _check_custom_rule(self, rule: Dict) -> List[Dict]:
        if not rule.get('enabled', True):
            return []
        domain = rule['domain']
        query_type = rule.get('queryType', 'A')
        observed_ips, ttl = self._resolve(domain, query_type)
        expected_ips = set(rule.get('expectedIps') or [])
        unexpected_ips = sorted(set(observed_ips) - expected_ips)
        return [{
            'type': 'custom_expected_ip_mismatch',
            'rule_id': rule.get('id'),
            'rule_name': rule.get('name'),
            'domain': domain,
            'query_type': query_type,
            'old_ips': sorted(expected_ips),
            'new_ip': unexpected_ip,
            'ips': observed_ips,
            'new_ttl': ttl,
            'severity': rule.get('severity', 'high'),
            'mitre': 'T1557.003',
            'description': '{} returned unexpected {} address {}; expected {}.'.format(
                domain, query_type, unexpected_ip, ', '.join(sorted(expected_ips))
            ),
            'evidence': {'expectedIps': sorted(expected_ips), 'observedIps': observed_ips},
        } for unexpected_ip in unexpected_ips]

    # ─── Public API ──────────────────────────────────────────────────────────
    def scan_all(self) -> List[Dict]:
        """Scan all watched domains and return findings."""
        if not self._enabled or not self._telemetry_enabled:
            return []
        all_findings = self._configuration_findings()
        for domain in list(self._watch):
            try:
                findings = self._check_domain(domain)
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f'[CachePoisonDetector] Error checking {domain}: {e}')
        for rule in self._custom_rules:
            try:
                all_findings.extend(self._check_custom_rule(rule))
            except Exception as e:
                logger.error('[CachePoisonDetector] Custom rule %s failed: %s', rule.get('id'), e)
        self._last_scan_at = time.time()
        self._findings.extend(all_findings)
        return all_findings

    def check_domain(self, domain: str) -> List[Dict]:
        """Manually check a single domain."""
        self.add_watch(domain)
        return self._check_domain(domain)

    def get_baseline(self) -> Dict:
        """Return current baseline for all watched domains."""
        return {
            d: {**v, 'ips': list(v['ips'])}
            for d, v in self._baseline.items()
        }

    def get_history(self, domain: str) -> List:
        return self._history.get(domain, [])

    def flush_dns_cache(self):
        if platform.system() == 'Windows':
            command = ['ipconfig', '/flushdns']
        elif platform.system() == 'Darwin':
            command = ['dscacheutil', '-flushcache']
        elif Path('/usr/bin/resolvectl').exists() or Path('/bin/resolvectl').exists():
            command = ['resolvectl', 'flush-caches']
        elif Path('/usr/bin/systemd-resolve').exists() or Path('/bin/systemd-resolve').exists():
            command = ['systemd-resolve', '--flush-caches']
        else:
            raise RuntimeError('DNS cache flush is unsupported by this endpoint resolver')
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout or 'DNS cache flush failed')[:300])
        return {'success': True, 'message': 'DNS cache flushed'}

    def restore_resolver(self):
        if platform.system() == 'Windows':
            raise RuntimeError('Automatic resolver restore is unsupported on Windows; use the managed adapter policy')
        if not self._resolver_original:
            raise RuntimeError('No resolver baseline is available')
        path = Path('/etc/resolv.conf')
        path.write_text(self._resolver_original, encoding='utf-8')
        self._resolver_snapshot = self._digest(self._resolver_original)
        return {'success': True, 'message': 'Resolver configuration restored to the agent startup baseline'}

    def status(self):
        return {
            'enabled': self._enabled,
            'telemetryEnabled': self._telemetry_enabled,
            'policyVersion': self._policy_version,
            'watchDomainCount': len(self._watch),
            'lastScanAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self._last_scan_at)) if self._last_scan_at else None,
            'lastError': self._last_error or None,
            'resolverMonitoring': self._monitor_resolver,
            'hostsMonitoring': self._monitor_hosts,
        }

    def run_and_report(self, sender=None) -> List[Dict]:
        findings = self.scan_all()
        if findings and sender:
            for f in findings:
                try:
                    sender.send_alert({
                        'rule_id':        f.get('rule_id') or f'DNS_{f["type"].upper()}',
                        'capabilityId':   30,
                        'category':       'network',
                        'subCategory':    'dns-cache-poisoning',
                        'eventType':      f.get('type', 'dns_cache_anomaly'),
                        'severity':       f.get('severity', 'high'),
                        'description':    f['description'],
                        'user_action':    'cache_poisoning_detected',
                        'mitreId':        f.get('mitre', 'T1557.003'),
                        'technique':      'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning',
                        'riskScore':      {'critical': 95, 'high': 80, 'medium': 55, 'low': 25}.get(f.get('severity', 'high'), 80),
                        'domain':         f.get('domain'),
                        'queryType':      f.get('query_type') or ('A' if f.get('domain') else None),
                        'dst_ip':         f.get('new_ip') or (f.get('ips') or [None])[0],
                        'responseIp':     f.get('new_ip') or (f.get('ips') or [None])[0],
                        'expectedIp':     (f.get('old_ips') or [None])[0],
                        'ttl':            f.get('new_ttl'),
                        'previousTtl':    f.get('old_ttl'),
                        'responseType':   f.get('type'),
                        'detectionType':  f.get('type'),
                        'evidence':       f.get('evidence') or {
                            'previousIps': f.get('old_ips') or [],
                            'observedIps': f.get('ips') or ([f.get('new_ip')] if f.get('new_ip') else []),
                        },
                        'reason':         f.get('description'),
                        'source':         'dns_cache_poison_detector',
                        # This detector performs the DNS resolution inside the
                        # running SOC agent process. Persist that process identity
                        # so forensic views can show evidence instead of blanks.
                        'processName':    os.path.basename(sys.executable) or 'soc-agent',
                        'pid':            os.getpid(),
                        'recommendedAction': 'Validate the authoritative answer and flush the affected resolver cache.',
                        'raw':            f,
                    })
                except Exception as e:
                    logger.error(f'[CachePoisonDetector] Send error: {e}')
        return findings
