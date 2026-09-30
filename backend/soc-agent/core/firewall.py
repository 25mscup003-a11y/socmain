"""
Firewall Control Module
Applies firewall rules from the SOC dashboard:
  - Block / unblock IPs
  - Open / close ports
  - Block / unblock domains (DNS)
  - Block / unblock applications (by process name)
  - Block / unblock protocols (tcp, udp, icmp)
  - Persist rules to JSON file for reboot survival

Enforced on-host via core.fw_backend:
  Linux   → UFW (if active) else nftables
  Windows → Windows Defender Firewall (netsh advfirewall)
  macOS   → pfctl
"""
import subprocess
import logging
import platform
import threading
import json
import os
import re
import ipaddress

from . import fw_backend
from .secure_file import load_json, save_json

logger = logging.getLogger('soc-agent.firewall')
SYSTEM = platform.system()

# Persist rules here so they survive agent restarts
RULES_FILE = '/etc/soc-agent/firewall_rules.json'


def _clean_domain(raw: str) -> str:
    """
    Clean a user-entered domain value.
    Handles: https://www.youtube.com/, http://example.com/path, www.google.com, etc.
    Returns: clean hostname like 'www.youtube.com'
    """
    d = raw.strip()
    if not d:
        return ''
    # Strip protocol
    d = re.sub(r'^https?://', '', d)
    # Strip path, query, fragment
    d = d.split('/')[0].split('?')[0].split('#')[0]
    # Strip port
    d = d.split(':')[0]
    # Strip whitespace
    d = d.strip().lower()
    return d


def _resolve_domain(domain: str) -> list:
    """Resolve all IPv4 and IPv6 addresses without trusting /etc/hosts.

    Browsers prefer IPv6 when it is available.  Resolving only A records makes
    a domain rule look deployed while the browser continues over an AAAA
    address, so both families must be sent to the host firewall.
    """
    import socket
    ips = set()

    def add_ip(value):
        candidate = str(value or '').strip().split('%', 1)[0]
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return
        if not address.is_unspecified and not address.is_loopback:
            ips.add(str(address))

    # Build list of domain variants to resolve
    variants = [domain]
    if domain.startswith('www.'):
        variants.append(domain[4:])  # also try without www
    else:
        variants.append(f'www.{domain}')  # also try with www

    for target in variants:
        # Try external DNS via dig (avoids an existing /etc/hosts sinkhole).
        for record_type in ('A', 'AAAA'):
            try:
                r = subprocess.run(
                    ['dig', '+short', record_type, target, '@8.8.8.8'],
                    capture_output=True, text=True, timeout=10
                )
                if r.returncode == 0:
                    for line in r.stdout.splitlines():
                        add_ip(line)
            except Exception:
                pass

        # Fallback: Try nslookup with external DNS
        if not ips:
            try:
                r = subprocess.run(
                    ['nslookup', target, '8.8.8.8'],
                    capture_output=True, text=True, timeout=10
                )
                if r.returncode == 0:
                    for line in r.stdout.split('\n'):
                        m = re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', line)
                        if m and m.group(1) != '8.8.8.8':
                            ips.add(m.group(1))
            except Exception:
                pass

        # Fallback: socket.getaddrinfo (may be affected by /etc/hosts, but it
        # still provides both families on systems without dig/nslookup).
        if not ips:
            try:
                for info in socket.getaddrinfo(target, None, socket.AF_UNSPEC):
                    add_ip(info[4][0])
            except Exception:
                pass

    return sorted(ips, key=lambda value: (ipaddress.ip_address(value).version, value))


class FirewallModule:
    def __init__(self, sender, config=None):
        self._sender  = sender
        self._config  = config
        self._encryption_key = config.get('storage_encryption_key', '') if config else ''
        self._lock    = threading.Lock()
        self._rules   = []   # list of applied rules for audit
        self._load_persisted_rules()

    # ── Persist / Load Rules ──────────────────────────────────────────────────
    def _save_rules(self):
        """Save current rules to disk for reboot persistence."""
        try:
            os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
            save_json(
                RULES_FILE, self._rules, self._encryption_key, 'firewall-rules'
            )
        except Exception as e:
            logger.warning('Failed to save firewall rules: %s', e)

    def _load_persisted_rules(self):
        """Load and re-apply persisted rules on startup."""
        try:
            if os.path.exists(RULES_FILE):
                saved = load_json(
                    RULES_FILE, self._encryption_key, 'firewall-rules', []
                )
                if saved:
                    logger.info('Re-applying %d persisted firewall rules', len(saved))
                    for rule in saved:
                        try:
                            act = rule.get('action', '')
                            if act == 'block_ip':
                                self.block_ip(rule['ip'], direction=rule.get('dir', 'both'),
                                              reason='persisted', persist=False)
                            elif act == 'close_port':
                                self.close_port(rule['port'], rule.get('protocol', 'tcp'), persist=False)
                            elif act == 'block_domain':
                                self.block_domain(rule['domain'], reason='persisted', persist=False)
                            elif act == 'block_protocol':
                                self.block_protocol(rule['protocol'], reason='persisted', persist=False)
                            elif act == 'block_application':
                                self.block_application(rule['application'], reason='persisted', persist=False)
                        except Exception as e:
                            logger.warning('Failed to re-apply rule %s: %s', rule, e)
        except Exception as e:
            logger.warning('Failed to load persisted rules: %s', e)

    # ── Block / Unblock IP ────────────────────────────────────────────────────
    def block_ip(self, ip: str, direction: str = 'both', reason: str = 'dashboard', persist: bool = True) -> bool:
        ip = ip.strip()
        if not ip:
            return False
        try:
            # Enforce on the local host firewall: UFW/nftables (Linux),
            # Windows Defender (netsh), or pfctl (macOS).
            ok = fw_backend.block_ip(ip, direction=direction, comment=reason)

            if ok:
                if persist:
                    self._rules.append({'action': 'block_ip', 'ip': ip, 'dir': direction, 'reason': reason})
                    self._save_rules()
                self._report('FIREWALL_BLOCK_IP',
                             f'Blocked IP {ip} ({direction}) — {reason}',
                             ip, 'medium',
                             dst_ip=ip,
                             domain=reason if '.' in reason else None,
                             query_type='A',
                             action_taken='Blocked',
                             protocol='IP',
                             blocked=True)
                logger.info('Firewall: blocked IP %s (%s)', ip, direction)
            else:
                logger.warning('Firewall: block_ip %s failed (returncode!=0)', ip)
            return ok
        except Exception as e:
            logger.error('Firewall block_ip %s: %s', ip, e)
            return False

    def unblock_ip(self, ip: str) -> bool:
        ip = ip.strip()
        try:
            fw_backend.unblock_ip(ip, direction='both')

            self._rules = [r for r in self._rules if not (r.get('action') == 'block_ip' and r.get('ip') == ip)]
            self._save_rules()

            self._report('FIREWALL_UNBLOCK_IP', f'Unblocked IP {ip}', ip, 'low',
                         dst_ip=ip, action_taken='Allowed')
            logger.info('Firewall: unblocked IP %s', ip)
            return True
        except Exception as e:
            logger.error('Firewall unblock_ip %s: %s', ip, e)
            return False


    # ── Open / Close Port ────────────────────────────────────────────────────
    def open_port(self, port: int, protocol: str = 'tcp', persist: bool = True) -> bool:
        """Re-open a port by removing the firewall rule that was previously added."""
        try:
            ok = fw_backend.unblock_port(port, protocol, direction='both')

            # Remove from persisted rules
            self._rules = [r for r in self._rules if not (r.get('action') == 'close_port' and r.get('port') == port and r.get('protocol') == protocol)]
            self._save_rules()

            if ok:
                self._report('FIREWALL_OPEN_PORT', f'Opened port {port}/{protocol}', '', 'low',
                             port=port, protocol=protocol, action_taken='Allowed')
                logger.info('Firewall: opened port %s/%s', port, protocol)
            return ok
        except Exception as e:
            logger.error('Firewall open_port %s: %s', port, e)
            return False

    def close_port(self, port: int, protocol: str = 'tcp', direction: str = 'both', persist: bool = True) -> bool:
        """Block traffic on a port — direction: 'in'/'inbound', 'out'/'outbound', 'both'."""
        # Normalize direction
        d = (direction or 'both').lower().strip()
        if d in ('in', 'inbound'):   d = 'in'
        elif d in ('out', 'outbound'): d = 'out'
        else:                          d = 'both'
        try:
            ok = fw_backend.block_port(port, protocol, direction=d)

            if ok:
                if persist:
                    self._rules.append({'action': 'close_port', 'port': port, 'protocol': protocol, 'dir': d})
                    self._save_rules()
                self._report('FIREWALL_CLOSE_PORT', f'Closed port {port}/{protocol} ({d})', '', 'medium',
                             port=port, protocol=protocol, action_taken='Blocked')
                logger.info('Firewall: closed port %s/%s direction=%s', port, protocol, d)
            return ok
        except Exception as e:
            logger.error('Firewall close_port %s: %s', port, e)
            return False

    # ── Block / Unblock Domain ─────────────────────────────────────────────────
    def block_domain(self, raw_domain: str, reason: str = 'dashboard', persist: bool = True) -> dict:
        """
        Block a domain by:
        1. Resolving it to IP(s) and adding iptables rules
        2. Adding iptables string-match rules to block TLS SNI / HTTP Host header
        3. Adding to /etc/hosts pointing to 0.0.0.0 (DNS-level block)
        Returns dict with results.
        """
        domain = _clean_domain(raw_domain)
        if not domain:
            return {'ok': False, 'error': 'empty domain'}

        # Get base domain (strip www.) for broader blocking
        base_domain = domain[4:] if domain.startswith('www.') else domain
        all_variants = list(set([domain, base_domain, f'www.{base_domain}']))

        results = {'domain': domain, 'ips_blocked': [], 'hosts_blocked': False, 'ok': False}

        # 1. Resolve and block all IPs
        resolved_ips = _resolve_domain(domain)
        for ip in resolved_ips:
            ok = self.block_ip(ip, direction='both', reason=f'domain:{domain}', persist=False)
            if ok:
                results['ips_blocked'].append(ip)

        # 2. Add to /etc/hosts for DNS-level blocking
        try:
            hosts_path = '/etc/hosts' if SYSTEM != 'Windows' else r'C:\Windows\System32\drivers\etc\hosts'
            if os.path.exists(hosts_path):
                existing = ''
                try:
                    with open(hosts_path, 'r') as f:
                        existing = f.read()
                except Exception:
                    pass

                new_lines = []
                for entry in all_variants:
                    for sinkhole in ('0.0.0.0', '::'):
                        line = f'{sinkhole} {entry}'
                        if line not in existing:
                            new_lines.append(line)

                if new_lines:
                    with open(hosts_path, 'a') as f:
                        f.write(f'\n# SOC Agent: blocked domain ({reason})\n')
                        for line in new_lines:
                            f.write(line + '\n')
                    logger.info('Firewall: added %d entries to %s for %s', len(new_lines), hosts_path, domain)

                # Existing entries are already successful enforcement; do not
                # report hosts=False merely because this poll added no new line.
                effective_hosts = existing + '\n' + '\n'.join(new_lines)
                results['hosts_blocked'] = all(
                    any(f'{sinkhole} {entry}' in effective_hosts for sinkhole in ('0.0.0.0', '::'))
                    for entry in all_variants
                )

                # Flush DNS cache aggressively
                if SYSTEM == 'Linux':
                    # Try multiple methods to flush DNS cache
                    for cmd in [
                        ['systemctl', 'restart', 'systemd-resolved'],
                        ['resolvectl', 'flush-caches'],
                        ['systemd-resolve', '--flush-caches'],
                        ['service', 'nscd', 'restart'],
                        ['service', 'systemd-resolved', 'restart'],
                        ['sudo', 'systemctl', 'restart', 'systemd-resolved'],
                    ]:
                        try:
                            subprocess.run(cmd, capture_output=True, timeout=5)
                        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                            pass
                elif SYSTEM == 'Darwin':
                    subprocess.run(['dscacheutil', '-flushcache'], capture_output=True)
                    subprocess.run(['killall', '-HUP', 'mDNSResponder'], capture_output=True)
                elif SYSTEM == 'Windows':
                    subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
        except PermissionError:
            logger.warning('Firewall: no permission to edit hosts file for domain %s', domain)
        except Exception as e:
            logger.warning('Firewall: hosts file edit failed for %s: %s', domain, e)
            # Try to flush DNS cache anyway, even if hosts edit failed
            if SYSTEM == 'Linux':
                for cmd in [['resolvectl', 'flush-caches'], ['sudo', 'resolvectl', 'flush-caches']]:
                    try:
                        subprocess.run(cmd, capture_output=True, timeout=5)
                    except Exception:
                        pass

        results['ok'] = len(results['ips_blocked']) > 0 or results['hosts_blocked']

        if results['ok']:
            if persist:
                self._rules.append({'action': 'block_domain', 'domain': domain, 'ips': results['ips_blocked'], 'reason': reason})
                self._save_rules()
            ip_str = ', '.join(results['ips_blocked']) if results['ips_blocked'] else 'none'
            self._report('FIREWALL_BLOCK_DOMAIN',
                         f'Blocked domain {domain} → IPs: {ip_str}, hosts: {results["hosts_blocked"]} — {reason}',
                         ip_str.split(',')[0].strip() if ip_str and ip_str != 'none' else '',
                         'medium',
                         domain=domain,
                         query_type='A',
                         dst_ip=ip_str.split(',')[0].strip() if ip_str and ip_str != 'none' else None,
                         action_taken='Blocked',
                         blocked=True)
            logger.info('Firewall: blocked domain %s (IPs: %s, hosts: %s)', domain, ip_str, results['hosts_blocked'])

        return results

    def unblock_domain(self, raw_domain: str) -> bool:
        """Remove domain block (IPs + hosts file entries + iptables string match)."""
        domain = _clean_domain(raw_domain)
        if not domain:
            return False

        # Get base domain for cleanup
        base_domain = domain[4:] if domain.startswith('www.') else domain

        # Resolve and unblock IPs
        resolved_ips = _resolve_domain(domain)
        for ip in resolved_ips:
            self.unblock_ip(ip)

        # Also unblock IPs from persisted rules
        for rule in self._rules:
            if rule.get('action') == 'block_domain' and rule.get('domain') in (domain, base_domain, f'www.{base_domain}'):
                for ip in rule.get('ips', []):
                    if ip not in ('0.0.0.0', '127.0.0.1'):
                        self.unblock_ip(ip)

        # Remove iptables string match rules
        # (removed - iptables string matching no longer supported)
        
        # Remove from /etc/hosts
        try:
            hosts_path = '/etc/hosts' if SYSTEM != 'Windows' else r'C:\Windows\System32\drivers\etc\hosts'
            if os.path.exists(hosts_path):
                with open(hosts_path, 'r') as f:
                    lines = f.readlines()
                # Remove any line containing the domain
                new_lines = [l for l in lines if base_domain not in l.lower()]
                with open(hosts_path, 'w') as f:
                    f.writelines(new_lines)
                # Flush DNS cache
                if SYSTEM == 'Linux':
                    # Try multiple methods
                    for cmd in [
                        ['systemctl', 'restart', 'systemd-resolved'],
                        ['resolvectl', 'flush-caches'],
                        ['systemd-resolve', '--flush-caches'],
                        ['service', 'nscd', 'restart'],
                        ['service', 'systemd-resolved', 'restart'],
                        ['sudo', 'systemctl', 'restart', 'systemd-resolved'],
                    ]:
                        try:
                            subprocess.run(cmd, capture_output=True, timeout=5)
                        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                            pass
                elif SYSTEM == 'Windows':
                    subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
        except Exception as e:
            logger.warning('Firewall: failed to clean hosts file for %s: %s', domain, e)

        # Remove from persisted rules (match all variants)
        self._rules = [r for r in self._rules if not (
            r.get('action') == 'block_domain' and 
            r.get('domain', '') in (domain, base_domain, f'www.{base_domain}')
        )]
        self._save_rules()

        self._report('FIREWALL_UNBLOCK_DOMAIN', f'Unblocked domain {domain}', '', 'low',
                     domain=domain, action_taken='Allowed')
        logger.info('Firewall: unblocked domain %s', domain)
        return True

    # ── Block / Unblock Protocol ──────────────────────────────────────────────
    def block_protocol(self, protocol: str, direction: str = 'both', reason: str = 'dashboard', persist: bool = True) -> bool:
        """Block an entire protocol (tcp, udp, icmp, all)."""
        protocol = protocol.strip().lower()
        d = (direction or 'both').lower().strip()
        if d in ('in', 'inbound'):    d = 'in'
        elif d in ('out', 'outbound'): d = 'out'
        else:                          d = 'both'

        if protocol == 'all':
            # Block all protocols = blanket INPUT/OUTPUT DROP (dangerous — only if explicitly requested)
            results = []
            for proto in ('tcp', 'udp', 'icmp'):
                ok = self.block_protocol(proto, direction=d, reason=reason, persist=False)
                results.append(ok)
            if persist:
                self._rules.append({'action': 'block_protocol', 'protocol': 'all', 'dir': d, 'reason': reason})
                self._save_rules()
            return any(results)

        if protocol not in ('tcp', 'udp', 'icmp'):
            logger.warning('Firewall: unsupported protocol to block: %s', protocol)
            return False

        try:
            ok = fw_backend.block_protocol(protocol, direction=d)

            if ok:
                if persist:
                    self._rules.append({'action': 'block_protocol', 'protocol': protocol, 'dir': d, 'reason': reason})
                    self._save_rules()
                self._report('FIREWALL_BLOCK_PROTOCOL', f'Blocked protocol {protocol} ({d}) — {reason}', '', 'high',
                             protocol=protocol, action_taken='Blocked', blocked=True)
                logger.info('Firewall: blocked protocol %s direction=%s', protocol, d)
            return ok
        except Exception as e:
            logger.error('Firewall block_protocol %s: %s', protocol, e)
            return False

    def unblock_protocol(self, protocol: str) -> bool:
        """Unblock an entire protocol."""
        protocol = protocol.strip().lower()
        try:
            fw_backend.unblock_protocol(protocol, direction='both')

            self._rules = [r for r in self._rules if not (r.get('action') == 'block_protocol' and r.get('protocol') == protocol)]
            self._save_rules()
            logger.info('Firewall: unblocked protocol %s', protocol)
            return True
        except Exception as e:
            logger.error('Firewall unblock_protocol %s: %s', protocol, e)
            return False

    # ── Block / Unblock Application ───────────────────────────────────────────
    def block_application(self, app_name: str, reason: str = 'dashboard', persist: bool = True) -> bool:
        """
        Block an application's network access using an OS firewall rule.
        Process termination is deliberately not used as a firewall fallback.
        """
        app_name = app_name.strip().lower()
        if not app_name:
            return False

        results = []
        ok = False
        if SYSTEM == 'Linux':
            results.append('not supported: Linux firewall requires an executable cgroup/UID policy, not a process-name kill')

        elif SYSTEM == 'Windows':
            try:
                import psutil
                exe_paths = set()
                for proc in psutil.process_iter(['name', 'exe']):
                    try:
                        pname = (proc.info['name'] or '').lower()
                        pexe = proc.info['exe'] or ''
                        if app_name in pname and pexe:
                            exe_paths.add(pexe)
                    except Exception:
                        pass

                for exe in exe_paths:
                    directions_ok = []
                    for direction in ('out', 'in'):
                        r = subprocess.run([
                            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                            f'name=SOCBlock_App_{app_name}_{direction}', f'dir={direction}', 'action=block',
                            f'program={exe}', 'enable=yes'
                        ], capture_output=True)
                        directions_ok.append(r.returncode == 0)
                    if all(directions_ok):
                        ok = True
                        results.append(f'firewall blocked inbound/outbound for {exe}')
                if not exe_paths:
                    results.append('not supported: executable path could not be resolved')
            except Exception as e:
                results.append(f'Windows block error: {e}')
        else:
            results.append('application blocking not supported on this OS')

        if persist and ok:
            self._rules.append({'action': 'block_application', 'application': app_name, 'reason': reason})
            self._save_rules()

        summary = '; '.join(results) if results else 'no action taken'
        self._report('FIREWALL_BLOCK_APP', f'Blocked application {app_name}: {summary} — {reason}', '', 'high',
                     process_name=app_name, action_taken='Blocked', blocked=True)
        logger.info('Firewall: blocked application %s: %s', app_name, summary)
        return ok

    def unblock_application(self, app_name: str) -> bool:
        """Remove application block."""
        app_name = app_name.strip().lower()
        try:
            if SYSTEM == 'Linux':
                # App block on Linux was process-kill only — no netfilter rule to remove.
                pass
            elif SYSTEM == 'Windows':
                for direction in ('out', 'in'):
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name=SOCBlock_App_{app_name}_{direction}'], capture_output=True)

            self._rules = [r for r in self._rules if not (r.get('action') == 'block_application' and r.get('application') == app_name)]
            self._save_rules()
            logger.info('Firewall: unblocked application %s', app_name)
            return True
        except Exception as e:
            logger.error('Firewall unblock_application %s: %s', app_name, e)
            return False

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _report(self, rule_id: str, description: str, ip: str, severity: str, **extra):
        import os, pwd
        # Collect current logged-in user for username field
        try:
            username = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            username = None

        payload = {
            'rule_id':      rule_id,
            'category':     'network',
            'severity':     severity,
            'description':  description,
            'raw_log':      description,
            'src_ip':       ip or None,
            # Extended fields for Web & DNS Monitoring dashboard
            'dst_ip':       extra.get('dst_ip') or None,
            'dest_ip':      extra.get('dst_ip') or None,
            'domain':       extra.get('domain') or None,
            'query_type':   extra.get('query_type') or None,
            'username':     extra.get('username') or username,
            'process_name': extra.get('process_name') or None,
            'action_taken': extra.get('action_taken') or None,
            'protocol':     extra.get('protocol') or None,
            'port':         extra.get('port') or None,
            'blocked':      extra.get('blocked', False),
        }
        # Remove None values to keep payload clean
        payload = {k: v for k, v in payload.items() if v is not None}
        self._sender.enqueue(payload)

    def get_rules(self):
        return list(self._rules)
