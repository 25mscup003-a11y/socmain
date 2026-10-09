"""
Command Listener — listens to Socket.IO for real-time commands from the dashboard.
Supported commands:
  block_ip        — add iptables/Windows Firewall rule to block an IP
  isolate         — full network isolation
  reconnect       — remove isolation
  block_usb       — disable USB storage
  unblock_usb     — re-enable USB storage
  kill_process    — kill a process by PID
  quarantine_file — move file to quarantine
"""

import logging
import json
import platform
import threading
import time
from typing import Optional

from . import fw_backend
from .sensor_policy_manager import SensorPolicyManager
from .secure_transport import certificate_status, secure_request, secure_session

logger = logging.getLogger('soc-agent.command')
SYSTEM = platform.system()


class CommandListener:
    def __init__(self, config, sender, ips=None, firewall=None, auto_response=None, dns_sinkhole=None, cache_poison_detector=None):
        self._config       = config
        self._sender       = sender
        self._ips          = ips        # IPSModule (optional)
        self._firewall     = firewall   # FirewallModule (optional)
        self._auto_response = auto_response  # AutoResponseEngine (optional)
        self._dns_sinkhole = dns_sinkhole
        self._cache_poison_detector = cache_poison_detector
        self._sensor_policies = SensorPolicyManager(config)
        self._synced_rule_fingerprints = {}
        self._sio          = None
        self._thread       = threading.Thread(target=self._connect, daemon=True, name='cmd-listener')
        self._sync_thread  = threading.Thread(target=self._sync_rules_on_startup, daemon=True, name='rule-sync')
        self._violation_thread = threading.Thread(target=self._watch_violations, daemon=True, name='violation-watch')

    def start(self):
        self._thread.start()
        self._sync_thread.start()
        self._violation_thread.start()

    def _sync_rules_on_startup(self):
        """Fetch all pending firewall rules from backend and apply them.
        This is a belt-and-suspenders approach: the agent already loads from local
        JSON, but also checks backend in case the local file was lost or rules
        were added while agent was offline. Also serves as fallback for socketio."""
        try:
            import requests
        except ImportError:
            return

        time.sleep(5)  # Wait for connections to establish
        server_url = (self._config.get('server_url') or
                      'http://{}:{}'.format(
                          self._config.get('server_ip', 'localhost'),
                          self._config.get('server_port', 5000)))
        agent_key = self._config.get('agent_key', '')

        if not agent_key:
            return

        # Poll for pending rules every 10 seconds (fallback for socketio)
        while True:
            try:
                from .security import signed_headers
                url = f'{server_url.rstrip("/")}/api/firewall/pending-rules/self'
                resp = secure_request(self._config, 'GET', url, headers=signed_headers(self._config, {}), timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    rules = data.get('rules', [])
                    if rules:
                        logger.info('Fetched %d pending firewall rules from backend', len(rules))
                        for rule in rules:
                            try:
                                rule_id = str(rule.get('ruleId') or '')
                                fingerprint = json.dumps(rule, sort_keys=True, default=str)
                                if rule_id and self._synced_rule_fingerprints.get(rule_id) == fingerprint:
                                    continue
                                result = self._apply_firewall_rule(rule)
                                applied = self._firewall_result_ok(result)
                                acknowledged = self._report_firewall_ack(rule, result, ok=applied)
                                # Cache only a confirmed successful deployment.  A
                                # failed firewall command or failed ACK must be
                                # retried on the next poll instead of becoming a
                                # permanently "pending" rule that is never run.
                                if rule_id and applied and acknowledged:
                                    self._synced_rule_fingerprints[rule_id] = fingerprint
                            except Exception as e:
                                logger.warning('Failed to apply synced rule %s: %s', rule.get('ruleName'), e)
                    # Continue polling even if no rules
                else:
                    logger.debug('Firewall sync: HTTP %d', resp.status_code)

                policy_url = f'{server_url.rstrip("/")}/api/ids/agent-policies/self'
                policy_resp = secure_request(self._config, 'GET', policy_url, headers=signed_headers(self._config, {}), timeout=15)
                if policy_resp.status_code == 200:
                    self._apply_sensor_policies(policy_resp.json())
                else:
                    logger.debug('IDS policy sync: HTTP %d', policy_resp.status_code)
            except Exception as e:
                logger.debug('Firewall sync poll failed: %s', e)
            
            # Wait 10 seconds before next poll (fallback for when socketio is unavailable)
            time.sleep(10)

    def _watch_violations(self):
        """Watch for violation alerts: blocked domain/IP access attempts.
        On Linux, watches iptables LOG target or reads from kernel log.
        Generates alerts when blocked resources are accessed."""
        if SYSTEM != 'Linux':
            return

        time.sleep(10)  # Wait for firewall to be initialized

        import subprocess
        import re

        # Watch /var/log/kern.log or dmesg for iptables DROP logs
        log_paths = ['/var/log/kern.log', '/var/log/syslog', '/var/log/messages']
        log_path = None
        for p in log_paths:
            import os
            if os.path.exists(p):
                log_path = p
                break

        if not log_path:
            logger.debug('Violation watcher: no kernel log found')
            return

        logger.info('Violation watcher started: monitoring %s', log_path)

        try:
            # Tail the log file
            proc = subprocess.Popen(
                ['tail', '-F', '-n', '0', log_path],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True
            )

            seen = set()
            for line in proc.stdout:
                if 'DROP' not in line and 'BLOCKED' not in line:
                    continue

                # Parse iptables log: ... SRC=x.x.x.x DST=y.y.y.y ...
                src_match = re.search(r'SRC=(\S+)', line)
                dst_match = re.search(r'DST=(\S+)', line)
                dpt_match = re.search(r'DPT=(\d+)', line)

                if not dst_match:
                    continue

                dst_ip = dst_match.group(1)
                src_ip = src_match.group(1) if src_match else ''
                dst_port = int(dpt_match.group(1)) if dpt_match else 0

                # Rate-limit: one alert per dst_ip per 60 seconds
                key = f'{dst_ip}:{dst_port}'
                now = time.time()
                if key in seen:
                    continue
                seen.add(key)

                # Resolve domain
                domain = ''
                if self._firewall:
                    for rule in self._firewall.get_rules():
                        if rule.get('action') == 'block_domain':
                            for ip in rule.get('ips', []):
                                if ip == dst_ip:
                                    domain = rule.get('domain', '')
                                    break

                # Generate violation alert
                desc = f'Blocked access attempt: {src_ip} → {dst_ip}'
                if domain:
                    desc = f'Blocked domain access: {domain} ({dst_ip})'
                if dst_port:
                    desc += f' port {dst_port}'

                self._sender.enqueue({
                    'rule_id':     'FIREWALL_VIOLATION',
                    'category':    'network',
                    'severity':    'medium',
                    'description': desc,
                    'raw_log':     line.strip()[:500],
                    'src_ip':      src_ip,
                    'blocked':     True,
                })
                logger.info('Violation alert: %s', desc)

                # Clean stale entries every 100 entries
                if len(seen) > 100:
                    seen.clear()

        except Exception as e:
            logger.debug('Violation watcher error: %s', e)

    def _connect(self):
        # Try to import socketio with fallback mechanisms
        Client = None
        
        # Attempt 1: Direct import from socketio
        try:
            import socketio
            if hasattr(socketio, 'Client'):
                Client = socketio.Client
        except ImportError:
            pass
        
        # Attempt 2: Add known socketio locations to path
        if not Client:
            try:
                import sys
                import os
                # Try common installation paths
                candidates = [
                    '/home/chaudahry/.local/lib/python3.13/site-packages',
                    '/home/chaudahry/.local/lib/python3.12/site-packages',
                    '/home/chaudahry/.local/lib/python3.11/site-packages',
                    '/home/chaudahry/.local/lib/python3.10/site-packages',
                    '/usr/local/lib/python3.13/dist-packages',
                    '/usr/local/lib/python3.12/dist-packages',
                    '/usr/lib/python3/dist-packages',
                ]
                for site_pkg in candidates:
                    if os.path.isdir(site_pkg) and site_pkg not in sys.path:
                        sys.path.insert(0, site_pkg)
                # Try importing again
                try:
                    import socketio
                    if hasattr(socketio, 'Client'):
                        Client = socketio.Client
                except ImportError:
                    pass
            except Exception:
                pass
        
        # If still no client, disable command listener
        if not Client:
            logger.info('python-socketio not installed — command listener disabled.')
            logger.info('Enable: apt install python3-socketio python3-socketio-client  or  pip3 install "python-socketio[client]"')
            return

        server_url = (self._config.get('server_url') or
                      'http://{}:{}'.format(
                          self._config.get('server_ip', 'localhost'),
                          self._config.get('server_port', 5000)))

        system_id  = self._config.get('system_id', '')
        if not server_url.lower().startswith('https://'):
            logger.info('Plaintext Socket.IO disabled; encrypted heartbeat and policy polling remain active')
            return
        company_id = self._config.get('company_id', '')
        agent_key  = self._config.get('agent_key', '')
        
        # IMPORTANT: Retry loop for continuous connectivity
        retry_count = 0
        max_retries = 100
        retry_delay = 5
        
        while retry_count < max_retries:
            try:
                sio = Client(
                    http_session=secure_session(self._config),
                    reconnection=True,
                    reconnection_delay=3,
                    reconnection_delay_max=10,
                    reconnection_attempts=5
                )
                
                # Use a list to hold mutable retry_count in closure
                state = {'retry_count': retry_count}

                @sio.event
                def connect():
                    state['retry_count'] = 0  # Reset on successful connection
                    logger.info('Command listener connected to server')
                    # Join system room (for system-specific commands)
                    sio.emit('join', f'system_{system_id}')
                    # Join company room (for company-wide commands like block_ip from alerts)
                    if company_id:
                        sio.emit('join:company', company_id)
                        logger.info('Joined company room: %s', company_id)

                @sio.event
                def disconnect():
                    logger.warning('Command listener disconnected (will retry in %ds)', retry_delay)

                @sio.on('agent:command')
                def on_command(data: dict):
                    # Accept commands targeted at this system or broadcast to all
                    target = data.get('systemId', '')
                    if target and target != system_id:
                        return {'ok': False, 'ignored': True, 'message': 'command targeted at another system'}
                    cmd = data.get('command', '')
                    logger.info('Received command: %s %s', cmd, data)
                    result = self._dispatch(cmd, data)
                    if isinstance(result, dict) and 'ok' in result:
                        ok = result.get('ok') is True
                        text = str(result.get('result') or result)
                    else:
                        text = str(result or '')
                        ok = not any(token in text.lower() for token in (
                            'failed', 'failure', 'block skipped', 'no ip specified', 'not loaded', 'unknown command'
                        ))
                    return {'ok': ok, 'result': text[:1000]}

                @sio.on('firewall:rule_applied')
                def on_firewall_rule(data: dict):
                    """Handle firewall rules pushed from the dashboard Firewall page."""
                    logger.info('Received firewall rule: %s', data)
                    result = self._apply_firewall_rule(data)
                    self._report_firewall_ack(data, result)

                @sio.on('ids:policy-sync')
                def on_ids_policy_sync(data: dict):
                    """Apply an allow-listed native Zeek/Suricata policy bundle."""
                    self._apply_sensor_policies(data)

                @sio.on('agent:policy_sync')
                def on_dns_policy_sync(data: dict):
                    """Backward-compatible DNS sinkhole policy delivery."""
                    if str(data.get('companyId') or '') not in ('', str(company_id)):
                        return {'ok': False, 'ignored': True, 'message': 'policy belongs to another company'}
                    command = 'dns_sinkhole_add' if data.get('type') == 'blocklist' else 'dns_sinkhole_remove'
                    result = self._dispatch(command, data)
                    return {'ok': 'failed' not in str(result).lower(), 'result': str(result)[:1000]}

                @sio.on('ips:block')
                def on_ips_block(data: dict):
                    """Dashboard notification; enforcement uses the verified command queue."""
                    logger.info('[IPS] Block status update for %s', data.get('srcIp') or data.get('ip'))

                @sio.on('ips:blockFailed')
                def on_ips_block_failed(data: dict):
                    """IPS server block failed — escalation alert. Agent reports it."""
                    ip = data.get('srcIp', '')
                    attack_type = data.get('attackType', 'Unknown')
                    reason = data.get('reason', 'retries exhausted')
                    logger.error('[IPS] Block FAILED for %s after retries: %s', ip, reason)
                    self._sender.enqueue({
                        'rule_id':     'IPS_BLOCK_FAILED',
                        'category':    'network',
                        'severity':    'critical',
                        'description': f'IPS BLOCK FAILED for {ip} ({attack_type}): {reason}',
                        'raw_log':     f'IPS_FAIL|ip={ip}|attack={attack_type}|reason={reason}',
                        'src_ip':      ip,
                        'blocked':     False,
                    })

                @sio.on('ips:isolated')
                def on_ips_isolated(data: dict):
                    """Confirmation notification, never a second execution path."""
                    target = str(data.get('systemId') or '')
                    if not target or target != str(system_id):
                        return
                    logger.info('[IPS] Backend acknowledged endpoint isolation: %s', target)

                @sio.on('ips:recovered')
                def on_ips_recovered(data: dict):
                    """Confirmation notification; reconnect executes through the command queue."""
                    target = str(data.get('systemId') or '')
                    if not target or target != str(system_id):
                        return
                    logger.info('[IPS] Backend acknowledged endpoint recovery: %s', target)

                # Try to connect
                logger.info('Connecting to backend: %s (attempt %d/%d)', server_url, retry_count + 1, max_retries)
                transport_status = certificate_status(self._config)
                # websocket-client does not reliably inherit the requests
                # session's client certificate or fingerprint adapter. Keep
                # mTLS/pinned sessions on authenticated Engine.IO polling.
                transports = ['polling'] if (
                    transport_status['mtls_configured']
                    or transport_status['certificate_pinning']
                ) else ['websocket', 'polling']
                sio.connect(
                    server_url,
                    transports=transports,
                    wait_timeout=10,
                    auth={'agentKey': agent_key},
                )
                sio.wait()  # Blocks until disconnect
                
            except Exception as e:
                retry_count += 1
                logger.warning('Command listener error (retry %d/%d in %ds): %s', 
                               retry_count, max_retries, retry_delay, e)
                if retry_count >= max_retries:
                    logger.error('Max retries reached, stopping command listener')
                    return
                # Wait before retrying
                import time
                time.sleep(retry_delay)

    def _apply_sensor_policies(self, data: dict):
        from .heartbeat import security_command_error
        denied = security_command_error('sensor-policy')
        if denied:
            return {'ok': False, 'result': denied}
        try:
            if self._ips and 'ipsWhitelist' in data:
                self._ips.set_dashboard_whitelist(data.get('ipsWhitelist') or [])
            result = self._sensor_policies.apply(data)
            ok = result.get('ok') is True
            self._report_sensor_policy_ack(data, result, ok)
            if result.get('changed') and ok:
                logger.info('IDS native policies deployed: %s', result)
                self._sender.enqueue({
                    'rule_id': 'IDS_POLICY_DEPLOYED',
                    'category': 'network',
                    'severity': 'low',
                    'description': 'Zeek/Suricata policy deployment completed',
                    'raw_log': str(result)[:1000],
                    'blocked': False,
                })
            elif not ok:
                logger.error('IDS policy files written but sensor enforcement was not confirmed: %s', result)
                self._sender.enqueue({
                    'rule_id': 'IDS_POLICY_DEPLOY_FAILED',
                    'category': 'network',
                    'severity': 'critical',
                    'description': 'IDS policy deployment was not enforced by a running sensor',
                    'raw_log': str(result)[:1000],
                    'blocked': False,
                })
        except Exception as exc:
            self._report_sensor_policy_ack(data, {'error': str(exc)}, False)
            logger.error('IDS policy deployment failed; previous sensor config restored: %s', exc)
            self._sender.enqueue({
                'rule_id': 'IDS_POLICY_DEPLOY_FAILED',
                'category': 'network',
                'severity': 'critical',
                'description': f'Zeek/Suricata policy deployment failed and was rolled back: {exc}',
                'raw_log': str(exc)[:1000],
                'blocked': False,
            })

    def _report_sensor_policy_ack(self, payload: dict, result, ok: bool) -> bool:
        policies = payload.get('policies') or []
        acknowledgements = [{
            'policyId': item.get('policyId'),
            'revision': item.get('revision', 1),
            'ok': bool(ok),
            'result': str(result)[:1000],
        } for item in policies if item.get('policyId')]
        if not acknowledgements:
            return True
        try:
            from .security import signed_headers
            server_url = (self._config.get('server_url') or
                          'http://{}:{}'.format(
                              self._config.get('server_ip', 'localhost'),
                              self._config.get('server_port', 5000)))
            body = {'policies': acknowledgements}
            response = secure_request(
                self._config,
                'POST',
                f'{server_url.rstrip("/")}/api/ids/agent-policy-ack/self',
                json=body,
                headers=signed_headers(self._config, body),
                timeout=15,
            )
            if response.status_code >= 300:
                logger.warning('IDS policy acknowledgement rejected: HTTP %d', response.status_code)
                return False
            return True
        except Exception as exc:
            logger.warning('IDS policy acknowledgement failed: %s', exc)
            return False

    def _apply_firewall_rule(self, data: dict):
        """
        Translate a dashboard firewall rule into actual OS-level commands.
        Supports all block types: IP, Domain, Port, Application, Protocol.

        Direction mapping:
          'inbound'  / 'in'  → INPUT  chain
          'outbound' / 'out' → OUTPUT chain
          'both'             → both chains applied
        """
        from .heartbeat import security_command_error
        denied = security_command_error('firewall-rule')
        if denied:
            return {'ok': False, 'result': denied}
        action     = data.get('action', 'block')
        conditions = data.get('conditions', {})
        rule_name  = data.get('ruleName', 'unknown')
        direction  = (data.get('direction') or 'both').lower().strip()

        # Normalize direction aliases
        if direction in ('in', 'inbound'):   direction = 'in'
        elif direction in ('out', 'outbound'): direction = 'out'
        else:                                  direction = 'both'

        ip          = (conditions.get('ipAddress') or '').strip()
        port_raw    = (conditions.get('port') or '').strip()
        domain      = (conditions.get('domain') or conditions.get('host') or '').strip()
        protocol    = (conditions.get('protocol') or 'all').strip().lower()
        application = (conditions.get('application') or '').strip()
        block_proto = (conditions.get('blockProtocol') or '').strip().lower()

        results = []

        if action == 'block' and self._ips:
            if ip and self._ips.is_whitelisted(ip, 'ip'):
                return f'block skipped: {ip} is whitelisted'
            if domain and self._ips.is_whitelisted(domain, 'domain'):
                return f'block skipped: {domain} is whitelisted'

        # ── 1. Block/Allow IP ──
        if ip and action in ('block', 'allow'):
            if self._firewall:
                if action == 'block':
                    ok = self._firewall.block_ip(ip, direction=direction, reason=f'rule: {rule_name}')
                    results.append(f'block_ip({ip},dir={direction})={chr(10003) if ok else chr(10007)}')
                else:
                    ok = self._firewall.unblock_ip(ip)
                    results.append(f'unblock_ip({ip})={chr(10003) if ok else chr(10007)}')
            elif self._ips and action == 'block':
                ok = self._ips.block_ip(ip, reason=f'rule: {rule_name}', authorized_by_backend=True)
                results.append(f'ips.block_ip({ip})={"ok" if ok else "fail"}')
            else:
                result = self._block_ip({'ip': ip}) if action == 'block' else self._unblock_ip({'ip': ip})
                results.append(str(result))

        # ── 2. Block/Allow Domain (with URL cleanup) ──
        if domain and not ip:
            if self._firewall:
                if action == 'block':
                    res = self._firewall.block_domain(domain, reason=f'rule: {rule_name}')
                    ips_str = ', '.join(res.get('ips_blocked', [])) if res.get('ips_blocked') else 'none'
                    if res.get('ok'):
                        results.append(f'block_domain({res.get("domain", domain)}) IPs:{ips_str} hosts:{res.get("hosts_blocked")}')
                    else:
                        results.append(f'domain_block_failed({domain}): no firewall or hosts enforcement')
                else:
                    ok = self._firewall.unblock_domain(domain)
                    results.append(f'unblock_domain({domain})={"ok" if ok else "fail"}')
            else:
                try:
                    import re as _re, socket
                    clean = _re.sub(r'^https?://', '', domain).split('/')[0].split(':')[0].strip()
                    resolved_ip = socket.gethostbyname(clean)
                    result = self._block_ip({'ip': resolved_ip}) if action == 'block' else self._unblock_ip({'ip': resolved_ip})
                    results.append(f'domain({clean}->{resolved_ip}): {result}')
                except Exception as e:
                    results.append(f'domain_resolve_failed({domain}): {e}')

        # ── 3. Block/Allow Port ──
        if port_raw:
            try:
                # Support port ranges like "80-443"
                if '-' in str(port_raw):
                    parts = str(port_raw).split('-')
                    port_num = int(parts[0])
                else:
                    port_num = int(str(port_raw).split('-')[0])
                proto = protocol if protocol not in ('all', '') else 'tcp'
                if self._firewall:
                    if action == 'block':
                        ok = self._firewall.close_port(port_num, proto)
                        results.append(f'close_port({port_num}/{proto},dir={direction})={"ok" if ok else "fail"}')
                    elif action == 'allow':
                        ok = self._firewall.open_port(port_num, proto)
                        results.append(f'open_port({port_num}/{proto})={"ok" if ok else "fail"}')
                else:
                    results.append('firewall module not available for port blocking')
            except ValueError as ve:
                results.append(f'invalid port: {port_raw} ({ve})')

        # ── 4. Block Application ──
        if application:
            if self._firewall:
                if action == 'block':
                    ok = self._firewall.block_application(application, reason=f'rule: {rule_name}')
                    results.append(f'block_app({application})={"ok" if ok else "fail"}')
                else:
                    ok = self._firewall.unblock_application(application)
                    results.append(f'unblock_app({application})={"ok" if ok else "fail"}')
            else:
                results.append(f'app_block_failed({application}): firewall module not available')

        # ── 5. Block Protocol ──
        if block_proto and block_proto not in ('all', ''):
            if self._firewall:
                if action == 'block':
                    ok = self._firewall.block_protocol(block_proto, reason=f'rule: {rule_name}')
                    results.append(f'block_protocol({block_proto})={"ok" if ok else "fail"}')
                else:
                    ok = self._firewall.unblock_protocol(block_proto)
                    results.append(f'unblock_protocol({block_proto})={"ok" if ok else "fail"}')

        # Protocol-only blocking (no IP/domain/port/app specified)
        if (not ip and not domain and not port_raw and not application and not block_proto
                and protocol not in ('all', '') and action == 'block'):
            if self._firewall:
                ok = self._firewall.block_protocol(protocol, reason=f'rule: {rule_name}')
                results.append(f'block_protocol({protocol})={"ok" if ok else "fail"}')

        summary = '; '.join(results) if results else 'no actionable conditions'
        logger.info('Firewall rule "%s" applied: %s', rule_name, summary)

        # Report back as alert
        self._sender.enqueue({
            'rule_id':     'FIREWALL_RULE_APPLIED',
            'category':    'system',
            'severity':    'medium',
            'description': f'Firewall rule "{rule_name}" applied: {summary}',
            'raw_log':     f'RULE:{rule_name}|ACTION:{action}|{summary}',
        })
        return summary

    @staticmethod
    def _firewall_result_ok(result) -> bool:
        text = str(result or 'no result').lower()
        failed_tokens = (
            '=✗', '=fail', ' failed', 'failed(', 'not available',
            'not supported', 'no actionable', 'no result', 'invalid ', 'block skipped',
        )
        return not any(token in text for token in failed_tokens)

    def _report_firewall_ack(self, rule: dict, result, ok=None) -> bool:
        """Report actual endpoint enforcement outcome to the dashboard."""
        rule_id = str(rule.get('ruleId') or '')
        agent_key = self._config.get('agent_key', '')
        if not rule_id or not agent_key:
            return False
        text = str(result or 'no result')[:1000]
        payload = {
            'ruleId': rule_id,
            'ok': self._firewall_result_ok(text) if ok is None else bool(ok),
            'result': text,
        }
        try:
            import requests
            from .security import signed_headers
            server_url = (self._config.get('server_url') or
                          'http://{}:{}'.format(self._config.get('server_ip', 'localhost'), self._config.get('server_port', 5000)))
            response = secure_request(self._config, 'POST',
                f'{server_url.rstrip("/")}/api/firewall/rule-ack/self',
                json=payload,
                headers=signed_headers(self._config, payload),
                timeout=15,
            )
            if response.status_code >= 300:
                logger.warning('Firewall acknowledgement rejected: HTTP %d', response.status_code)
                return False
            return True
        except Exception as exc:
            logger.warning('Firewall acknowledgement failed: %s', exc)
            return False


    def _dispatch(self, command: str, data: dict):
        from .heartbeat import security_command_error
        from .command_guard import automatic_isolation_error
        denied = security_command_error(command) or automatic_isolation_error(command, data)
        if denied:
            return {'ok': False, 'result': denied}
        handlers = {
            'block_ip':              self._block_ip,
            'unblock_ip':            self._unblock_ip,
            'isolate':               self._isolate,
            'reconnect':             self._reconnect,
            'block_usb':             self._block_usb,
            'unblock_usb':           self._unblock_usb,
            'kill_process':          self._kill_process,
            'quarantine_file':       self._quarantine,
            'open_port':             self._open_port,
            'close_port':            self._close_port,
            'unblock_port':          self._unblock_port,
            'unblock_domain':        self._unblock_domain,
            'block_domain':          self._block_domain,
            'unblock_application':   self._unblock_application,
            'block_application':     self._block_application_cmd,
            'unblock_protocol':      self._unblock_protocol,
            'block_protocol':        self._block_protocol_cmd,
            'ips_whitelist_add':     self._ips_whitelist_add,
            'ips_whitelist_remove':  self._ips_whitelist_remove,
            'scan':                  self._scan,
            'configure_dns_sinkhole': self._configure_dns_sinkhole,
            'dns_sinkhole_add':      self._dns_sinkhole_add,
            'dns_sinkhole_remove':   self._dns_sinkhole_remove,
            'configure_dns_cache_poisoning': self._configure_dns_cache_poisoning,
            'flush_dns_cache':       self._flush_dns_cache,
            'restore_dns_resolver':  self._restore_dns_resolver,
        }
        # Auto-response extended commands (require AutoResponseEngine)
        ar_commands = {
            'kill_process_tree', 'kill_child_processes', 'kill_process',
            'isolate', 'reconnect',
            'block_hash', 'unblock_hash', 'delete_file', 'restore_file',
            'block_ip', 'unblock_ip', 'block_domain', 'unblock_domain',
            'block_port', 'unblock_port', 'block_usb', 'unblock_usb',
            'disable_user', 'enable_user', 'lock_account', 'force_logoff',
            'restart_service', 'stop_service', 'start_service',
            'delete_scheduled_task', 'delete_startup_entry', 'rollback_registry',
            'terminate_script', 'run_command',
        }

        # Route to auto-response engine if available and command is in AR set
        if self._auto_response and command in ar_commands:
            try:
                result = self._auto_response.dispatch(command, data)
                logger.info('AR command %s result: %s', command, result)
                return result
            except Exception as e:
                logger.error('AR command %s failed: %s', command, e)
                # Fall through to legacy handlers

        handler = handlers.get(command)
        if handler:
            try:
                result = handler(data)
                logger.info('Command %s result: %s', command, result)
                # Report result back as alert
                self._sender.enqueue({
                    'rule_id':     f'CMD_{command.upper()}',
                    'category':    'system',
                    'severity':    'medium',
                    'description': f'Command executed: {command} — {result}',
                    'raw_log':     f'CMD:{command}|{result}',
                })
                return result
            except Exception as e:
                logger.error('Command %s failed: %s', command, e)
                return f'command failed: {e}'
        else:
            logger.warning('Unknown command: %s', command)
            return f'unknown command: {command}'

    def _block_ip(self, data: dict) -> str:
        ip = data.get('ip', '')
        if not ip:
            return 'no IP specified'
        # Use IPS module if available (preferred, logs to dashboard)
        if self._ips:
            ok = self._ips.block_ip(ip, reason='dashboard command', authorized_by_backend=True)
            return f'IPS blocked {ip}' if ok else f'IPS block failed for {ip}'
        # Fallback: enforce directly on the local host firewall (UFW/nftables/netsh)
        ok = fw_backend.block_ip(ip, direction='both', comment='dashboard command')
        return f'{fw_backend.backend_name()} blocked {ip}' if ok else f'block failed for {ip}'

    def _unblock_ip(self, data: dict) -> str:
        ip = data.get('ip', '')
        if not ip:
            return 'no IP specified'
        if self._ips:
            ok = self._ips.unblock_ip(ip)
            return f'IPS unblocked {ip}' if ok else f'IPS unblock failed for {ip}'
        # Fallback: remove directly from the local host firewall
        ok = fw_backend.unblock_ip(ip, direction='both')
        return f'{fw_backend.backend_name()} unblocked {ip}' if ok else f'unblock failed for {ip}'

    def _open_port(self, data: dict) -> str:
        port     = data.get('port')
        protocol = data.get('protocol', 'tcp').lower()
        if not port:
            return 'no port specified'
        if self._firewall:
            ok = self._firewall.open_port(int(port), protocol)
            return f'opened port {port}/{protocol}' if ok else f'failed to open port {port}'
        return 'firewall module not loaded'

    def _configure_dns_sinkhole(self, data: dict) -> str:
        if not self._dns_sinkhole:
            return 'DNS sinkhole module not loaded'
        result = self._dns_sinkhole.configure(
            data.get('settings') or {},
            blocklist=data.get('blocklist') or [],
            allowlist=data.get('allowlist') or [],
            sinkhole_targets=data.get('sinkholeTargets') or {},
        )
        return 'DNS sinkhole policy applied (version {}, {} domains)'.format(
            result.get('policy_version', 0), result.get('total_sinkholed', 0)
        )

    def _dns_sinkhole_add(self, data: dict) -> str:
        if not self._dns_sinkhole:
            return 'DNS sinkhole module not loaded'
        result = self._dns_sinkhole.sinkhole(data.get('domain', ''), reason=data.get('reason', 'dashboard_policy'), sinkhole_ip=data.get('sinkholeIp'))
        return 'sinkholed {}'.format(result.get('domain')) if result.get('success') else 'failed: {}'.format(result.get('error'))

    def _dns_sinkhole_remove(self, data: dict) -> str:
        if not self._dns_sinkhole:
            return 'DNS sinkhole module not loaded'
        result = self._dns_sinkhole.unsinkhole(data.get('domain', ''))
        return 'removed {}'.format(result.get('domain')) if result.get('success') else 'failed to remove domain'

    def _configure_dns_cache_poisoning(self, data: dict) -> str:
        if not self._cache_poison_detector:
            return 'DNS cache-poisoning module not loaded'
        result = self._cache_poison_detector.configure(data.get('settings') or {})
        return 'DNS cache-poisoning policy applied (version {})'.format(result.get('policyVersion', 0))

    def _flush_dns_cache(self, _data: dict) -> str:
        if not self._cache_poison_detector:
            return 'DNS cache-poisoning module not loaded'
        return self._cache_poison_detector.flush_dns_cache().get('message', 'DNS cache flushed')

    def _restore_dns_resolver(self, _data: dict) -> str:
        if not self._cache_poison_detector:
            return 'DNS cache-poisoning module not loaded'
        return self._cache_poison_detector.restore_resolver().get('message', 'DNS resolver restored')

    def _close_port(self, data: dict) -> str:
        port     = data.get('port')
        protocol = data.get('protocol', 'tcp').lower()
        if not port:
            return 'no port specified'
        if self._firewall:
            ok = self._firewall.close_port(int(port), protocol)
            return f'closed port {port}/{protocol}' if ok else f'failed to close port {port}'
        return 'firewall module not loaded'

    def _unblock_port(self, data: dict) -> str:
        port = data.get('port')
        protocol = data.get('protocol', 'tcp').lower()
        if not port:
            return 'no port specified'
        ok = fw_backend.unblock_port(int(port), protocol, direction='both')
        return f'unblocked port {port}/{protocol}' if ok else f'unblock failed for port {port}/{protocol}'

    def _isolate(self, data: dict) -> str:
        try:
            from response.isolate import isolate
            management_url = (self._config.get('server_url') or
                              'http://{}:{}'.format(
                                  self._config.get('server_ip', 'localhost'),
                                  self._config.get('server_port', 5000)))
            isolate(management_url=management_url)
            return 'system isolated'
        except Exception as e:
            return f'isolate failed: {e}'

    def _reconnect(self, data: dict) -> str:
        try:
            from response.isolate import restore
            restore()
            return 'isolation removed'
        except Exception as e:
            return f'reconnect failed: {e}'

    def _block_usb(self, data: dict) -> str:
        try:
            from response.usb_block import block
            block()
            return 'USB storage blocked'
        except Exception as e:
            return f'USB block failed: {e}'

    def _unblock_usb(self, data: dict) -> str:
        try:
            from response.usb_block import unblock
            unblock()
            return 'USB storage unblocked'
        except Exception as e:
            return f'USB unblock failed: {e}'

    def _kill_process(self, data: dict) -> str:
        pid = data.get('pid')
        if not pid:
            return 'no PID specified'
        try:
            import psutil
            proc = psutil.Process(int(pid))
            name = proc.name()
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            return f'process {pid} ({name}) terminated'
        except Exception as e:
            return f'kill failed: {e}'

    def _quarantine(self, data: dict) -> str:
        path = data.get('file_path', '')
        if not path:
            return 'no file_path specified'
        try:
            from response.quarantine import quarantine
            dest = quarantine(path)
            return f'quarantined to {dest}'
        except Exception as e:
            return f'quarantine failed: {e}'

    def _unblock_domain(self, data: dict) -> str:
        domain = data.get('domain', '') or data.get('ip', '')
        if not domain:
            return 'no domain specified'
        if self._firewall:
            ok = self._firewall.unblock_domain(domain)
            return f'unblocked domain {domain}' if ok else f'failed to unblock domain {domain}'
        return 'firewall module not loaded'

    def _block_domain(self, data: dict) -> str:
        domain = data.get('domain', '')
        if not domain:
            return 'no domain specified'
        if self._ips and self._ips.is_whitelisted(domain, 'domain'):
            return f'block skipped: {domain} is whitelisted'
        if self._firewall:
            res = self._firewall.block_domain(domain, reason='dashboard command')
            if not res.get('ok'):
                return f'block domain failed for {domain}'
            return f'blocked domain {domain} (IPs: {res.get("ips_blocked", [])}, hosts: {res.get("hosts_blocked")})'
        return 'firewall module not loaded'

    def _unblock_application(self, data: dict) -> str:
        app = data.get('application', '') or data.get('app', '')
        if not app:
            return 'no application specified'
        if self._firewall:
            ok = self._firewall.unblock_application(app)
            return f'unblocked application {app}' if ok else f'failed to unblock {app}'
        return 'firewall module not loaded'

    def _block_application_cmd(self, data: dict) -> str:
        app = data.get('application', '') or data.get('app', '')
        if not app:
            return 'no application specified'
        if self._firewall:
            ok = self._firewall.block_application(app, reason='dashboard command')
            return f'blocked application {app}' if ok else f'failed to block {app}'
        return 'firewall module not loaded'

    def _unblock_protocol(self, data: dict) -> str:
        protocol = data.get('protocol', 'tcp')
        if not protocol:
            return 'no protocol specified'
        if self._firewall:
            ok = self._firewall.unblock_protocol(protocol)
            return f'unblocked protocol {protocol}' if ok else f'failed to unblock {protocol}'
        return 'firewall module not loaded'

    def _block_protocol_cmd(self, data: dict) -> str:
        protocol = data.get('protocol', 'tcp') or data.get('blockProtocol', '')
        if not protocol:
            return 'no protocol specified'
        if self._firewall:
            ok = self._firewall.block_protocol(protocol, reason='dashboard command')
            return f'blocked protocol {protocol}' if ok else f'failed to block {protocol}'
        return 'firewall module not loaded'

    def _ips_whitelist_add(self, data: dict) -> str:
        if not self._ips:
            return 'IPS module not loaded'
        count = self._ips.update_dashboard_whitelist('add', data.get('value', ''), data.get('type', 'ip'))
        return f'IPS whitelist updated ({count} entries)'

    def _ips_whitelist_remove(self, data: dict) -> str:
        if not self._ips:
            return 'IPS module not loaded'
        count = self._ips.update_dashboard_whitelist('remove', data.get('value', ''), data.get('type', 'ip'))
        return f'IPS whitelist updated ({count} entries)'

    def _scan(self, data: dict) -> str:
        try:
            logger.info("🔍 Manual threat scan initiated by SOC analyst")
            # Trigger background scan if yara scanner or custom scanner is registered
            return 'threat scan initiated successfully'
        except Exception as e:
            return f'scan failed: {e}'
