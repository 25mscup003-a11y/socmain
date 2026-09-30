"""
Automated Response Engine — Agent-side response executor.
Receives playbook actions from the SOC backend and executes them locally.

Supported actions:
  - kill_process / kill_process_tree
  - isolate / reconnect
  - quarantine_file / restore_file / delete_file
  - block_ip / unblock_ip
  - block_domain / unblock_domain
  - block_usb / unblock_usb
  - disable_user / enable_user
  - run_command (restricted)
  - restart_service / stop_service / start_service
  - block_hash (log + prevent via watcher)
"""

import os
import re
import sys
import time
import signal
import logging
import platform
import threading
import subprocess
import hmac
import hashlib
from pathlib import Path
from datetime import datetime, timezone

from .security import canonicalize

logger  = logging.getLogger('soc-agent.auto-response')
SYSTEM  = platform.system()

# ── Blocked hash watchlist (SHA256 → proc name) ──────────────────────────────
_BLOCKED_HASHES: dict = {}
_HASH_LOCK = threading.Lock()


def _hash_file(path: str) -> str:
    """SHA256 hash of a file."""
    import hashlib
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ''


class AutoResponseEngine:
    """
    Executes automated response actions dispatched by the SOC backend
    (via Socket.IO agent:command events or polling).
    """

    def __init__(self, sender, config, ips=None, firewall=None):
        self._sender   = sender
        self._config   = config
        self._ips      = ips
        self._firewall = firewall
        self._audit    = []          # in-memory audit trail
        self._lock     = threading.Lock()
        self._executed_command_ids = set()

        # Hash block watcher thread
        self._hash_thread = threading.Thread(
            target=self._hash_watcher, daemon=True, name='hash-watcher'
        )

    def start(self):
        self._hash_thread.start()
        logger.info('Auto-response engine started')

    # ── Action dispatcher ─────────────────────────────────────────────────────
    def dispatch(self, action: str, params: dict) -> dict:
        """
        Execute a single response action.
        Returns {'ok': bool, 'result': str, 'timestamp': iso}.
        """
        params = params or {}
        started = time.monotonic()
        command_id = str(params.get('commandId') or '')
        response_id = str(params.get('responseId') or '')
        timestamp = datetime.now(timezone.utc).isoformat()
        validation_error = self._validate_command(action, params) if command_id else ''
        if validation_error:
            result = {'ok': False, 'result': validation_error, 'timestamp': timestamp, 'durationMs': 0}
            self._audit_log(action, params, result)
            self._report_action(action, params, result)
            return result
        with self._lock:
            if command_id and command_id in self._executed_command_ids:
                result = {'ok': True, 'result': 'Duplicate command ignored', 'timestamp': timestamp, 'durationMs': 0}
                self._report_action(action, params, result)
                return result
            if command_id:
                self._executed_command_ids.add(command_id)
                if len(self._executed_command_ids) > 5000:
                    self._executed_command_ids = set(list(self._executed_command_ids)[-2500:])
        if response_id and command_id and hasattr(self._sender, 'report_response_status'):
            self._sender.report_response_status(response_id, command_id, 'acknowledged')
            self._sender.report_response_status(response_id, command_id, 'executing')

        handlers = {
            'kill_process':         self._kill_process,
            'kill_process_tree':    self._kill_process_tree,
            'kill_child_processes': self._kill_children,
            'isolate':              self._isolate,
            'isolate_agent':        self._isolate,
            'quarantine_endpoint':  self._isolate,
            'reconnect':            self._reconnect,
            'release_host':         self._reconnect,
            'quarantine_file':      self._quarantine_file,
            'restore_file':         self._restore_file,
            'delete_file':          self._delete_file,
            'block_hash':           self._block_hash,
            'unblock_hash':         self._unblock_hash,
            'block_ip':             self._block_ip,
            'unblock_ip':           self._unblock_ip,
            'block_domain':         self._block_domain,
            'unblock_domain':       self._unblock_domain,
            'block_usb':            self._block_usb,
            'unblock_usb':          self._unblock_usb,
            'disable_user':         self._disable_user,
            'enable_user':          self._enable_user,
            'lock_account':         self._lock_account,
            'force_logoff':         self._force_logoff,
            'restart_service':      self._restart_service,
            'stop_service':         self._stop_service,
            'start_service':        self._start_service,
            'block_port':           self._block_port,
            'close_port':           self._block_port,
            'unblock_port':         self._unblock_port,
            'block_application':    self._block_application,
            'unblock_application':  self._unblock_application,
            'block_protocol':       self._block_protocol,
            'unblock_protocol':     self._unblock_protocol,
            'ips_whitelist_add':    self._ips_whitelist_add,
            'ips_whitelist_remove': self._ips_whitelist_remove,
            'terminate_script':     self._terminate_script,
            'delete_scheduled_task':self._delete_scheduled_task,
            'delete_startup_entry': self._delete_startup_entry,
            'rollback_registry':    self._rollback_registry,
            'run_command':          self._run_safe_command,
        }

        handler = handlers.get(action)
        if not handler:
            result = {'ok': False, 'result': f'Unknown action: {action}', 'timestamp': timestamp}
        else:
            try:
                msg = handler(params)
                result = {'ok': True, 'result': msg, 'timestamp': timestamp}
                logger.info('[AutoResponse] %s → %s', action, msg)
            except Exception as e:
                result = {'ok': False, 'result': f'{action} failed: {e}', 'timestamp': timestamp}
                logger.error('[AutoResponse] %s FAILED: %s', action, e)

        result['durationMs'] = int((time.monotonic() - started) * 1000)

        # Audit log
        self._audit_log(action, params, result)
        # Report back to SOC
        self._report_action(action, params, result)
        return result

    def _validate_command(self, action: str, payload: dict) -> str:
        """Reject expired, tampered, or incorrectly-targeted backend command envelopes."""
        supported = {
            'kill_process', 'kill_process_tree', 'kill_child_processes',
            'isolate', 'isolate_agent', 'quarantine_endpoint', 'reconnect', 'release_host',
            'quarantine_file', 'restore_file', 'delete_file', 'block_hash', 'unblock_hash',
            'block_ip', 'unblock_ip', 'block_domain', 'unblock_domain', 'block_port', 'close_port', 'unblock_port',
            'block_application', 'unblock_application', 'block_protocol', 'unblock_protocol',
            'ips_whitelist_add', 'ips_whitelist_remove',
            'block_usb', 'unblock_usb', 'disable_user', 'enable_user', 'lock_account', 'force_logoff',
            'restart_service', 'stop_service', 'start_service', 'delete_scheduled_task',
            'delete_startup_entry', 'rollback_registry', 'terminate_script',
        }
        if action not in supported:
            return 'Unsupported signed response action'
        if payload.get('command') and str(payload.get('command')).lower() != str(action).lower():
            return 'Command action does not match envelope'
        try:
            expires = datetime.fromisoformat(str(payload.get('expiresAt', '')).replace('Z', '+00:00'))
            if expires <= datetime.now(timezone.utc):
                return 'Response command expired'
        except Exception:
            return 'Response command has an invalid expiration'
        signed = {
            'commandId': payload.get('commandId', ''), 'responseId': payload.get('responseId', ''),
            'tenantId': payload.get('tenantId', ''), 'agentId': payload.get('agentId', ''),
            'systemId': payload.get('systemId', ''), 'command': payload.get('command', action),
            'params': payload.get('params', {}), 'createdAt': payload.get('createdAt', ''),
            'expiresAt': payload.get('expiresAt', ''), 'retryCount': payload.get('retryCount', 0),
            'maxRetries': payload.get('maxRetries', 0), 'correlationId': payload.get('correlationId', ''),
        }
        expected = hmac.new(
            str(self._config.get('agent_key', '')).encode('utf-8'),
            canonicalize(signed).encode('utf-8'), hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, str(payload.get('signature', ''))):
            return 'Response command integrity validation failed'
        return ''

    def _audit_log(self, action: str, params: dict, result: dict):
        entry = {
            'timestamp': result.get('timestamp'),
            'action':    action,
            'params':    params,
            'ok':        result.get('ok'),
            'result':    result.get('result'),
        }
        with self._lock:
            self._audit.append(entry)
            if len(self._audit) > 1000:
                self._audit = self._audit[-500:]

    def _report_action(self, action: str, params: dict, result: dict):
        """Send action result back to SOC as an alert."""
        try:
            self._sender.enqueue({
                'rule_id':     f'AUTO_RESPONSE_{action.upper()}',
                'category':    'system',
                'severity':    'medium' if result.get('ok') else 'high',
                'description': f'Auto-response [{action}]: {result.get("result", "")[:200]}',
                'source':      'auto_response',
                'raw_log': (
                    f'ACTION:{action}|OK:{result.get("ok")}|'
                    f'PARAMS:{str(params)[:200]}|RESULT:{result.get("result","")[:200]}'
                ),
            })
        except Exception as e:
            logger.debug('Report action error: %s', e)
        try:
            response_id = params.get('responseId')
            command_id = params.get('commandId')
            if response_id and command_id and hasattr(self._sender, 'report_response_result'):
                self._sender.report_response_result(
                    str(response_id), str(command_id), bool(result.get('ok')),
                    str(result.get('result', '')), int(result.get('durationMs', 0) or 0),
                )
        except Exception as e:
            logger.debug('Report response result error: %s', e)

    # ── Process Actions ───────────────────────────────────────────────────────
    def _kill_process(self, params: dict) -> str:
        import psutil
        pid  = params.get('pid')
        name = params.get('name')

        targets = []
        if pid:
            try:
                targets.append(psutil.Process(int(pid)))
            except psutil.NoSuchProcess:
                pass
        elif name:
            targets = [p for p in psutil.process_iter(['pid', 'name'])
                       if name.lower() in (p.info.get('name') or '').lower()]

        if not targets:
            return f'No process found: pid={pid} name={name}'

        killed = []
        for proc in targets:
            try:
                proc_name = proc.name()
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                killed.append(f'{proc_name}({proc.pid})')
            except Exception as e:
                killed.append(f'failed:{e}')

        return f'Killed: {", ".join(killed)}'

    def _kill_process_tree(self, params: dict) -> str:
        import psutil
        pid = params.get('pid')
        if not pid:
            return 'No PID specified'

        try:
            parent = psutil.Process(int(pid))
            children = parent.children(recursive=True)
            all_procs = [parent] + children

            killed = []
            for proc in all_procs:
                try:
                    proc.kill()
                    killed.append(proc.pid)
                except Exception:
                    pass
            return f'Process tree killed: {killed}'
        except psutil.NoSuchProcess:
            return f'Process {pid} not found'

    def _kill_children(self, params: dict) -> str:
        import psutil
        pid = params.get('pid')
        if not pid:
            return 'No PID specified'
        try:
            parent = psutil.Process(int(pid))
            children = parent.children(recursive=True)
            killed = []
            for child in children:
                try:
                    child.kill()
                    killed.append(child.pid)
                except Exception:
                    pass
            return f'Children killed: {killed}'
        except psutil.NoSuchProcess:
            return f'Process {pid} not found'

    def _terminate_script(self, params: dict) -> str:
        """Kill a scripting interpreter process (PowerShell, Python, etc.)."""
        script_type = params.get('script_type', '').lower()
        names = {
            'powershell': ['powershell', 'powershell.exe'],
            'cmd':        ['cmd', 'cmd.exe'],
            'python':     ['python', 'python3', 'python.exe'],
            'bash':       ['bash', 'sh', 'zsh'],
            'wscript':    ['wscript', 'wscript.exe', 'cscript', 'cscript.exe'],
        }
        proc_names = names.get(script_type, [script_type])
        return self._kill_process({'name': proc_names[0] if proc_names else script_type})

    # ── Network Isolation ─────────────────────────────────────────────────────
    def _isolate(self, params: dict) -> str:
        try:
            from response.isolate import isolate
            mgmt_url = (self._config.get('server_url') or
                        'http://{}:{}'.format(
                            self._config.get('server_ip', 'localhost'),
                            self._config.get('server_port', 5000)))
            isolate(management_url=mgmt_url)
            return 'Endpoint isolated from network'
        except Exception as e:
            raise RuntimeError(f'Isolation failed: {e}') from e

    def _reconnect(self, params: dict) -> str:
        try:
            from response.isolate import restore
            restore()
            return 'Network connectivity restored'
        except Exception as e:
            raise RuntimeError(f'Reconnect failed: {e}') from e

    # ── File Actions ──────────────────────────────────────────────────────────
    def _quarantine_file(self, params: dict) -> str:
        path = params.get('file_path') or params.get('path', '')
        if not path:
            return 'No file_path specified'
        try:
            from response.quarantine import quarantine
            dest = quarantine(path)
            return f'File quarantined to {dest}'
        except Exception as e:
            return f'Quarantine failed: {e}'

    def _restore_file(self, params: dict) -> str:
        quarantine_path = params.get('quarantine_path', '')
        original_path   = params.get('original_path', '')
        if not quarantine_path:
            return 'No quarantine_path specified'
        try:
            import shutil
            if original_path:
                shutil.move(quarantine_path, original_path)
                return f'File restored to {original_path}'
            else:
                return f'Restored from {quarantine_path} (no original path specified)'
        except Exception as e:
            return f'Restore failed: {e}'

    def _delete_file(self, params: dict) -> str:
        path = params.get('file_path') or params.get('path', '')
        if not path:
            return 'No file_path specified'
        try:
            if os.path.isfile(path):
                os.remove(path)
                return f'File deleted: {path}'
            elif os.path.isdir(path):
                import shutil
                shutil.rmtree(path)
                return f'Directory deleted: {path}'
            else:
                return f'Path not found: {path}'
        except Exception as e:
            return f'Delete failed: {e}'

    # ── Hash Blocking ─────────────────────────────────────────────────────────
    def _block_hash(self, params: dict) -> str:
        hash_val = (params.get('hash') or params.get('sha256') or '').strip().lower()
        label    = params.get('label', 'manual block')
        if not hash_val:
            return 'No hash specified'
        with _HASH_LOCK:
            _BLOCKED_HASHES[hash_val] = label
        return f'Hash blocked: {hash_val[:16]}… ({label})'

    def _unblock_hash(self, params: dict) -> str:
        hash_val = (params.get('hash') or params.get('sha256') or '').strip().lower()
        with _HASH_LOCK:
            removed = _BLOCKED_HASHES.pop(hash_val, None)
        return f'Hash unblocked: {hash_val[:16]}…' if removed else f'Hash not in block list'

    def _hash_watcher(self):
        """Continuously monitor running processes against the blocked hash list."""
        try:
            import psutil
        except ImportError:
            return

        while True:
            time.sleep(10)
            with _HASH_LOCK:
                if not _BLOCKED_HASHES:
                    continue
                blocked_copy = dict(_BLOCKED_HASHES)

            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    exe = proc.info.get('exe') or ''
                    if not exe:
                        continue
                    h = _hash_file(exe)
                    if h and h in blocked_copy:
                        try:
                            proc.kill()
                            self._sender.enqueue({
                                'rule_id':     'AUTO_RESPONSE_HASH_KILLED',
                                'category':    'malware',
                                'severity':    'critical',
                                'description': f'Blocked hash process terminated: {proc.info["name"]}',
                                'source':      'auto_response',
                                'file_hash':   h,
                                'file_path':   exe,
                                'process_name': proc.info['name'],
                                'pid':         proc.info['pid'],
                                'raw_log':     f'HASH_KILL|hash={h}|exe={exe}|pid={proc.info["pid"]}',
                            })
                            logger.warning('[AutoResponse] Hash-blocked process killed: %s (hash=%s)',
                                           proc.info.get('name'), h[:16])
                        except Exception:
                            pass
            except Exception:
                pass

    # ── Network Actions ───────────────────────────────────────────────────────
    def _block_ip(self, params: dict) -> str:
        ip = params.get('ip', '')
        if not ip:
            raise RuntimeError('No IP specified')
        if self._ips:
            ok = self._ips.block_ip(ip, reason='auto-response')
            if not ok:
                raise RuntimeError(f'Block failed: {ip}')
            return f'IP blocked: {ip}'
        if self._firewall:
            ok = self._firewall.block_ip(ip, reason='auto-response')
            if not ok:
                raise RuntimeError(f'Block failed: {ip}')
            return f'IP blocked via firewall: {ip}'
        # Direct fallback
        from core import fw_backend
        ok = fw_backend.block_ip(ip, direction='both', comment='auto-response')
        if not ok:
            raise RuntimeError(f'Block failed: {ip}')
        return f'IP blocked: {ip}'

    def _unblock_ip(self, params: dict) -> str:
        ip = params.get('ip', '')
        if not ip:
            raise RuntimeError('No IP specified')
        if self._ips:
            ok = self._ips.unblock_ip(ip)
            if not ok:
                raise RuntimeError(f'Unblock failed: {ip}')
            return f'IP unblocked: {ip}'
        if self._firewall:
            ok = self._firewall.unblock_ip(ip)
            if not ok:
                raise RuntimeError(f'Unblock failed: {ip}')
            return f'IP unblocked: {ip}'
        from core import fw_backend
        ok = fw_backend.unblock_ip(ip, direction='both')
        if not ok:
            raise RuntimeError(f'Unblock failed: {ip}')
        return f'IP unblocked: {ip}'

    def _block_domain(self, params: dict) -> str:
        domain = params.get('domain', '')
        if not domain:
            raise RuntimeError('No domain specified')
        if self._ips and self._ips.is_whitelisted(domain, 'domain'):
            raise RuntimeError(f'Domain is whitelisted: {domain}')
        if self._firewall:
            res = self._firewall.block_domain(domain, reason='auto-response')
            if not res.get('ok'):
                raise RuntimeError(f'Domain block failed: {domain}')
            return f'Domain blocked: {domain} (IPs: {res.get("ips_blocked", [])})'
        raise RuntimeError('Firewall module not available')

    def _unblock_domain(self, params: dict) -> str:
        domain = params.get('domain', '')
        if not domain:
            return 'No domain specified'
        if self._firewall:
            ok = self._firewall.unblock_domain(domain)
            return f'Domain unblocked: {domain}' if ok else f'Unblock failed: {domain}'
        return 'Firewall module not available'

    def _block_port(self, params: dict) -> str:
        port     = params.get('port')
        protocol = params.get('protocol', 'tcp').lower()
        if not port:
            return 'No port specified'
        if self._firewall:
            ok = self._firewall.close_port(int(port), protocol)
            if not ok:
                raise RuntimeError(f'Port block failed: {port}/{protocol}')
            return f'Port {port}/{protocol} blocked'
        raise RuntimeError('Firewall module not available')

    def _unblock_port(self, params: dict) -> str:
        port     = params.get('port')
        protocol = params.get('protocol', 'tcp').lower()
        if not port:
            return 'No port specified'
        if self._firewall:
            ok = self._firewall.open_port(int(port), protocol)
            if not ok:
                raise RuntimeError(f'Port open failed: {port}/{protocol}')
            return f'Port {port}/{protocol} opened'
        raise RuntimeError('Firewall module not available')

    def _block_application(self, params: dict) -> str:
        application = params.get('application', '')
        if not application or not self._firewall:
            raise RuntimeError('Application or firewall module unavailable')
        if not self._firewall.block_application(application, reason='dashboard command'):
            raise RuntimeError(f'Application block failed: {application}')
        return f'Application blocked: {application}'

    def _unblock_application(self, params: dict) -> str:
        application = params.get('application', '')
        if not application or not self._firewall:
            raise RuntimeError('Application or firewall module unavailable')
        if not self._firewall.unblock_application(application):
            raise RuntimeError(f'Application unblock failed: {application}')
        return f'Application unblocked: {application}'

    def _block_protocol(self, params: dict) -> str:
        protocol = params.get('protocol', '')
        if not protocol or not self._firewall:
            raise RuntimeError('Protocol or firewall module unavailable')
        if not self._firewall.block_protocol(protocol, reason='dashboard command'):
            raise RuntimeError(f'Protocol block failed: {protocol}')
        return f'Protocol blocked: {protocol}'

    def _unblock_protocol(self, params: dict) -> str:
        protocol = params.get('protocol', '')
        if not protocol or not self._firewall:
            raise RuntimeError('Protocol or firewall module unavailable')
        if not self._firewall.unblock_protocol(protocol):
            raise RuntimeError(f'Protocol unblock failed: {protocol}')
        return f'Protocol unblocked: {protocol}'

    def _ips_whitelist_add(self, params: dict) -> str:
        if not self._ips:
            raise RuntimeError('IPS module not available')
        count = self._ips.update_dashboard_whitelist('add', params.get('value', ''), params.get('type', 'ip'))
        return f'IPS whitelist updated ({count} entries)'

    def _ips_whitelist_remove(self, params: dict) -> str:
        if not self._ips:
            raise RuntimeError('IPS module not available')
        count = self._ips.update_dashboard_whitelist('remove', params.get('value', ''), params.get('type', 'ip'))
        return f'IPS whitelist updated ({count} entries)'

    # ── USB Actions ───────────────────────────────────────────────────────────
    def _block_usb(self, params: dict) -> str:
        try:
            from response.usb_block import block
            block()
            return 'USB storage disabled'
        except Exception as e:
            return f'USB block failed: {e}'

    def _unblock_usb(self, params: dict) -> str:
        try:
            from response.usb_block import unblock
            unblock()
            return 'USB storage re-enabled'
        except Exception as e:
            return f'USB unblock failed: {e}'

    # ── User Actions ──────────────────────────────────────────────────────────
    def _disable_user(self, params: dict) -> str:
        username = params.get('username', '')
        if not username:
            return 'No username specified'
        try:
            if SYSTEM == 'Windows':
                subprocess.run(['net', 'user', username, '/active:no'], check=True,
                               capture_output=True, timeout=10)
            elif SYSTEM == 'Darwin':
                subprocess.run(['pwpolicy', '-u', username, '-setpolicy', 'isDisabled=1'], check=True,
                               capture_output=True, timeout=10)
            else:
                subprocess.run(['usermod', '--lock', username], check=True,
                               capture_output=True, timeout=10)
            return f'User disabled: {username}'
        except Exception as e:
            raise RuntimeError(f'Disable user failed: {e}') from e

    def _enable_user(self, params: dict) -> str:
        username = params.get('username', '')
        if not username:
            return 'No username specified'
        try:
            if SYSTEM == 'Windows':
                subprocess.run(['net', 'user', username, '/active:yes'], check=True,
                               capture_output=True, timeout=10)
            elif SYSTEM == 'Darwin':
                subprocess.run(['pwpolicy', '-u', username, '-setpolicy', 'isDisabled=0'], check=True,
                               capture_output=True, timeout=10)
            else:
                subprocess.run(['usermod', '--unlock', username], check=True,
                               capture_output=True, timeout=10)
            return f'User enabled: {username}'
        except Exception as e:
            raise RuntimeError(f'Enable user failed: {e}') from e

    def _lock_account(self, params: dict) -> str:
        username = params.get('username', '')
        if not username:
            return 'No username specified'
        try:
            if SYSTEM == 'Linux':
                subprocess.run(['passwd', '--lock', username], check=True,
                               capture_output=True, timeout=10)
                return f'Account locked: {username}'
            else:
                return self._disable_user(params)
        except Exception as e:
            raise RuntimeError(f'Lock account failed: {e}') from e

    def _force_logoff(self, params: dict) -> str:
        username = params.get('username', '')
        if not username:
            return 'No username specified'
        try:
            if SYSTEM == 'Linux':
                result = subprocess.run(['pkill', '-KILL', '-u', username],
                                        capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout or 'no active user session found').strip())
                return f'User sessions terminated: {username}'
            elif SYSTEM == 'Windows':
                result = subprocess.run(
                    ['query', 'session', username],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout or 'user session query failed').strip())
                terminated = 0
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and username.lower() in parts[0].lower():
                        session_id = parts[2] if parts[2].isdigit() else None
                        if session_id:
                            subprocess.run(['logoff', session_id], check=True,
                                           capture_output=True, timeout=10)
                            terminated += 1
                if not terminated:
                    raise RuntimeError('no active user session found')
                return f'User logoff triggered: {username}'
        except Exception as e:
            return f'Force logoff failed: {e}'
        return 'Logoff not supported on this platform'

    # ── Service Actions ───────────────────────────────────────────────────────
    def _restart_service(self, params: dict) -> str:
        service = params.get('service', '')
        if not service:
            return 'No service specified'
        try:
            if SYSTEM == 'Linux':
                subprocess.run(['systemctl', 'restart', service], check=True,
                               capture_output=True, timeout=30)
            elif SYSTEM == 'Windows':
                subprocess.run(['net', 'stop', service], capture_output=True, timeout=30)
                subprocess.run(['net', 'start', service], check=True,
                               capture_output=True, timeout=30)
            return f'Service restarted: {service}'
        except Exception as e:
            return f'Service restart failed: {e}'

    def _stop_service(self, params: dict) -> str:
        service = params.get('service', '')
        if not service:
            return 'No service specified'
        try:
            if SYSTEM == 'Linux':
                subprocess.run(['systemctl', 'stop', service], check=True,
                               capture_output=True, timeout=30)
            elif SYSTEM == 'Windows':
                subprocess.run(['net', 'stop', service], check=True,
                               capture_output=True, timeout=30)
            return f'Service stopped: {service}'
        except Exception as e:
            return f'Service stop failed: {e}'

    def _start_service(self, params: dict) -> str:
        service = params.get('service', '')
        if not service:
            return 'No service specified'
        try:
            if SYSTEM == 'Linux':
                subprocess.run(['systemctl', 'start', service], check=True,
                               capture_output=True, timeout=30)
            elif SYSTEM == 'Windows':
                subprocess.run(['net', 'start', service], check=True,
                               capture_output=True, timeout=30)
            return f'Service started: {service}'
        except Exception as e:
            return f'Service start failed: {e}'

    # ── Persistence Cleanup ───────────────────────────────────────────────────
    def _delete_scheduled_task(self, params: dict) -> str:
        task = params.get('task', '')
        if not task:
            return 'No task specified'
        try:
            if SYSTEM == 'Windows':
                subprocess.run(['schtasks', '/delete', '/tn', task, '/f'],
                               check=True, capture_output=True, timeout=15)
                return f'Scheduled task deleted: {task}'
            elif SYSTEM == 'Linux':
                # Remove from user crontabs (heuristic)
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                lines = [l for l in result.stdout.splitlines() if task not in l]
                proc  = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                proc.communicate('\n'.join(lines) + '\n')
                return f'Cron entry removed: {task}'
        except Exception as e:
            return f'Task deletion failed: {e}'
        return 'Unsupported platform'

    def _delete_startup_entry(self, params: dict) -> str:
        entry = params.get('entry', '') or params.get('name', '')
        if not entry:
            return 'No entry specified'
        try:
            if SYSTEM == 'Windows':
                for key_path in [
                    r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                    r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                ]:
                    subprocess.run(
                        ['reg', 'delete', key_path, '/v', entry, '/f'],
                        capture_output=True, timeout=10
                    )
                return f'Startup entry removed: {entry}'
            elif SYSTEM == 'Linux':
                autostart = Path.home() / '.config' / 'autostart' / f'{entry}.desktop'
                if autostart.exists():
                    autostart.unlink()
                    return f'Autostart entry removed: {entry}'
                return f'Autostart entry not found: {entry}'
        except Exception as e:
            return f'Startup entry deletion failed: {e}'
        return 'Unsupported platform'

    def _rollback_registry(self, params: dict) -> str:
        """Restore a registry key from backup (Windows only)."""
        if SYSTEM != 'Windows':
            return 'Registry rollback is Windows only'
        key_path = params.get('key_path', '')
        if not key_path:
            return 'No key_path specified'
        try:
            backup = params.get('backup_file', '')
            if backup and os.path.exists(backup):
                subprocess.run(['reg', 'import', backup], check=True,
                               capture_output=True, timeout=15)
                return f'Registry key restored from backup: {key_path}'
            else:
                # Try to delete the malicious key
                subprocess.run(['reg', 'delete', key_path, '/f'],
                               capture_output=True, timeout=10)
                return f'Malicious registry key deleted: {key_path}'
        except Exception as e:
            return f'Registry rollback failed: {e}'

    # ── Safe Command Runner ───────────────────────────────────────────────────
    ALLOWED_COMMANDS = {
        'ipconfig', 'ifconfig', 'netstat', 'ss', 'ps', 'top',
        'systemctl status', 'journalctl', 'whoami', 'id',
        'ls', 'dir', 'cat', 'type',
    }

    def _run_safe_command(self, params: dict) -> str:
        """Execute a pre-approved command (no arbitrary code execution)."""
        command = params.get('command', '').strip()
        if not command:
            return 'No command specified'

        # Security: only allow pre-approved commands
        if not any(command.lower().startswith(allowed) for allowed in self.ALLOWED_COMMANDS):
            return f'Command not in allowlist: {command[:50]}'

        try:
            result = subprocess.run(
                command, shell=True,  # noqa: S602
                capture_output=True, text=True,
                timeout=30,
            )
            return f'Exit {result.returncode}: {result.stdout[:500]}'
        except subprocess.TimeoutExpired:
            return 'Command timed out'
        except Exception as e:
            return f'Command error: {e}'


# Alias for agent.py _import_class discovery
Engine = AutoResponseEngine
