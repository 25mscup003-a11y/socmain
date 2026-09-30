"""Process Collector — process inventory, lifecycle, resource and abuse monitoring."""

import os
import time
import logging
import threading
import platform
import ipaddress
import queue
import re
import hashlib
import shlex
from datetime import datetime, timezone

logger = logging.getLogger('soc-agent.collector.processes')

SUSPICIOUS_NAMES = {
    'meterpreter', 'mimikatz', 'cobalt', 'psexec', 'netcat', 'nc.exe',
    'ncat', 'socat', 'wce.exe', 'fgdump', 'pwdump', 'gsecdump',
    'procdump', 'lsassy', 'lazagne', 'crackmapexec', 'metasploit',
    'beacon.exe', 'msfconsole', 'empire', 'sliver', 'havoc',
}
SUSPICIOUS_CMDLINE = (
    'invoke-mimikatz', 'invoke-shellcode', 'frombase64string',
    '-encodedcommand', 'downloadstring', 'iex(', 'bypass',
    'certutil -decode', 'certutil -urlcache', 'bitsadmin /transfer',
    'curl http', 'wget http', '/dev/tcp/', 'nc -e', 'bash -i',
)
UNAUTHORIZED_PATH_HINTS = (
    '/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/',
    '\\temp\\', '\\appdata\\local\\temp\\', '\\downloads\\',
)
CPU_THRESHOLD = 90.0
MEM_THRESHOLD = 15.0
DISK_IO_THRESHOLD_BYTES_PER_SECOND = 50 * 1024 * 1024
INTERNAL_SCAN_UNIQUE_HOST_THRESHOLD = 20
POLL_INTERVAL = 30
SUMMARY_INTERVAL = 60
MAX_LIFECYCLE_ALERTS_PER_CYCLE = 50

SCRIPT_INTERPRETERS = {
    'powershell.exe': 'PowerShell', 'powershell': 'PowerShell', 'pwsh.exe': 'PowerShell', 'pwsh': 'PowerShell',
    'cmd.exe': 'CMD / Batch', 'cmd': 'CMD / Batch', 'wscript.exe': 'VBScript', 'wscript': 'VBScript',
    'cscript.exe': 'VBScript', 'cscript': 'VBScript', 'bash': 'Unix Shell', 'sh': 'Unix Shell',
    'zsh': 'Unix Shell', 'dash': 'Unix Shell', 'python': 'Python', 'python.exe': 'Python',
    'python3': 'Python', 'node': 'Node.js / JavaScript', 'node.exe': 'Node.js / JavaScript',
    'perl': 'Perl', 'ruby': 'Ruby', 'php': 'PHP', 'php.exe': 'PHP',
}
SCRIPT_SUFFIXES = ('.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.py', '.sh', '.pl', '.rb', '.php')

CRITICAL_SECURITY_PROCESSES = {
    'msmpeng.exe', 'sense.exe', 'nisserv.exe', 'clamd', 'clamdscan',
    'auditd', 'suricata', 'zeek', 'osqueryd', 'falcon-sensor',
    'wazuh-agentd', 'elastic-agent',
}

class ProcessCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config
        self._alerted_keys: set = set()
        self._known = {}
        self._cpu_samples = {}
        self._io_samples = {}
        self._baseline_done = False
        self._last_summary = 0
        self._trust_queue = queue.Queue(maxsize=256)
        self._trust_seen = set()
        self._script_hash_cache = {}
        self._script_last_alert = {}
        self._connection_snapshot_cache = {}
        self._connection_snapshot_at = 0.0
        self._thread = threading.Thread(target=self._loop, daemon=True, name='proc-monitor')
        self._trust_thread = threading.Thread(
            target=self._trust_worker, daemon=True, name='proc-executable-trust'
        )

    def start(self):
        self._trust_thread.start()
        self._thread.start()

    def _loop(self):
        logger.info('Process monitor started')
        while True:
            try:
                self._check()
            except Exception as e:
                logger.error(f'Process check error: {e}')
            time.sleep(self._cfg_float('process_poll_interval_seconds', POLL_INTERVAL))

    def _cfg_float(self, key, default):
        try:
            return float(self._config.get(key, default)) if self._config else float(default)
        except Exception:
            return float(default)

    def _cfg_bool(self, key, default):
        try:
            value = self._config.get(key, default) if self._config else default
        except Exception:
            value = default
        if isinstance(value, str):
            return value.strip().lower() not in ('0', 'false', 'no', 'off', '')
        return bool(value)

    def _check(self):
        try:
            import psutil
        except ImportError:
            return

        had_baseline = self._baseline_done
        current = {}
        lifecycle_sent = 0
        processes = []
        fields = ['pid', 'ppid', 'name', 'cmdline', 'cpu_times', 'memory_percent', 'memory_info', 'username', 'exe', 'create_time', 'status', 'io_counters']
        sample_time = time.monotonic()
        cpu_count = psutil.cpu_count() or 1
        process_connections = self._cached_connection_snapshot(psutil, sample_time)
        parent_cache = {}

        for proc in psutil.process_iter(fields):
            try:
                info = dict(proc.info)
                name = (info.get('name') or '').lower()
                pid = proc.info['pid']
                create_time = info.get('create_time') or 0
                key = f'{pid}:{create_time}'
                ppid = info.get('ppid') or 0
                parent_name, parent_cmdline, parent_username = parent_cache.get(ppid, ('', '', ''))
                if ppid and ppid not in parent_cache:
                    try:
                        parent = proc.parent()
                        if parent:
                            parent_name = parent.name() or ''
                            parent_cmdline = ' '.join(parent.cmdline() or [])
                            try:
                                parent_username = parent.username() or ''
                            except Exception:
                                parent_username = ''
                    except Exception:
                        parent_name = ''
                        parent_cmdline = ''
                        parent_username = ''
                    parent_cache[ppid] = (parent_name, parent_cmdline, parent_username)

                cmdline = ' '.join(info.get('cmdline') or [])
                exe = info.get('exe') or ''
                cpu = self._process_cpu_percent(key, info.get('cpu_times'), sample_time, cpu_count)
                mem = float(info.get('memory_percent') or 0)
                memory_info = info.get('memory_info')
                memory_mb = round(float(getattr(memory_info, 'rss', 0) or 0) / (1024 * 1024), 2)
                io_counters = info.get('io_counters')
                connection_stats = process_connections.get(pid, {})
                username = info.get('username') or ''
                classifications = self._classify_process(name, cmdline, exe, username)
                if connection_stats.get('total', 0):
                    classifications.append('network_enabled')
                if connection_stats.get('external', 0):
                    classifications.append('outbound_internet')
                disk_read_bytes = int(getattr(io_counters, 'read_bytes', 0) or 0)
                disk_write_bytes = int(getattr(io_counters, 'write_bytes', 0) or 0)
                disk_read_rate, disk_write_rate = self._disk_io_rate(
                    key, disk_read_bytes, disk_write_bytes, sample_time
                )
                current[key] = {
                    'pid': pid,
                    'ppid': ppid,
                    'name': name,
                    'parent_name': parent_name,
                    'parent_cmdline': parent_cmdline,
                    'parent_username': parent_username,
                    'cmdline': cmdline,
                    'exe': exe,
                    'username': username,
                    'cpu': cpu,
                    'mem': mem,
                    'memory_mb': memory_mb,
                    'disk_read_bytes': disk_read_bytes,
                    'disk_write_bytes': disk_write_bytes,
                    'disk_read_bytes_per_second': disk_read_rate,
                    'disk_write_bytes_per_second': disk_write_rate,
                    'network_connection_count': int(connection_stats.get('total', 0)),
                    'external_connection_count': int(connection_stats.get('external', 0)),
                    'remote_addresses': connection_stats.get('remote_addresses', []),
                    'unique_remote_ip_count': int(connection_stats.get('unique_remote_ip_count', 0)),
                    'unique_remote_port_count': int(connection_stats.get('unique_remote_port_count', 0)),
                    'private_remote_ip_count': int(connection_stats.get('private_remote_ip_count', 0)),
                    'classifications': sorted(set(classifications)),
                    'status': info.get('status') or '',
                    'create_time': create_time,
                }
                current[key].update(self._script_context(name, cmdline, exe, parent_name, int(connection_stats.get('external', 0))))
                processes.append(current[key])

                is_suspicious = any(s in name for s in SUSPICIOUS_NAMES)
                is_suspicious_cmd = any(s in cmdline.lower() for s in SUSPICIOUS_CMDLINE)
                cpu_threshold = self._cfg_float('process_cpu_threshold_percent', CPU_THRESHOLD)
                mem_threshold = self._cfg_float('process_memory_threshold_percent', MEM_THRESHOLD)
                disk_threshold = self._cfg_float(
                    'process_disk_io_threshold_bytes_per_second',
                    DISK_IO_THRESHOLD_BYTES_PER_SECOND,
                )
                scan_threshold = int(self._cfg_float(
                    'process_internal_scan_unique_hosts',
                    INTERNAL_SCAN_UNIQUE_HOST_THRESHOLD,
                ))
                lifecycle_enabled = bool(self._config.get('process_lifecycle_alerts_enabled', True)) if self._config else True
                is_high_cpu = cpu > cpu_threshold
                is_high_mem = mem > mem_threshold
                is_high_disk = (disk_read_rate + disk_write_rate) > disk_threshold
                is_internal_scan = current[key]['private_remote_ip_count'] >= max(scan_threshold, 5)
                is_unauthorized = self._is_unauthorized_execution(exe, cmdline)
                is_new = self._baseline_done and key not in self._known

                if lifecycle_enabled and is_new and lifecycle_sent < MAX_LIFECYCLE_ALERTS_PER_CYCLE:
                    lifecycle_sent += 1
                    self._send_process_alert('PROC_STARTED', 'low', 'Process started', current[key])

                # Trust inspection is deliberately asynchronous. Authenticode
                # and package-manager verification can take seconds and must
                # never delay lifecycle/resource collection.
                if (not self._baseline_done or is_new) and self._cfg_bool('process_executable_trust_enabled', True):
                    self._schedule_executable_trust(current[key])

                if is_new:
                    command_findings = self._command_activity(name, cmdline)
                    if current[key].get('interpreter') and current[key].get('external_connection_count', 0) > 0:
                        command_findings.append(('SCRIPT_EXTERNAL_NETWORK', 'medium', 'Script interpreter opened an external network connection'))
                    if current[key].get('interpreter') and 'Suspicious or remote parent process' in (current[key].get('detection_reasons') or []):
                        command_findings.append(('SCRIPT_SUSPICIOUS_PARENT', 'high', 'Script started by a suspicious or remote parent process'))
                    for rule_id, severity, reason in command_findings:
                        if rule_id.startswith('SCRIPT_'):
                            if not self._cfg_bool('script_monitoring_enabled', True) or self._script_allowed(current[key]):
                                continue
                            risk = int(current[key].get('script_risk_score') or 0)
                            threshold = int(self._cfg_float('script_risk_threshold', 30))
                            if rule_id != 'SCRIPT_EXECUTION_OBSERVED' and risk < max(0, min(100, threshold)):
                                continue
                            feature_key = {
                                'SCRIPT_DOWNLOAD_EXECUTE': 'script_detect_download_execution',
                                'SCRIPT_PERSISTENCE': 'script_detect_persistence',
                                'SCRIPT_EXTERNAL_NETWORK': 'script_detect_external_connections',
                            }.get(rule_id)
                            if rule_id == 'SCRIPT_OBFUSCATED_COMMAND' and not (
                                self._cfg_bool('script_detect_obfuscation', True)
                                or self._cfg_bool('script_detect_encoded_commands', True)
                            ):
                                continue
                            if feature_key and not self._cfg_bool(feature_key, True):
                                continue
                            if rule_id != 'SCRIPT_EXECUTION_OBSERVED':
                                signature = f'{rule_id}:{current[key].get("script_hash") or current[key].get("script_path") or cmdline}:{username}'
                                cooldown = max(60, int(self._cfg_float('script_alert_cooldown_seconds', 900)))
                                previous = self._script_last_alert.get(signature, 0)
                                if time.time() - previous < cooldown:
                                    continue
                                self._script_last_alert[signature] = time.time()
                        alert_key = f'{rule_id}:{key}'
                        if alert_key not in self._alerted_keys:
                            self._alerted_keys.add(alert_key)
                            self._send_process_alert(rule_id, severity, reason, current[key])

                if is_suspicious or is_suspicious_cmd or is_unauthorized or is_high_cpu or is_high_mem:
                    rule_id = (
                        'PROC_SUSPICIOUS' if is_suspicious else
                        'PROC_SUSPICIOUS_CMDLINE' if is_suspicious_cmd else
                        'PROC_UNAUTHORIZED_EXECUTION' if is_unauthorized else
                        'PROC_HIGH_CPU' if is_high_cpu else
                        'PROC_HIGH_MEMORY'
                    )
                    severity = 'critical' if is_suspicious or is_suspicious_cmd else 'high' if is_unauthorized else 'medium'
                    reason = (
                        'Suspicious process' if is_suspicious else
                        'Suspicious command line' if is_suspicious_cmd else
                        'Unauthorized process location' if is_unauthorized else
                        'High CPU process' if is_high_cpu else
                        'High memory process'
                    )
                    alert_key = f'{rule_id}:{key}'
                    if alert_key not in self._alerted_keys:
                        self._alerted_keys.add(alert_key)
                        self._send_process_alert(rule_id, severity, reason, current[key])

                for matched, rule_id, severity, reason in (
                    (is_high_disk, 'PROC_HIGH_DISK_IO', 'medium', 'High disk I/O process'),
                    (is_internal_scan, 'PROC_INTERNAL_NETWORK_SCAN', 'high', 'Process connected to many internal hosts'),
                ):
                    alert_key = f'{rule_id}:{key}'
                    if matched and alert_key not in self._alerted_keys:
                        self._alerted_keys.add(alert_key)
                        self._send_process_alert(rule_id, severity, reason, current[key])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        lifecycle_enabled = bool(self._config.get('process_lifecycle_alerts_enabled', True)) if self._config else True
        if lifecycle_enabled and self._baseline_done:
            terminated = [v for k, v in self._known.items() if k not in current]
            for item in terminated[:MAX_LIFECYCLE_ALERTS_PER_CYCLE]:
                self._send_process_alert('PROC_TERMINATED', 'low', 'Process terminated', item)
                if self._is_critical_security_process(item):
                    self._send_process_alert(
                        'PROC_SECURITY_TOOL_TERMINATED', 'high',
                        'Critical security process terminated', item,
                    )

        self._known = current
        self._cpu_samples = {k: self._cpu_samples[k] for k in current.keys() if k in self._cpu_samples}
        self._io_samples = {k: self._io_samples[k] for k in current.keys() if k in self._io_samples}
        self._baseline_done = True
        if had_baseline:
            self._send_summary(processes)

        if len(self._alerted_keys) > 2000:
            self._alerted_keys.clear()
        if len(self._script_last_alert) > 2000:
            cutoff = time.time() - max(60, int(self._cfg_float('script_alert_cooldown_seconds', 900)))
            self._script_last_alert = {key: value for key, value in self._script_last_alert.items() if value >= cutoff}

    def _process_cpu_percent(self, key: str, cpu_times, sample_time: float, cpu_count: int) -> float:
        try:
            total_cpu = float((cpu_times.user or 0) + (cpu_times.system or 0))
        except Exception:
            return 0.0
        prev = self._cpu_samples.get(key)
        self._cpu_samples[key] = (total_cpu, sample_time)
        if not prev:
            return 0.0
        prev_cpu, prev_time = prev
        elapsed = max(sample_time - prev_time, 0.001)
        cpu_delta = max(total_cpu - prev_cpu, 0.0)
        return max(0.0, min(100.0, (cpu_delta / elapsed) * 100.0 / max(cpu_count, 1)))

    def _disk_io_rate(self, key: str, read_bytes: int, write_bytes: int, sample_time: float):
        prev = self._io_samples.get(key)
        self._io_samples[key] = (read_bytes, write_bytes, sample_time)
        if not prev:
            return 0.0, 0.0
        prev_read, prev_write, prev_time = prev
        elapsed = max(sample_time - prev_time, 0.001)
        return (
            max(read_bytes - prev_read, 0) / elapsed,
            max(write_bytes - prev_write, 0) / elapsed,
        )

    def _is_unauthorized_execution(self, exe: str, cmdline: str) -> bool:
        # Judge the executable location, not arbitrary command arguments. A
        # trusted /usr/bin binary may legitimately receive /tmp or /run/user
        # paths (bwrap, browsers, package managers), which previously produced
        # hundreds of false unauthorized-execution alerts.
        executable = (exe or '').lower().strip()
        if not executable:
            return False
        custom = []
        try:
            custom = self._config.get('unauthorized_process_paths', []) if self._config else []
        except Exception:
            custom = []
        hints = tuple(str(p).lower() for p in custom if str(p).strip()) or UNAUTHORIZED_PATH_HINTS
        return any(h in executable for h in hints)

    @staticmethod
    def _connection_snapshot(psutil):
        """Collect one system-wide socket snapshot and attribute it by PID."""
        result = {}
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, OSError):
            return result
        for connection in connections:
            if not connection.pid:
                continue
            stats = result.setdefault(connection.pid, {
                'total': 0, 'external': 0, 'remote_addresses': [],
                '_remote_ips': set(), '_remote_ports': set(), '_private_ips': set(),
            })
            stats['total'] += 1
            remote = getattr(connection, 'raddr', None)
            ip = getattr(remote, 'ip', None) if remote else None
            port = getattr(remote, 'port', None) if remote else None
            if not ip:
                continue
            address = None
            try:
                address = ipaddress.ip_address(str(ip).split('%')[0])
                external = not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast)
            except ValueError:
                external = False
            if external:
                stats['external'] += 1
            elif address is not None and not (address.is_loopback or address.is_link_local or address.is_multicast):
                stats['_private_ips'].add(str(address))
            stats['_remote_ips'].add(str(ip))
            if port:
                stats['_remote_ports'].add(int(port))
            endpoint = f'{ip}:{port}' if port else str(ip)
            if endpoint not in stats['remote_addresses'] and len(stats['remote_addresses']) < 20:
                stats['remote_addresses'].append(endpoint)
        for stats in result.values():
            stats['unique_remote_ip_count'] = len(stats.pop('_remote_ips'))
            stats['unique_remote_port_count'] = len(stats.pop('_remote_ports'))
            stats['private_remote_ip_count'] = len(stats.pop('_private_ips'))
        return result

    def _cached_connection_snapshot(self, psutil, sample_time: float):
        """Rate-limit the expensive system-wide socket table scan."""
        interval = max(10.0, self._cfg_float('process_connection_snapshot_interval_seconds', 60))
        if self._connection_snapshot_at and sample_time - self._connection_snapshot_at < interval:
            return self._connection_snapshot_cache
        self._connection_snapshot_cache = self._connection_snapshot(psutil)
        self._connection_snapshot_at = sample_time
        return self._connection_snapshot_cache

    @staticmethod
    def _classify_process(name: str, cmdline: str, exe: str, username: str):
        """Return evidence-backed workload tags; these are not threat verdicts."""
        text = f'{name} {cmdline} {exe}'.lower()
        tags = []
        patterns = {
            'powershell': ('powershell', 'pwsh'),
            'command_shell': ('cmd.exe', '/bin/sh', '/bin/bash', ' bash ', ' zsh '),
            'python': ('python',),
            'java': ('java', 'java.exe'),
            'vbscript_javascript': ('wscript', 'cscript', '.vbs', '.js', 'node ', 'node.exe'),
            'browser': ('chrome', 'firefox', 'msedge', 'safari', 'chromium'),
            'web_server': ('apache', 'httpd', 'nginx', 'iisexpress', 'w3wp', 'tomcat'),
            'database': ('mysqld', 'mysql', 'postgres', 'sqlservr', 'oracle', 'mongod', 'redis-server'),
            'remote_access': ('sshd', 'mstsc', 'xrdp', 'teamviewer', 'anydesk', 'psexec'),
            'scheduled_task': ('cron', 'crond', 'atd', 'taskeng', 'taskhostw'),
            'service': ('systemd', 'services.exe', 'svchost', 'launchd'),
            'backup': ('backup', 'rsync', 'veeam', 'wbadmin'),
            'security_tool': ('defender', 'msmpeng', 'clamd', 'suricata', 'zeek', 'auditd'),
            'lolbin': ('mshta', 'regsvr32', 'rundll32', 'certutil', 'bitsadmin', 'wmic'),
            'credential_tool': ('mimikatz', 'procdump', 'lsassy', 'lazagne', 'pwdump'),
            'crypto_miner': ('xmrig', 'minerd', 'cryptonight'),
            'container_cloud': ('dockerd', 'docker ', 'containerd', 'containerd-shim', 'podman', 'runc', 'crio', 'kubelet', 'kubectl', 'helm '),
            'active_directory': ('lsass.exe', 'ntdsutil', 'repadmin', 'dcdiag', 'kadmin', 'krb5kdc'),
            'ssh': ('sshd', 'ssh '),
            'rdp': ('mstsc', 'xrdp', 'termsrv'),
        }
        for tag, needles in patterns.items():
            if any(needle in text for needle in needles):
                tags.append(tag)
        user = (username or '').lower()
        if user in ('root', 'system', 'nt authority\\system') or user.endswith('\\administrator'):
            tags.append('privileged_user')
        if '-encodedcommand' in text or ' -enc ' in text or 'frombase64string' in text:
            tags.append('encoded_command')
        if any(value in text for value in ('/dev/tcp/', 'nc -e', 'bash -i', 'powershell -nop -w hidden')):
            tags.append('reverse_shell_indicator')
        normalized_path = (exe or cmdline or '').lower().replace('\\', '/')
        if any(marker in normalized_path for marker in ('/media/', '/run/media/', '/volumes/', '/mnt/usb', '/removable/')):
            tags.append('usb_related')
        return sorted(set(tags))

    def _script_context(self, name: str, cmdline: str, exe: str, parent_name: str = '', external_connections: int = 0) -> dict:
        """Extract normalized script evidence from one observed process.

        Hashing is performed only for an actual script file, is size bounded,
        and is cached by path/size/mtime so the collector never repeatedly
        reads unchanged scripts.
        """
        executable = os.path.basename(name or exe or '').lower()
        command = str(cmdline or '')
        lower = f'{executable} {command}'.lower()
        interpreter = SCRIPT_INTERPRETERS.get(executable)
        script_path = ''
        try:
            tokens = shlex.split(command, posix=platform.system().lower() != 'windows')
        except ValueError:
            tokens = command.split()
        for token in tokens[1:] if interpreter else tokens:
            candidate = str(token).strip('"\'')
            if candidate.lower().endswith(SCRIPT_SUFFIXES):
                script_path = candidate
                break
        if not script_path:
            match = re.search(r'(?i)(?:"([^"\r\n]+\.(?:ps1|bat|cmd|vbs|vbe|js|jse|py|sh|pl|rb|php))"|([^\s"\']+\.(?:ps1|bat|cmd|vbs|vbe|js|jse|py|sh|pl|rb|php)))', command)
            if match:
                script_path = next((value for value in match.groups() if value), '')
        if not interpreter and (script_path or str(exe or '').lower().endswith(SCRIPT_SUFFIXES)):
            interpreter = 'Direct / Shebang'
        if not interpreter:
            return {}

        indicators = []
        weights = []
        obfuscation_weights = []
        patterns = (
            ('Encoded command', r'-encodedcommand|(?:^|\s)-enc(?:\s|$)|frombase64string|base64\s+(?:-d|--decode)|[A-Za-z0-9+/]{160,}={0,2}', 25, True),
            ('Dynamic expression execution', r'invoke-expression|\biex\s*\(|\beval\s*\(', 20, True),
            ('Excessive escaping or concatenation', r'(?:[`^\\]{2,}.{0,12}){4,}|(?:["\'][^"\']{0,8}["\']\s*\+\s*){4,}', 15, True),
            ('Download behavior', r'invoke-webrequest|downloadstring|downloadfile|start-bitstransfer|\bcurl\b.+https?://|\bwget\b.+https?://', 25, False),
            ('Execution policy or hidden-window bypass', r'executionpolicy\s+bypass|windowstyle\s+hidden|-w(?:indowstyle)?\s+hidden|(?:^|\s)-(?:nop|noprofile)\b', 20, False),
            ('Persistence behavior', r'schtasks|new-service|sc(?:\.exe)?\s+create|crontab|systemctl\s+enable|startup', 25, False),
            ('Credential-access behavior', r'lsass|mimikatz|credential|sekurlsa|sam\b|security\b.*hive', 35, False),
            ('Reverse-shell behavior', r'/dev/tcp/|\bnc\s+-e|bash\s+-i|reverse\s+shell|invoke-shellcode', 40, False),
            ('Lateral-movement behavior', r'\bpsexec\b|\bwinrs\b|invoke-command|enter-pssession|wmic.+/node:|\bssh\b.+@', 35, False),
            ('Data-exfiltration behavior', r'\bscp\b|\brclone\b|\bazcopy\b|curl.+(?:--upload-file|-t\s)|invoke-restmethod.+-method\s+post', 30, False),
            ('Mass file operation', r'get-childitem.+(?:remove-item|set-content)|find\s+\S+.+-delete|forfiles.+/c|cipher\s+/w', 30, False),
        )
        for reason, pattern, score, is_obfuscation in patterns:
            if re.search(pattern, lower):
                indicators.append(reason)
                weights.append(score)
                if is_obfuscation:
                    obfuscation_weights.append(score)
        if external_connections > 0:
            indicators.append('External network connection')
            weights.append(15)
        if re.search(r'winword|excel|outlook|acrord32|chrome|firefox|msedge|wsmprovhost|sshd|psexec', str(parent_name or '').lower()):
            indicators.append('Suspicious or remote parent process')
            weights.append(15)
        obfuscation_score = min(100, sum(obfuscation_weights))
        risk_score = min(100, 10 + sum(weights))
        hashes = self._hash_script_file(script_path)
        return {
            'script_name': os.path.basename(script_path) if script_path else (name or executable),
            'script_path': script_path,
            'interpreter': interpreter,
            'command_line': command[:4000],
            'execution_source': parent_name or 'Direct process execution',
            'obfuscation_score': obfuscation_score,
            'detection_reasons': indicators or ['Script interpreter execution observed'],
            'script_hash': hashes.get('sha256'),
            'script_sha1': hashes.get('sha1'),
            'script_md5': hashes.get('md5'),
            'script_size': hashes.get('size'),
            'script_modified_at': hashes.get('modified_at'),
            'script_risk_score': risk_score,
        }

    def _script_allowed(self, item: dict) -> bool:
        script_hash = str(item.get('script_hash') or '').lower()
        trusted_hashes = {str(value).strip().lower() for value in (self._config.get('script_trusted_hashes', []) or [])} if self._config else set()
        if script_hash and script_hash in trusted_hashes:
            return True
        normalized = str(item.get('script_path') or '').lower().replace('\\', '/')
        trusted_paths = [str(value).strip().lower().replace('\\', '/') for value in (self._config.get('script_trusted_paths', []) or [])] if self._config else []
        return bool(normalized and any(normalized == path or normalized.startswith(path.rstrip('/') + '/') for path in trusted_paths if path))

    def _hash_script_file(self, path: str) -> dict:
        if not path or not self._cfg_bool('script_hashing_enabled', True):
            return {}
        try:
            absolute = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
            stat = os.stat(absolute, follow_symlinks=False)
            max_bytes = int(self._cfg_float('script_hash_max_bytes', 16 * 1024 * 1024))
            if not os.path.isfile(absolute) or stat.st_size > max(1024, max_bytes):
                return {}
            key = (os.path.normcase(absolute), int(stat.st_size), int(stat.st_mtime_ns))
            cached = self._script_hash_cache.get(key)
            if cached:
                return cached
            digests = {'sha256': hashlib.sha256()}
            if self._cfg_bool('hash_sha1_enabled', True):
                digests['sha1'] = hashlib.sha1()
            if self._cfg_bool('hash_md5_enabled', False):
                try:
                    digests['md5'] = hashlib.md5(usedforsecurity=False)
                except TypeError:
                    digests['md5'] = hashlib.md5()
            with open(absolute, 'rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    for digest in digests.values():
                        digest.update(chunk)
            result = {name: digest.hexdigest() for name, digest in digests.items()}
            result.update({'size': int(stat.st_size), 'modified_at': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()})
            self._script_hash_cache[key] = result
            if len(self._script_hash_cache) > 1024:
                self._script_hash_cache.pop(next(iter(self._script_hash_cache)))
            return result
        except (OSError, ValueError, TypeError):
            return {}

    @staticmethod
    def _command_activity(name: str, cmdline: str):
        """Return auditable command activities backed by the observed command line."""
        text = f'{name} {cmdline}'.lower()
        findings = []
        executable = os.path.basename(name or '').lower()
        is_script = executable in SCRIPT_INTERPRETERS or any(suffix in text for suffix in SCRIPT_SUFFIXES)
        if is_script:
            findings.append(('SCRIPT_EXECUTION_OBSERVED', 'low', 'Script interpreter execution observed'))
        obfuscation = re.search(
            r'-encodedcommand|(?:^|\s)-enc(?:\s|$)|frombase64string|invoke-expression|\biex\s*\(|'
            r'base64\s+(?:-d|--decode)|eval\s*\(|[A-Za-z0-9+/]{180,}={0,2}',
            text,
        )
        if is_script and obfuscation:
            findings.append(('SCRIPT_OBFUSCATED_COMMAND', 'high', 'Encoded or obfuscated script command'))
        if is_script and re.search(r'invoke-webrequest|downloadstring|downloadfile|start-bitstransfer|\bcurl\b.+https?://|\bwget\b.+https?://', text):
            findings.append(('SCRIPT_DOWNLOAD_EXECUTE', 'high', 'Script download behavior observed'))
        if is_script and re.search(r'windowstyle\s+hidden|-w(?:indowstyle)?\s+hidden|executionpolicy\s+bypass|(?:^|\s)-(?:nop|noprofile)\b', text):
            findings.append(('SCRIPT_POLICY_BYPASS', 'high', 'Hidden or policy-bypass script execution'))
        if is_script and re.search(r'\bschtasks(?:\.exe)?.*/create\b|\bcrontab\b|\bsystemctl\s+enable\b|\bnew-service\b|\bsc(?:\.exe)?\s+create\b', text):
            findings.append(('SCRIPT_PERSISTENCE', 'high', 'Script-based persistence behavior observed'))
        if is_script and not any(suffix in text for suffix in SCRIPT_SUFFIXES) and re.search(r'\s-(?:command|c)\s|\biex\b|\beval\s*\(', text):
            findings.append(('SCRIPT_FILELESS_EXECUTION', 'high', 'Fileless inline script execution observed'))
        if is_script and re.search(r'\bpsexec\b|\bwinrs\b|invoke-command|enter-pssession|wmic.+/node:|\bssh\b.+@', text):
            findings.append(('SCRIPT_REMOTE_EXECUTION', 'critical', 'Remote or lateral script execution behavior observed'))
        if is_script and re.search(r'lsass|mimikatz|credential|sekurlsa|sam\b|security\b.*hive', text):
            findings.append(('SCRIPT_CREDENTIAL_ACCESS', 'critical', 'Script-based credential access behavior observed'))
        if is_script and re.search(r'\bscp\b|\brclone\b|\bazcopy\b|curl.+(?:--upload-file|-t\s)|invoke-restmethod.+-method\s+post', text):
            findings.append(('SCRIPT_DATA_EXFILTRATION', 'high', 'Script-based data exfiltration behavior observed'))
        if is_script and re.search(r'get-childitem.+(?:remove-item|set-content)|find\s+\S+.+-delete|forfiles.+/c|cipher\s+/w', text):
            findings.append(('SCRIPT_MASS_FILE_OPERATION', 'high', 'Mass file operation from a script observed'))
        if re.search(r'(^|\s)(sudo|pkexec|runas(?:\.exe)?)(\s|$)|start-process.+-verb\s+runas', text):
            findings.append(('PROC_PRIVILEGED_COMMAND', 'medium', 'Privileged command execution'))
        if re.search(r'chmod\s+(?:[0-7]*[46][0-7]{2}|[ug]\+s)|setcap\s+[^\n]*cap_setuid|token::elevate|\bgetsystem\b|uac.{0,20}bypass', text):
            findings.append(('PROC_PRIVILEGE_ESCALATION', 'high', 'Privilege escalation behavior'))
        if re.search(r'\bsc(?:\.exe)?\s+create\b|\bnew-service\b|\bsystemctl\s+enable\b|\blaunchctl\s+bootstrap\b', text):
            findings.append(('PROC_SERVICE_CREATED', 'medium', 'Service creation or enable command'))
        elif re.search(r'\b(?:sc(?:\.exe)?|net)\s+(?:start|stop)\b|\bsystemctl\s+(?:start|stop|restart)\b|\bservice\s+\S+\s+(?:start|stop|restart)\b|\blaunchctl\s+(?:kickstart|bootout)\b', text):
            findings.append(('PROC_SERVICE_CONTROL', 'low', 'Service start/stop command'))
        if re.search(r'\bschtasks(?:\.exe)?.*/create\b|\bcrontab\b|\bsystemctl\s+enable\s+\S+\.timer\b|\blaunchctl\s+(?:load|bootstrap)\b', text):
            findings.append(('PROC_SCHEDULED_TASK_CHANGE', 'medium', 'Scheduled task persistence change'))
        security_names = r'(?:msmpeng|windefend|sense|clamd|clamav|auditd|suricata|zeek|falcon-sensor|wazuh-agentd|elastic-agent)'
        if re.search(rf'(?:taskkill|killall|pkill).{{0,80}}{security_names}|(?:net\s+stop|sc(?:\.exe)?\s+stop|systemctl\s+(?:stop|disable)).{{0,80}}{security_names}|set-mppreference.+disable', text):
            findings.append(('PROC_SECURITY_TOOL_TAMPER', 'critical', 'Security monitoring disable/kill attempt'))
        if re.search(r'\bwevtutil(?:\.exe)?\s+cl\b|\bclear-eventlog\b|\bjournalctl\b[^\n]*(?:--vacuum|--rotate)|\brm\b[^\n]*/var/log/(?:auth|secure|audit)', text):
            findings.append(('PROC_SECURITY_LOG_CLEARED', 'critical', 'Security log clearing or deletion observed'))
        if re.search(r'\b(?:7z|7za|rar|winrar|zip|tar)(?:\.exe)?\b[^\n]*(?:-p\S*|--password|\.zip\b|\.7z\b|\.rar\b|\.tar(?:\.gz)?\b)', text):
            findings.append(('PROC_ARCHIVE_STAGING', 'medium', 'Archive creation or encrypted staging command observed'))
        return findings

    @staticmethod
    def _is_critical_security_process(item: dict) -> bool:
        return (item.get('name') or '').lower() in CRITICAL_SECURITY_PROCESSES

    def _schedule_executable_trust(self, item: dict):
        exe = item.get('exe') or ''
        if not exe:
            return
        try:
            stat = os.stat(exe, follow_symlinks=False)
            identity = (os.path.normcase(os.path.abspath(exe)), int(stat.st_size), int(stat.st_mtime_ns))
        except OSError:
            return
        if identity in self._trust_seen:
            return
        self._trust_seen.add(identity)
        try:
            self._trust_queue.put_nowait(dict(item))
        except queue.Full:
            self._trust_seen.discard(identity)
            logger.warning('Executable trust queue full; deferred inspection for %s', exe)

    def _trust_worker(self):
        try:
            from collectors.hash_signature import ENGINE
        except ImportError as exc:
            logger.warning('Executable trust inspection unavailable: %s', exc)
            return
        while True:
            item = self._trust_queue.get()
            try:
                if self._cfg_bool('hash_monitoring_enabled', True):
                    trust = ENGINE.inspect(
                        item.get('exe') or '',
                        include_sha1=self._cfg_bool('hash_sha1_enabled', True),
                        include_md5=self._cfg_bool('hash_md5_enabled', False),
                        signature=self._cfg_bool('hash_signature_validation_enabled', True),
                    )
                    self._emit_trust_finding(item, trust)
            except Exception as exc:
                logger.debug('Executable trust inspection failed: %s', exc)
            finally:
                self._trust_queue.task_done()
            delay = max(0.0, self._cfg_float('process_trust_worker_interval_seconds', 2))
            if delay:
                time.sleep(delay)

    def _emit_trust_finding(self, item: dict, trust: dict):
        if not trust:
            return
        enriched = dict(item)
        enriched.update({
            'executable_sha256': trust.get('sha256'),
            'executable_sha1': trust.get('sha1'),
            'executable_md5': trust.get('md5'),
            'signature_status': trust.get('signatureStatus'),
            'trust_status': trust.get('trustStatus'),
            'publisher': trust.get('publisher'),
            'certificate_subject': trust.get('certificateSubject'),
            'certificate_issuer': trust.get('certificateIssuer'),
            'certificate_serial': trust.get('certificateSerial'),
            'certificate_thumbprint': trust.get('certificateThumbprint'),
            'certificate_valid_from': trust.get('certificateValidFrom'),
            'certificate_valid_until': trust.get('certificateValidUntil'),
            'package_owner': trust.get('packageOwner'),
            'package_verification_status': trust.get('packageVerificationStatus'),
        })
        signature = str(trust.get('signatureStatus') or '').upper()
        package_status = str(trust.get('packageVerificationStatus') or '').upper()
        unauthorized_path = self._is_unauthorized_execution(item.get('exe') or '', item.get('cmdline') or '')
        finding = None
        if signature in ('INVALID', 'UNTRUSTED_PUBLISHER', 'EXPIRED'):
            finding = ('PROC_UNTRUSTED_EXECUTABLE', 'high', f'Executable trust validation failed ({signature})')
        elif signature == 'UNSIGNED':
            finding = ('PROC_UNSIGNED_EXECUTABLE', 'medium', 'Unsigned executable started')
        elif package_status == 'MODIFIED':
            finding = ('PROC_MODIFIED_PACKAGE_EXECUTABLE', 'high', 'Modified package-managed executable started')
        elif package_status == 'NOT_PACKAGE_MANAGED' and unauthorized_path:
            finding = ('PROC_UNKNOWN_EXECUTABLE', 'medium', 'Unknown executable started from an untrusted location')
        if not finding:
            return
        rule_id, severity, reason = finding
        identity = trust.get('sha256') or item.get('exe') or item.get('name')
        alert_key = f'{rule_id}:{identity}'
        if alert_key in self._alerted_keys:
            return
        self._alerted_keys.add(alert_key)
        self._send_process_alert(rule_id, severity, reason, enriched)

    def _send_process_alert(self, rule_id: str, severity: str, title: str, item: dict):
        pid = item.get('pid')
        name = item.get('name') or 'unknown'
        ppid = item.get('ppid') or 0
        parent_name = item.get('parent_name') or ''
        parent_cmdline = item.get('parent_cmdline') or ''
        cpu = float(item.get('cpu') or 0)
        mem = float(item.get('mem') or 0)
        capability_ids = {1}
        if item.get('executable_sha256') or item.get('signature_status'):
            capability_ids.add(25)
        mitre_id = None
        technique = None
        mitre_tactic = None
        mitre_techniques = []
        if rule_id.startswith('SCRIPT_'):
            capability_ids.add(21)
            interpreter = str(item.get('interpreter') or '')
            interpreter_mitre = {
                'PowerShell': 'T1059.001', 'CMD / Batch': 'T1059.003',
                'Unix Shell': 'T1059.004', 'Python': 'T1059.006',
                'Node.js / JavaScript': 'T1059.007', 'VBScript': 'T1059.005',
            }.get(interpreter, 'T1059')
            behavior_mitre = {
                'SCRIPT_OBFUSCATED_COMMAND': ('T1027', 'Obfuscated Files or Information', 'Defense Evasion'),
                'SCRIPT_DOWNLOAD_EXECUTE': ('T1105', 'Ingress Tool Transfer', 'Command and Control'),
                'SCRIPT_POLICY_BYPASS': ('T1562.001', 'Impair Defenses', 'Defense Evasion'),
                'SCRIPT_PERSISTENCE': ('T1053', 'Scheduled Task/Job', 'Persistence'),
                'SCRIPT_FILELESS_EXECUTION': (interpreter_mitre, 'Command and Scripting Interpreter', 'Execution'),
                'SCRIPT_REMOTE_EXECUTION': ('T1021', 'Remote Services', 'Lateral Movement'),
                'SCRIPT_CREDENTIAL_ACCESS': ('T1003', 'OS Credential Dumping', 'Credential Access'),
                'SCRIPT_DATA_EXFILTRATION': ('T1041', 'Exfiltration Over C2 Channel', 'Exfiltration'),
            }.get(rule_id)
            if behavior_mitre:
                mitre_id, technique, mitre_tactic = behavior_mitre
                mitre_techniques = sorted({interpreter_mitre, mitre_id})
            if rule_id == 'SCRIPT_REMOTE_EXECUTION':
                capability_ids.add(14)
        if rule_id in ('PROC_SERVICE_CREATED', 'PROC_SERVICE_CONTROL', 'PROC_SECURITY_TOOL_TAMPER', 'PROC_SECURITY_TOOL_TERMINATED'):
            capability_ids.update((7, 24))
        if rule_id == 'PROC_SCHEDULED_TASK_CHANGE':
            capability_ids.update((7, 8))
            mitre_id, technique = 'T1053', 'Scheduled Task/Job'
        if rule_id in ('PROC_PRIVILEGED_COMMAND', 'PROC_PRIVILEGE_ESCALATION'):
            capability_ids.update((11, 13, 16))
            if rule_id == 'PROC_PRIVILEGE_ESCALATION':
                mitre_id, technique, mitre_tactic = 'T1548', 'Abuse Elevation Control Mechanism', 'Privilege Escalation'
        if rule_id in ('PROC_SECURITY_TOOL_TAMPER', 'PROC_SECURITY_TOOL_TERMINATED'):
            capability_ids.add(16)
            mitre_id, technique, mitre_tactic = 'T1562.001', 'Impair Defenses', 'Defense Evasion'
        if rule_id == 'PROC_SECURITY_LOG_CLEARED':
            capability_ids.add(16)
            mitre_id, technique, mitre_tactic = 'T1070.001', 'Clear Windows Event Logs', 'Defense Evasion'
        if rule_id == 'PROC_ARCHIVE_STAGING':
            capability_ids.update((12, 16))
            mitre_id, technique, mitre_tactic = 'T1560.001', 'Archive via Utility', 'Collection'
        if rule_id == 'SCRIPT_DATA_EXFILTRATION':
            capability_ids.add(12)
        if rule_id == 'PROC_INTERNAL_NETWORK_SCAN':
            capability_ids.update((3, 14))
        self._sender.enqueue({
            'rule_id': rule_id,
            'capabilityId': 21 if rule_id.startswith('SCRIPT_') else 1,
            'capabilityIds': sorted(capability_ids),
            'category': 'edr',
            'source': 'script_execution' if rule_id.startswith('SCRIPT_') else 'process',
            'severity': severity,
            'description': f'{title}: {name} (PID {pid}, parent {parent_name or ppid}, CPU {cpu:.1f}%, RAM {mem:.1f}%)',
            'eventType': 'script_execution' if rule_id.startswith('SCRIPT_') else rule_id.lower(),
            'actionable': rule_id.startswith('SCRIPT_') and rule_id != 'SCRIPT_EXECUTION_OBSERVED',
            'process_name': name,
            'pid': pid,
            'parent_pid': ppid,
            'parent_process_name': parent_name,
            'parent_cmdline': parent_cmdline[:800],
            'parent_username': item.get('parent_username', ''),
            'cpu_percent': round(cpu, 2),
            'memory_percent': round(mem, 2),
            'memory_mb': round(float(item.get('memory_mb') or 0), 2),
            'disk_read_bytes': int(item.get('disk_read_bytes') or 0),
            'disk_write_bytes': int(item.get('disk_write_bytes') or 0),
            'disk_read_bytes_per_second': round(float(item.get('disk_read_bytes_per_second') or 0), 2),
            'disk_write_bytes_per_second': round(float(item.get('disk_write_bytes_per_second') or 0), 2),
            'network_connection_count': int(item.get('network_connection_count') or 0),
            'external_connection_count': int(item.get('external_connection_count') or 0),
            'remote_addresses': item.get('remote_addresses') or [],
            'unique_remote_ip_count': int(item.get('unique_remote_ip_count') or 0),
            'unique_remote_port_count': int(item.get('unique_remote_port_count') or 0),
            'private_remote_ip_count': int(item.get('private_remote_ip_count') or 0),
            'process_classifications': item.get('classifications') or [],
            'executable_sha256': item.get('executable_sha256'),
            'executable_sha1': item.get('executable_sha1'),
            'executable_md5': item.get('executable_md5'),
            'signature_status': item.get('signature_status'),
            'trust_status': item.get('trust_status'),
            'publisher': item.get('publisher'),
            'certificate_subject': item.get('certificate_subject'),
            'certificate_issuer': item.get('certificate_issuer'),
            'certificate_serial': item.get('certificate_serial'),
            'certificate_thumbprint': item.get('certificate_thumbprint'),
            'certificate_valid_from': item.get('certificate_valid_from'),
            'certificate_valid_until': item.get('certificate_valid_until'),
            'package_owner': item.get('package_owner'),
            'package_verification_status': item.get('package_verification_status'),
            'username': item.get('username', ''),
            'exe': item.get('exe', ''),
            'cmdline': item.get('cmdline', '')[:800],
            'process_status': item.get('status', ''),
            'process_create_time': item.get('create_time'),
            'script_name': item.get('script_name'),
            'script_path': item.get('script_path'),
            'script_hash': item.get('script_hash'),
            'script_sha1': item.get('script_sha1'),
            'script_md5': item.get('script_md5'),
            'interpreter': item.get('interpreter'),
            'command_line': item.get('command_line') or item.get('cmdline', '')[:4000],
            'execution_source': item.get('execution_source'),
            'obfuscation_score': item.get('obfuscation_score', 0),
            'detection_reasons': item.get('detection_reasons') or [title],
            'risk_score': max(
                int(item.get('script_risk_score') or 0),
                {'low': 15, 'medium': 45, 'high': 70, 'critical': 90}.get(severity, 15),
            ) if rule_id.startswith('SCRIPT_') else None,
            'network_connections': item.get('remote_addresses') or [],
            'child_processes': [],
            'files_created': [],
            'files_modified': [],
            'files_deleted': [],
            'process_tree': [entry for entry in (
                {
                    'pid': ppid, 'name': parent_name, 'cmd': parent_cmdline[:800],
                    'status': 'Observed',
                } if parent_name else None,
                {
                    'pid': pid, 'name': name, 'path': item.get('exe', ''),
                    'cmd': item.get('cmdline', '')[:800],
                    'status': 'Critical' if severity == 'critical' else 'Suspicious' if severity in ('high', 'medium') else 'Observed',
                },
            ) if entry],
            'user_action': rule_id.lower(),
            'mitre_id': mitre_id,
            'technique': technique,
            'mitre_tactic': mitre_tactic,
            'mitre_techniques': mitre_techniques,
            'raw_log': (
                f'PROC|rule={rule_id}|name={name}|pid={pid}|ppid={ppid}|parent={parent_name}|'
                f'cpu={cpu:.2f}|mem={mem:.2f}|user={item.get("username","")}|exe={item.get("exe","")}|'
                f'cmd={item.get("cmdline","")[:300]}'
            ),
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _send_summary(self, processes: list):
        now = time.time()
        interval = self._cfg_float('process_inventory_interval_seconds', SUMMARY_INTERVAL)
        if now - self._last_summary < interval:
            return
        self._last_summary = now
        inventory = sorted(
            processes,
            key=lambda p: ((p.get('cpu') or 0), (p.get('mem') or 0)),
            reverse=True,
        )[:80]
        top_cpu = inventory[:10]
        top_mem = sorted(processes, key=lambda p: p.get('mem') or 0, reverse=True)[:10]
        cpu_threshold = self._cfg_float('process_cpu_threshold_percent', CPU_THRESHOLD)
        mem_threshold = self._cfg_float('process_memory_threshold_percent', MEM_THRESHOLD)
        suspicious_count = 0
        unauthorized_count = 0
        high_cpu_count = 0
        high_memory_count = 0
        high_disk_count = 0
        running_count = 0
        for item in processes:
            name = (item.get('name') or '').lower()
            cmdline = (item.get('cmdline') or '').lower()
            exe = item.get('exe') or ''
            status = (item.get('status') or '').lower()
            if status in ('running', 'sleeping', 'disk-sleep', 'idle') or not status:
                running_count += 1
            if any(s in name for s in SUSPICIOUS_NAMES) or any(s in cmdline for s in SUSPICIOUS_CMDLINE):
                suspicious_count += 1
            if self._is_unauthorized_execution(exe, cmdline):
                unauthorized_count += 1
            if float(item.get('cpu') or 0) > cpu_threshold:
                high_cpu_count += 1
            if float(item.get('mem') or 0) > mem_threshold:
                high_memory_count += 1
            if (float(item.get('disk_read_bytes_per_second') or 0) + float(item.get('disk_write_bytes_per_second') or 0)) > self._cfg_float('process_disk_io_threshold_bytes_per_second', DISK_IO_THRESHOLD_BYTES_PER_SECOND):
                high_disk_count += 1
        summary = {
            'process_count': len(processes),
            'running_count': running_count,
            'suspicious_count': suspicious_count,
            'unauthorized_count': unauthorized_count,
            'high_cpu_count': high_cpu_count,
            'high_memory_count': high_memory_count,
            'high_disk_count': high_disk_count,
            'cpu_threshold_percent': cpu_threshold,
            'memory_threshold_percent': mem_threshold,
            'processes': inventory,
            'top_cpu': top_cpu,
            'top_memory': top_mem,
        }
        self._sender.enqueue({
            'rule_id': 'PROC_INVENTORY_SUMMARY',
            'capabilityId': 1,
            'category': 'edr',
            'severity': 'low',
            'description': f'Running process inventory: {len(processes)} processes',
            'process_count': len(processes),
            'raw_log': str(summary)[:2000],
            'raw': summary,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })
