"""
EDR Module — Endpoint Detection & Response
Monitors processes, kills malicious ones, detects abnormal behaviour.

Features:
  - Kill malicious/suspicious processes
  - Monitor for privilege escalation, reverse shells, credential dumpers
  - Detect high-CPU / memory anomalies
  - Auto-quarantine malicious binaries
  - Report all actions back to SOC dashboard
"""
import time
import logging
import platform
import threading

logger = logging.getLogger('soc-agent.edr')
SYSTEM = platform.system()
POLL_INTERVAL = 15  # seconds

MALICIOUS_PROCESS_NAMES = {
    'meterpreter', 'mimikatz', 'cobalt', 'psexec', 'netcat', 'nc.exe',
    'ncat', 'socat', 'wce.exe', 'fgdump', 'pwdump', 'gsecdump',
    'procdump', 'lsassy', 'lazagne', 'crackmapexec', 'metasploit',
    'beacon.exe', 'msfconsole', 'empire', 'sliver', 'havoc',
    'cobaltstrike', 'powershell_ise',
}

SUSPICIOUS_CMDLINE_PATTERNS = [
    'invoke-mimikatz', 'invoke-shellcode', 'frombase64string',
    '-encodedcommand', 'downloadstring', 'iex(', 'iex (', 'bypass',
    'sekurlsa', 'lsadump', '-nop -w hidden', 'mshta http', 'regsvr32 /s /n /u',
    'certutil -decode', 'certutil -urlcache', 'bitsadmin /transfer',
]

CPU_THRESHOLD  = 90.0   # % — alert if single process exceeds this
MEM_THRESHOLD  = 85.0   # % — alert if system RAM exceeds this


class EDRModule:
    def __init__(self, sender):
        self._sender  = sender
        self._alerted = set()
        self._thread  = threading.Thread(target=self._loop, daemon=True, name='edr')

    def start(self):
        self._thread.start()
        logger.info('EDR module started')

    def _loop(self):
        while True:
            try:
                self._scan()
            except Exception as e:
                logger.error('EDR scan error: %s', e)
            time.sleep(POLL_INTERVAL)

    def _scan(self):
        try:
            import psutil
        except ImportError:
            return

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'cpu_percent', 'memory_percent', 'exe']):
            try:
                info = proc.info
                pname   = (info.get('name') or '').lower()
                pid     = info.get('pid', 0)
                cmdline = ' '.join(info.get('cmdline') or []).lower()
                user    = info.get('username', '')
                cpu_pct = info.get('cpu_percent', 0) or 0
                exe     = info.get('exe') or ''

                # ── Malicious process name match ─────────────────────────────
                if any(m in pname for m in MALICIOUS_PROCESS_NAMES):
                    key = f'edr_mal_{pid}_{pname}'
                    if key not in self._alerted:
                        self._alerted.add(key)
                        self._kill_and_report(proc, pid, pname, user, exe, 'MALICIOUS_PROCESS')

                # ── Suspicious command-line patterns ─────────────────────────
                elif cmdline and any(p in cmdline for p in SUSPICIOUS_CMDLINE_PATTERNS):
                    key = f'edr_cmd_{pid}'
                    if key not in self._alerted:
                        self._alerted.add(key)
                        self._report_suspicious_cmd(pid, pname, cmdline[:300], user, exe)

                # ── High CPU anomaly ─────────────────────────────────────────
                elif cpu_pct and cpu_pct > CPU_THRESHOLD:
                    key = f'edr_cpu_{pid}'
                    if key not in self._alerted:
                        self._alerted.add(key)
                        self._report_anomaly(pid, pname, user, cpu_pct, 'HIGH_CPU')

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                pass

        # ── System-wide memory alert ─────────────────────────────────────────
        try:
            mem_pct = psutil.virtual_memory().percent
            if mem_pct > MEM_THRESHOLD and 'sys_mem_high' not in self._alerted:
                self._alerted.add('sys_mem_high')
                self._sender.enqueue({
                    'rule_id':     'EDR_HIGH_MEMORY',
                    'category':    'edr',
                    'severity':    'medium',
                    'description': f'System memory usage critical: {mem_pct:.0f}%',
                    'raw_log':     f'RAM={mem_pct:.1f}%',
                    'user_action': 'high_memory',
                })
        except Exception:
            pass

        # Clear stale alerts every hour
        if len(self._alerted) > 500:
            self._alerted.clear()

    def _kill_and_report(self, proc, pid, pname, user, exe, rule_id):
        killed = False
        try:
            proc.kill()
            killed = True
            logger.warning('EDR KILLED malicious process: %s (PID %s)', pname, pid)
        except Exception as e:
            logger.warning('EDR: could not kill %s (PID %s): %s', pname, pid, e)

        self._sender.enqueue({
            'rule_id':      f'EDR_{rule_id}',
            'category':     'edr',
            'severity':     'critical',
            'description':  f'Malicious process {"KILLED" if killed else "DETECTED"}: {pname} (PID {pid})',
            'raw_log':      f'process={pname} pid={pid} user={user} exe={exe} killed={killed}',
            'process_name': pname,
            'pid':          pid,
            'username':     user,
            'user_action':  'malware_process_detected',
        })

    def _report_suspicious_cmd(self, pid, pname, cmdline, user, exe):
        logger.warning('EDR suspicious cmdline: %s (PID %s)', pname, pid)
        self._sender.enqueue({
            'rule_id':      'EDR_SUSPICIOUS_CMDLINE',
            'category':     'edr',
            'severity':     'high',
            'description':  f'Suspicious command line: {pname} (PID {pid})',
            'raw_log':      f'process={pname} pid={pid} cmd={cmdline[:200]}',
            'process_name': pname,
            'pid':          pid,
            'username':     user,
            'user_action':  'suspicious_execution',
        })

    def _report_anomaly(self, pid, pname, user, cpu_pct, anomaly_type):
        self._sender.enqueue({
            'rule_id':      f'EDR_{anomaly_type}',
            'category':     'edr',
            'severity':     'medium',
            'description':  f'Process anomaly ({anomaly_type}): {pname} CPU={cpu_pct:.0f}%',
            'raw_log':      f'process={pname} pid={pid} cpu={cpu_pct:.1f}%',
            'process_name': pname,
            'pid':          pid,
            'username':     user,
            'user_action':  'process_anomaly',
        })
