"""
core/memory_scanner.py
Memory Activity Monitoring — EDR capability #5

Fills the pre-wired slot in agent.py (`_import_class('core.memory_scanner', 'Scanner')`),
run on its own daemon thread every 60s via `run_and_report(sender=)`.

Complements core/memory_overflow.py (which covers crashes / heap-spray / RSS spikes).
This module targets the *offensive* memory-abuse gap that had no coverage:

  1. RWX / W^X-violating memory regions        (T1055  Process Injection / shellcode)
  2. Fileless execution — deleted / memfd exec  (T1620  Reflective Loading)
  3. LSASS / credential-dump activity           (T1003.001 LSASS Memory)
  4. Injection-tool & living-off-memory procs   (T1055 / T1003)
  5. High memory consumers snapshot             (feeds the "Top Memory Processes" table)
  6. Host memory pressure (RAM/swap)            (feeds the "Total Memory Usage" KPI)

Findings are shipped through the shared AlertSender (`sender.enqueue`) tagged with
`capabilityId=5` + `category='memory'`, which the backend already classifies and the
frontend MemoryActivityDashboardPanel already knows how to render.

Design constraints (matches the rest of the agent):
  * psutil is optional — degrade gracefully if missing.
  * Deep-memory reads are NOT performed (need ptrace/root + a kernel driver on Windows);
    we rely on /proc metadata + process attributes, which are cheap and safe.
  * Everything is wrapped so a single unreadable process never aborts a scan cycle.
  * The AlertSender already dedups (24h) and rate-limits (60s/key), so re-emitting the
    same finding each cycle is safe — it is collapsed downstream.

MITRE ATT&CK: T1055, T1055.001/002/012, T1003.001, T1620
"""

import os
import re
import time
import logging
import platform
from datetime import datetime, timezone
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import psutil
    HAS_PSUTIL = True
except Exception:                       # pragma: no cover
    HAS_PSUTIL = False

CAPABILITY_ID = 5                        # Memory Activity Monitoring (backend + UI contract)

# ── Tunables (overridable via agent config) ───────────────────────────────────
DEFAULTS = {
    'memory_scanner_maps_max':       500,   # max /proc/<pid>/maps to parse per cycle
    'memory_scanner_high_mem_pct':   15.0,  # process memory_percent to flag as "high"
    'memory_scanner_top_n':          8,     # top consumers reported for the table
    'memory_scanner_host_ram_pct':   90.0,  # host RAM usage % -> pressure alert
    'memory_scanner_host_swap_pct':  60.0,  # host swap usage % -> pressure alert
    'memory_rwx_detection_enabled':  True,
}

# Legit JIT / runtime engines that map RWX pages as normal behaviour — downgrade,
# don't suppress (an injected thread inside one still deserves a low-noise record).
JIT_RUNTIMES = {
    'java', 'javaw', 'node', 'node.exe', 'chrome', 'chrome.exe', 'msedge.exe',
    'firefox', 'firefox.exe', 'mono', 'dotnet', 'python', 'python3', 'ruby',
    'code', 'code.exe', 'electron', 'wine', 'wine64', 'clr.dll',
}

# Credential-dump / injection tooling (name or cmdline match). Case-insensitive.
CRED_DUMP_PATTERNS = re.compile(
    r'mimikatz|sekurlsa|lsadump|procdump|lsassy|gsecdump|wce\.exe|'
    r'comsvcs\.dll|minidump|nanodump|pypykatz|dumpert|sqldumper|'
    r'reg\s+save.*sam|reg\s+save.*system',
    re.I,
)

# Generic shellcode / injection tradecraft seen on a command line.
INJECTION_CMDLINE = re.compile(
    r'virtualalloc|writeprocessmemory|createremotethread|ntmapviewofsection|'
    r'reflectiveloader|-enc\b|-encodedcommand|frombase64string|iex\s*\(|'
    r'shellcode|inject|memfd_create',
    re.I,
)

# Windows protected processes whose memory should never be opened by userland tools.
PROTECTED_PROCESSES = {
    'lsass.exe', 'winlogon.exe', 'csrss.exe', 'services.exe', 'smss.exe',
}


class MemoryScanner:
    """Real-time memory-activity threat scanner (EDR capability #5)."""

    def __init__(self, config=None):
        self.config  = config
        self.os_type = platform.system().lower()          # 'linux' | 'windows' | 'darwin'
        self._findings: List[Dict] = []
        # Emit the (noisy but useful) inventory snapshots less often than threats.
        self._cycle = 0

    # ── config helper ─────────────────────────────────────────────────────────
    def _cfg(self, key: str):
        default = DEFAULTS[key]
        try:
            if self.config is not None:
                return self.config.get(key, default)
        except Exception:
            pass
        return default

    # ── /proc/<pid>/maps parsing (Linux) ──────────────────────────────────────
    @staticmethod
    def _parse_maps(pid: int) -> Optional[List[Dict]]:
        """Return list of {perms, path} for a pid, or None if unreadable."""
        try:
            with open(f'/proc/{pid}/maps', 'r', errors='replace') as fh:
                rows = []
                for line in fh:
                    # addr perms offset dev inode  pathname
                    parts = line.split(maxsplit=5)
                    if len(parts) < 5:
                        continue
                    perms = parts[1]
                    path  = parts[5].strip() if len(parts) == 6 else ''
                    rows.append({'perms': perms, 'path': path})
                return rows
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None

    def _scan_maps_linux(self) -> List[Dict]:
        """Detect RWX regions and fileless (deleted / memfd) executable mappings."""
        findings: List[Dict] = []
        if self.os_type != 'linux' or not HAS_PSUTIL or not bool(self._cfg('memory_rwx_detection_enabled')):
            return findings

        budget = int(self._cfg('memory_scanner_maps_max'))
        scanned = 0
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'ppid']):
            if scanned >= budget:
                break
            try:
                pid = proc.info['pid']
                if pid <= 1:
                    continue
                maps = self._parse_maps(pid)
                if maps is None:
                    continue
                scanned += 1

                name   = (proc.info.get('name') or 'unknown')
                exe    = proc.info.get('exe') or ''
                user   = proc.info.get('username') or ''
                ppid   = proc.info.get('ppid')
                is_jit = name.lower() in JIT_RUNTIMES

                # Two distinct signals, deliberately narrow to stay low-noise:
                #   * file_rwx  = a real file's code mapped writable+executable (W^X
                #     violation) — abnormal even for JIT engines, which use *anonymous*
                #     RWX. Rare and high-signal.
                #   * fileless  = executable region backed by a deleted file / memfd —
                #     reflective loading / in-memory payload.
                # Anonymous RWX (JIT/heap) is intentionally NOT alerted: on any desktop
                # it fires for every Chromium/Electron/JVM process and buries real hits.
                file_rwx, fileless_paths = [], []
                anon_rwx = 0
                for m in maps:
                    perms, path = m['perms'], m['path']
                    if 'x' not in perms:
                        continue
                    if 'w' in perms:
                        if path.startswith('/'):
                            file_rwx.append(path)
                        else:
                            anon_rwx += 1
                    if '(deleted)' in path or 'memfd:' in path:
                        fileless_paths.append(path)

                if fileless_paths:
                    findings.append(self._finding(
                        rule_id='MEM_FILELESS_EXEC',
                        sub='Fileless Malware', event='In-Memory Payload',
                        severity='critical', risk=92, mitre='T1620',
                        proc=proc, name=name, pid=pid, ppid=ppid, exe=exe, user=user,
                        desc=(f'Fileless execution: {name} (PID {pid}) has executable memory '
                              f'backed by a deleted/anonymous file — reflective loading indicator'),
                        recommended='Isolate through the approved workflow, preserve process metadata, and verify the executable and process tree',
                        raw_extra={'regions': fileless_paths[:10], 'anon_rwx': anon_rwx},
                    ))

                if file_rwx:
                    findings.append(self._finding(
                        rule_id='MEM_RWX_REGION',
                        sub='RWX Memory', event='RWX Memory Region',
                        severity='high', risk=80, mitre='T1055',
                        proc=proc, name=name, pid=pid, ppid=ppid, exe=exe, user=user,
                        desc=(f'Writable+executable file-backed code in {name} (PID {pid}) — '
                              f'{len(file_rwx)} region(s); possible code patching / injection'),
                        recommended='Investigate process injection or code patching; preserve limited metadata and consider approved isolation',
                        raw_extra={'rwx_files': file_rwx[:5], 'anon_rwx': anon_rwx,
                                   'jit_runtime': is_jit},
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:                       # never let one proc kill the scan
                logger.debug(f'[MemScanner] maps scan skip pid: {e}')
                continue
        return findings

    # ── Credential-dump / injection-tool detection (all platforms) ─────────────
    def _scan_processes(self) -> List[Dict]:
        findings: List[Dict] = []
        if not HAS_PSUTIL:
            return findings

        for proc in psutil.process_iter(
                ['pid', 'name', 'username', 'exe', 'cmdline', 'ppid', 'memory_percent']):
            try:
                info    = proc.info
                pid     = info['pid']
                name    = info.get('name') or 'unknown'
                cmdline = ' '.join(info.get('cmdline') or [])[:800]
                haystack = f'{name} {cmdline} {info.get("exe") or ""}'
                ppid    = info.get('ppid')
                user    = info.get('username') or ''
                mem_pct = info.get('memory_percent')

                # 1) Credential dumping tooling
                if CRED_DUMP_PATTERNS.search(haystack):
                    findings.append(self._finding(
                        rule_id='MEM_CRED_DUMP',
                        sub='Credential Dumping', event='Credential Dumping',
                        severity='critical', risk=95, mitre='T1003.001',
                        proc=proc, name=name, pid=pid, ppid=ppid,
                        exe=info.get('exe') or '', user=user, mem_pct=mem_pct, cmdline=cmdline,
                        desc=f'Credential-dumping tool/technique detected: {name} (PID {pid})',
                        recommended='Validate the finding, then use approved containment to suspend the process or isolate the host; rotate exposed credentials and hunt for lateral movement',
                    ))

                # 2) Generic injection / shellcode tradecraft on the command line
                elif INJECTION_CMDLINE.search(cmdline):
                    findings.append(self._finding(
                        rule_id='MEM_INJECTION_CMDLINE',
                        sub='Process Injection', event='Process Injection Detected',
                        severity='high', risk=82, mitre='T1055',
                        proc=proc, name=name, pid=pid, ppid=ppid,
                        exe=info.get('exe') or '', user=user, mem_pct=mem_pct, cmdline=cmdline,
                        desc=f'Memory-injection tradecraft in command line: {name} (PID {pid})',
                        recommended='Investigate the parent process, preserve limited forensic metadata, and isolate if confirmed',
                    ))

                # 3) A userland process apparently opening a protected process' memory
                #    (Windows heuristic: name references lsass + a dump verb).
                elif (self.os_type == 'windows'
                      and 'lsass' in haystack.lower()
                      and name.lower() not in PROTECTED_PROCESSES):
                    findings.append(self._finding(
                        rule_id='MEM_LSASS_ACCESS',
                        sub='LSASS Access', event='LSASS Memory Access',
                        severity='critical', risk=90, mitre='T1003.001',
                        proc=proc, name=name, pid=pid, ppid=ppid,
                        exe=info.get('exe') or '', user=user, mem_pct=mem_pct, cmdline=cmdline,
                        desc=f'Non-system process referencing LSASS memory: {name} (PID {pid})',
                        recommended='Verify legitimacy, use approved containment if unauthorized, and rotate potentially exposed credentials',
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f'[MemScanner] proc scan skip: {e}')
                continue
        return findings

    # ── Top memory consumers snapshot (feeds the dashboard table / KPI) ────────
    def _scan_top_memory(self) -> List[Dict]:
        """Emit the current top-N processes by memory as low-severity inventory so the
        'Top Memory Consuming Processes' table shows real, live data. Processes over
        the high-mem threshold are bumped to 'medium' as a runaway/heap-spray hint."""
        findings: List[Dict] = []
        if not HAS_PSUTIL:
            return findings

        top_n        = int(self._cfg('memory_scanner_top_n'))
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'ppid', 'memory_percent', 'memory_info']):
            try:
                mp = proc.info.get('memory_percent')
                if mp:
                    procs.append((mp, proc.info))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        procs.sort(key=lambda x: x[0], reverse=True)

        for mem_pct, info in procs[:top_n]:
            memory = info.get('memory_info')
            rss = int(getattr(memory, 'rss', 0) or 0)
            findings.append({
                'rule_id': 'MEM_PROCESS_METRIC', 'capabilityId': CAPABILITY_ID,
                'capabilityIds': [CAPABILITY_ID, 29], 'category': 'memory',
                'subCategory': 'Process Memory Metrics', 'eventType': 'memory.metric',
                'severity': 'low', 'riskScore': 0, 'confidenceScore': 100,
                'actionable': False, 'user_action': 'memory_metric',
                'description': f'Process memory metric: {info.get("name") or "unknown"} (PID {info["pid"]}) {rss / 1024 / 1024:.1f} MiB',
                'memory_metric_type': 'process', 'process_name': info.get('name') or 'unknown',
                'pid': info['pid'], 'parent_pid': info.get('ppid'),
                'process_exe': info.get('exe') or '', 'username': info.get('username') or '',
                'memory_percent': round(float(mem_pct), 2), 'memory_mb': round(rss / 1024 / 1024, 2),
                'process_rss_bytes': rss, 'virtual_memory_bytes': getattr(memory, 'vms', None),
                'shared_memory_bytes': getattr(memory, 'shared', None),
                'source': 'memory_activity_scanner', 'timestamp': datetime.now(timezone.utc).isoformat(),
            })
        return findings

    # ── Host memory pressure ───────────────────────────────────────────────────
    def _scan_host_memory(self) -> List[Dict]:
        findings: List[Dict] = []
        if not HAS_PSUTIL:
            return findings
        try:
            vm = psutil.virtual_memory()
            sw = psutil.swap_memory()
            ram_pct  = vm.percent
            swap_pct = sw.percent
            raw = {
                'total_mb':  round(vm.total / 1024 / 1024),
                'used_mb':   round(vm.used  / 1024 / 1024),
                'free_mb':   round(vm.available / 1024 / 1024),
                'ram_pct':   ram_pct,
                'swap_total_mb': round(sw.total / 1024 / 1024),
                'swap_used_mb':  round(sw.used  / 1024 / 1024),
                'swap_pct':  swap_pct,
            }
            findings.append({
                'rule_id': 'MEM_HOST_METRIC', 'capabilityId': CAPABILITY_ID,
                'capabilityIds': [CAPABILITY_ID, 29], 'category': 'memory',
                'subCategory': 'Memory Metrics', 'eventType': 'memory.metric',
                'severity': 'low', 'riskScore': 0, 'confidenceScore': 100,
                'actionable': False, 'user_action': 'memory_metric',
                'description': f'Host memory metric: RAM {ram_pct:.1f}%, swap {swap_pct:.1f}%',
                'memory_metric_type': 'host', 'memory_total_bytes': vm.total,
                'memory_used_bytes': vm.used, 'memory_available_bytes': vm.available,
                'memory_percent': round(ram_pct, 2), 'memory_pressure': round(ram_pct, 2),
                'swap_total_bytes': sw.total, 'swap_used_bytes': sw.used,
                'swap_percent': round(swap_pct, 2), 'commit_charge_bytes': vm.used + sw.used,
                'source': 'memory_activity_scanner', 'timestamp': datetime.now(timezone.utc).isoformat(),
            })
            if (ram_pct >= float(self._cfg('memory_scanner_host_ram_pct'))
                    or swap_pct >= float(self._cfg('memory_scanner_host_swap_pct'))):
                findings.append({
                    'rule_id': 'MEM_HOST_PRESSURE',
                    'capabilityId': CAPABILITY_ID, 'capabilityIds': [CAPABILITY_ID, 29], 'category': 'memory',
                    'subCategory': 'Memory Pressure', 'eventType': 'Host Memory Pressure',
                    'severity': 'medium', 'riskScore': 40, 'mitreId': 'T1499',
                    'description': (f'Host memory pressure: RAM {ram_pct:.0f}% used, '
                                    f'swap {swap_pct:.0f}% used'),
                    'recommendedAction': 'Review top memory processes for leaks or abuse',
                    'user_action': 'memory_activity', 'memory_percent': ram_pct,
                    'memory_total_bytes': vm.total, 'memory_used_bytes': vm.used,
                    'memory_available_bytes': vm.available, 'memory_pressure': ram_pct,
                    'swap_total_bytes': sw.total, 'swap_used_bytes': sw.used, 'swap_percent': swap_pct,
                    'raw': raw, 'raw_log': f'RAM={ram_pct}% SWAP={swap_pct}%',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
        except Exception as e:
            logger.debug(f'[MemScanner] host memory read failed: {e}')
        return findings

    # ── Finding builder → canonical capabilityId=5 alert dict ──────────────────
    def _finding(self, *, rule_id, sub, event, severity, risk, mitre,
                 proc=None, name='', pid=-1, ppid=None, exe='', user='',
                 mem_pct=None, cmdline='', desc='', recommended='', raw_extra=None) -> Dict:
        raw = {
            'process': name, 'pid': pid, 'parent_pid': ppid, 'exe': exe,
            'username': user, 'threat_type': sub, 'os': self.os_type,
        }
        if raw_extra:
            raw.update(raw_extra)
        alert = {
            'rule_id':          rule_id,
            'capabilityId':     CAPABILITY_ID,
            'capabilityIds':    [CAPABILITY_ID, 29],
            'category':         'memory',
            'subCategory':      sub,
            'eventType':        event,
            'severity':         severity,
            'riskScore':        risk,
            'mitreId':          mitre,
            'technique':        sub,
            'description':      desc,
            'recommendedAction': recommended,
            'user_action':      'memory_activity',
            'process_name':     name,
            'pid':              pid,
            'parent_pid':       ppid,
            'exe':              exe,
            'username':         user,
            'raw':              raw,
            'raw_log':          desc,
            'timestamp':        datetime.now(timezone.utc).isoformat(),
        }
        if mem_pct is not None:
            alert['memory_percent'] = round(float(mem_pct), 2)
        if cmdline:
            alert['cmdline'] = cmdline
        return alert

    # ── Public API (contract expected by agent.py:390) ─────────────────────────
    def run_and_report(self, sender=None) -> List[Dict]:
        """Run one full memory-activity scan; emit findings; return them."""
        self._cycle += 1
        findings: List[Dict] = []
        try:
            findings += self._scan_maps_linux()      # Linux: RWX + fileless
            findings += self._scan_processes()        # all OS: cred-dump / injection / lsass
            findings += self._scan_top_memory()       # all OS: top-N memory inventory
            findings += self._scan_host_memory()      # all OS: RAM/swap pressure
        except Exception as e:
            logger.warning(f'[MemScanner] scan cycle error: {e}')

        self._findings.extend(findings)
        self._findings = self._findings[-500:]        # bound in-memory history

        if findings and sender is not None:
            for f in findings:
                try:
                    sender.enqueue(f)                 # sender adds identity + HMAC + ships
                except Exception as e:
                    logger.error(f'[MemScanner] send error: {e}')

        if findings:
            crit = sum(1 for f in findings if f.get('severity') in ('critical', 'high'))
            logger.warning(f'[MemScanner] {len(findings)} memory events '
                           f'({crit} high/critical) — capability #{CAPABILITY_ID}')
        return findings

    def recent(self, limit: int = 50) -> List[Dict]:
        return self._findings[-limit:]


# Backwards-friendly alias: agent.py looks for the first class whose name ends in
# "Scanner"; both names resolve to the same implementation.
Scanner = MemoryScanner
