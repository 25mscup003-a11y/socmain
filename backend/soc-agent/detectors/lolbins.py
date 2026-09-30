"""
LOLBins Detector — Living-off-the-Land Binary Detection
Monitors process creation events for suspicious use of built-in OS tools.
Integrates with the existing agent sender pipeline.
"""

import re
import time
import logging
import platform
import threading
import hashlib
import os
import subprocess
import queue
from datetime import datetime, timezone

logger = logging.getLogger('soc-agent.lolbins')
SYSTEM = platform.system()


def _hashes(path: str) -> tuple[str, str]:
    """Hash a suspicious executable in one bounded, streaming pass."""
    try:
        if not path or not os.path.isfile(path) or os.path.getsize(path) > 100 * 1024 * 1024:
            return '', ''
        sha256 = hashlib.sha256()
        try:
            md5 = hashlib.md5(usedforsecurity=False)
        except TypeError:  # Python < 3.9 agent compatibility
            md5 = hashlib.md5()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest(), md5.hexdigest()
    except (OSError, PermissionError, TypeError):
        return '', ''


def _windows_file_metadata(path: str) -> dict:
    """Read Authenticode/version metadata only for an alerted executable.

    Results are cached by the detector, so this never runs in the normal
    process polling hot path more than once per executable.
    """
    if SYSTEM != 'Windows' or not path:
        return {}
    escaped = path.replace("'", "''")
    script = (
        f"$p='{escaped}';$s=Get-AuthenticodeSignature -LiteralPath $p;"
        "$v=(Get-Item -LiteralPath $p).VersionInfo;"
        "[pscustomobject]@{signature_status=$s.Status.ToString();"
        "publisher=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''};"
        "company=$v.CompanyName;version=$v.FileVersion}|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, timeout=4, check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        import json
        return json.loads(result.stdout.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}

# ── Windows LOLBins registry ─────────────────────────────────────────────────
WINDOWS_LOLBINS = {
    'powershell.exe', 'powershell', 'cmd.exe', 'cmd',
    'wmic.exe', 'wmic', 'rundll32.exe', 'rundll32',
    'regsvr32.exe', 'regsvr32', 'mshta.exe', 'mshta',
    'certutil.exe', 'certutil', 'bitsadmin.exe', 'bitsadmin',
    'cscript.exe', 'cscript', 'wscript.exe', 'wscript',
    'installutil.exe', 'installutil', 'msbuild.exe', 'msbuild',
    'reg.exe', 'reg', 'net.exe', 'net', 'netsh.exe', 'netsh',
    'sc.exe', 'sc', 'schtasks.exe', 'schtasks',
    'psexec.exe', 'psexec', 'explorer.exe',
    'ftp.exe', 'ftp', 'curl.exe', 'curl',
    'winget.exe', 'winget', 'robocopy.exe', 'robocopy',
    'xcopy.exe', 'xcopy', 'bcdedit.exe', 'bcdedit',
    'diskshadow.exe', 'diskshadow', 'forfiles.exe', 'forfiles',
    'odbcconf.exe', 'odbcconf', 'control.exe', 'mmc.exe', 'mmc',
    'presentationhost.exe', 'rasautou.exe',
    'syncappvpublishingserver.exe',
}

# ── Linux LOLBins registry ───────────────────────────────────────────────────
LINUX_LOLBINS = {
    'bash', 'sh', 'dash', 'zsh', 'ksh', 'fish',
    'curl', 'wget', 'scp', 'ssh', 'nc', 'netcat', 'ncat',
    'python', 'python2', 'python3', 'python3.10', 'python3.11', 'python3.12',
    'perl', 'ruby', 'php', 'php7', 'php8',
    'tar', 'find', 'chmod', 'chown', 'crontab',
    'systemctl', 'journalctl', 'screen', 'tmux',
    'socat', 'openssl', 'gpg', 'rsync', 'mount', 'umount',
    'awk', 'gawk', 'mawk', 'sed', 'tee', 'base64',
    'dd', 'xxd', 'od', 'strings', 'strace', 'ltrace',
    'gdb', 'nmap', 'tcpdump', 'wireshark',
    'git', 'svn', 'pip', 'pip3', 'npm', 'node',
    'docker', 'kubectl', 'helm',
}

# ── Suspicious pattern matchers ──────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [

    # PowerShell encoded commands
    (re.compile(r'powershell.*(-[Ee]nc|-EncodedCommand)', re.IGNORECASE),
     'Encoded PowerShell command', 'T1059.001', 'critical'),
    (re.compile(r'powershell.*(IEX|Invoke-Expression|FromBase64String)', re.IGNORECASE),
     'PowerShell in-memory execution', 'T1059.001', 'critical'),
    (re.compile(r'powershell.*(bypass|hidden|NonInteractive|noprofile)', re.IGNORECASE),
     'PowerShell execution policy bypass', 'T1059.001', 'high'),

    # PowerShell download cradles
    (re.compile(r'powershell.*(Invoke-WebRequest|DownloadFile|DownloadString|Net\.WebClient|Start-BitsTransfer)', re.IGNORECASE),
     'PowerShell download cradle', 'T1105', 'critical'),

    # CMD abuse
    (re.compile(r'cmd\s+/[ckrq].*powershell', re.IGNORECASE),
     'CMD spawning PowerShell', 'T1059.003', 'high'),
    (re.compile(r'cmd\s+/[ckrq].*(mshta|certutil|rundll32|regsvr32|wscript|cscript)', re.IGNORECASE),
     'CMD spawning LOLBin', 'T1059.003', 'high'),
    (re.compile(r'(?:^|[\\/])?cmd(?:\.exe)?\s+/(?:c|k)\b', re.IGNORECASE),
     'Command shell execution', 'T1059.003', 'medium'),

    # WMIC abuse
    (re.compile(r'wmic.*process.*call.*create', re.IGNORECASE),
     'WMIC process creation', 'T1047', 'critical'),
    (re.compile(r'wmic.*(shadowcopy.*delete|shadow.*delete)', re.IGNORECASE),
     'WMIC shadow copy deletion', 'T1490', 'critical'),
    (re.compile(r'wmic.*(node:|/node:)', re.IGNORECASE),
     'Remote WMIC execution', 'T1047', 'high'),
    (re.compile(r'wmic.*(?:__eventfilter|commandlineeventconsumer|filtertoconsumerbinding)', re.IGNORECASE),
     'WMI event subscription persistence', 'T1546.003', 'critical'),

    # Rundll32 abuse
    (re.compile(r'rundll32.*(temp|appdata|downloads|public|\\\\|\.txt|\.jpg|\.png)', re.IGNORECASE),
     'Rundll32 executing from suspicious location', 'T1218.011', 'critical'),
    (re.compile(r'rundll32.*javascript:', re.IGNORECASE),
     'Rundll32 JavaScript execution', 'T1218.011', 'critical'),

    # Regsvr32 abuse
    (re.compile(r'regsvr32.*/s.*/n.*/i:', re.IGNORECASE),
     'Regsvr32 scriptlet execution', 'T1218.010', 'critical'),
    (re.compile(r'regsvr32.*(http://|https://|ftp://)', re.IGNORECASE),
     'Regsvr32 remote scriptlet', 'T1218.010', 'critical'),

    # Mshta abuse
    (re.compile(r'mshta.*(http://|https://|javascript:|vbscript:)', re.IGNORECASE),
     'Mshta remote HTA execution', 'T1218.005', 'critical'),

    # Certutil abuse
    (re.compile(r'certutil.*((-urlcache|-decode|-verifyctl|-encode)|(http://|https://))', re.IGNORECASE),
     'Certutil file download/decode abuse', 'T1105', 'critical'),

    # Bitsadmin abuse
    (re.compile(r'bitsadmin.*(transfer|download|/create|/addfile)', re.IGNORECASE),
     'Bitsadmin file transfer', 'T1197', 'high'),

    # InstallUtil abuse
    (re.compile(r'installutil.*/logfile=|installutil.*\\.txt|\\.xml|\\.inf', re.IGNORECASE),
     'InstallUtil executing unknown assembly', 'T1218.004', 'high'),

    # MSBuild abuse
    (re.compile(r'msbuild.*(\.xml|\.csproj|\.proj).*(/p:|/t:|/target:)', re.IGNORECASE),
     'MSBuild inline task execution', 'T1127.001', 'high'),

    # Linux suspicious patterns
    (re.compile(r'(bash|sh|zsh|dash)\s+-[ic]\s*[\'"]?(wget|curl|nc |netcat|socat|python|perl|ruby)', re.IGNORECASE),
     'Shell executing remote payload', 'T1059.004', 'critical'),
    (re.compile(r'(curl|wget)\s+.*\s*\|\s*(bash|sh|python|perl)', re.IGNORECASE),
     'Download and execute pipe', 'T1105', 'critical'),
    (re.compile(r'base64\s+(-d|--decode)', re.IGNORECASE),
     'Base64 decode execution', 'T1027', 'high'),
    (re.compile(r'(python|python3|perl|ruby)\s+-[ce]\s*["\']', re.IGNORECASE),
     'Script interpreter inline execution', 'T1059', 'high'),
    (re.compile(r'(nc|netcat|ncat)\s+.*(-e|-c)\s*(bash|sh|cmd|powershell)', re.IGNORECASE),
     'Netcat reverse shell', 'T1059', 'critical'),
    (re.compile(r'crontab\s+-[lr]|echo.*\*\s*\*\s*\*.*>>\s*/etc/cron', re.IGNORECASE),
     'Cron persistence modification', 'T1053.003', 'high'),
    (re.compile(r'(chmod|chown)\s+[0-9]{3,4}\s+.*/(tmp|dev/shm|var/tmp)', re.IGNORECASE),
     'Suspicious permission change in temp', 'T1222.002', 'high'),
    (re.compile(r'find\s+.*/\s+.*-perm\s+(-?[0-9]{3,4}|-u=s|-g=s)', re.IGNORECASE),
     'SUID/SGID binary search', 'T1548.001', 'high'),

    # Lateral movement
    (re.compile(r'(psexec|psexesvc)', re.IGNORECASE),
     'PsExec lateral movement', 'T1021.002', 'critical'),
    (re.compile(r'wmic.*(/node:|node=).*process', re.IGNORECASE),
     'Remote WMIC lateral movement', 'T1021.003', 'high'),
    (re.compile(r'(net\s+use|net\s+view|net\s+session).*\\\\.+\\', re.IGNORECASE),
     'Admin share access', 'T1021.002', 'high'),
    (re.compile(r'powershell(?:\.exe)?.*(?:invoke-command\s+.*-computername|\s-session(?:\s|$))', re.IGNORECASE),
     'Remote PowerShell execution', 'T1021.006', 'high'),

    # Persistence
    (re.compile(r'(reg\s+add|Set-ItemProperty).*(\\Run\\|\\RunOnce\\)', re.IGNORECASE),
     'Registry run key persistence', 'T1547.001', 'high'),
    (re.compile(r'schtasks.*/create', re.IGNORECASE),
     'Scheduled task creation', 'T1053.005', 'high'),
    (re.compile(r'(sc\s+create|sc\s+config|New-Service)\s+', re.IGNORECASE),
     'Service creation for persistence', 'T1543.003', 'high'),

    # Fileless / in-memory
    (re.compile(r'(Invoke-Shellcode|Invoke-ReflectivePEInjection|PowerSploit|Invoke-Mimikatz)', re.IGNORECASE),
     'Fileless PowerShell framework detected', 'T1055', 'critical'),
    (re.compile(r'(amsibypass|AMSI.*bypass|Set-MpPreference.*Disable)', re.IGNORECASE),
     'AMSI bypass attempt', 'T1562.001', 'critical'),

    # Credential access
    (re.compile(r'(mimikatz|sekurlsa|lsadump|DCSync|kerberoast|Pass-the-Hash)', re.IGNORECASE),
     'Credential dumping tool detected', 'T1003', 'critical'),
    (re.compile(r'(procdump|task.*lsass|lsass.*dump|minidump.*lsass)', re.IGNORECASE),
     'LSASS memory dump attempt', 'T1003.001', 'critical'),
]

# ── Suspicious parent → child process combos ─────────────────────────────────
SUSPICIOUS_PARENT_CHILD = {
    ('winword.exe',   'powershell.exe'): ('Office spawning PowerShell', 'T1566.001', 'critical'),
    ('winword.exe',   'cmd.exe'):        ('Office spawning CMD', 'T1566.001', 'high'),
    ('excel.exe',     'powershell.exe'): ('Excel spawning PowerShell', 'T1566.001', 'critical'),
    ('excel.exe',     'cmd.exe'):        ('Excel spawning CMD', 'T1566.001', 'high'),
    ('outlook.exe',   'cmd.exe'):        ('Outlook spawning CMD', 'T1566.002', 'high'),
    ('outlook.exe',   'powershell.exe'): ('Outlook spawning PowerShell', 'T1566.002', 'critical'),
    ('acrobat.exe',   'powershell.exe'): ('PDF reader spawning PowerShell', 'T1566', 'critical'),
    ('acrobat.exe',   'cmd.exe'):        ('PDF reader spawning CMD', 'T1566', 'high'),
    ('acrord32.exe',  'powershell.exe'): ('PDF reader spawning PowerShell', 'T1566', 'critical'),
    ('acrord32.exe',  'cmd.exe'):        ('PDF reader spawning CMD', 'T1566', 'high'),
    ('chrome.exe',    'powershell.exe'): ('Browser spawning PowerShell', 'T1566', 'critical'),
    ('firefox.exe',   'powershell.exe'): ('Browser spawning PowerShell', 'T1566', 'critical'),
    ('msedge.exe',    'powershell.exe'): ('Browser spawning PowerShell', 'T1566', 'critical'),
    ('chrome.exe',    'mshta.exe'):      ('Browser spawning Mshta', 'T1218.005', 'critical'),
    ('chrome.exe',    'rundll32.exe'):   ('Browser spawning Rundll32', 'T1218.011', 'critical'),
    ('firefox.exe',   'mshta.exe'):      ('Browser spawning Mshta', 'T1218.005', 'critical'),
    ('firefox.exe',   'rundll32.exe'):   ('Browser spawning Rundll32', 'T1218.011', 'critical'),
    ('msedge.exe',    'mshta.exe'):      ('Browser spawning Mshta', 'T1218.005', 'critical'),
    ('msedge.exe',    'rundll32.exe'):   ('Browser spawning Rundll32', 'T1218.011', 'critical'),
    ('winword.exe',   'wscript.exe'):    ('Office spawning WScript', 'T1059.005', 'high'),
    ('winword.exe',   'cscript.exe'):    ('Office spawning CScript', 'T1059.005', 'high'),
    ('excel.exe',     'wscript.exe'):    ('Office spawning WScript', 'T1059.005', 'high'),
    ('excel.exe',     'cscript.exe'):    ('Office spawning CScript', 'T1059.005', 'high'),
    ('explorer.exe',  'certutil.exe'):   ('Explorer spawning Certutil', 'T1105', 'high'),
    ('explorer.exe',  'wscript.exe'):    ('Explorer spawning WScript', 'T1059.005', 'high'),
    ('powershell.exe','cmd.exe'):        ('PowerShell spawning CMD', 'T1059', 'medium'),
}


def _calculate_risk_score(proc_name: str, cmdline: str, parent_name: str,
                           matched_patterns: list, is_network: bool,
                           is_persistence: bool) -> int:
    """Dynamically calculate a risk score 0-100."""
    score = 0

    # Base score from matched pattern count
    score += min(len(matched_patterns) * 15, 50)

    # Unsigned binary bonus (can't check easily without Windows, so heuristic)
    if proc_name.lower() in WINDOWS_LOLBINS or proc_name.lower() in LINUX_LOLBINS:
        score += 10

    # Network activity
    if is_network:
        score += 15

    # Persistence
    if is_persistence:
        score += 15

    # Suspicious parent
    if parent_name:
        parent_lo = parent_name.lower()
        if any(parent_lo.endswith(k[0]) for k in SUSPICIOUS_PARENT_CHILD):
            score += 20

    # Encoded command
    if re.search(r'(-enc|-EncodedCommand|IEX|Invoke-Expression|base64.*decode)', cmdline, re.IGNORECASE):
        score += 20

    return min(score, 100)


def _sev_from_score(score: int) -> str:
    if score >= 80: return 'critical'
    if score >= 60: return 'high'
    if score >= 40: return 'medium'
    return 'low'


class LOLBinsDetector:
    """
    Monitors process creation events in real-time.
    Uses psutil to poll new processes and analyze command lines.
    """

    def __init__(self, sender, config=None):
        self._sender   = sender
        self._config   = config or {}
        self._seen     = {}          # pid → create_time to avoid duplicate alerts
        self._file_metadata_cache = {}
        self._file_hash_cache = {}
        self._enrichment_queue = queue.Queue(maxsize=max(32, int(self._config.get('lolbins_enrichment_queue_size', 256))))
        self._enrichment_workers = [
            threading.Thread(target=self._enrichment_loop, daemon=True, name=f'lolbins-enrich-{index + 1}')
            for index in range(max(1, min(4, int(self._config.get('lolbins_enrichment_workers', 2)))))
        ]
        self._thread   = threading.Thread(target=self._run, daemon=True, name='lolbins-detector')
        self._interval = float(self._config.get('lolbins_poll_interval', 3))

    def start(self):
        for worker in self._enrichment_workers:
            worker.start()
        self._thread.start()
        logger.info('LOLBins detector started (poll interval: %ss)', self._interval)

    def _cached_hashes(self, path: str) -> tuple[str, str]:
        try:
            stat = os.stat(path)
            identity = (int(stat.st_mtime_ns), int(stat.st_size))
        except (OSError, TypeError):
            return '', ''
        cached = self._file_hash_cache.get(path)
        if cached and cached[0] == identity:
            return cached[1]
        hashes = _hashes(path)
        if len(self._file_hash_cache) >= 2048:
            self._file_hash_cache.clear()
        self._file_hash_cache[path] = (identity, hashes)
        return hashes

    def _enrichment_loop(self):
        while True:
            event = self._enrichment_queue.get()
            try:
                path = event.get('process_exe') or ''
                sha256, md5 = self._cached_hashes(path)
                metadata = self._file_metadata_cache.get(path)
                if metadata is None:
                    metadata = _windows_file_metadata(path)
                    if len(self._file_metadata_cache) >= 2048:
                        self._file_metadata_cache.clear()
                    self._file_metadata_cache[path] = metadata

                event.update({
                    'file_hash': sha256,
                    'file_hash_md5': md5,
                    'executable_sha256': sha256,
                    'executable_md5': md5,
                    'signature_status': metadata.get('signature_status', ''),
                    'publisher': metadata.get('publisher', ''),
                    'company': metadata.get('company', ''),
                    'version': metadata.get('version', ''),
                })
                signature = str(metadata.get('signature_status') or '').lower()
                risk = int(event.get('risk_score') or 0)
                if signature in {'notsigned', 'hashmismatch', 'nottrusted', 'unknownerror'}:
                    risk += 15
                if not event.get('parent_process_name'):
                    risk += 5
                event['risk_score'] = min(100, risk)
                severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                scored_severity = _sev_from_score(event['risk_score'])
                if severity_order[scored_severity] > severity_order.get(event.get('severity'), 0):
                    event['severity'] = scored_severity
                self._sender.enqueue(event)
            except Exception as exc:
                logger.debug('LOLBins enrichment failed: %s', exc)
                self._sender.enqueue(event)
            finally:
                self._enrichment_queue.task_done()

    def _submit(self, event: dict):
        try:
            self._enrichment_queue.put_nowait(event)
        except queue.Full:
            # Never lose the security event because optional hashing/signature
            # enrichment is saturated.
            logger.warning('LOLBins enrichment queue full; sending core event without file metadata')
            self._sender.enqueue(event)

    def _run(self):
        try:
            import psutil
        except ImportError:
            logger.warning('psutil not available — LOLBins detector disabled')
            return

        while True:
            try:
                self._scan(psutil)
            except Exception as e:
                logger.debug('LOLBins scan error: %s', e)
            time.sleep(self._interval)

    def _scan(self, psutil):
        current_pids = set()
        try:
            proc_list = list(psutil.process_iter([
                'pid', 'name', 'exe', 'cmdline', 'username',
                'create_time', 'ppid', 'status',
            ]))
        except Exception:
            return

        for proc in proc_list:
            try:
                info = proc.info
                pid  = info.get('pid')
                if pid is None:
                    continue

                create_time = info.get('create_time', 0)
                cache_key   = f'{pid}:{create_time}'
                current_pids.add(cache_key)

                # Only analyze new processes
                if cache_key in self._seen:
                    continue
                self._seen[cache_key] = True

                name    = (info.get('name') or '').lower().strip()
                cmdline_parts = info.get('cmdline') or []
                cmdline = ' '.join(cmdline_parts) if cmdline_parts else ''
                exe     = info.get('exe') or ''
                user    = info.get('username') or ''

                if not name or not cmdline:
                    continue

                # Get parent info
                parent_name = ''
                parent_cmdline = ''
                parent_username = ''
                try:
                    parent = proc.parent()
                    if parent:
                        parent_name = (parent.name() or '').lower()
                        parent_cmdline = ' '.join(parent.cmdline() or [])[:1000]
                        parent_username = parent.username() or ''
                except Exception:
                    pass

                # Check if it's a LOLBin
                is_lolbin = (name in WINDOWS_LOLBINS or name in LINUX_LOLBINS or
                             any(name.endswith(lb) for lb in WINDOWS_LOLBINS))

                # Check parent-child suspicious combinations
                parent_child_alert = None
                if parent_name and name:
                    key = (parent_name, name)
                    if key in SUSPICIOUS_PARENT_CHILD:
                        parent_child_alert = SUSPICIOUS_PARENT_CHILD[key]

                # Scan command line against suspicious patterns
                matched_patterns = []
                for pat, desc, mitre, sev in SUSPICIOUS_PATTERNS:
                    if pat.search(cmdline):
                        matched_patterns.append((desc, mitre, sev))

                # A LOLBin name alone is not malicious. Common ssh/git/curl/bash
                # usage must only alert when its arguments or process ancestry
                # match a reviewed abuse pattern.
                if not is_lolbin and not matched_patterns and not parent_child_alert:
                    continue
                if is_lolbin and not matched_patterns and not parent_child_alert:
                    continue

                # Detect network activity and persistence patterns
                is_network = bool(re.search(
                    r'(http://|https://|ftp://|:\\d{2,5}|\\.onion|/dev/tcp|/dev/udp)',
                    cmdline, re.IGNORECASE
                ))
                is_persistence = bool(re.search(
                    r'(\\Run\\|\\RunOnce\\|schtasks.*create|crontab|systemctl.*enable|'
                    r'sc.*create|startup|autorun)',
                    cmdline, re.IGNORECASE
                ))

                risk_score = _calculate_risk_score(
                    name, cmdline, parent_name,
                    matched_patterns, is_network, is_persistence
                )

                # Determine severity and primary description
                if matched_patterns:
                    # Pick highest severity pattern
                    sev_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                    primary   = max(matched_patterns, key=lambda x: sev_order.get(x[2], 0))
                    desc      = primary[0]
                    mitre_id  = primary[1]
                    severity  = primary[2]
                elif parent_child_alert:
                    desc, mitre_id, severity = parent_child_alert
                else:
                    desc      = f'LOLBin execution detected: {name}'
                    mitre_id  = 'T1218'
                    severity  = _sev_from_score(risk_score)

                event = {
                    'rule_id':          'LOLBIN_DETECTED',
                    'capabilityId':      28,
                    'capabilityIds':     [1, 21, 28],
                    'category':         'malware',
                    'severity':         severity,
                    'description':      f'[LOLBins] {desc}: {name}',
                    'source':           'lolbins',
                    'malware_type':     'LolBin',
                    'risk_score':       risk_score,
                    'mitre_id':         mitre_id,
                    'technique':        desc,
                    'process_name':     name,
                    'process_exe':      exe,
                    'process_cmdline':  cmdline[:1000],
                    'command_line':      cmdline[:1000],
                    'pid':              pid,
                    'parent_pid':       info.get('ppid'),
                    'parent_process_name': parent_name,
                    'parent_command_line': parent_cmdline,
                    'parent_username':  parent_username,
                    'username':         user,
                    'file_path':        exe,
                    'process_create_time': create_time,
                    'start_time':       datetime.fromtimestamp(create_time, timezone.utc).isoformat() if create_time else '',
                    'integrity_level':  '',
                    # This is the endpoint/AD domain, not a DNS query domain.
                    # Keeping it separate prevents LOLBins events from leaking
                    # into the Web & DNS capability.
                    'user_domain':      os.environ.get('USERDOMAIN', '') if SYSTEM == 'Windows' else '',
                    'is_network':       is_network,
                    'is_persistence':   is_persistence,
                    'matched_patterns': [p[0] for p in matched_patterns],
                    'raw_log': (
                        f'LOLBin|proc={name}|pid={pid}|parent={parent_name}|'
                        f'user={user}|risk={risk_score}|cmd={cmdline[:300]}'
                    ),
                }
                self._submit(event)

                logger.warning(
                    '[LOLBins] %s PID=%s parent=%s risk=%s sev=%s — %s',
                    name, pid, parent_name, risk_score, severity, desc
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug('LOLBins proc error: %s', e)

        # Clean up stale PIDs from cache to prevent unbounded growth
        if len(self._seen) > 10000:
            keep = set(current_pids)
            self._seen = {k: v for k, v in self._seen.items() if k in keep}


# Alias for agent.py _import_class discovery
Detector = LOLBinsDetector
