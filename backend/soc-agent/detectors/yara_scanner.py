"""
YARA Scanner — scans dirs every 5 minutes for malware signatures.
Enriches matches with VirusTotal hash scan.
Sends category='malware' alerts with file_hash, file_path, malware_type.
"""

import os
import time
import hashlib
import logging
import threading
import platform
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger('soc-agent.detector.yara')
SYSTEM = platform.system()
SCAN_INTERVAL = 300   # 5 minutes

SCAN_DIRS = {
    # Broad /home, /root and /opt walks repeatedly scan worktrees, VM images
    # and dependency caches. Real-time FIM covers changes outside these focused
    # malware drop locations.
    'Linux':   ['/tmp', '/var/tmp', '/dev/shm', '/var/www'],
    'Darwin':  ['/tmp', '/private/tmp',
                os.path.expanduser('~/Downloads'),
                os.path.expanduser('~/Desktop')],
    'Windows': [
        os.environ.get('TEMP', 'C:\\Windows\\Temp'),
        os.environ.get('TMP',  'C:\\Temp'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Downloads'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Desktop'),
        'C:\\Users\\Public',
    ],
}

YARA_RULES_DIR = Path(__file__).parent.parent / 'yara_rules'

MAX_FILE_SIZE = 50 * 1024 * 1024   # 50 MB
MAX_FILES_PER_SCAN = 5000
SKIP_DIR_NAMES = {
    '.git', '.cache', '.npm', '.yarn', '.pnpm-store', '__pycache__',
    'node_modules', 'vendor', '.venv', 'venv', 'proc', 'sys',
}


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


def _md5(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read(1024 * 1024)).hexdigest()
    except Exception:
        return ''


class YaraScanner:
    def __init__(self, sender, vt_scanner=None, config=None):
        self._sender = sender
        self._vt     = vt_scanner
        self._config = config or {}
        self._rules  = None
        self._scanned_hashes: set = set()
        self._scanned_files: dict = {}
        self._quarantined_hashes: set = set()
        self._thread = threading.Thread(target=self._loop, daemon=True, name='yara-scanner')

    def _compile(self):
        try:
            import yara
        except ImportError:
            logger.info('yara-python not installed — YARA scanning disabled.')
            logger.info('Enable: pip3 install yara-python')
            return None

        rule_files = list(YARA_RULES_DIR.glob('*.yar')) + list(YARA_RULES_DIR.glob('*.yara'))
        if not rule_files:
            logger.warning('No YARA rules found in %s', YARA_RULES_DIR)
            return None

        try:
            rules = yara.compile(filepaths={f.stem: str(f) for f in rule_files})
            logger.info('YARA rules compiled: %s', [f.name for f in rule_files])
            return rules
        except Exception as e:
            logger.error('YARA compile error: %s', e)
            return None

    def start(self):
        self._rules = self._compile()
        self._thread.start()

    def _loop(self):
        logger.info('YARA scanner started (interval: %ds)', SCAN_INTERVAL)
        while True:
            try:
                self._scan_all()
            except Exception as e:
                logger.error('YARA scan error: %s', e)
            time.sleep(SCAN_INTERVAL)

    def _scan_all(self):
        scanned = 0
        for scan_dir in SCAN_DIRS.get(SYSTEM, []):
            p = Path(scan_dir)
            if not p.exists():
                continue
            try:
                for root, dirs, files in os.walk(scan_dir):
                    dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES and not d.startswith('.')]
                    for fname in files:
                        if scanned >= int(self._config.get('yara_max_files_per_scan', MAX_FILES_PER_SCAN)):
                            logger.warning('YARA scan budget reached (%d files); remaining files deferred', scanned)
                            return
                        fpath = os.path.join(root, fname)
                        self._scan_file(fpath)
                        scanned += 1
            except PermissionError:
                pass

    def _scan_file(self, file_path: str):
        if not self._rules:
            return
        try:
            stat = Path(file_path).stat()
            size = stat.st_size
            if size == 0 or size > MAX_FILE_SIZE:
                return

            signature = (stat.st_mtime_ns, size)
            if self._scanned_files.get(file_path) == signature:
                return

            # Avoid hashing every clean file before matching. YARA reads once;
            # hashes and VirusTotal enrichment are only needed for a match.
            matches = self._rules.match(file_path, timeout=10)
            self._scanned_files[file_path] = signature
            if not matches:
                return

            sha256 = _sha256(file_path)
            if sha256 and sha256 in self._scanned_hashes:
                return

            rule_names = [m.rule for m in matches]
            fname      = os.path.basename(file_path)

            # Determine malware type from matched rule names
            rule_str = ' '.join(rule_names).lower()
            if 'ransomware' in rule_str or 'wanna' in rule_str or 'ryuk' in rule_str:
                malware_type = 'Ransomware'
            elif 'miner' in rule_str or 'coin' in rule_str:
                malware_type = 'Miner'
            elif 'shell' in rule_str or 'webshell' in rule_str:
                malware_type = 'WebShell'
            elif 'credential' in rule_str or 'mimikatz' in rule_str:
                malware_type = 'Credential Dumper'
            elif 'trojan' in rule_str:
                malware_type = 'Trojan'
            else:
                malware_type = 'Generic Malware'

            severity = 'critical' if malware_type in ('Ransomware', 'Credential Dumper') else 'high'

            alert: dict = {
                'capabilityId':  18,
                'capabilityIds': sorted({2, 18, 25, *([27] if malware_type == 'Ransomware' else []), *([13] if malware_type == 'Credential Dumper' else [])}),
                'rule_id':      'YARA_MATCH',
                'category':     'malware',
                'severity':     severity,
                'description':  f'YARA match: {", ".join(rule_names)} in {fname}',
                'file_path':    file_path,
                'file_name':    fname,
                'file_hash':    sha256,
                'file_hash_md5': _md5(file_path),
                'malware_type': malware_type,
                'yara_rules':   rule_names,
                'raw_log':      f'YARA:{"|".join(rule_names)}|{file_path}|{sha256[:16]}',
                'timestamp':    datetime.now(timezone.utc).isoformat(),
            }

            # VT hash enrichment
            if self._vt and sha256:
                try:
                    vt = self._vt.scan_hash(sha256, file_path)
                    if vt:
                        alert['virustotal'] = vt
                        if vt.get('verdict') == 'malicious':
                            alert['severity'] = 'critical'
                        logger.info('YARA+VT: %s → %s (%s)',
                                    fname, vt.get('detection_ratio'), vt.get('verdict'))
                except Exception as e:
                    logger.debug('VT scan error: %s', e)

            self._sender.enqueue(alert)

            # Auto-quarantine if response_enabled and critical malware
            if self._config.get('response_enabled', True) and severity == 'critical':
                self._auto_quarantine(file_path, sha256, malware_type, rule_names)

            if sha256:
                self._scanned_hashes.add(sha256)

        except PermissionError:
            pass
        except Exception as e:
            logger.debug('YARA file scan error (%s): %s', file_path, e)

    def _auto_quarantine(self, file_path: str, sha256: str, malware_type: str, rules: list):
        """Auto-quarantine detected malware files."""
        if sha256 in self._quarantined_hashes:
            return

        try:
            from response.quarantine import quarantine
            dest = quarantine(file_path)
            self._quarantined_hashes.add(sha256)

            logger.critical('🚨 AUTO-QUARANTINED malware: %s → %s (type=%s, rules=%s)',
                           file_path, dest, malware_type, ','.join(rules))

            # Send quarantine confirmation alert
            self._sender.enqueue({
                'capabilityId':  18,
                'capabilityIds': [2, 18, 25],
                'rule_id':      'MALWARE_QUARANTINED',
                'category':     'malware',
                'severity':     'critical',
                'description':  f'Malware auto-quarantined: {malware_type} ({",".join(rules)})',
                'file_path':    file_path,
                'file_hash':    sha256,
                'malware_type': malware_type,
                'yara_rules':   rules,
                'quarantined':  True,
                'raw_log':      f'QUARANTINED:{malware_type}|{file_path}',
                'timestamp':    datetime.now(timezone.utc).isoformat(),
            })

        except Exception as e:
            logger.error('Failed to quarantine %s: %s', file_path, e)
