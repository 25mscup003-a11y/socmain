"""Evidence-preserving runtime integrity and analysis-tool monitoring.

This module intentionally never deletes agent files or attacks analysis tools.
It produces bounded telemetry so the server can alert and the agent can enter a
recoverable lockdown while preserving evidence for incident response.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ANALYSIS_TOOLS = {
    'gdb', 'lldb', 'strace', 'ltrace', 'frida', 'frida-server',
    'x64dbg', 'x32dbg', 'ollydbg', 'windbg', 'cdb', 'ida', 'ida64',
    'ghidra', 'dnspy', 'processhacker', 'processhacker2', 'procmon',
}
MAX_FINDINGS = 40
RUNTIME_PYTHON_DIRS = {'venv', '.venv'}


def _sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(root):
    path = root / 'integrity_manifest.json'
    if not path.is_file():
        return None, 'integrity_manifest.json is missing'
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        files = value.get('files') if isinstance(value, dict) else None
        if not isinstance(files, dict) or not files:
            return None, 'integrity manifest contains no protected files'
        clean = {}
        for name, digest in files.items():
            relative = str(name).replace('\\', '/')
            digest = str(digest).lower()
            if (relative.startswith('/') or '..' in Path(relative).parts
                    or not relative.endswith('.py')
                    or len(digest) != 64
                    or any(char not in '0123456789abcdef' for char in digest)):
                return None, 'integrity manifest contains an invalid entry'
            clean[relative] = digest
        return {
            'files': clean,
            'fleetSha256': str(value.get('fleetSha256') or '').lower(),
            'version': int(value.get('version') or 1),
        }, ''
    except Exception as exc:
        return None, f'integrity manifest could not be read: {str(exc)[:160]}'


def _debugger_attached():
    reasons = []
    try:
        if sys.gettrace() is not None:
            reasons.append('python runtime tracing/debugger is attached')
    except Exception:
        pass
    if sys.platform.startswith('linux'):
        try:
            for line in Path('/proc/self/status').read_text(encoding='utf-8').splitlines():
                if line.startswith('TracerPid:') and int(line.split(':', 1)[1].strip() or '0') > 0:
                    reasons.append('operating-system process tracer is attached')
                    break
        except Exception:
            pass
    return reasons


def _running_analysis_tools():
    names = set()
    try:
        import psutil
        for process in psutil.process_iter(['name']):
            name = str(process.info.get('name') or '').lower()
            if name.endswith('.exe'):
                name = name[:-4]
            if name in ANALYSIS_TOOLS:
                names.add(name)
    except Exception:
        try:
            command = ['tasklist', '/fo', 'csv', '/nh'] if os.name == 'nt' else ['ps', '-eo', 'comm=']
            output = subprocess.run(
                command, capture_output=True, text=True, timeout=3, check=False,
            ).stdout.lower()
            for line in output.splitlines():
                name = Path(line.split(',', 1)[0].strip('" ')).name
                if name.endswith('.exe'):
                    name = name[:-4]
                if name in ANALYSIS_TOOLS:
                    names.add(name)
        except Exception:
            pass
    return sorted(names)[:20]


def collect_security_report(root=None):
    root = Path(root or Path(__file__).resolve().parent.parent).resolve()
    findings = []
    manifest, manifest_error = _load_manifest(root)
    expected_files = manifest['files'] if manifest else {}
    actual_files = {}

    try:
        # The supported installers create the dependency virtual environment
        # inside the agent directory. Third-party modules are not protected
        # agent code and are intentionally absent from the signed manifest.
        paths = sorted(
            path for path in root.rglob('*.py')
            if not (
                path.relative_to(root).parts
                and path.relative_to(root).parts[0].lower() in RUNTIME_PYTHON_DIRS
            )
        )
        for path in paths:
            relative = str(path.relative_to(root)).replace(os.sep, '/')
            if path.is_symlink():
                findings.append({'type': 'symlink', 'file': relative, 'detail': 'protected code is a symbolic link'})
                continue
            if os.name != 'nt' and path.stat().st_mode & 0o022:
                findings.append({'type': 'permissions', 'file': relative, 'detail': 'protected code is group/world writable'})
            actual_files[relative] = _sha256(path)

        if not manifest:
            integrity_status = 'missing'
            findings.append({'type': 'manifest', 'file': 'integrity_manifest.json', 'detail': manifest_error})
        else:
            for relative, expected in sorted(expected_files.items()):
                actual = actual_files.get(relative)
                if actual is None:
                    findings.append({'type': 'missing_file', 'file': relative, 'detail': 'protected file is missing'})
                elif actual != expected:
                    findings.append({'type': 'hash_mismatch', 'file': relative, 'detail': 'SHA-256 does not match signed package inventory'})
            for relative in sorted(set(actual_files) - set(expected_files)):
                findings.append({'type': 'unexpected_file', 'file': relative, 'detail': 'unmanifested Python code is present'})
            integrity_status = 'mismatch' if findings else 'verified'

        aggregate = hashlib.sha256()
        for relative in sorted(actual_files):
            aggregate.update(f'{relative}\0{actual_files[relative]}\n'.encode('utf-8'))
        reported_fleet_hash = aggregate.hexdigest()
    except Exception as exc:
        integrity_status = 'error'
        reported_fleet_hash = ''
        findings.append({'type': 'scan_error', 'file': '', 'detail': str(exc)[:200]})

    debugger_reasons = _debugger_attached()
    for detail in debugger_reasons:
        findings.append({'type': 'debugger', 'file': '', 'detail': detail})
    tools = _running_analysis_tools()
    for tool in tools:
        findings.append({'type': 'analysis_tool', 'file': '', 'detail': f'analysis tool process detected: {tool}'})

    expected_hash = manifest.get('fleetSha256', '') if manifest else ''
    if expected_hash and expected_hash != reported_fleet_hash and integrity_status == 'verified':
        integrity_status = 'mismatch'
        findings.append({'type': 'aggregate_mismatch', 'file': '', 'detail': 'aggregate package hash does not match manifest'})

    return {
        'version': 1,
        'checkedAt': datetime.now(timezone.utc).isoformat(),
        'integrityStatus': integrity_status,
        'expectedFleetSha256': expected_hash[:64],
        'reportedFleetSha256': reported_fleet_hash[:64],
        'debuggerDetected': bool(debugger_reasons),
        'analysisTools': tools,
        'findings': findings[:MAX_FINDINGS],
    }
