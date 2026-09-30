"""Bounded, cross-platform kernel and driver telemetry for capability 19.

Uses native OS inventories and security logs. It never labels unsupported deep
kernel inspection (SSDT/DKOM/PatchGuard internals) as healthy or compromised.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

logger = logging.getLogger('soc-agent.collector.kernel-monitor')

KERNEL_RISK = re.compile(
    r'rootkit|hidden (?:process|module|driver)|sys_?call(?:_table)?.{0,20}(?:hook|tamper)|'
    r'ssdt.{0,20}(?:hook|tamper)|dkom|kernel.{0,20}(?:shellcode|exploit|memory corruption)|'
    r'unsigned (?:kernel )?(?:module|driver)|lockdown.*disabled|secure boot.*disabled|testsigning.*yes',
    re.I,
)


def _run(args, timeout=15):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _sha256(path):
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return ''


def _fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _linux_module_paths():
    release = platform.release()
    dep = f'/lib/modules/{release}/modules.dep'
    result = {}
    try:
        with open(dep, encoding='utf-8', errors='replace') as handle:
            for line in handle:
                rel = line.partition(':')[0].strip()
                name = os.path.basename(rel).split('.ko', 1)[0].replace('-', '_')
                if name:
                    result[name] = os.path.join(f'/lib/modules/{release}', rel)
    except (OSError, PermissionError):
        pass
    return result


def linux_modules():
    paths = _linux_module_paths()
    rows = []
    try:
        with open('/proc/modules', encoding='utf-8', errors='replace') as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 6:
                    continue
                name = parts[0]
                path = paths.get(name, '')
                taint = ''
                try:
                    with open(f'/sys/module/{name}/taint', encoding='utf-8', errors='replace') as taint_file:
                        taint = taint_file.read().strip()
                except (OSError, PermissionError):
                    pass
                rows.append({
                    'id': name, 'name': name, 'module_name': name, 'driver_name': name,
                    'path': path, 'module_path': path, 'driver_path': path,
                    'size': int(parts[1]) if parts[1].isdigit() else 0,
                    'reference_count': int(parts[2]) if parts[2].isdigit() else 0,
                    'state': parts[4], 'address': parts[5], 'taint': taint,
                    'signature_status': 'tainted' if taint else 'not_reported',
                })
    except (OSError, PermissionError):
        pass
    return rows


def linux_posture():
    posture = {
        'platform': 'Linux', 'kernel_version': platform.release(),
        'secure_boot': 'not_reported', 'kernel_lockdown': 'not_reported',
        'module_signature_enforcement': 'not_reported', 'strict_module_rwx': 'not_reported',
        'ebpf_sensor': 'available' if shutil.which('bpftool') else 'unavailable',
        'audit_sensor': 'available' if shutil.which('auditctl') else 'unavailable',
    }
    files = {
        'kernel_lockdown': '/sys/kernel/security/lockdown',
        'module_signature_enforcement': '/proc/sys/kernel/module_sig_enforce',
    }
    for key, path in files.items():
        try:
            with open(path, encoding='utf-8', errors='replace') as handle:
                posture[key] = handle.read().strip()[:200]
        except (OSError, PermissionError):
            pass
    config_paths = [f'/boot/config-{platform.release()}', '/proc/config.gz']
    config_text = ''
    for path in config_paths:
        if path.endswith('.gz') or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding='utf-8', errors='replace') as handle:
                config_text = handle.read()
            break
        except (OSError, PermissionError):
            pass
    if config_text:
        posture['strict_module_rwx'] = 'enabled' if 'CONFIG_STRICT_MODULE_RWX=y' in config_text else 'disabled'
    mokutil = _run(['mokutil', '--sb-state'], 5) if shutil.which('mokutil') else None
    if mokutil and mokutil.stdout:
        posture['secure_boot'] = 'enabled' if 'enabled' in mokutil.stdout.lower() else 'disabled'
    return posture


def windows_drivers():
    script = r'''$ErrorActionPreference='SilentlyContinue'; Get-CimInstance Win32_SystemDriver | ForEach-Object { $p=[Environment]::ExpandEnvironmentVariables([string]$_.PathName).Trim('"'); if($p -match '^\\SystemRoot'){ $p=$p -replace '^\\SystemRoot',$env:SystemRoot }; if($p -match '^System32'){ $p=Join-Path $env:SystemRoot $p }; $sig=$null; $hash=$null; if(Test-Path -LiteralPath $p){$sig=Get-AuthenticodeSignature -LiteralPath $p; $hash=Get-FileHash -Algorithm SHA256 -LiteralPath $p}; [pscustomobject]@{id=$_.Name;name=$_.Name;driver_name=$_.Name;display_name=$_.DisplayName;driver_path=$p;state=$_.State;start_mode=$_.StartMode;service_type=$_.ServiceType;sha256=$hash.Hash;signature_status=$sig.Status.ToString();publisher=$sig.SignerCertificate.Subject;certificate_issuer=$sig.SignerCertificate.Issuer;certificate_valid_until=$sig.SignerCertificate.NotAfter} } | ConvertTo-Json -Compress -Depth 4'''
    result = _run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], 45)
    if not result or result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        value = json.loads(result.stdout)
        return value if isinstance(value, list) else [value]
    except (ValueError, TypeError):
        return []


def windows_posture():
    script = r'''$ErrorActionPreference='SilentlyContinue'; $sb='not_reported'; try {$sb=if(Confirm-SecureBootUEFI){'enabled'}else{'disabled'}}catch{}; $bcd=(bcdedit /enum '{current}' | Out-String); $dg=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; [pscustomobject]@{platform='Windows';kernel_version=[Environment]::OSVersion.VersionString;secure_boot=$sb;test_signing=if($bcd -match 'testsigning\s+Yes'){'enabled'}else{'disabled'};vbs_status=$dg.VirtualizationBasedSecurityStatus;credential_guard=$dg.SecurityServicesRunning;memory_integrity=$dg.SecurityServicesConfigured;patch_guard='not_directly_observable'} | ConvertTo-Json -Compress -Depth 4'''
    result = _run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], 20)
    if not result or not result.stdout.strip():
        return {'platform': 'Windows', 'kernel_version': platform.version(), 'sensor_status': 'degraded'}
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        return {'platform': 'Windows', 'kernel_version': platform.version(), 'sensor_status': 'degraded'}


class KernelMonitorCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._system = platform.system()
        self._previous = None
        self._posture_fingerprint = ''
        self._hash_cache = {}
        self._interval = max(30, int(self._config.get('kernel_monitor_interval_seconds', 300) or 300))
        self._vulnerable_hashes = {
            str(item).lower() for item in self._config.get('kernel_vulnerable_driver_hashes', [])
            if re.fullmatch(r'[a-fA-F0-9]{64}', str(item))
        }
        self._thread = threading.Thread(target=self._loop, daemon=True, name='kernel-monitor')

    def start(self):
        self.collect_once()
        self._thread.start()

    def _emit(self, rule_id, description, severity='low', risk_score=10, **fields):
        event_type = fields.pop('event_type', rule_id)
        persistence_change = rule_id in (
            'KERNEL_DRIVER_LOADED', 'KERNEL_BYOVD_DETECTED',
            'KERNEL_DRIVER_CHANGED', 'KERNEL_SECURITY_POSTURE_CHANGED',
        )
        payload = {
            'rule_id': rule_id, 'capabilityId': 19, 'capabilityIds': [8, 19] if persistence_change else [19],
            'category': 'kernel', 'subCategory': fields.get('kernel_category', 'kernel'),
            'eventType': event_type, 'source': 'kernel_monitor',
            'severity': severity, 'risk_score': min(100, max(0, int(risk_score))),
            'description': description, 'timestamp': datetime.now(timezone.utc).isoformat(),
            'evidence_type': 'native_kernel_inventory', **fields,
        }
        if persistence_change:
            payload.update({
                'is_persistence': True,
                'persistence_type': 'boot_configuration' if rule_id == 'KERNEL_SECURITY_POSTURE_CHANGED' else 'kernel_driver',
                'persistence_location': fields.get('driver_path') or fields.get('module_path') or 'kernel security posture',
                'technique': fields.get('technique') or ('Pre-OS Boot' if rule_id == 'KERNEL_SECURITY_POSTURE_CHANGED' else 'Kernel Modules and Extensions'),
                'mitre_id': fields.get('mitre_id') or ('T1542' if rule_id == 'KERNEL_SECURITY_POSTURE_CHANGED' else 'T1547.006'),
            })
        payload.setdefault('raw', {key: value for key, value in fields.items() if value is not None})
        self._sender.enqueue(payload)

    def _details(self, row):
        path = row.get('driver_path') or row.get('module_path') or row.get('path') or ''
        digest = str(row.get('sha256') or '').lower()
        if not digest and path and os.path.isfile(path):
            try:
                stat = os.stat(path)
                cache_key = (path, stat.st_size, stat.st_mtime_ns)
                digest = self._hash_cache.get(cache_key) or _sha256(path)
                if digest:
                    self._hash_cache = {key: value for key, value in self._hash_cache.items() if key[0] != path}
                    self._hash_cache[cache_key] = digest
            except (OSError, PermissionError):
                digest = ''
        signature = str(row.get('signature_status') or 'not_reported').lower()
        vulnerable = bool(digest and digest in self._vulnerable_hashes)
        unsigned = signature in {'notsigned', 'unsigned', 'invalid', 'tainted'}
        reasons = []
        if vulnerable:
            reasons.append('Hash matched configured vulnerable-driver intelligence')
        if unsigned:
            reasons.append(f'Driver/module signature status is {signature}')
        return path, digest, signature, vulnerable, unsigned, reasons

    def _emit_change(self, rule_id, row):
        path, digest, signature, vulnerable, unsigned, reasons = self._details(row)
        severity = 'critical' if vulnerable else 'high' if unsigned else 'medium'
        risk = 95 if vulnerable else 75 if unsigned else 45
        action = 'loaded' if rule_id == 'KERNEL_DRIVER_LOADED' else 'unloaded'
        name = row.get('name') or row.get('driver_name') or 'unknown'
        self._emit(
            'KERNEL_BYOVD_DETECTED' if vulnerable else rule_id,
            f'Kernel driver/module {action}: {name}', severity, risk,
            event_type=rule_id, kernel_category='driver', driver_name=name,
            module_name=name, driver_path=path, module_path=path, sha256=digest,
            signature_status=signature, publisher=row.get('publisher'),
            certificate_issuer=row.get('certificate_issuer'),
            certificate_valid_until=row.get('certificate_valid_until'),
            driver_state=row.get('state'), driver_start_mode=row.get('start_mode'),
            vulnerable_driver=vulnerable, detection_reasons=reasons,
            mitre_id='T1068' if vulnerable else 'T1547.006',
            mitre_tactic='Privilege Escalation' if vulnerable else 'Persistence',
            inventory_item=row,
        )

    def _emit_inventory(self, modules, posture):
        batches = [modules[index:index + 100] for index in range(0, len(modules), 100)] or [[]]
        # Every batch from one inventory pass must carry the same stable ID.
        # Per-event timestamps differ by a few milliseconds and therefore
        # cannot safely be used to reconstruct inventories with 100+ items.
        inventory_snapshot_id = uuid.uuid4().hex
        for index, batch in enumerate(batches, 1):
            self._emit(
                'KERNEL_INVENTORY_SNAPSHOT',
                f'Kernel driver/module inventory: {len(modules)} item(s)',
                'low', 10, event_type='Inventory Snapshot', inventory_type='kernel_module',
                inventory_count=len(modules), inventory_items=batch,
                inventory_snapshot_id=inventory_snapshot_id,
                inventory_batch_index=index, inventory_batch_count=len(batches),
                kernel_posture=posture, sensor_status='active' if modules else 'degraded',
            )

    def collect_once(self):
        modules = windows_drivers() if self._system == 'Windows' else linux_modules() if self._system == 'Linux' else []
        posture = windows_posture() if self._system == 'Windows' else linux_posture() if self._system == 'Linux' else {'platform': self._system}
        for row in modules:
            path, digest, signature, vulnerable, _unsigned, reasons = self._details(row)
            row.update({
                'driver_path': path, 'module_path': path, 'sha256': digest,
                'signature_status': signature, 'vulnerable_driver': vulnerable,
                'detection_reasons': reasons,
            })
        current = {str(row.get('id') or row.get('name')): row for row in modules if row.get('id') or row.get('name')}
        added = set() if self._previous is None else current.keys() - self._previous.keys()
        removed = set() if self._previous is None else self._previous.keys() - current.keys()
        changed = set() if self._previous is None else {
            key for key in current.keys() & self._previous.keys()
            if _fingerprint(current[key]) != _fingerprint(self._previous[key])
        }
        posture_hash = _fingerprint(posture)
        posture_changed = bool(self._posture_fingerprint and posture_hash != self._posture_fingerprint)

        # Publish a fresh inventory only at startup or when inventory/posture
        # changes. This keeps active-driver cards current without periodic
        # high-volume duplicate snapshots.
        if self._previous is None or added or removed or changed or posture_changed:
            self._emit_inventory(modules, posture)

        if self._previous is None:
            pass
        else:
            for key in sorted(added):
                self._emit_change('KERNEL_DRIVER_LOADED', current[key])
            for key in sorted(removed):
                self._emit_change('KERNEL_DRIVER_UNLOADED', self._previous[key])
            for key in sorted(changed):
                self._emit('KERNEL_DRIVER_CHANGED', f'Kernel driver/module metadata changed: {key}', 'high', 70,
                           event_type='KERNEL_DRIVER_CHANGED', kernel_category='driver',
                           driver_name=key, inventory_item=current[key], old_inventory_item=self._previous[key],
                           detection_reasons=['Driver/module metadata changed after baseline'])
        if posture_changed:
            dangerous = any(str(posture.get(key)).lower() in {'disabled', '0', 'off'} for key in ('secure_boot', 'kernel_lockdown', 'module_signature_enforcement'))
            self._emit('KERNEL_SECURITY_POSTURE_CHANGED', 'Kernel security posture changed', 'high' if dangerous else 'medium', 75 if dangerous else 45,
                       event_type='KERNEL_SECURITY_POSTURE_CHANGED', kernel_category='integrity', kernel_posture=posture,
                       detection_reasons=['Native kernel security control state changed'])
        self._posture_fingerprint = posture_hash
        self._previous = current
        return {'modules': modules, 'posture': posture}

    def _loop(self):
        while True:
            time.sleep(self._interval)
            try:
                self.collect_once()
            except Exception as exc:
                logger.warning('Kernel monitor collection failed: %s', exc)


Collector = KernelMonitorCollector
