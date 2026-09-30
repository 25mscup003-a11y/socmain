"""Cross-platform patch and software inventory for EDR capability 17.

The collector is intentionally read-only. It inventories installed packages and
uses the operating system's local update cache where available; it never
downloads or installs updates. CVE/KEV/EPSS enrichment belongs in the backend,
where feeds can be cached once for all endpoints.
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger('soc-agent.collector.patch-inventory')


def _run(args, timeout=45):
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _fingerprint(rows):
    canonical = json.dumps(rows, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canonical.encode('utf-8', errors='replace')).hexdigest()


class PatchInventoryCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._system = platform.system()
        self._previous_packages = None
        self._previous_installed_patches = None
        self._previous_pending = None
        self._thread = threading.Thread(target=self._loop, daemon=True, name='patch-inventory')

    def start(self):
        sensors = self._sensor_status()
        self._emit(
            'PATCH_INVENTORY_SENSOR_HEALTH',
            'Patch and software inventory collector initialized',
            sensor_status=sensors,
            coverage_status='active' if any(sensors.values()) else 'unavailable',
            eventType='Sensor Health',
            evidence_type='collector_health',
        )
        self._thread.start()

    def _emit(self, rule_id, description, severity='low', **fields):
        self._sender.enqueue({
            'rule_id': rule_id,
            'capabilityId': 17,
            'capabilityIds': [7, 17],
            'category': 'systemchanges',
            'source': 'patch_inventory',
            'severity': severity,
            'description': description,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'eventType': fields.pop('eventType', 'Patch Inventory'),
            'raw': {key: value for key, value in fields.items() if value is not None},
            **fields,
        })

    def _sensor_status(self):
        if self._system == 'Windows':
            return {'powershell': bool(shutil.which('powershell.exe') or shutil.which('powershell'))}
        if self._system == 'Darwin':
            return {'system_profiler': bool(shutil.which('system_profiler')), 'softwareupdate': bool(shutil.which('softwareupdate'))}
        return {
            'dpkg': bool(shutil.which('dpkg-query')),
            'rpm': bool(shutil.which('rpm')),
            'apt_cache': bool(shutil.which('apt')),
            'dnf_cache': bool(shutil.which('dnf')),
            'yum_cache': bool(shutil.which('yum')),
            'zypper_cache': bool(shutil.which('zypper')),
        }

    def _windows_inventory(self):
        powershell = shutil.which('powershell.exe') or shutil.which('powershell')
        if not powershell:
            return [], [], []
        package_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$apps=@();"
            "$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
            "foreach($p in $paths){$apps+=Get-ItemProperty $p|Where-Object DisplayName|"
            "Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}},@{n='publisher';e={$_.Publisher}}};"
            "$apps|Sort-Object name,version -Unique|ConvertTo-Json -Compress"
        )
        hotfix_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-HotFix|Select-Object @{n='id';e={$_.HotFixID}},@{n='installedOn';e={[string]$_.InstalledOn}},"
            "@{n='description';e={$_.Description}}|ConvertTo-Json -Compress"
        )
        # The Windows Update COM search is read-only. It reads the endpoint's
        # locally known update catalogue and never downloads, approves or
        # installs an update.
        pending_script = (
            "$ErrorActionPreference='Stop';"
            "$session=New-Object -ComObject Microsoft.Update.Session;"
            "$searcher=$session.CreateUpdateSearcher();"
            "$result=$searcher.Search('IsInstalled=0 and IsHidden=0');"
            "$updates=@();"
            "foreach($u in $result.Updates){"
            "$kb=@($u.KBArticleIDs);"
            "$updates+=[pscustomobject]@{name=$u.Title;kb=($kb -join ',');"
            "candidateVersion='';source='windows-update';rebootRequired=[bool]$u.RebootRequired;"
            "severity=[string]$u.MsrcSeverity;categories=@($u.Categories|ForEach-Object {$_.Name})}"
            "};$updates|ConvertTo-Json -Compress -Depth 4"
        )
        return (
            self._powershell_json(powershell, package_script),
            self._powershell_json(powershell, hotfix_script),
            self._powershell_json(powershell, pending_script),
        )

    @staticmethod
    def _powershell_json(executable, script):
        result = _run([executable, '-NoProfile', '-NonInteractive', '-Command', script], timeout=90)
        if not result or result.returncode or not result.stdout.strip():
            return []
        try:
            value = json.loads(result.stdout)
            return value if isinstance(value, list) else [value]
        except (json.JSONDecodeError, TypeError):
            return []

    def _linux_inventory(self):
        packages = []
        if shutil.which('dpkg-query'):
            result = _run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n'])
            if result and result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        packages.append({'name': parts[0], 'version': parts[1], 'architecture': parts[2] if len(parts) > 2 else ''})
        elif shutil.which('rpm'):
            result = _run(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'])
            if result and result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        packages.append({'name': parts[0], 'version': parts[1], 'architecture': parts[2] if len(parts) > 2 else ''})

        pending = []
        if shutil.which('apt'):
            result = _run(['apt', 'list', '--upgradable'])
            if result and result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith('Listing') or '/' not in line:
                        continue
                    name, rest = line.split('/', 1)
                    fields = rest.split()
                    pending.append({'name': name, 'candidateVersion': fields[1] if len(fields) > 1 else '', 'source': 'apt-cache'})
        elif shutil.which('dnf'):
            result = _run(['dnf', '--cacheonly', '-q', 'check-update'])
            pending = self._parse_rpm_updates(result, 'dnf-cache')
        elif shutil.which('yum'):
            result = _run(['yum', '-C', '-q', 'check-update'])
            pending = self._parse_rpm_updates(result, 'yum-cache')
        elif shutil.which('zypper'):
            result = _run(['zypper', '--no-refresh', '--non-interactive', 'list-updates'])
            if result and result.returncode in (0, 100):
                for line in result.stdout.splitlines():
                    parts = [part.strip() for part in line.split('|')]
                    if len(parts) >= 5 and parts[0].lower() in ('v', ''):
                        pending.append({'name': parts[2], 'currentVersion': parts[3], 'candidateVersion': parts[4], 'source': 'zypper-cache'})
        return packages, pending

    @staticmethod
    def _parse_rpm_updates(result, source):
        if not result or result.returncode not in (0, 100):
            return []
        rows = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and not line.startswith(('Last metadata', 'Obsoleting')):
                rows.append({'name': parts[0], 'candidateVersion': parts[1], 'repository': parts[2], 'source': source})
        return rows

    def _darwin_inventory(self):
        packages = []
        result = _run(['system_profiler', 'SPApplicationsDataType', '-json'], timeout=90)
        if result and result.returncode == 0:
            try:
                for item in json.loads(result.stdout).get('SPApplicationsDataType', []):
                    packages.append({'name': item.get('_name'), 'version': item.get('version'), 'path': item.get('path')})
            except (json.JSONDecodeError, TypeError):
                pass
        pending = []
        result = _run(['softwareupdate', '--list'], timeout=90)
        if result and result.returncode == 0:
            for line in result.stdout.splitlines():
                value = line.strip().lstrip('*').strip()
                if value.startswith('Label:'):
                    pending.append({'name': value.split(':', 1)[1].strip(), 'source': 'softwareupdate'})
        return packages, pending

    def _inventory(self):
        if self._system == 'Windows':
            return self._windows_inventory()
        if self._system == 'Darwin':
            packages, pending = self._darwin_inventory()
            return packages, [], pending
        packages, pending = self._linux_inventory()
        return packages, [], pending

    def _emit_batches(self, rule_id, description, items, inventory_type):
        batches = [items[index:index + 100] for index in range(0, len(items), 100)] or [[]]
        snapshot_id = _fingerprint(items)
        for index, batch in enumerate(batches, 1):
            self._emit(
                rule_id,
                f'{description}: {len(items)} item(s), batch {index}/{len(batches)}',
                inventory_type=inventory_type,
                inventory_count=len(items),
                inventory_items=batch,
                inventory_batch_index=index,
                inventory_batch_count=len(batches),
                inventory_snapshot_id=snapshot_id,
                os_name=platform.system(),
                os_version=platform.version(),
                kernel_version=platform.release(),
                evidence_type='native_package_manager',
            )

    def collect_once(self, force=False):
        inventory = self._inventory()
        # Keep compatibility with third-party collectors/tests implementing
        # the earlier two-list interface.
        if len(inventory) == 2:
            packages, pending = inventory
            installed_patches = []
        else:
            packages, installed_patches, pending = inventory
        packages = sorted((item for item in packages if item.get('name')), key=lambda item: (str(item.get('name')), str(item.get('version'))))
        installed_patches = sorted(
            (item for item in installed_patches if item.get('id') or item.get('name')),
            key=lambda item: (str(item.get('id')), str(item.get('installedOn'))),
        )
        pending = sorted((item for item in pending if item.get('name')), key=lambda item: (str(item.get('name')), str(item.get('candidateVersion'))))
        package_fingerprint = _fingerprint(packages)
        installed_patch_fingerprint = _fingerprint(installed_patches)
        pending_fingerprint = _fingerprint(pending)
        if force or package_fingerprint != self._previous_packages:
            self._emit_batches('PATCH_SOFTWARE_INVENTORY', 'Installed software inventory', packages, 'installed_software')
            self._previous_packages = package_fingerprint
        if force or installed_patch_fingerprint != self._previous_installed_patches:
            self._emit_batches('PATCH_INSTALLED_UPDATES', 'Installed patch inventory', installed_patches, 'installed_patches')
            self._previous_installed_patches = installed_patch_fingerprint
        if force or pending_fingerprint != self._previous_pending:
            self._emit_batches('PATCH_PENDING_UPDATES', 'Locally known pending updates', pending, 'pending_updates')
            self._previous_pending = pending_fingerprint
        return {'installed': len(packages), 'installed_patches': len(installed_patches), 'pending': len(pending)}

    def _loop(self):
        interval = max(900.0, float(self._config.get('patch_inventory_interval_seconds', 21600)))
        while True:
            try:
                # Publish a fresh snapshot every configured interval even when
                # inventory is unchanged. This keeps bounded dashboard queries
                # current while fingerprint deduplication still protects
                # ad-hoc collect_once calls from duplicates.
                self.collect_once(force=True)
            except Exception as exc:
                logger.warning('Patch inventory failed: %s', exc)
                self._emit('PATCH_INVENTORY_SENSOR_ERROR', f'Patch inventory failed: {exc}', 'medium', coverage_status='degraded')
            time.sleep(interval)


Collector = PatchInventoryCollector
