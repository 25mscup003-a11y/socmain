"""Cross-platform service, task, startup, workload and container telemetry.

The collector produces auditable inventories and change events.  It does not
infer that a product is compromised merely because it is installed or running.
"""

from __future__ import annotations

import csv
import glob
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
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger('soc-agent.collector.process-assets')

WORKLOAD_NAMES = {
    'apache': {'apache2', 'httpd'},
    'nginx': {'nginx'},
    'iis': {'w3wp.exe', 'iisexpress.exe'},
    'tomcat': {'tomcat', 'tomcat.exe', 'catalina'},
    'mysql': {'mysqld', 'mysqld.exe', 'mysql'},
    'mssql': {'sqlservr.exe', 'sqlservr'},
    'postgresql': {'postgres', 'postgres.exe', 'postmaster'},
    'oracle': {'oracle', 'oracle.exe', 'tnslsnr', 'tnslsnr.exe'},
    'mongodb': {'mongod', 'mongod.exe'},
    'redis': {'redis-server', 'redis-server.exe'},
    'ssh': {'sshd', 'sshd.exe'},
    'rdp': {'termsrv', 'svchost.exe', 'xrdp', 'xrdp-sesman'},
    'active_directory': {'lsass.exe', 'dns.exe', 'dfsr.exe', 'kdc', 'samba'},
    'docker': {'dockerd', 'docker', 'containerd', 'containerd-shim'},
    'kubernetes': {'kubelet', 'kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'kube-proxy'},
}

SECURITY_SERVICE_PATTERN = re.compile(
    r'(?:ajnat|soc-agent|windefend|sense|msmpeng|securityhealth|mpssvc|firewall|'
    r'clamd|clamav|auditd|rsyslog|syslog-ng|suricata|zeek|wazuh|elastic-agent|'
    r'falcon|crowdstrike|sentinel|backup|veeam)', re.I,
)
SUSPICIOUS_SERVICE_PATH_PATTERN = re.compile(
    r'(?:\\|/)(?:temp|tmp|appdata|downloads?|public|users?/[^/\\]+/(?:desktop|downloads?))(?:\\|/)', re.I,
)


def _run(args, timeout=12):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _fingerprint(value) -> str:
    packed = json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(packed.encode('utf-8', errors='replace')).hexdigest()


def workload_role(name: str, cmdline: str = '') -> str:
    name = (name or '').lower()
    text = f'{name} {cmdline or ""}'.lower()
    for role, names in WORKLOAD_NAMES.items():
        if name in names:
            if role == 'rdp' and name == 'svchost.exe' and 'termsrv' not in text:
                continue
            return role
    if 'org.apache.catalina.startup.bootstrap' in text:
        return 'tomcat'
    if 'weblogic.server' in text or 'jboss' in text or 'wildfly' in text:
        return 'application_server'
    return ''


def container_risks(inspect: dict) -> list[str]:
    """Return concrete risky Docker/Podman configuration findings."""
    host = inspect.get('HostConfig') or {}
    cfg = inspect.get('Config') or {}
    risks = []
    if host.get('Privileged'):
        risks.append('privileged')
    if str(host.get('NetworkMode') or '').lower() == 'host':
        risks.append('host_network')
    if str(host.get('PidMode') or '').lower() == 'host':
        risks.append('host_pid')
    if str(host.get('IpcMode') or '').lower() == 'host':
        risks.append('host_ipc')
    caps = {str(item).upper() for item in (host.get('CapAdd') or [])}
    if 'SYS_ADMIN' in caps:
        risks.append('cap_sys_admin')
    if any(str(bind).split(':', 1)[0] in ('/', '/etc', '/var/run/docker.sock') for bind in (host.get('Binds') or [])):
        risks.append('sensitive_host_mount')
    if str(cfg.get('User') or '') in ('', '0', 'root'):
        risks.append('runs_as_root')
    return risks


def kubernetes_pod_risks(pod: dict) -> list[str]:
    spec = pod.get('spec') or {}
    risks = []
    if spec.get('hostPID'):
        risks.append('host_pid')
    if spec.get('hostNetwork'):
        risks.append('host_network')
    if spec.get('hostIPC'):
        risks.append('host_ipc')
    for volume in spec.get('volumes') or []:
        if volume.get('hostPath'):
            risks.append('host_path_mount')
            break
    for container in (spec.get('initContainers') or []) + (spec.get('containers') or []):
        security = container.get('securityContext') or {}
        if security.get('privileged'):
            risks.append('privileged')
        if security.get('allowPrivilegeEscalation') is True:
            risks.append('privilege_escalation_allowed')
        caps = {str(item).upper() for item in ((security.get('capabilities') or {}).get('add') or [])}
        if 'SYS_ADMIN' in caps:
            risks.append('cap_sys_admin')
        if security.get('runAsUser') == 0:
            risks.append('runs_as_root')
    return sorted(set(risks))


class ProcessAssetCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._system = platform.system()
        self._snapshots = {}
        self._thread = threading.Thread(target=self._loop, daemon=True, name='process-assets')

    def start(self):
        self._emit(
            'PROC_ASSET_TELEMETRY_HEALTH',
            'Cross-platform process asset telemetry initialized',
            sensor_status={
                'platform': self._system,
                'service_inventory': bool(self._config.get('service_monitoring_enabled', True)),
                'scheduled_task_inventory': True,
                'startup_inventory': True,
                'workload_inventory': True,
                'docker_cli': bool(shutil.which('docker')),
                'podman_cli': bool(shutil.which('podman')),
                'kubernetes_cli': bool(shutil.which('kubectl')),
                'linux_audit': bool(shutil.which('auditctl')) if self._system == 'Linux' else False,
            },
            coverage_status='active', eventType='Sensor Health', evidence_type='collector_health',
        )
        self._thread.start()
        if self._config.get('container_monitor_enabled', True):
            for runtime in ('docker', 'podman'):
                if shutil.which(runtime):
                    threading.Thread(
                        target=self._runtime_event_loop, args=(runtime,), daemon=True,
                        name=f'{runtime}-security-events',
                    ).start()
            if shutil.which('kubectl'):
                threading.Thread(
                    target=self._kubernetes_event_loop, daemon=True,
                    name='kubernetes-security-events',
                ).start()

    def _emit(self, rule_id, description, severity='low', **fields):
        inventory_type = str(fields.get('inventory_type') or '').lower()
        capability_ids = {1}
        if rule_id == 'PROC_ASSET_TELEMETRY_HEALTH':
            capability_ids.update((7, 8, 24))
        if inventory_type == 'service' or 'SERVICE' in rule_id:
            capability_ids.update((7, 24))
        persistence_types = {
            'scheduled_task', 'startup', 'ssh_key', 'wmi_subscription',
            'browser_extension', 'boot_configuration',
        }
        if inventory_type in persistence_types:
            capability_ids.update((7, 8))
        if inventory_type == 'service' and rule_id in ('SERVICE_CREATED', 'SERVICE_CONFIG_CHANGED'):
            capability_ids.add(8)
        if inventory_type == 'container' or 'CONTAINER' in rule_id:
            capability_ids.update((7, 19))
        is_persistence_change = 8 in capability_ids and rule_id not in (
            'PROC_ASSET_TELEMETRY_HEALTH', 'PROC_ASSET_INVENTORY',
        )
        is_system_change = 7 in capability_ids and rule_id not in (
            'PROC_ASSET_TELEMETRY_HEALTH', 'PROC_ASSET_INVENTORY',
        )
        if is_system_change:
            category_map = {
                'service': 'services', 'scheduled_task': 'scheduled_tasks',
                'startup': 'startup_configuration', 'ssh_key': 'remote_access',
                'wmi_subscription': 'registry_configuration',
                'browser_extension': 'software', 'boot_configuration': 'boot_kernel',
                'container': 'container_virtualization',
            }
            change_type = fields.get('change_type') or rule_id.lower()
            current_item = fields.get('inventory_item') or {
                key: fields.get(key) for key in (
                    'service_name', 'current_status', 'service_binary_path',
                    'runtime_type', 'container_id', 'pod_name', 'namespace', 'container_risks',
                ) if fields.get(key) is not None
            }
            previous_item = fields.get('old_inventory_item') or {
                key: fields.get(key) for key in ('previous_status',) if fields.get(key) is not None
            }
            fields.update({
                'system_change_category': category_map.get(inventory_type, 'system_configuration'),
                'system_change_type': change_type,
                'system_change_target': fields.get('inventory_name') or fields.get('service_name')
                    or fields.get('container_id') or fields.get('pod_name'),
                'previous_state': previous_item or None,
                'new_state': current_item or None,
                'baseline_status': 'removed' if 'REMOVED' in rule_id or 'DELETED' in rule_id
                    else 'new' if 'CREATED' in rule_id or 'STARTED' in rule_id
                    else 'modified',
                'change_source': 'native_inventory',
                'detection_reason': fields.get('detection_reason') or description,
            })
        payload = {
            'rule_id': rule_id, 'capabilityId': 8 if is_persistence_change else 1,
            'capabilityIds': sorted(capability_ids), 'category': 'edr',
            'source': 'process_assets', 'severity': severity,
            'description': description, 'user_action': rule_id.lower(),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            **fields,
        }
        if is_persistence_change:
            payload.update({'category': 'persistence', 'is_persistence': True})
        payload.setdefault('raw', {key: value for key, value in fields.items() if value is not None})
        self._sender.enqueue(payload)

    def _persistence_assessment(self, kind, row):
        """Score concrete persistence evidence without flagging every admin change."""
        text = json.dumps(row or {}, sort_keys=True, default=str).lower().replace('\\\\', '/')
        base = {
            'scheduled_task': 35, 'startup': 40, 'ssh_key': 65,
            'wmi_subscription': 65, 'browser_extension': 30,
            'boot_configuration': 65,
        }.get(kind, 30)
        indicators = []
        suspicious = {
            'user_writable_path': r'/(?:temp|tmp|appdata|downloads?|public)/',
            'script_or_lolbin': r'powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|curl|wget',
            'encoded_or_hidden': r'encodedcommand|(?:^|\s)-enc\b|frombase64|string.*hidden|hidden.?task',
            'download_execute': r'https?://|downloadstring|invoke-webrequest|curl.+\|.+sh|wget.+\|.+sh',
            'privileged_context': r'"user":\s*"(?:root|system|localservice|networkservice)"|/root/\.ssh/',
            'unsigned': r'"(?:signature_status|signature)":\s*"(?:unsigned|invalid|revoked|untrusted)',
        }
        for reason, pattern in suspicious.items():
            if re.search(pattern, text):
                indicators.append(reason)
                base += 12 if reason not in ('encoded_or_hidden', 'download_execute', 'unsigned') else 20
        trusted = bool(re.search(r'microsoft|windows/system32|/usr/(?:lib|bin)/|/lib/systemd/system/', text))
        if trusted and not indicators:
            base -= 15
        risk = min(100, max(10, base))
        severity = 'critical' if risk >= 85 else 'high' if risk >= 65 else 'medium' if risk >= 40 else 'low'
        return risk, severity, indicators

    def _diff(self, kind, rows):
        current = {str(row.get('id') or row.get('name')): row for row in rows if row.get('id') or row.get('name')}
        previous = self._snapshots.get(kind)
        self._snapshots[kind] = current
        if previous is None:
            items = list(current.values())
            batches = [items[index:index + 200] for index in range(0, len(items), 200)] or [[]]
            for index, batch in enumerate(batches, 1):
                self._emit(
                    'PROC_ASSET_INVENTORY',
                    f'{kind.replace("_", " ").title()} inventory: {len(current)} item(s), batch {index}/{len(batches)}',
                    inventory_type=kind, inventory_count=len(current), inventory_items=batch,
                    inventory_batch_index=index, inventory_batch_count=len(batches),
                    eventType='Inventory Snapshot', evidence_type='native_inventory',
                )
            return
        for key in sorted(current.keys() - previous.keys()):
            row = current[key]
            if kind == 'service':
                self._emit_service_event('SERVICE_CREATED', row, None)
                continue
            metadata = {
                'scheduled_task': ('high', 'T1053.005' if self._system == 'Windows' else 'T1053.003', 'Scheduled Task/Job'),
                'startup': ('high', 'T1547.001' if self._system == 'Windows' else 'T1547', 'Boot or Logon Autostart Execution'),
                'ssh_key': ('high', 'T1098.004', 'SSH Authorized Keys'),
                'wmi_subscription': ('critical', 'T1546.003', 'WMI Event Subscription'),
                'browser_extension': ('medium', 'T1176', 'Browser Extensions'),
                'boot_configuration': ('high', 'T1542', 'Pre-OS Boot'),
            }.get(kind, ('medium', None, kind.replace('_', ' ').title()))
            severity, mitre_id, technique = metadata
            risk_score, severity, indicators = self._persistence_assessment(kind, row)
            self._emit('PROC_ASSET_CREATED', f'New {kind.replace("_", " ")} detected: {row.get("name") or key}', severity,
                       inventory_type=kind, inventory_name=row.get('name') or key,
                       change_type='created', inventory_item=row, eventType='Inventory Change',
                       persistence_type=kind, persistence_location=row.get('location') or row.get('path'),
                       persistence_key=row.get('fingerprint') or row.get('id'),
                       mitre_id=mitre_id, technique=technique,
                       risk_score=risk_score, confidence_score=min(98, 55 + len(indicators) * 8),
                       detection_indicators=indicators,
                       detection_reason=f'New {kind.replace("_", " ")} differs from the endpoint baseline')
        for key in sorted(previous.keys() - current.keys()):
            row = previous[key]
            if kind == 'service':
                self._emit_service_event('SERVICE_DELETED', row, row)
                continue
            self._emit('PROC_ASSET_REMOVED', f'{kind.replace("_", " ").title()} removed: {row.get("name") or key}', 'medium',
                       inventory_type=kind, inventory_name=row.get('name') or key,
                       change_type='removed', inventory_item=row, eventType='Inventory Change')
        for key in sorted(current.keys() & previous.keys()):
            if _fingerprint(current[key]) != _fingerprint(previous[key]):
                if kind == 'service':
                    self._emit_service_change(previous[key], current[key])
                    continue
                metadata = {
                    'scheduled_task': ('high', 'T1053.005' if self._system == 'Windows' else 'T1053.003', 'Scheduled Task/Job'),
                    'startup': ('high', 'T1547.001' if self._system == 'Windows' else 'T1547', 'Boot or Logon Autostart Execution'),
                    'ssh_key': ('high', 'T1098.004', 'SSH Authorized Keys'),
                    'wmi_subscription': ('critical', 'T1546.003', 'WMI Event Subscription'),
                    'browser_extension': ('medium', 'T1176', 'Browser Extensions'),
                    'boot_configuration': ('high', 'T1542', 'Pre-OS Boot'),
                }.get(kind, ('medium', None, kind.replace('_', ' ').title()))
                severity, mitre_id, technique = metadata
                risk_score, severity, indicators = self._persistence_assessment(kind, current[key])
                self._emit('PROC_ASSET_CHANGED', f'{kind.replace("_", " ").title()} changed: {current[key].get("name") or key}', severity,
                           inventory_type=kind, inventory_name=current[key].get('name') or key,
                           change_type='modified', old_inventory_item=previous[key], inventory_item=current[key],
                           eventType='Inventory Change', persistence_type=kind,
                           persistence_location=current[key].get('location') or current[key].get('path'),
                           persistence_key=current[key].get('fingerprint') or current[key].get('id'),
                           mitre_id=mitre_id, technique=technique,
                           risk_score=risk_score, confidence_score=min(98, 55 + len(indicators) * 8),
                           detection_indicators=indicators,
                           detection_reason=f'{kind.replace("_", " ").title()} changed from the endpoint baseline')

    @staticmethod
    def _normalized_service_state(row):
        value = str(row.get('sub_status') or row.get('status') or row.get('state') or 'unknown').strip().lower()
        return {
            'active': 'RUNNING', 'running': 'RUNNING', 'start_pending': 'START_PENDING',
            'inactive': 'STOPPED', 'stopped': 'STOPPED', 'dead': 'STOPPED',
            'stop_pending': 'STOP_PENDING', 'paused': 'PAUSED', 'pause_pending': 'PAUSE_PENDING',
            'continue_pending': 'CONTINUE_PENDING', 'failed': 'FAILED',
        }.get(value, value.upper() or 'UNKNOWN')

    @staticmethod
    def _service_binary_path(row):
        value = str(row.get('binary_path') or row.get('exec_start') or '').strip()
        if not value:
            return ''
        quoted = re.match(r'^\s*[{-]*\s*["\']([^"\']+)["\']', value)
        if quoted:
            return quoted.group(1)
        token = value.lstrip('{ -').split(';', 1)[0].strip().split(None, 1)[0]
        return token.strip('"\'')

    def _service_fields(self, row, previous=None, inspect_binary=False):
        previous = previous or {}
        name = str(row.get('name') or row.get('id') or 'unknown')
        binary_path = self._service_binary_path(row)
        fields = {
            'inventory_type': 'service',
            'inventory_name': name,
            'service_name': name,
            'service_display_name': row.get('display_name') or row.get('description') or name,
            'previous_status': self._normalized_service_state(previous) if previous else None,
            'current_status': self._normalized_service_state(row),
            'startup_type': row.get('start_type') or row.get('unit_file_state'),
            'service_account': row.get('username') or row.get('user'),
            'service_binary_path': binary_path,
            'service_dependencies': row.get('dependencies') or [],
            'service_pid': row.get('pid') or row.get('main_pid'),
            'service_restart_count': row.get('restart_count'),
            'service_unit_path': row.get('unit_path'),
            'old_inventory_item': previous or None,
            'inventory_item': row,
            'evidence_type': 'native_service_manager',
        }
        if inspect_binary and binary_path:
            try:
                from collectors.hash_signature import ENGINE
                trust = ENGINE.inspect(
                    binary_path,
                    include_sha1=bool(self._config.get('hash_sha1_enabled', True)),
                    include_md5=bool(self._config.get('hash_md5_enabled', False)),
                    signature=bool(self._config.get('hash_signature_validation_enabled', True)),
                )
                fields.update({
                    'service_binary_sha256': trust.get('sha256'),
                    'service_binary_sha1': trust.get('sha1'),
                    'service_binary_md5': trust.get('md5'),
                    'service_signature_status': trust.get('signatureStatus'),
                    'service_publisher': trust.get('publisher'),
                    'service_package_owner': trust.get('packageOwner'),
                    'service_package_verification_status': trust.get('packageVerificationStatus'),
                })
            except (ImportError, OSError, ValueError):
                pass
        return {key: value for key, value in fields.items() if value is not None}

    def _emit_service_event(self, event_type, row, previous=None):
        fields = self._service_fields(row, previous, inspect_binary=event_type in ('SERVICE_CREATED', 'SERVICE_CONFIG_CHANGED'))
        name = fields['service_name']
        current = fields.get('current_status', 'UNKNOWN')
        binary = fields.get('service_binary_path', '')
        security_service = bool(SECURITY_SERVICE_PATTERN.search(name))
        suspicious_path = bool(binary and SUSPICIOUS_SERVICE_PATH_PATTERN.search(binary.replace('\\', '/')))
        signature = str(fields.get('service_signature_status') or '').upper()
        risk = {
            'SERVICE_CREATED': 45,
            'SERVICE_DELETED': 55,
            'SERVICE_STARTED': 15,
            'SERVICE_STOPPED': 25,
            'SERVICE_RESTARTED': 30,
            'SERVICE_FAILED': 55,
            'SERVICE_CONFIG_CHANGED': 45,
        }.get(event_type, 20)
        if security_service and event_type in ('SERVICE_STOPPED', 'SERVICE_FAILED', 'SERVICE_DELETED'):
            risk += 40
        if suspicious_path:
            risk += 25
        if signature in ('INVALID', 'REVOKED', 'UNTRUSTED_PUBLISHER'):
            risk += 30
        elif signature == 'UNSIGNED':
            risk += 15
        risk = min(100, risk)
        severity = 'critical' if risk >= 80 else 'high' if risk >= 60 else 'medium' if risk >= 40 else 'low'
        labels = {
            'SERVICE_CREATED': 'Service created', 'SERVICE_DELETED': 'Service deleted',
            'SERVICE_STARTED': 'Service started', 'SERVICE_STOPPED': 'Service stopped',
            'SERVICE_RESTARTED': 'Service restarted', 'SERVICE_FAILED': 'Service failed',
            'SERVICE_CONFIG_CHANGED': 'Service configuration changed',
        }
        self._emit(
            event_type,
            f'{labels.get(event_type, "Service changed")}: {name} ({fields.get("previous_status", "UNKNOWN")} -> {current})',
            severity,
            **fields,
            change_type=event_type.lower().replace('service_', ''),
            eventType=event_type,
            risk_score=risk,
            security_service=security_service,
            suspicious_service_path=suspicious_path,
            mitre_id='T1543.003' if self._system == 'Windows' else 'T1543.002',
            technique='Create or Modify System Process: Service',
            recommended_action='Validate the service owner, binary integrity and approved change record.',
        )

    def _emit_service_change(self, previous, current):
        old_state = self._normalized_service_state(previous)
        new_state = self._normalized_service_state(current)
        old_restarts = int(previous.get('restart_count') or 0)
        new_restarts = int(current.get('restart_count') or 0)
        if new_state == 'FAILED':
            event_type = 'SERVICE_FAILED'
        elif new_restarts > old_restarts and new_state == 'RUNNING':
            event_type = 'SERVICE_RESTARTED'
        elif old_state != new_state and new_state == 'RUNNING':
            event_type = 'SERVICE_STARTED'
        elif old_state != new_state and new_state == 'STOPPED':
            event_type = 'SERVICE_STOPPED'
        else:
            event_type = 'SERVICE_CONFIG_CHANGED'
        self._emit_service_event(event_type, current, previous)

    def _windows_services(self):
        try:
            import psutil
            rows = []
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    rows.append({
                        'id': info.get('name'), 'name': info.get('name'),
                        'display_name': info.get('display_name'), 'status': info.get('status'),
                        'start_type': info.get('start_type'), 'binary_path': info.get('binpath'),
                        'username': info.get('username'),
                    })
                except Exception:
                    continue
            return rows
        except Exception:
            return []

    def _unix_services(self):
        if self._system == 'Darwin':
            result = _run(['launchctl', 'list'])
            if not result or result.returncode:
                return []
            rows = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split(None, 2)
                if len(parts) == 3:
                    rows.append({'id': parts[2], 'name': parts[2], 'pid': parts[0], 'status': parts[1]})
            return rows
        result = _run([
            'systemctl', 'show', '--type=service', '--all', '--no-pager',
            '--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,ExecStart,User,MainPID,NRestarts',
        ], timeout=30)
        if not result or result.returncode:
            return []
        rows = []
        for block in re.split(r'\r?\n\r?\n', result.stdout.strip()):
            values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            name = values.get('Id')
            if not name:
                continue
            rows.append({
                'id': name, 'name': name, 'description': values.get('Description'),
                'load': values.get('LoadState'), 'status': values.get('ActiveState'),
                'sub_status': values.get('SubState'), 'unit_file_state': values.get('UnitFileState'),
                'unit_path': values.get('FragmentPath'), 'exec_start': values.get('ExecStart'),
                'user': values.get('User') or 'root', 'main_pid': values.get('MainPID'),
                'restart_count': values.get('NRestarts'),
            })
        return rows

    def _windows_tasks(self):
        script = (
            "Get-ScheduledTask | ForEach-Object { [pscustomobject]@{"
            "TaskName=$_.TaskName;TaskPath=$_.TaskPath;State=[string]$_.State;"
            "Author=$_.Author;Description=$_.Description;"
            "Hidden=$_.Settings.Hidden;RunLevel=[string]$_.Principal.RunLevel;Principal=$_.Principal.UserId;"
            "Actions=@($_.Actions | ForEach-Object { [pscustomobject]@{Execute=$_.Execute;Arguments=$_.Arguments;WorkingDirectory=$_.WorkingDirectory} });"
            "Triggers=@($_.Triggers | ForEach-Object { [pscustomobject]@{Enabled=$_.Enabled;StartBoundary=$_.StartBoundary;EndBoundary=$_.EndBoundary} })"
            "} } | ConvertTo-Json -Compress -Depth 6"
        )
        native = _run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], timeout=30)
        if native and native.returncode == 0 and native.stdout.strip():
            try:
                parsed = json.loads(native.stdout)
                values = parsed if isinstance(parsed, list) else [parsed]
                return [{
                    'id': f'{row.get("TaskPath") or ""}{row.get("TaskName") or ""}',
                    'name': f'{row.get("TaskPath") or ""}{row.get("TaskName") or ""}',
                    'status': row.get('State'), 'author': row.get('Author'),
                    'description': row.get('Description'), 'actions': row.get('Actions'),
                    'triggers': row.get('Triggers'), 'hidden': row.get('Hidden'),
                    'run_level': row.get('RunLevel'), 'principal': row.get('Principal'),
                } for row in values if isinstance(row, dict) and row.get('TaskName')]
            except (json.JSONDecodeError, TypeError):
                pass
        result = _run(['schtasks.exe', '/Query', '/FO', 'CSV', '/V'])
        if not result or result.returncode:
            return []
        rows = []
        try:
            for row in csv.DictReader(result.stdout.splitlines()):
                lowered = {str(k).lower(): v for k, v in row.items()}
                name = lowered.get('taskname') or lowered.get('task name')
                if name:
                    rows.append({'id': name, 'name': name, 'status': lowered.get('status'),
                                 'next_run': lowered.get('next run time'), 'run_as': lowered.get('run as user'),
                                 'command': lowered.get('task to run') or lowered.get('actions')})
        except csv.Error:
            pass
        return rows

    def _unix_tasks(self):
        rows = []
        if self._system == 'Linux':
            result = _run(['systemctl', 'list-timers', '--all', '--no-legend', '--plain'])
            if result and result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    unit = next((part for part in parts if part.endswith('.timer')), '')
                    if unit:
                        rows.append({'id': f'timer:{unit}', 'name': unit, 'source': 'systemd_timer'})
        cron_paths = ['/etc/crontab', '/etc/cron.d/*', '/var/spool/cron/*', '/var/spool/cron/crontabs/*']
        for pattern in cron_paths:
            for value in glob.glob(pattern):
                try:
                    stat = os.stat(value)
                    rows.append({'id': f'cron:{value}', 'name': value, 'source': 'cron',
                                 'mtime_ns': stat.st_mtime_ns, 'size': stat.st_size})
                except OSError:
                    pass
        return rows

    def _windows_startup(self):
        rows = []
        try:
            import winreg
            locations = [
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM'),
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU'),
            ]
            for hive, key_path, hive_name in locations:
                for view in (getattr(winreg, 'KEY_WOW64_64KEY', 0), getattr(winreg, 'KEY_WOW64_32KEY', 0)):
                    try:
                        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                            index = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, index)
                                    path = f'{hive_name}\\{key_path}\\{name}'
                                    rows.append({'id': path, 'name': name, 'location': path, 'command': str(value)})
                                    index += 1
                                except OSError:
                                    break
                    except OSError:
                        continue
            # The service runs as LocalSystem, so HKCU alone is insufficient.
            # Enumerate every currently loaded user hive as well.
            index = 0
            while True:
                try:
                    sid = winreg.EnumKey(winreg.HKEY_USERS, index)
                    index += 1
                except OSError:
                    break
                if sid.endswith('_Classes'):
                    continue
                for suffix in (
                    r'Software\Microsoft\Windows\CurrentVersion\Run',
                    r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                ):
                    key_path = f'{sid}\\{suffix}'
                    try:
                        with winreg.OpenKey(winreg.HKEY_USERS, key_path, 0, winreg.KEY_READ) as key:
                            value_index = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, value_index)
                                    location = f'HKU\\{key_path}\\{name}'
                                    rows.append({'id': location, 'name': name, 'location': location, 'command': str(value)})
                                    value_index += 1
                                except OSError:
                                    break
                    except OSError:
                        continue
        except ImportError:
            pass
        startup_dirs = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp'),
            os.path.expandvars(r'%SystemDrive%\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*'),
        ]
        rows.extend(self._path_inventory(startup_dirs, 'startup_folder'))
        return rows

    @staticmethod
    def _path_inventory(patterns, source):
        rows = []
        for pattern in patterns:
            for value in glob.glob(pattern):
                path = Path(value)
                try:
                    stat = path.stat()
                    if path.is_dir():
                        for child in path.iterdir():
                            child_stat = child.stat()
                            rows.append({'id': str(child), 'name': child.name, 'source': source,
                                         'mtime_ns': child_stat.st_mtime_ns, 'size': child_stat.st_size})
                    else:
                        rows.append({'id': str(path), 'name': path.name, 'source': source,
                                     'mtime_ns': stat.st_mtime_ns, 'size': stat.st_size})
                except OSError:
                    pass
        return rows

    def _unix_startup(self):
        patterns = [
            '/etc/rc.local', '/etc/systemd/system/*.service', '/etc/init.d/*',
            str(Path.home() / '.config/autostart/*'),
        ]
        if self._system == 'Darwin':
            patterns = [
                '/Library/LaunchAgents/*.plist', '/Library/LaunchDaemons/*.plist',
                str(Path.home() / 'Library/LaunchAgents/*.plist'),
            ]
        return self._path_inventory(patterns, 'startup_file')

    @staticmethod
    def _bounded_file_row(path, source, owner=''):
        """Return metadata plus a bounded hash; never transmit file contents."""
        try:
            stat = path.stat()
            if not path.is_file() or stat.st_size > 4 * 1024 * 1024:
                return None
            digest = hashlib.sha256()
            with path.open('rb') as handle:
                for chunk in iter(lambda: handle.read(256 * 1024), b''):
                    digest.update(chunk)
            return {
                'id': str(path), 'name': path.name, 'path': str(path),
                'location': str(path), 'source': source, 'owner': owner,
                'mtime_ns': stat.st_mtime_ns, 'size': stat.st_size,
                'sha256': digest.hexdigest(),
            }
        except OSError:
            return None

    def _ssh_keys(self):
        if self._system == 'Windows':
            patterns = [r'C:\\Users\\*\\.ssh\\authorized_keys', r'C:\\ProgramData\\ssh\\administrators_authorized_keys']
        else:
            patterns = ['/root/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys', str(Path.home() / '.ssh/authorized_keys')]
        rows = []
        for pattern in patterns:
            for value in glob.glob(pattern):
                path = Path(value)
                owner = path.parts[-3] if len(path.parts) >= 3 else ''
                row = self._bounded_file_row(path, 'ssh_authorized_keys', owner)
                if row:
                    rows.append(row)
        return rows

    def _browser_extensions(self):
        home = str(Path.home())
        if self._system == 'Windows':
            roots = [
                os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\*\Extensions\*\*\manifest.json'),
                os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Extensions\*\*\manifest.json'),
                os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json'),
            ]
        elif self._system == 'Darwin':
            roots = [f'{home}/Library/Application Support/Google/Chrome/*/Extensions/*/*/manifest.json',
                     f'{home}/Library/Application Support/Firefox/Profiles/*/extensions.json']
        else:
            roots = [f'{home}/.config/google-chrome/*/Extensions/*/*/manifest.json',
                     f'{home}/.config/chromium/*/Extensions/*/*/manifest.json',
                     f'{home}/.mozilla/firefox/*/extensions.json']
        rows = []
        for pattern in roots:
            for value in glob.glob(pattern)[:1000]:
                row = self._bounded_file_row(Path(value), 'browser_extension')
                if row:
                    row['id'] = str(Path(value).parent)
                    row['name'] = Path(value).parent.name
                    rows.append(row)
        return rows

    def _boot_configuration(self):
        if self._system == 'Windows':
            result = _run(['bcdedit.exe', '/enum', '{current}'], timeout=10)
            if not result or result.returncode:
                return []
            value = result.stdout[:65536]
            return [{'id': 'windows:bcd:current', 'name': 'Windows BCD', 'location': 'BCD {current}',
                     'sha256': hashlib.sha256(value.encode(errors='replace')).hexdigest()}]
        patterns = ['/etc/default/grub', '/boot/grub/grub.cfg', '/boot/grub2/grub.cfg', '/boot/loader/entries/*.conf']
        rows = []
        for pattern in patterns:
            for value in glob.glob(pattern):
                row = self._bounded_file_row(Path(value), 'boot_configuration')
                if row:
                    rows.append(row)
        return rows

    def _wmi_subscriptions(self):
        if self._system != 'Windows':
            return []
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ns='root/subscription';"
            "$items=@();"
            "Get-CimInstance -Namespace $ns -ClassName __EventFilter | % {$items += [pscustomobject]@{Kind='Filter';Name=$_.Name;Query=$_.Query}};"
            "Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer | % {$items += [pscustomobject]@{Kind='CommandLineConsumer';Name=$_.Name;Command=$_.CommandLineTemplate}};"
            "Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer | % {$items += [pscustomobject]@{Kind='ScriptConsumer';Name=$_.Name;Command=$_.ScriptText}};"
            "Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | % {$items += [pscustomobject]@{Kind='Binding';Name=([string]$_.Filter+' -> '+[string]$_.Consumer);Command=''}};"
            "$items | ConvertTo-Json -Compress -Depth 4"
        )
        result = _run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], timeout=20)
        if not result or result.returncode or not result.stdout.strip():
            return []
        try:
            parsed = json.loads(result.stdout)
            values = parsed if isinstance(parsed, list) else [parsed]
            return [{'id': f'{row.get("Kind")}:{row.get("Name")}', 'name': row.get('Name'),
                     'location': r'root\subscription', 'subscription_type': row.get('Kind'),
                     'command': str(row.get('Command') or row.get('Query') or '')[:4000]}
                    for row in values if isinstance(row, dict) and row.get('Name')]
        except (json.JSONDecodeError, TypeError):
            return []

    def _workloads(self):
        try:
            import psutil
        except ImportError:
            return []
        sockets = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid:
                    item = sockets.setdefault(conn.pid, {'listeners': [], 'remote': []})
                    if conn.status == 'LISTEN' and conn.laddr:
                        item['listeners'].append(getattr(conn.laddr, 'port', 0))
                    elif conn.raddr:
                        item['remote'].append(f'{getattr(conn.raddr, "ip", "")}:{getattr(conn.raddr, "port", 0)}')
        except (psutil.AccessDenied, OSError):
            pass
        rows = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'exe', 'username', 'create_time']):
            try:
                info = proc.info
                cmd = ' '.join(info.get('cmdline') or [])
                role = workload_role(info.get('name') or '', cmd)
                if not role:
                    continue
                net = sockets.get(info['pid'], {})
                rows.append({
                    'id': f'{info["pid"]}:{info.get("create_time") or 0}', 'name': info.get('name'),
                    'pid': info['pid'], 'ppid': info.get('ppid'), 'role': role,
                    'exe': info.get('exe'), 'cmdline': cmd[:2000], 'username': info.get('username'),
                    'listener_ports': sorted(set(net.get('listeners') or [])),
                    'remote_addresses': list(dict.fromkeys(net.get('remote') or []))[:30],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return rows

    def _diff_workloads(self, rows):
        current = {row['id']: row for row in rows}
        previous = self._snapshots.get('workload')
        self._snapshots['workload'] = current
        if previous is None:
            batches = [rows[index:index + 200] for index in range(0, len(rows), 200)] or [[]]
            for index, batch in enumerate(batches, 1):
                self._emit('PROC_WORKLOAD_INVENTORY', f'Dedicated application/database inventory: {len(rows)} workload(s), batch {index}/{len(batches)}',
                           inventory_type='workload', inventory_count=len(rows), inventory_items=batch,
                           inventory_batch_index=index, inventory_batch_count=len(batches),
                           eventType='Workload Inventory', evidence_type='process_socket_inventory')
            return
        for key in current.keys() - previous.keys():
            row = current[key]
            self._emit('PROC_WORKLOAD_STARTED', f'{row["role"]} workload started: {row["name"]}',
                       process_name=row['name'], pid=row['pid'], parent_pid=row.get('ppid'), cmdline=row.get('cmdline'),
                       exe=row.get('exe'), username=row.get('username'), workload_type=row['role'],
                       listener_ports=row.get('listener_ports'), remote_addresses=row.get('remote_addresses'),
                       process_classifications=['server_workload', row['role']], eventType='Workload Started')
        for key in previous.keys() - current.keys():
            row = previous[key]
            self._emit('PROC_WORKLOAD_STOPPED', f'{row["role"]} workload stopped: {row["name"]}', 'medium',
                       process_name=row['name'], pid=row['pid'], workload_type=row['role'],
                       process_classifications=['server_workload', row['role']], eventType='Workload Stopped')

    def _docker_inventory(self, runtime):
        result = _run([runtime, 'ps', '-a', '--no-trunc', '--format', '{{json .}}'])
        if not result or result.returncode:
            return []
        rows = []
        for line in result.stdout.splitlines():
            try:
                summary = json.loads(line)
            except json.JSONDecodeError:
                continue
            container_id = summary.get('ID') or summary.get('Id')
            inspect = {}
            if container_id:
                detail = _run([runtime, 'inspect', container_id], timeout=8)
                if detail and detail.returncode == 0:
                    try:
                        values = json.loads(detail.stdout)
                        inspect = values[0] if values else {}
                    except (json.JSONDecodeError, TypeError):
                        pass
            rows.append({
                'id': f'{runtime}:{container_id}', 'name': summary.get('Names') or container_id,
                'runtime': runtime, 'container_id': container_id, 'image': summary.get('Image'),
                'state': summary.get('State'), 'status': summary.get('Status'),
                'ports': summary.get('Ports'), 'risks': container_risks(inspect),
            })
        return rows

    def _kubernetes_inventory(self):
        result = _run(['kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json', '--request-timeout=8s'], timeout=12)
        if not result or result.returncode:
            return []
        try:
            pods = (json.loads(result.stdout) or {}).get('items') or []
        except json.JSONDecodeError:
            return []
        rows = []
        for pod in pods:
            meta, status = pod.get('metadata') or {}, pod.get('status') or {}
            uid = meta.get('uid') or f'{meta.get("namespace")}:{meta.get("name")}'
            rows.append({
                'id': f'kubernetes:{uid}', 'name': meta.get('name'), 'runtime': 'kubernetes',
                'namespace': meta.get('namespace'), 'pod_uid': uid, 'state': status.get('phase'),
                'node': (pod.get('spec') or {}).get('nodeName'), 'risks': kubernetes_pod_risks(pod),
                'images': [c.get('image') for c in (pod.get('spec') or {}).get('containers') or []],
            })
        return rows

    def _container_inventory(self):
        rows = []
        for runtime in ('docker', 'podman'):
            rows.extend(self._docker_inventory(runtime))
        rows.extend(self._kubernetes_inventory())
        return rows

    def _runtime_event_loop(self, runtime):
        """Stream lifecycle/exec events directly from Docker or Podman."""
        while True:
            try:
                proc = subprocess.Popen(
                    [runtime, 'events', '--format', '{{json .}}'],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                )
                for line in proc.stdout or []:
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    action = str(event.get('Action') or event.get('status') or '').lower()
                    event_type = str(event.get('Type') or event.get('type') or 'container').lower()
                    if event_type not in ('container', 'pod'):
                        continue
                    actor = event.get('Actor') or event.get('actor') or {}
                    attrs = actor.get('Attributes') or actor.get('attributes') or {}
                    container_id = actor.get('ID') or actor.get('id') or event.get('id') or ''
                    name = attrs.get('name') or container_id[:12] or 'unknown'
                    suspicious = action.startswith('exec_') or action in ('attach', 'commit', 'export')
                    self._emit(
                        'PROC_CONTAINER_RUNTIME_EVENT',
                        f'{runtime} {event_type} event: {name} {action or "activity"}',
                        'medium' if suspicious else 'low',
                        inventory_type='container', inventory_name=name, runtime_type=runtime,
                        container_id=container_id, change_type=action,
                        eventType='Container Runtime Event', evidence_type=f'{runtime}_event_stream',
                        container_event=event,
                    )
                if proc.poll() is None:
                    proc.terminate()
            except Exception as exc:
                logger.info('%s event stream unavailable: %s', runtime, exc)
            time.sleep(15)

    def _kubernetes_event_loop(self):
        """Stream Kubernetes warning/lifecycle events through the local context."""
        while True:
            try:
                proc = subprocess.Popen(
                    ['kubectl', 'get', 'events', '--all-namespaces', '--watch-only',
                     '--output-watch-events=false',
                     '-o', r'custom-columns=NAMESPACE:.metadata.namespace,TYPE:.type,REASON:.reason,OBJECT:.involvedObject.name,MESSAGE:.message',
                     '--no-headers'],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                )
                for line in proc.stdout or []:
                    parts = line.rstrip().split(None, 4)
                    if len(parts) < 4:
                        continue
                    namespace, level, reason, obj = parts[:4]
                    message = parts[4] if len(parts) > 4 else ''
                    severity = 'medium' if level.lower() == 'warning' else 'low'
                    self._emit(
                        'PROC_KUBERNETES_RUNTIME_EVENT',
                        f'Kubernetes {level} event {reason}: {obj}', severity,
                        inventory_type='container', inventory_name=obj, runtime_type='kubernetes',
                        pod_name=obj, namespace=namespace, change_type=reason,
                        eventType='Kubernetes Runtime Event', evidence_type='kubernetes_watch_api',
                        raw_log=line[:4000], kubernetes_message=message,
                    )
                if proc.poll() is None:
                    proc.terminate()
            except Exception as exc:
                logger.info('Kubernetes event stream unavailable: %s', exc)
            time.sleep(15)

    def _diff_containers(self, rows):
        current = {row['id']: row for row in rows}
        previous = self._snapshots.get('container')
        self._snapshots['container'] = current
        if previous is None:
            runtime_available = any(shutil.which(name) for name in ('docker', 'podman', 'kubectl'))
            status = 'active' if runtime_available else 'unavailable'
            batches = [rows[index:index + 200] for index in range(0, len(rows), 200)] or [[]]
            for index, batch in enumerate(batches, 1):
                self._emit('PROC_CONTAINER_INVENTORY', f'Container/Kubernetes inventory: {len(rows)} workload(s), batch {index}/{len(batches)}',
                           inventory_type='container', inventory_count=len(rows), inventory_items=batch,
                           inventory_batch_index=index, inventory_batch_count=len(batches),
                           coverage_status=status,
                           sensor_status={'docker': bool(shutil.which('docker')), 'podman': bool(shutil.which('podman')), 'kubernetes': bool(shutil.which('kubectl'))},
                           eventType='Container Inventory', evidence_type='runtime_api')
            for row in rows:
                if row.get('risks'):
                    self._emit('PROC_CONTAINER_RISK', f'Risky {row["runtime"]} workload {row.get("name")}: {", ".join(row["risks"])}', 'high',
                               inventory_type='container', inventory_name=row.get('name'), runtime_type=row['runtime'],
                               container_id=row.get('container_id'), pod_name=row.get('name'), namespace=row.get('namespace'),
                               container_risks=row['risks'], eventType='Container Security Risk', mitre_id='T1611')
            return
        for key in current.keys() - previous.keys():
            row = current[key]
            severity = 'high' if row.get('risks') else 'low'
            self._emit('PROC_CONTAINER_STARTED', f'{row["runtime"]} workload discovered: {row.get("name")}', severity,
                       inventory_type='container', inventory_name=row.get('name'), runtime_type=row['runtime'],
                       container_id=row.get('container_id'), pod_name=row.get('name'), namespace=row.get('namespace'),
                       container_risks=row.get('risks'), eventType='Container Started')
        for key in previous.keys() - current.keys():
            row = previous[key]
            self._emit('PROC_CONTAINER_STOPPED', f'{row["runtime"]} workload removed/stopped: {row.get("name")}', 'medium',
                       inventory_type='container', inventory_name=row.get('name'), runtime_type=row['runtime'],
                       container_id=row.get('container_id'), pod_name=row.get('name'), namespace=row.get('namespace'),
                       eventType='Container Stopped')
        for key in current.keys() & previous.keys():
            if _fingerprint(current[key]) != _fingerprint(previous[key]) and current[key].get('risks'):
                row = current[key]
                self._emit('PROC_CONTAINER_RISK', f'Risky {row["runtime"]} workload changed: {row.get("name")}', 'high',
                           inventory_type='container', inventory_name=row.get('name'), runtime_type=row['runtime'],
                           container_id=row.get('container_id'), pod_name=row.get('name'), namespace=row.get('namespace'),
                           container_risks=row.get('risks'), eventType='Container Security Risk', mitre_id='T1611')

    def _loop(self):
        interval = max(30.0, float(self._config.get('process_asset_inventory_interval_seconds', 300)))
        while True:
            try:
                if not (self._config.get('persistence_monitoring_enabled', True)
                        or self._config.get('system_changes_monitoring_enabled', True)):
                    time.sleep(interval)
                    continue
                service_monitoring = self._config.get('service_monitoring_enabled', True)
                services = (self._windows_services() if self._system == 'Windows' else self._unix_services()) if service_monitoring else []
                tasks = self._windows_tasks() if self._system == 'Windows' else self._unix_tasks()
                startup = self._windows_startup() if self._system == 'Windows' else self._unix_startup()
                if service_monitoring:
                    self._diff('service', services)
                self._diff('scheduled_task', tasks)
                self._diff('startup', startup)
                self._diff('ssh_key', self._ssh_keys())
                self._diff('browser_extension', self._browser_extensions())
                self._diff('boot_configuration', self._boot_configuration())
                if self._system == 'Windows':
                    self._diff('wmi_subscription', self._wmi_subscriptions())
                self._diff_workloads(self._workloads())
                if self._config.get('container_monitor_enabled', True):
                    self._diff_containers(self._container_inventory())
            except Exception as exc:
                logger.warning('Process asset inventory failed: %s', exc)
            time.sleep(interval)


Collector = ProcessAssetCollector
