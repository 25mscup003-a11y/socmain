"""High-fidelity Windows process telemetry from modern Event Log channels.

This collector intentionally uses the Windows Event Log (Evt*) API rather than
the legacy OpenEventLog API.  The latter cannot reliably read channels such as
Sysmon/Operational, DNS-Client/Operational, PowerShell/Operational, or
TaskScheduler/Operational.

Deep process-injection evidence is supplied by Sysmon when it is installed and
configured.  Native Security audit events remain useful for process/service/
task activity, but are never presented as equivalent to Sysmon's kernel driver.
"""

from __future__ import annotations

import logging
import json
import os
import platform
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger('soc-agent.collector.windows-process-events')

EVENT_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

CHANNELS = {
    'Microsoft-Windows-Sysmon/Operational': {
        1, 3, 5, 7, 8, 10, 12, 13, 22, 25,
    },
    'Security': {4688, 4697, 4698, 4699, 4702},
    'System': {7035, 7036, 7045},
    'Microsoft-Windows-TaskScheduler/Operational': {106, 140, 141, 200, 201},
    'Microsoft-Windows-PowerShell/Operational': {4103, 4104},
}

REGISTRY_CONFIG_RE = re.compile(
    r'\\(?:currentversion\\run(?:once)?|winlogon|image file execution options|'
    r'windows nt\\currentversion\\windows|services\\[^\\]+\\imagepath|'
    r'windows defender|firewallpolicy|policies\\system|control\\lsa|'
    r'terminal server|services\\eventlog|policies\\microsoft\\windows\\powershell)', re.I,
)
SUSPICIOUS_DLL_PATH_RE = re.compile(
    r'\\(?:users\\[^\\]+\\(?:downloads|appdata\\local\\temp)|windows\\temp|programdata)\\', re.I,
)
SUSPICIOUS_ACCESS_MASKS = {'0x1fffff', '0x1f0fff', '0x143a', '0x1438', '0x40', '0x20'}


def parse_event_xml(xml_text: str) -> dict:
    """Convert rendered Windows event XML into a small stable dictionary."""
    root = ET.fromstring(xml_text)
    system = root.find('e:System', EVENT_NS)
    if system is None:
        return {}
    provider = system.find('e:Provider', EVENT_NS)
    time_node = system.find('e:TimeCreated', EVENT_NS)
    data = {}
    unnamed = []
    event_data = root.find('e:EventData', EVENT_NS)
    if event_data is not None:
        for node in event_data.findall('e:Data', EVENT_NS):
            value = node.text or ''
            key = node.attrib.get('Name')
            if key:
                data[key] = value
            else:
                unnamed.append(value)
    user_data = root.find('e:UserData', EVENT_NS)
    if user_data is not None:
        for node in user_data.iter():
            if node is user_data:
                continue
            key = node.tag.rsplit('}', 1)[-1]
            if node.text and key not in data:
                data[key] = node.text
    return {
        'event_id': int((system.findtext('e:EventID', default='0', namespaces=EVENT_NS) or '0').split()[0]),
        'record_id': int(system.findtext('e:EventRecordID', default='0', namespaces=EVENT_NS) or 0),
        'computer': system.findtext('e:Computer', default='', namespaces=EVENT_NS),
        'provider': provider.attrib.get('Name', '') if provider is not None else '',
        'timestamp': (time_node.attrib.get('SystemTime') if time_node is not None else '') or datetime.now(timezone.utc).isoformat(),
        'data': data,
        'unnamed': unnamed,
    }


def _int(value, default=None):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _registry_classification(target: str):
    text = str(target or '').lower()
    if any(value in text for value in ('windows defender', 'firewallpolicy', 'services\\eventlog')):
        return 'security_configuration', 'critical', 90, 'T1562.001'
    if 'control\\lsa' in text:
        return 'user_authentication', 'critical', 88, 'T1556'
    if 'terminal server' in text:
        return 'network_configuration', 'high', 72, 'T1112'
    if 'services\\' in text:
        return 'service_configuration', 'high', 72, 'T1543.003'
    return 'persistence', 'high', 78, 'T1547.001'


def classify_windows_event(channel: str, event: dict) -> list[dict]:
    """Return capability-1 records for one parsed Windows event."""
    event_id = int(event.get('event_id') or 0)
    d = event.get('data') or {}
    source_image = d.get('SourceImage') or d.get('NewProcessName') or d.get('Image') or ''
    target_image = d.get('TargetImage') or ''
    image = d.get('Image') or source_image or target_image
    process_name = image.replace('/', '\\').rsplit('\\', 1)[-1] if image else ''
    pid = _int(d.get('ProcessId') or d.get('NewProcessId') or d.get('SourceProcessId'))
    parent_pid = _int(d.get('ParentProcessId') or d.get('ProcessId'))
    command = d.get('CommandLine') or d.get('ProcessCommandLine') or d.get('ScriptBlockText') or ''
    user = d.get('User') or d.get('SubjectUserName') or d.get('UserContext') or ''
    common = {
        'capabilityId': 1,
        'category': 'edr',
        'source': 'windows_event_log',
        'telemetry_provider': event.get('provider') or channel,
        'provider_channel': channel,
        'provider_event_id': event_id,
        'provider_record_id': event.get('record_id'),
        'hostname': event.get('computer'),
        'timestamp': event.get('timestamp'),
        'process_name': process_name,
        'pid': pid,
        'parent_pid': parent_pid,
        'cmdline': command[:4000],
        'exe': image,
        'username': user,
        'raw': {'windows_event_data': d},
    }
    findings = []

    def add(rule_id, severity, description, event_type, **extra):
        memory_related = rule_id in {
            'PROC_SUSPICIOUS_DLL_LOAD', 'PROC_DLL_INJECTION',
            'PROC_REMOTE_THREAD_INJECTION', 'PROC_KERNEL_PROCESS_ACCESS',
            'PROC_HOLLOWING',
        }
        findings.append({
            **common,
            'rule_id': rule_id,
            **({'capabilityIds': [1, 5, 29]} if memory_related else {}),
            'severity': severity,
            'description': description,
            'eventType': event_type,
            'user_action': rule_id.lower(),
            **extra,
        })

    if channel.endswith('Sysmon/Operational'):
        if event_id == 1:
            add('PROC_KERNEL_START', 'low', f'Kernel-backed process creation: {process_name or image}', 'Process Create',
                parent_process_name=d.get('ParentImage', '').replace('/', '\\').rsplit('\\', 1)[-1],
                parent_cmdline=d.get('ParentCommandLine', ''), evidence_type='sysmon_process_create', mitre_id='T1059')
        elif event_id == 3:
            destination = d.get('DestinationIp') or ''
            destination_port = _int(d.get('DestinationPort'))
            add('PROC_NETWORK_CONNECTION', 'low',
                f'{process_name or "Process"} connected to {destination}:{destination_port or 0}',
                'Process Network Connection', dest_ip=destination, dst_port=destination_port,
                protocol=d.get('Protocol'), source_ip=d.get('SourceIp'), source_port=_int(d.get('SourcePort')),
                attribution_confidence='exact', evidence_type='sysmon_network_connect', mitre_id='T1071')
        elif event_id == 5:
            add('PROC_KERNEL_TERMINATED', 'low', f'Kernel-backed process termination: {process_name or image}',
                'Process Terminate', evidence_type='sysmon_process_terminate')
        elif event_id == 7:
            loaded = d.get('ImageLoaded') or ''
            signature_status = d.get('SignatureStatus') or ('Valid' if str(d.get('Signed', '')).lower() == 'true' else 'Unsigned')
            suspicious = signature_status.lower() not in ('valid', '') or bool(SUSPICIOUS_DLL_PATH_RE.search(loaded))
            if suspicious:
                add('PROC_SUSPICIOUS_DLL_LOAD', 'high',
                    f'Suspicious DLL loaded into {process_name}: {loaded}', 'DLL Load',
                    image_loaded=loaded, signature_status=signature_status,
                    publisher=d.get('Signature'), evidence_type='sysmon_image_load', mitre_id='T1055.001')
        elif event_id == 8:
            start_module = d.get('StartModule') or ''
            is_dll = start_module.lower().endswith('.dll') or bool(start_module)
            rule = 'PROC_DLL_INJECTION' if is_dll else 'PROC_REMOTE_THREAD_INJECTION'
            add(rule, 'critical',
                f'Remote thread from {source_image or "unknown"} into {target_image or "unknown"}',
                'DLL Injection' if is_dll else 'Remote Thread Injection',
                source_process_name=source_image.replace('/', '\\').rsplit('\\', 1)[-1],
                source_pid=_int(d.get('SourceProcessId')), target_process_name=target_image.replace('/', '\\').rsplit('\\', 1)[-1],
                target_pid=_int(d.get('TargetProcessId')), image_loaded=start_module,
                evidence_type='sysmon_create_remote_thread', mitre_id='T1055.001')
        elif event_id == 10:
            access = str(d.get('GrantedAccess') or '').lower()
            target_low = target_image.lower()
            suspicious = 'lsass.exe' in target_low or access in SUSPICIOUS_ACCESS_MASKS
            if suspicious:
                add('PROC_KERNEL_PROCESS_ACCESS', 'critical' if 'lsass.exe' in target_low else 'high',
                    f'Sensitive process access from {source_image or "unknown"} to {target_image or "unknown"} ({access or "unknown mask"})',
                    'Kernel Process Access', source_process_name=source_image.replace('/', '\\').rsplit('\\', 1)[-1],
                    source_pid=_int(d.get('SourceProcessId')), target_process_name=target_image.replace('/', '\\').rsplit('\\', 1)[-1],
                    target_pid=_int(d.get('TargetProcessId')), granted_access=access,
                    call_trace=d.get('CallTrace'), evidence_type='sysmon_process_access', mitre_id='T1055')
        elif event_id == 22:
            query = d.get('QueryName') or ''
            add('PROC_DNS_QUERY', 'low', f'{process_name or "Process"} queried DNS name {query}', 'Process DNS Query',
                domain=query, dns_query=query, query_status=d.get('QueryStatus'),
                query_results=d.get('QueryResults'), attribution_confidence='exact',
                evidence_type='sysmon_dns_query', mitre_id='T1071.004')
        elif event_id == 25:
            add('PROC_HOLLOWING', 'critical',
                f'Process tampering/hollowing detected in {process_name or image}', 'Process Hollowing',
                tamper_type=d.get('Type'), evidence_type='sysmon_process_tampering', mitre_id='T1055.012')
        elif event_id in (12, 13):
            target = d.get('TargetObject') or ''
            if REGISTRY_CONFIG_RE.search(target):
                config_category, config_severity, config_risk, config_mitre = _registry_classification(target)
                registry_operation = str(d.get('EventType') or ('SetValue' if event_id == 13 else 'CreateOrDeleteKey')).lower()
                add('PROC_REGISTRY_CONFIGURATION_CHANGE', config_severity,
                    f'Registry/configuration change: {target}', 'Registry Configuration Change',
                    capabilityIds=[1, 6, 7] + ([8] if config_category == 'persistence' else []),
                    registry_key=target, registry_value=d.get('Details'), new_value=d.get('Details'),
                    risk_score=config_risk,
                    configuration_category=config_category,
                    configuration_operation=registry_operation,
                    configuration_object=target, configuration_platform='windows',
                    configuration_baseline_status='unexpected',
                    configuration_policy_violation=True,
                    configuration_risk_factors=['sysmon_registry_event', config_category],
                    registry_value_name=target.rsplit('\\', 1)[-1] if '\\' in target else '',
                    process_attribution='sysmon_exact',
                    evidence_type='sysmon_registry_event', mitre_id=config_mitre)

    elif channel == 'Security':
        if event_id == 4688:
            add('PROC_AUDIT_START', 'low', f'Audited process creation: {process_name or image}', 'Process Create',
                parent_process_name=(d.get('ParentProcessName') or '').replace('/', '\\').rsplit('\\', 1)[-1],
                evidence_type='windows_security_4688', mitre_id='T1059')
        elif event_id == 4697:
            name = d.get('ServiceName') or ''
            add('PROC_SERVICE_CREATED', 'medium', f'Windows service installed: {name}', 'Service Created',
                inventory_type='service', inventory_name=name, service_image=d.get('ServiceFileName'),
                evidence_type='windows_security_4697', mitre_id='T1543.003')
        elif event_id in (4698, 4699, 4702):
            action = {4698: 'created', 4699: 'deleted', 4702: 'updated'}[event_id]
            name = d.get('TaskName') or ''
            add('PROC_SCHEDULED_TASK_CHANGE', 'medium', f'Scheduled task {action}: {name}', 'Scheduled Task Change',
                inventory_type='scheduled_task', inventory_name=name, change_type=action,
                evidence_type=f'windows_security_{event_id}', mitre_id='T1053.005')

    elif channel == 'System' and event_id in (7035, 7036, 7045):
        service_name = d.get('ServiceName') or (event.get('unnamed') or [''])[0]
        if event_id == 7045:
            add('PROC_SERVICE_CREATED', 'medium', f'Service installed: {service_name}', 'Service Created',
                inventory_type='service', inventory_name=service_name,
                service_image=d.get('ImagePath') or d.get('ServiceFileName'), evidence_type='service_control_manager_7045', mitre_id='T1543.003')
        else:
            add('PROC_SERVICE_CONTROL', 'low', f'Service state/control event: {service_name}', 'Service State Change',
                inventory_type='service', inventory_name=service_name,
                service_state=d.get('param2') or d.get('State'), evidence_type=f'service_control_manager_{event_id}')

    elif channel.endswith('TaskScheduler/Operational') and event_id in (106, 140, 141, 200, 201):
        task_name = d.get('TaskName') or d.get('Task') or ''
        action = {106: 'registered', 140: 'updated', 141: 'deleted', 200: 'started', 201: 'completed'}[event_id]
        add('PROC_SCHEDULED_TASK_ACTIVITY', 'low' if event_id in (200, 201) else 'medium',
            f'Scheduled task {action}: {task_name}', 'Scheduled Task Activity',
            inventory_type='scheduled_task', inventory_name=task_name, change_type=action,
            evidence_type=f'task_scheduler_{event_id}', mitre_id='T1053.005')

    elif channel.endswith('PowerShell/Operational') and event_id in (4103, 4104):
        script = d.get('ScriptBlockText') or d.get('Payload') or command
        suspicious = bool(re.search(r'-enc(?:odedcommand)?\b|frombase64string|invoke-expression|\biex\b|downloadstring|reflection\.assembly', script, re.I))
        add('PROC_POWERSHELL_SCRIPT_BLOCK', 'high' if suspicious else 'low',
            'Suspicious PowerShell script block' if suspicious else 'PowerShell script block executed',
            'PowerShell Script', cmdline=script[:4000], evidence_type=f'powershell_{event_id}',
            mitre_id='T1059.001', script_content=script[:8000], process_classifications=['powershell'])

    return findings


class WindowsProcessEventCollector:
    """Poll modern Windows channels and retain per-channel cursors in StateManager."""

    def __init__(self, sender, state, config=None, on_dns_query=None, on_network_connection=None):
        self._sender = sender
        self._state = state
        self._config = config or {}
        self._on_dns_query = on_dns_query
        self._on_network_connection = on_network_connection
        self._thread = threading.Thread(target=self._loop, daemon=True, name='win-process-events')
        self._win32evtlog = None
        self._available = {}

    def start(self):
        if platform.system() != 'Windows':
            return
        self._thread.start()

    def _emit_health(self):
        sysmon_channel = bool(self._available.get('Microsoft-Windows-Sysmon/Operational'))
        sysmon_installed = sysmon_channel
        sysmon_configured = False
        status_path = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'AJNAT' / 'state' / 'advanced-process-telemetry.json'
        try:
            status = json.loads(status_path.read_text(encoding='utf-8-sig'))
            if isinstance(status, dict):
                sysmon_installed = bool(status.get('sysmonInstalled', sysmon_channel))
                sysmon_configured = bool(status.get('sysmonConfigured'))
        except (OSError, ValueError):
            pass
        sysmon = sysmon_channel and sysmon_configured
        native = bool(self._available.get('Security'))
        self._sender.enqueue({
            'rule_id': 'PROC_TELEMETRY_HEALTH', 'capabilityId': 1, 'category': 'edr',
            'severity': 'low' if sysmon else 'medium',
            'description': 'Advanced Windows process telemetry active' if sysmon else 'Advanced Windows telemetry degraded: Sysmon channel unavailable',
            'eventType': 'Sensor Health', 'source': 'windows_event_log',
            'sensor_status': {
                'sysmon': sysmon,
                'sysmonInstalled': sysmon_installed,
                'sysmonConfigured': sysmon_configured,
                'security_audit': native,
                'channels': self._available,
            },
            'coverage_status': 'full' if sysmon else 'degraded',
            'recommendedAction': None if sysmon else 'Install/configure Microsoft Sysmon with ProcessAccess, CreateRemoteThread, ImageLoad, DNSQuery and ProcessTampering events.',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _query(self, channel, query, flags=0):
        handle = self._win32evtlog.EvtQuery(channel, flags or self._win32evtlog.EvtQueryChannelPath, query)
        while True:
            events = self._win32evtlog.EvtNext(handle, 64, 0)
            if not events:
                break
            for handle_event in events:
                yield parse_event_xml(self._win32evtlog.EvtRender(handle_event, self._win32evtlog.EvtRenderEventXml))

    def _latest_record(self, channel):
        flags = self._win32evtlog.EvtQueryChannelPath | self._win32evtlog.EvtQueryReverseDirection
        for event in self._query(channel, '*', flags):
            return event.get('record_id') or 0
        return 0

    def _initialize(self):
        try:
            import win32evtlog
            self._win32evtlog = win32evtlog
        except ImportError:
            logger.warning('pywin32 unavailable; advanced Windows event telemetry disabled')
            self._available = {channel: False for channel in CHANNELS}
            self._emit_health()
            return False
        for channel in CHANNELS:
            try:
                latest = self._latest_record(channel)
                self._available[channel] = True
                cursor_key = f'advanced:{channel}'
                if self._state.get_win_cursor(cursor_key) is None:
                    self._state.set_win_cursor(cursor_key, latest)
            except Exception as exc:
                self._available[channel] = False
                logger.info('Windows telemetry channel unavailable (%s): %s', channel, exc)
        self._emit_health()
        return any(self._available.values())

    def _poll_channel(self, channel, event_ids):
        cursor_key = f'advanced:{channel}'
        cursor = int(self._state.get_win_cursor(cursor_key) or 0)
        id_query = ' or '.join(f'EventID={event_id}' for event_id in sorted(event_ids))
        query = f'*[System[(EventRecordID > {cursor}) and ({id_query})]]'
        newest = cursor
        for event in self._query(channel, query):
            newest = max(newest, int(event.get('record_id') or 0))
            if not self._state.event_is_after_install(event.get('timestamp')):
                continue
            for alert in classify_windows_event(channel, event):
                if alert.get('rule_id') == 'PROC_NETWORK_CONNECTION' and callable(self._on_network_connection):
                    try:
                        self._on_network_connection({
                            'local_ip': alert.get('source_ip'),
                            'local_port': alert.get('source_port'),
                            'remote_ip': alert.get('dest_ip'),
                            'remote_port': alert.get('dst_port'),
                            'protocol': alert.get('protocol'),
                            'process_name': alert.get('process_name'),
                            'pid': alert.get('pid'),
                            'parent_pid': alert.get('parent_pid'),
                            'parent_process': alert.get('parent_process_name'),
                            'executable': alert.get('exe'),
                            'command_line': alert.get('cmdline'),
                            'username': alert.get('username'),
                        })
                    except Exception as exc:
                        logger.debug('Windows connection beacon observation failed: %s', exc)
                if alert.get('rule_id') == 'PROC_DNS_QUERY' and callable(self._on_dns_query):
                    try:
                        self._on_dns_query(alert.get('domain'), {
                            'query_results': alert.get('query_results'),
                            'process_name': alert.get('process_name'),
                            'pid': alert.get('pid'),
                            'parent_pid': alert.get('parent_pid'),
                            'parent_process': alert.get('parent_process_name'),
                            'executable': alert.get('exe'),
                            'command_line': alert.get('cmdline'),
                            'username': alert.get('username'),
                        })
                    except Exception as exc:
                        logger.debug('Windows DNS beacon observation failed: %s', exc)
                self._sender.enqueue(alert)
        if newest > cursor:
            self._state.set_win_cursor(cursor_key, newest)

    def _loop(self):
        if not self._initialize():
            return
        interval = max(2.0, float(self._config.get('windows_event_poll_interval_seconds', 10)))
        while True:
            for channel, event_ids in CHANNELS.items():
                if not self._available.get(channel):
                    continue
                try:
                    self._poll_channel(channel, event_ids)
                except Exception as exc:
                    logger.warning('Windows telemetry read failed (%s): %s', channel, exc)
            time.sleep(interval)


Collector = WindowsProcessEventCollector
