"""
Heartbeat — pings /api/agent/heartbeat every N seconds to keep system Active.
Now includes subscription enforcement:
  - If server returns stop_monitoring=True → agent sets a global flag
  - All collectors check this flag and halt if true.
"""

import platform
import json
import hashlib
import hmac
import re
import socket
import time
import logging
import threading
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from .config import AgentConfig
from .security import signed_headers
from .secure_transport import secure_request, certificate_status
from .self_protection import collect_security_report
from .security_controls import RuntimeSecurity, normalize_policy
from .country_block import CountryBlockEnforcer

logger = logging.getLogger('soc-agent.heartbeat')


def _advanced_process_sensor_status() -> dict:
    system = platform.system()
    status = {
        'platform': system,
        'sysmonInstalled': False,
        'sysmonConfigured': False,
        'linuxAuditAvailable': bool(shutil.which('auditctl')) if system == 'Linux' else False,
        'dockerAvailable': bool(shutil.which('docker')),
        'podmanAvailable': bool(shutil.which('podman')),
        'kubernetesAvailable': bool(shutil.which('kubectl')),
    }
    if system == 'Windows':
        path = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'AJNAT' / 'state' / 'advanced-process-telemetry.json'
        try:
            if path.is_file():
                value = json.loads(path.read_text(encoding='utf-8-sig'))
                if isinstance(value, dict):
                    status.update(value)
        except (OSError, ValueError):
            pass
    elif system == 'Linux':
        path = Path('/var/lib/soc-agent/advanced-process-telemetry.json')
        try:
            if path.is_file():
                value = json.loads(path.read_text(encoding='utf-8'))
                if isinstance(value, dict):
                    status.update(value)
        except (OSError, ValueError):
            pass
    return status

# Commands that can be delivered either over Socket.IO or through the durable
# heartbeat queue.  Keeping the heartbeat path feature-equivalent is important:
# Socket.IO may be unavailable while an endpoint is still checking in normally.
_RESPONSE_COMMANDS = frozenset({
    'kill_process', 'kill_process_tree', 'kill_child_processes',
    'isolate', 'isolate_agent', 'quarantine_endpoint', 'reconnect', 'release_host',
    'quarantine_file', 'restore_file', 'delete_file', 'block_hash', 'unblock_hash',
    'block_ip', 'unblock_ip', 'block_domain', 'unblock_domain',
    'block_port', 'unblock_port', 'close_port',
    'block_application', 'unblock_application', 'block_protocol', 'unblock_protocol',
    'ips_whitelist_add', 'ips_whitelist_remove', 'block_usb', 'unblock_usb',
    'disable_user', 'enable_user', 'lock_account', 'force_logoff',
    'restart_service', 'stop_service', 'start_service',
    'delete_scheduled_task', 'delete_startup_entry', 'rollback_registry',
    'terminate_script',
})

# ── Global stop flag (thread-safe) ────────────────────────────────────────────
_STOP_MONITORING = threading.Event()   # Set → monitoring must stop
_MAINTENANCE_MODE = threading.Event()  # Platform Super Admin passive mode
_SECURITY_LOCKDOWN = threading.Event()  # Evidence-preserving tamper containment

_LOCKDOWN_ALLOWED_COMMANDS = frozenset({
    'verify-integrity', 'update', 'security-force-recovery',
    'security-policy-sync', 'security-lockdown', 'security-unlock',
})


def _sensor_executable_available(name: str) -> bool:
    if shutil.which(name) or shutil.which(f'{name}.exe'):
        return True
    if platform.system() != 'Windows':
        return False
    roots = [
        os.environ.get('ProgramFiles', r'C:\Program Files'),
        os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
    ]
    candidates = {
        'suricata': ('Suricata/suricata.exe', 'Suricata/bin/suricata.exe'),
        'zeek': ('Zeek/bin/zeek.exe',),
    }.get(name, ())
    return any(os.path.isfile(os.path.join(root, relative)) for root in roots for relative in candidates)


def is_monitoring_stopped() -> bool:
    """Returns True if the server told the agent to halt (subscription expired)."""
    return _STOP_MONITORING.is_set() or _MAINTENANCE_MODE.is_set()


def security_command_error(command):
    if str(command).lower() in _LOCKDOWN_ALLOWED_COMMANDS:
        return ''
    if _SECURITY_LOCKDOWN.is_set():
        return 'Command denied: agent is in evidence-preserving security lockdown'
    if _MAINTENANCE_MODE.is_set():
        return 'Command denied: agent is in maintenance mode'
    return ''


def _get_primary_ip() -> str:
    """Return the primary (outbound) IP address of this machine."""
    try:
        # Connect to an external address to discover the primary interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return ''


def _valid_mac(value: str) -> bool:
    try:
        parts = str(value or '').replace('-', ':').split(':')
        octets = [int(part, 16) for part in parts]
        return len(octets) == 6 and any(octets) and not (octets[0] & 1)
    except (TypeError, ValueError):
        return False


def _get_mac_address() -> str:
    """Return the primary-route physical NIC MAC, never a multicast identity."""
    try:
        import psutil as _ps
        stats = _ps.net_if_stats()
        addrs = _ps.net_if_addrs()
        primary_ip = _get_primary_ip()
        virtual_prefixes = ('lo', 'docker', 'veth', 'br-', 'virbr', 'tun', 'tap', 'tailscale', 'zt', 'vmnet')
        candidates = []
        for iface, snic in stats.items():
            if not snic.isup or iface.lower().startswith(virtual_prefixes):
                continue
            iface_addrs = addrs.get(iface, [])
            owns_primary_ip = any(addr.address == primary_ip for addr in iface_addrs)
            for addr in addrs.get(iface, []):
                if addr.family == _ps.AF_LINK and _valid_mac(addr.address):
                    candidates.append((not owns_primary_ip, iface, addr.address.replace('-', ':').upper()))
        if candidates:
            candidates.sort()
            return candidates[0][2]
    except Exception:
        pass
    # Fallback: uuid.getnode()
    try:
        import uuid
        mac_int = uuid.getnode()
        mac = ':'.join(f'{(mac_int >> (8*i)) & 0xFF:02X}' for i in reversed(range(6)))
        return mac if _valid_mac(mac) else ''
    except Exception:
        return ''


def _system_info() -> dict:
    return {
        'hostname':    socket.gethostname(),
        'os':          platform.system(),
        'os_version':  platform.version()[:80],
        'arch':        platform.machine(),
        'ip':          _get_primary_ip(),
        'macAddress':  _get_mac_address(),
    }


def _sandbox_vm_status() -> dict:
    """Detect active guest VM processes on the endpoint without executing them."""
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        import psutil
    except ImportError:
        return {
            'state': 'unavailable', 'vmRunning': False, 'vmCount': 0,
            'providers': [], 'instances': [], 'checkedAt': checked_at,
            'reason': 'process inspection unavailable',
        }

    signatures = {
        'vmwp.exe': 'Hyper-V',
        'vmware-vmx.exe': 'VMware', 'vmware-vmx': 'VMware',
        'virtualboxvm.exe': 'VirtualBox', 'virtualboxvm': 'VirtualBox',
        'vboxheadless.exe': 'VirtualBox', 'vboxheadless': 'VirtualBox',
        'qemu-kvm': 'KVM/QEMU', 'kvm': 'KVM/QEMU',
        'firecracker': 'Firecracker', 'cloud-hypervisor': 'Cloud Hypervisor',
        'prl_vm_app': 'Parallels', 'prl_vm_app.exe': 'Parallels',
        'vmmem': 'Hyper-V/WSL', 'vmmemwsl': 'WSL2',
    }
    instances = []
    try:
        processes = psutil.process_iter(['pid', 'name', 'cmdline'])
        for process in processes:
            try:
                info = process.info
                process_name = str(info.get('name') or '').lower()
                provider = signatures.get(process_name)
                if not provider and process_name.startswith('qemu-system'):
                    provider = 'KVM/QEMU'
                if not provider:
                    continue
                cmdline = [str(item) for item in (info.get('cmdline') or [])]
                guest_name = ''
                for index, item in enumerate(cmdline[:-1]):
                    if item in {'-name', '--name', '--comment', '--startvm'}:
                        guest_name = cmdline[index + 1].split(',', 1)[0][:120]
                        break
                if not guest_name:
                    vmx = next((Path(item).stem for item in cmdline if item.lower().endswith('.vmx')), '')
                    guest_name = vmx[:120]
                instances.append({
                    'provider': provider,
                    'process': str(info.get('name') or '')[:80],
                    'pid': int(info.get('pid') or 0),
                    'name': guest_name,
                })
                if len(instances) >= 25:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError):
                continue
    except Exception as exc:
        return {
            'state': 'unavailable', 'vmRunning': False, 'vmCount': 0,
            'providers': [], 'instances': [], 'checkedAt': checked_at,
            'reason': str(exc)[:160],
        }

    providers = sorted({item['provider'] for item in instances})
    return {
        'state': 'running' if instances else 'idle',
        'vmRunning': bool(instances),
        'vmCount': len(instances),
        'providers': providers,
        'instances': instances,
        'checkedAt': checked_at,
        'reason': '',
    }


def _module_status(config: AgentConfig) -> dict:
    system = platform.system()
    # The built-in endpoint IDS (C2-port, suspicious connection, port-scan and
    # brute-force detection) is implemented in Python and runs on Windows too.
    # Suricata/Zeek are an additional full-packet capability; their absence
    # must not make the dashboard claim that endpoint IDS is disabled.
    endpoint_ids = bool(config.get('ids_enabled', True))
    zeek_available = _sensor_executable_available('zeek')
    suricata_available = _sensor_executable_available('suricata')
    packet_sensors = bool(config.get('network_ids_sensors_enabled', True)) and (zeek_available or suricata_available)
    firewall_backend = (
        (system == 'Linux' and bool(shutil.which('nft') or shutil.which('ufw')))
        or (system == 'Windows' and bool(shutil.which('netsh') or shutil.which('netsh.exe')))
        or (system == 'Darwin' and bool(shutil.which('pfctl')))
    )
    endpoint_response = system in {'Linux', 'Windows', 'Darwin'}
    inline_ips = bool(config.get('ips_enabled', True)) and firewall_backend
    advanced = _advanced_process_sensor_status()
    try:
        import watchdog  # noqa: F401
        filesystem_mode = 'event-driven'
    except ImportError:
        filesystem_mode = 'polling-fallback'
    kernel_native = bool(
        (system == 'Windows' and advanced.get('sysmonConfigured'))
        or (system == 'Linux' and advanced.get('linuxAuditAvailable'))
    )
    live_threads = {thread.name for thread in threading.enumerate() if thread.is_alive()}
    sandbox_configured = bool(config.get('sandbox_analysis_enabled', True))
    if not sandbox_configured:
        sandbox_status = 'disabled'
    elif 'file-monitor' in live_threads and (not config.get('yara_enabled', True) or 'yara-scanner' in live_threads):
        sandbox_status = 'active'
    else:
        sandbox_status = 'degraded'
    telemetry_sensor_status = {
        'waf': 'active' if config.get('waf_enabled', True) else 'disabled',
        'powershellLogging': (
            'active' if system == 'Windows' and advanced.get('powerShellLoggingConfigured')
            else 'degraded' if system == 'Windows' else 'not-applicable'
        ),
        'linuxAudit': (
            'active' if system == 'Linux' and advanced.get('linuxAuditAvailable')
            else 'degraded' if system == 'Linux' else 'not-applicable'
        ),
        'kernelProvider': 'active' if kernel_native else 'degraded',
        'dnsMetadata': 'active' if config.get('network_monitor_enabled', True) else 'disabled',
        'rawPacketCapture': 'active' if packet_sensors else 'unavailable',
        'ransomwareFilesystemWatcher': (
            filesystem_mode if config.get('ransomware_enabled', True) else 'disabled'
        ),
        'patchInventory': 'active' if config.get('patch_inventory_enabled', True) else 'disabled',
        'serviceMonitoring': 'active' if config.get('service_monitoring_enabled', True) and config.get('advanced_process_monitor_enabled', True) else 'disabled',
        'sandboxCollection': sandbox_status,
        'sandboxDetonation': 'not-applicable',
    }
    return {
        'edrEnabled': config.get('edr_enabled', True),
        'idsEnabled': endpoint_ids,
        'endpointIdsEnabled': endpoint_ids,
        'ipsEnabled': inline_ips,
        'firewallEnabled': bool(config.get('firewall_enabled', True)) and firewall_backend,
        'yaraEnabled': config.get('yara_enabled', True),
        # Endpoint-side sandbox support means evidence detection/collection only.
        # Malware detonation is never performed on the monitored endpoint.
        'sandboxAnalysisEnabled': sandbox_status == 'active',
        'sandboxAnalysisStatus': {
            'collection': sandbox_status,
            'detonation': 'not-applicable',
            'reason': 'Agent collects suspicious-file telemetry; isolated backend sandbox performs detonation',
        },
        'sandboxVmStatus': _sandbox_vm_status(),
        'wafEnabled': config.get('waf_enabled', True),
        'networkMonitorEnabled': config.get('network_monitor_enabled', True),
        'dnsSinkholeEnabled': config.get('dns_sinkhole_enabled', True),
        'dnsSinkholeTelemetryEnabled': config.get('dns_sinkhole_telemetry_enabled', True),
        'dnsSinkholeEnforcementMode': config.get('dns_sinkhole_enforcement_mode', 'both'),
        'dnsSinkholePolicyVersion': config.get('dns_sinkhole_policy_version', 0),
        'dnsCachePoisonEnabled': config.get('cache_poison_enabled', True),
        'dnsCachePoisonTelemetryEnabled': config.get('cache_poison_telemetry_enabled', True),
        'dnsCachePoisonPolicyVersion': config.get('cache_poison_policy_version', 0),
        'usbMonitorEnabled': config.get('usb_monitor_enabled', True),
        'processMonitorEnabled': config.get('process_monitor_enabled', True),
        'advancedProcessMonitorEnabled': config.get('advanced_process_monitor_enabled', True),
        'serviceMonitoringEnabled': config.get('service_monitoring_enabled', True) and config.get('advanced_process_monitor_enabled', True),
        'containerMonitorEnabled': config.get('container_monitor_enabled', True),
        'advancedProcessSensorStatus': advanced,
        'telemetrySensorStatus': telemetry_sensor_status,
        'patchInventoryEnabled': config.get('patch_inventory_enabled', True),
        'memoryMonitorEnabled': config.get('memory_scanner_enabled', True),
        'responseEnabled': bool(config.get('response_enabled', True)) and endpoint_response,
        'geoEnrichmentEnabled': config.get('geo_enrichment_enabled', True),
        'zeekAvailable': zeek_available,
        'suricataAvailable': suricata_available,
        'packetSensorAvailable': packet_sensors,
        'packetIdsMode': config.get('packet_ids_mode', ''),
        'ipsEnforcementMode': config.get('ips_enforcement_mode', ''),
        'inlinePacketVerdict': bool(config.get('inline_packet_verdict', False)),
        'firewallBackendAvailable': firewall_backend,
    }


def _read_text(path: Path) -> str:
    try:
        if path.exists() and path.is_file() and path.stat().st_size <= 1024 * 1024:
            return path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        pass
    return ''


def _client_id_from_text(text: str) -> str:
    if not text:
        return ''
    match = re.search(r'(?im)^\s*client_id\s*:\s*(C\.[A-Za-z0-9]+)\s*$', text)
    return match.group(1).strip() if match else ''


def _writeback_paths_from_config(config_path: Path) -> list:
    text = _read_text(config_path)
    if not text:
        return []

    paths = []
    for key in ('writeback_linux', 'writeback_windows', 'writeback_darwin'):
        match = re.search(rf'(?im)^\s*{key}\s*:\s*(.+?)\s*$', text)
        if not match:
            continue
        raw = match.group(1).strip().strip('"\'')
        if raw:
            paths.append(Path(raw.replace('%NONCE%', '*').replace('%25NONCE%25', '*')))
    return paths


def _glob_client_id(pattern: Path) -> str:
    try:
        for p in sorted(pattern.parent.glob(pattern.name)):
            client_id = _client_id_from_text(_read_text(p))
            if client_id:
                return client_id
    except Exception:
        pass
    return ''


def _detect_velociraptor_client_id() -> str:
    """Find local Velociraptor C.xxxx id from env, config, or writeback files."""
    for env_name in ('SOC_AGENT_VELOCIRAPTOR_CLIENT_ID', 'VELOCIRAPTOR_CLIENT_ID'):
        value = os.getenv(env_name, '').strip()
        if value.startswith('C.'):
            return value

    windows_program_files = os.getenv('ProgramFiles', r'C:\Program Files')
    windows_program_files_x86 = os.getenv('ProgramFiles(x86)', r'C:\Program Files (x86)')
    windows_program_data = os.getenv('ProgramData', r'C:\ProgramData')

    candidate_configs = [
        Path(os.getenv('VELOCIRAPTOR_CLIENT_CONFIG', '')),
        Path('/etc/velociraptor/client.config.yaml'),
        Path('/opt/velociraptor/client.config.yaml'),
        Path('/opt/soc-agent/velociraptor/client.config.yaml'),
        Path('/tmp/gui_datastore/client.config.yaml'),
        Path(os.path.expandvars(r'%ProgramFiles%\Velociraptor\client.config.yaml')),
        Path(windows_program_files) / 'Velociraptor' / 'client.config.yaml',
        Path(windows_program_files_x86) / 'Velociraptor' / 'client.config.yaml',
        Path(windows_program_data) / 'Velociraptor' / 'client.config.yaml',
        Path('/Library/Application Support/Velociraptor/client.config.yaml'),
    ]

    candidate_writebacks = [
        Path(os.getenv('VELOCIRAPTOR_WRITEBACK', '')),
        Path('/etc/velociraptor/client.writeback.yaml'),
        Path('/etc/velociraptor/Velociraptor.writeback*.yaml'),
        Path('/var/lib/velociraptor/Velociraptor.writeback*.yaml'),
        Path('/opt/velociraptor/Velociraptor.writeback*.yaml'),
        Path('/tmp/gui_datastore/Velociraptor.writeback*.yaml'),
        Path(os.path.expandvars(r'%ProgramFiles%\Velociraptor\Velociraptor.writeback*.yaml')),
        Path(windows_program_files) / 'Velociraptor' / 'velociraptor.writeback*.yaml',
        Path(windows_program_files_x86) / 'Velociraptor' / 'velociraptor.writeback*.yaml',
        Path(windows_program_data) / 'Velociraptor' / 'velociraptor.writeback*.yaml',
        Path(windows_program_data) / 'Velociraptor' / 'Velociraptor.writeback*.yaml',
        Path('/Library/Application Support/Velociraptor/Velociraptor.writeback*.yaml'),
    ]

    for config_path in candidate_configs:
        if str(config_path):
            direct_id = _client_id_from_text(_read_text(config_path))
            if direct_id:
                return direct_id
            candidate_writebacks.extend(_writeback_paths_from_config(config_path))

    for path_pattern in candidate_writebacks:
        if not str(path_pattern):
            continue
        if any(ch in path_pattern.name for ch in '*?['):
            client_id = _glob_client_id(path_pattern)
        else:
            client_id = _client_id_from_text(_read_text(path_pattern))
        if client_id:
            return client_id

    return ''


class HeartbeatService:
    def __init__(self, config: AgentConfig):
        self.config    = config
        self._interval = config.get('heartbeat_interval_seconds', 60)  # 60s — matches backend offline threshold
        self._thread   = threading.Thread(target=self._loop, daemon=True, name='heartbeat')
        self._last_isolation_state = None
        # OTA self-update progress reported back to the server on heartbeats.
        self._update_status = None   # None | 'downloading' | 'installing' | 'failed'
        self._update_error  = None
        self._active_update_request_id = ''
        self._response_handler = None
        self._dns_sinkhole = None
        self._cache_poison_detector = None
        self._security_action_results = []
        self._security_report = None
        self._security_report_at = 0.0
        self._runtime_security = RuntimeSecurity()
        self._security_policy_error = ''
        self._security_completed = dict(config.get('security_completed_commands', {}))
        self._country_blocks = CountryBlockEnforcer(config)

    def set_response_handler(self, handler):
        self._response_handler = handler

    def set_dns_sinkhole(self, sinkhole):
        self._dns_sinkhole = sinkhole

    def set_cache_poison_detector(self, detector):
        self._cache_poison_detector = detector

    def start(self):
        self._runtime_security.apply(self.config)
        if self.config.get('security_lockdown_active', False):
            _SECURITY_LOCKDOWN.set()
        if self.config.get('maintenance_mode', False):
            _MAINTENANCE_MODE.set()
        self._country_blocks.start()
        self._thread.start()
        logger.info(f'Heartbeat started (every {self._interval}s)')

    def _server_url(self):
        return self.config.get('server_url') or \
            f'http://{self.config.get("server_ip","localhost")}:{self.config.get("server_port",5000)}'

    def _execute_pending_commands(self, commands):
        for item in commands or []:
            command = str(item.get('command', '')).lower()
            audit_id = str(item.get('auditId', ''))
            command_id = str(item.get('id') or item.get('commandId') or '')
            message = ''
            try:
                if audit_id and audit_id in self._security_completed:
                    self._security_action_results.append(self._security_completed[audit_id])
                    continue
                if _SECURITY_LOCKDOWN.is_set() and command not in _LOCKDOWN_ALLOWED_COMMANDS:
                    raise RuntimeError(
                        'command denied: agent is in evidence-preserving security lockdown'
                    )
                if _MAINTENANCE_MODE.is_set() and command not in _LOCKDOWN_ALLOWED_COMMANDS:
                    raise RuntimeError('command denied: agent is in maintenance mode')
                if self._response_handler and command in _RESPONSE_COMMANDS:
                    result = self._response_handler.dispatch(command, item)
                    ok = bool(result and result.get('ok') is True)
                    message = str((result or {}).get('result') or 'No result')[:500]
                    if not ok:
                        raise RuntimeError(message)
                    if command in ('isolate', 'isolate_agent', 'quarantine_endpoint'):
                        self._last_isolation_state = True
                    elif command in ('reconnect', 'release_host'):
                        self._last_isolation_state = False
                    logger.warning('Executed pending response command: %s — %s', command, message)
                    if audit_id:
                        self._security_action_results.append({
                            'auditId': audit_id, 'ok': True, 'message': message,
                        })
                    if command_id and not audit_id:
                        self._security_action_results.append({
                            'commandId': command_id, 'command': command,
                            'ip': item.get('ip'), 'ok': True, 'message': message,
                        })
                    continue
                if command == 'configure_dns_sinkhole':
                    if not self._dns_sinkhole:
                        logger.info('DNS sinkhole command deferred until module initialization')
                        continue
                    result = self._dns_sinkhole.configure(
                        item.get('settings') or {},
                        blocklist=item.get('blocklist') or [],
                        allowlist=item.get('allowlist') or [],
                        sinkhole_targets=item.get('sinkholeTargets') or {},
                    )
                    message = 'DNS sinkhole policy applied (version {}, {} domains)'.format(
                        result.get('policy_version', 0), result.get('total_sinkholed', 0)
                    )
                elif command == 'configure_dns_cache_poisoning':
                    if not self._cache_poison_detector:
                        logger.info('DNS cache-poisoning command deferred until module initialization')
                        continue
                    result = self._cache_poison_detector.configure(item.get('settings') or {})
                    message = 'DNS cache-poisoning policy applied (version {})'.format(result.get('policyVersion', 0))
                elif command == 'flush_dns_cache':
                    if not self._cache_poison_detector:
                        raise RuntimeError('DNS cache-poisoning module not loaded')
                    result = self._cache_poison_detector.flush_dns_cache()
                    message = result.get('message', 'DNS cache flushed')
                elif command == 'restore_dns_resolver':
                    if not self._cache_poison_detector:
                        raise RuntimeError('DNS cache-poisoning module not loaded')
                    result = self._cache_poison_detector.restore_resolver()
                    message = result.get('message', 'DNS resolver restored')
                elif command == 'dns_sinkhole_add':
                    if not self._dns_sinkhole:
                        logger.info('DNS sinkhole command deferred until module initialization')
                        continue
                    result = self._dns_sinkhole.sinkhole(item.get('domain', ''), reason=item.get('reason', 'dashboard_policy'), sinkhole_ip=item.get('sinkholeIp'))
                    if not result.get('success'):
                        raise RuntimeError(result.get('error', 'DNS sinkhole policy add failed'))
                    message = 'sinkholed {}'.format(result.get('domain'))
                elif command == 'dns_sinkhole_remove':
                    if not self._dns_sinkhole:
                        logger.info('DNS sinkhole command deferred until module initialization')
                        continue
                    result = self._dns_sinkhole.unsinkhole(item.get('domain', ''))
                    message = 'removed {}'.format(result.get('domain'))
                elif command == 'isolate':
                    from response.isolate import isolate
                    isolate(management_url=self._server_url())
                    self._last_isolation_state = True
                elif command == 'reconnect':
                    from response.isolate import restore
                    restore()
                    self._last_isolation_state = False
                elif command == 'update':
                    self._perform_self_update(item)
                    failed = self._update_status == 'failed'
                    message = self._update_error or (
                        'Update installer started; final version will be confirmed after restart'
                    )
                    if audit_id:
                        self._security_action_results.append({
                            'auditId': audit_id,
                            'ok': not failed,
                            'message': message,
                        })
                    if command_id and not audit_id:
                        self._security_action_results.append({
                            'commandId': command_id, 'command': command,
                            'ok': not failed, 'message': message,
                        })
                    continue  # status is reported inside _perform_self_update
                elif command == 'verify-integrity':
                    self._verify_agent_integrity()
                elif command == 'security-policy-sync':
                    if self._security_policy_error:
                        raise RuntimeError(self._security_policy_error)
                    message = 'Security policy applied (v{})'.format(self.config.get('policy_version', 0))
                elif command == 'security-lockdown':
                    self.config.update_runtime({'security_lockdown_active': True}, persist=True, strict=True)
                    _SECURITY_LOCKDOWN.set()
                    logger.warning('Security lockdown enabled by authorized server command')
                elif command == 'security-unlock':
                    report = self._refresh_security_report(force=True)
                    if not _MAINTENANCE_MODE.is_set() and self.config.get('self_protection', True) and (
                        report.get('integrityStatus') in {'mismatch', 'missing', 'error'}
                        or report.get('debuggerDetected') or report.get('analysisTools')
                    ):
                        raise RuntimeError('Active security findings remain. Repair the agent or use authorized maintenance before unlocking.')
                    self.config.update_runtime({'security_lockdown_active': False}, persist=True, strict=True)
                    _SECURITY_LOCKDOWN.clear()
                    self._security_report_at = 0.0
                    logger.warning('Security lockdown cleared by authorized server command')
                elif command == 'security-force-recovery':
                    # Persist a restart marker before exec; the next process
                    # reports completion, rather than losing the audit ACK.
                    self.config.update_runtime({'security_recovery_audit': audit_id}, persist=True, strict=True)
                    logger.warning('Agent recovery requested; restarting service process')
                    os.execv(os.sys.executable, [os.sys.executable] + os.sys.argv)
                else:
                    logger.warning('Unsupported heartbeat command: %s', command)
                    message = f'Unsupported command: {command}'
                    if audit_id:
                        self._security_action_results.append({
                            'auditId': audit_id, 'ok': False,
                            'message': message,
                        })
                    if command_id and not audit_id:
                        self._security_action_results.append({
                            'commandId': command_id, 'command': command,
                            'ip': item.get('ip'), 'ok': False, 'message': message,
                        })
                    continue
                logger.warning('Executed pending heartbeat command: %s', command)
                if audit_id:
                    result = {
                        'auditId': audit_id, 'ok': True,
                        'message': message or f'{command} executed by agent',
                    }
                    self._remember_security_result(audit_id, result)
                    self._security_action_results.append(result)
                if command_id and not audit_id:
                    self._security_action_results.append({
                        'commandId': command_id, 'command': command,
                        'ip': item.get('ip'), 'ok': True,
                        'message': message or f'{command} executed by agent',
                    })
            except Exception as exc:
                logger.error('Pending heartbeat command %s failed: %s', command, exc)
                if audit_id:
                    self._security_action_results.append({
                        'auditId': audit_id, 'ok': False, 'message': str(exc)[:500],
                    })
                if command_id and not audit_id:
                    self._security_action_results.append({
                        'commandId': command_id, 'command': command,
                        'ip': item.get('ip'), 'ok': False, 'message': str(exc)[:500],
                    })

    def _remember_security_result(self, audit_id, result):
        self._security_completed[audit_id] = result
        self._security_completed = dict(list(self._security_completed.items())[-100:])
        if hasattr(self.config, 'update_runtime'):
            self.config.update_runtime({'security_completed_commands': self._security_completed}, persist=True, strict=True)

    def _verify_agent_integrity(self):
        """Check packaged files against a build manifest and unsafe permissions."""
        report = self._refresh_security_report(force=True)
        if report.get('integrityStatus') != 'verified':
            details = '; '.join(
                str(item.get('detail') or item.get('type'))
                for item in report.get('findings', [])[:10]
            )
            raise RuntimeError(f'integrity verification failed: {details}')
        logger.warning(
            'Agent integrity verified: fleet_sha256=%s',
            report.get('reportedFleetSha256', ''),
        )

    def _refresh_security_report(self, force=False):
        now = time.monotonic()
        if force or self._security_report is None or now - self._security_report_at >= 30:
            master = self.config.get('self_protection', True)
            verify = master and self.config.get('integrity_verification', True)
            self._security_report = collect_security_report(
                check_integrity=force or (verify and (self._security_report is None or self.config.get('code_integrity_monitoring', True))),
                check_debugger=master and self.config.get('anti_debugging', True),
                check_tools=master and self.config.get('anti_reverse_engineering', True),
                check_permissions=master and self.config.get('tamper_protection', True),
                previous=self._security_report if verify else None,
            )
            self._security_report_at = now
        report = dict(self._security_report)
        open_findings = self._runtime_security.file_open.findings()
        if open_findings:
            report['findings'] = (open_findings + list(report.get('findings', [])))[:40]
            report['integrityStatus'] = 'mismatch' if any(item['type'] == 'source_cleared_on_open' for item in open_findings) else 'error'
        should_lock = (
            report.get('integrityStatus') in {'mismatch', 'missing', 'error'}
            or (report.get('debuggerDetected') and self.config.get('anti_debugging', True))
            or (report.get('analysisTools') and self.config.get('anti_reverse_engineering', True))
        )
        if should_lock and self.config.get('self_protection', True) and self.config.get('lockdown_mode', True) and not _MAINTENANCE_MODE.is_set():
            if not _SECURITY_LOCKDOWN.is_set():
                logger.critical('Agent tamper/analysis activity detected; entering safe security lockdown')
            _SECURITY_LOCKDOWN.set()
            if not self.config.get('security_lockdown_active', False) and hasattr(self.config, 'update_runtime'):
                self.config.update_runtime({'security_lockdown_active': True}, persist=True)
        report['lockdownActive'] = _SECURITY_LOCKDOWN.is_set()
        report['version'] = 2
        report['policyVersion'] = self.config.get('policy_version', 0)
        file_open_status = self._runtime_security.file_open.report(self.config)
        file_open_error = file_open_status['detail'] if file_open_status['enabled'] and file_open_status['state'] in {'error', 'unsupported'} else ''
        report['policyError'] = file_open_error or self._security_policy_error
        report['maintenanceActive'] = _MAINTENANCE_MODE.is_set()
        report['controls'] = self._runtime_security.report(self.config, report, certificate_status(self.config), report['lockdownActive'], report['maintenanceActive'])
        recovery_audit = self.config.get('security_recovery_audit', '')
        if recovery_audit:
            result = {'auditId': recovery_audit, 'ok': report.get('integrityStatus') == 'verified', 'message': 'Agent restarted; integrity ' + str(report.get('integrityStatus'))}
            self._remember_security_result(recovery_audit, result)
            self._security_action_results.append(result)
            self.config.update_runtime({'security_recovery_audit': ''}, persist=True, strict=True)
        return report

    def _apply_security_policy(self, policy):
        if not isinstance(policy, dict):
            return
        try:
            normalized = normalize_policy(policy)
            if normalized['policy_version'] < self.config.get('policy_version', 0):
                raise ValueError('Refusing an older security policy')
            changed = self.config.update_runtime(normalized, persist=True, strict=True)
            self._runtime_security.apply(self.config)
            self._security_policy_error = self._runtime_security.dump_status['detail'] if self._runtime_security.dump_status['state'] == 'error' else ''
            if changed:
                self._security_report = None
                self._security_report_at = 0.0
        except Exception as error:
            self._security_policy_error = str(error)[:500]
            logger.error('Security policy could not be applied: %s', error)
            return
        if policy.get('maintenance_mode') is True:
            if not _MAINTENANCE_MODE.is_set():
                logger.warning('Maintenance Mode enabled by Platform Super Admin')
            _MAINTENANCE_MODE.set()
        else:
            if _MAINTENANCE_MODE.is_set():
                logger.info('Maintenance Mode disabled; monitoring resumed')
            _MAINTENANCE_MODE.clear()
        if changed:
            logger.info('Protected security policy applied (v%s)', policy.get('policy_version', '?'))

    # ── OTA self-update ────────────────────────────────────────────────────
    def _detect_package_type(self):
        import shutil
        system = platform.system()
        if system == 'Windows':
            configured = str(self.config.get('installer_type', '')).strip().lower()
            if configured in ('msi', 'exe'):
                return configured
            # Older agents did not persist installer_type. Preserve MSI ownership
            # when Windows Installer still has SOC Agent registered; otherwise the
            # EXE updater would leave a stale MSI product behind.
            try:
                import winreg
                uninstall_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
                views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
                for view in views:
                    try:
                        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key, 0, winreg.KEY_READ | view)
                    except OSError:
                        continue
                    with root:
                        index = 0
                        while True:
                            try:
                                child_name = winreg.EnumKey(root, index)
                                index += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(root, child_name) as child:
                                    display_name = str(winreg.QueryValueEx(child, 'DisplayName')[0]).strip()
                                    windows_installer = int(winreg.QueryValueEx(child, 'WindowsInstaller')[0])
                                if display_name == 'SOC Agent' and windows_installer == 1:
                                    return 'msi'
                            except (OSError, TypeError, ValueError):
                                continue
            except (ImportError, OSError):
                pass
            return 'exe'
        if system == 'Darwin':
            return 'macpkg'
        if shutil.which('rpm') and not shutil.which('dpkg'):
            return 'rpm'
        return 'deb'  # Debian/Ubuntu/Kali/Mint default

    def _download_update_package(self, pkg_type, update_request_id=''):
        import tempfile
        url = f'{self._server_url().rstrip("/")}/api/agent/self-update/package/{pkg_type}'
        params = {}
        if update_request_id:
            params['update_request_id'] = update_request_id
        headers = signed_headers(self.config, {})  # GET has an empty body → sign {}
        secret = self.config.get('integration_secret', '')
        if secret:
            headers['x-integration-secret'] = secret
        resp = secure_request(self.config, 'GET', url, params=params, headers=headers, timeout=180, stream=True)
        resp.raise_for_status()
        expected_sha256 = str(resp.headers.get('X-AJNAT-Artifact-SHA256', '')).strip().lower()
        if not re.fullmatch(r'[a-f0-9]{64}', expected_sha256):
            resp.close()
            raise RuntimeError('update package response is missing a valid SHA-256 digest')
        suffix = {'deb': '.deb', 'rpm': '.rpm', 'exe': '.exe', 'msi': '.msi', 'macpkg': '.pkg'}.get(pkg_type, '.pkg')
        # Keep every downloaded AJNAT component under AJNAT-owned storage on
        # Windows. This also makes cleanup/auditing predictable and avoids
        # executing an updater from the shared Windows TEMP directory.
        package_dir = None
        if platform.system() == 'Windows':
            package_dir = os.path.join(
                os.environ.get('ProgramData', r'C:\ProgramData'),
                'AJNAT', 'packages'
            )
            os.makedirs(package_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix='soc-agent-update-', suffix=suffix, dir=package_dir
        )
        digest = hashlib.sha256()
        try:
            with os.fdopen(fd, 'wb') as fh:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        digest.update(chunk)
                        fh.write(chunk)
            actual_sha256 = digest.hexdigest()
            if not hmac.compare_digest(actual_sha256, expected_sha256):
                raise RuntimeError(
                    f'update package SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}'
                )
            logger.info('Update package SHA-256 verified: %s', actual_sha256)
        except Exception:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise
        finally:
            resp.close()
        return tmp_path

    def _install_update_package(self, pkg_type, path):
        import shutil
        import shlex
        import subprocess
        system = platform.system()
        if pkg_type == 'deb':
            cmd = ['dpkg', '-i', path]
        elif pkg_type == 'rpm':
            cmd = ['rpm', '-Uvh', '--force', path]
        elif pkg_type == 'macpkg':
            cmd = ['installer', '-pkg', path, '-target', '/']
        elif pkg_type == 'msi':
            cmd = ['msiexec', '/i', path, '/quiet', '/norestart']
        elif pkg_type == 'exe':
            cmd = [path, '/S']  # NSIS silent install
        else:
            raise RuntimeError(f'unsupported update package type: {pkg_type}')

        # ── Linux: install DETACHED from our own service cgroup ──────────────────
        # The .deb/.rpm maintainer scripts run `systemctl stop soc-agent` during the
        # upgrade. With systemd's default KillMode=control-group, stopping the service
        # kills EVERY process in its cgroup — including a dpkg/rpm child spawned here —
        # so the upgrade dies half-way (files not replaced, service never restarts).
        # Launch the installer in a transient systemd unit (its own cgroup) so it
        # survives the stop and finishes the install + restart on its own.
        if system == 'Linux' and pkg_type in ('deb', 'rpm') and shutil.which('systemd-run'):
            # Work off a private copy — _perform_self_update deletes `path` on return,
            # which would otherwise race the detached installer reading it.
            stable = path + '.deploy'
            try:
                shutil.copyfile(path, stable)
            except Exception:
                stable = path
            tool = 'dpkg -i' if pkg_type == 'deb' else 'rpm -Uvh --force'
            inner = f'{tool} {shlex.quote(stable)}; rm -f {shlex.quote(stable)}'
            runner = ['systemd-run', '--collect', '--description', 'SOC Agent self-update',
                      '/bin/sh', '-c', inner]
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                runner = ['sudo', '-n'] + runner
            # systemd-run returns immediately; the transient unit runs the install
            # detached and restarts the service into the new build.
            subprocess.run(runner, check=True, timeout=60)
            logger.warning('OTA installer launched detached via systemd-run (%s)', pkg_type)
            return

        # Windows installers stop SOCAgent before replacing its files. Waiting
        # for that installer from inside SOCAgent deadlocks: the installer waits
        # for this service to stop while this process waits for the installer.
        # Detach it so Service Control Manager can stop the old service and the
        # restarted build can confirm the target version on its next heartbeat.
        if system == 'Windows':
            creation_flags = (
                getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
                | getattr(subprocess, 'DETACHED_PROCESS', 0)
                | getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creation_flags,
            )
            logger.warning('OTA installer launched detached on Windows (%s)', pkg_type)
            return

        # macOS (no cgroup self-kill issue) — install directly.
        if system != 'Windows' and hasattr(os, 'geteuid') and os.geteuid() != 0:
            cmd = ['sudo', '-n'] + cmd
        subprocess.run(cmd, check=True, timeout=600)

    def _report_update_status(self):
        """Best-effort out-of-band heartbeat carrying only the update progress/error."""
        if not HAS_REQUESTS:
            return
        try:
            url = f'{self._server_url().rstrip("/")}/api/agent/heartbeat'
            payload = {
                'agent_key':     self.config.get('agent_key', ''),
                'agent_version': self.config.get('agent_version', '0.1.13'),
                'status':        'running',
                'update_status': self._update_status,
                'update_error':  self._update_error or '',
                'update_request_id': (
                    self._active_update_request_id
                    or self.config.get('update_request_id', '')
                ),
                **_system_info(),
            }
            secure_request(self.config, 'POST', url, json=payload, headers=signed_headers(self.config, payload), timeout=10)
        except Exception:
            pass

    def _perform_self_update(self, item):
        target = item.get('targetVersion') or item.get('target_version') or '?'
        pkg_type = item.get('type') or self._detect_package_type()
        update_request_id = str(item.get('id') or '')
        self._active_update_request_id = update_request_id
        logger.warning('OTA update requested → v%s (%s)', target, pkg_type)

        self._update_status = 'downloading'
        self._update_error = None
        self._report_update_status()
        try:
            path = self._download_update_package(pkg_type, update_request_id)
        except Exception as exc:
            self._update_status = 'failed'
            self._update_error = f'download failed: {exc}'
            logger.error('OTA download failed: %s', exc)
            self._report_update_status()
            return

        self._update_status = 'installing'
        self._report_update_status()  # push progress before the installer may restart us
        try:
            self._runtime_security.file_open.suspend_for_update()
            self._install_update_package(pkg_type, path)
            logger.warning('OTA installer finished; service restarting into v%s', target)
            # Success is confirmed by the backend when the new build reports its version.
        except Exception as exc:
            self._update_status = 'failed'
            self._update_error = f'install failed: {exc}'
            logger.error('OTA install failed: %s', exc)
            self._runtime_security.file_open.update_failed(self.config)
            self._report_update_status()
        finally:
            try:
                os.remove(path)
            except Exception:
                pass

    def _sync_isolation_state(self, data):
        desired = data.get('is_isolated')
        if desired is None:
            return

        # The backend owns the durable isolation deadline. Re-apply an active
        # isolation after an agent/host restart because Linux nftables and
        # macOS PF runtime state can disappear across reboot. The isolation
        # rule preserves the management channel, so the durable reconnect
        # command can still arrive when the quiet window expires.
        if self._last_isolation_state is None:
            if desired is True:
                logger.warning(
                    'Server reports this system isolated at startup — re-applying '
                    'isolation while preserving the AJNAT management channel.'
                )
                self._execute_pending_commands([{'command': 'isolate'}])
            else:
                self._last_isolation_state = False
            return

        if desired is True and self._last_isolation_state is not True:
            self._execute_pending_commands([{'command': 'isolate'}])
        elif desired is False and self._last_isolation_state is True:
            self._execute_pending_commands([{'command': 'reconnect'}])

    def _ping(self):
        if not HAS_REQUESTS:
            return

        # ── New dedicated heartbeat endpoint ──────────────────────────────────
        url = f'{self._server_url().rstrip("/")}/api/agent/heartbeat'
        try:
            velociraptor_client_id = (
                self.config.get('velociraptor_client_id', '')
                or _detect_velociraptor_client_id()
            )
            payload = {
                'agent_key':     self.config.get('agent_key', ''),
                'agent_version': self.config.get('agent_version', '0.1.13'),
                'velociraptor_client_id': velociraptor_client_id,
                'status':        'running',
                'update_request_id': (
                    self._active_update_request_id
                    or self.config.get('update_request_id', '')
                ),
                **_system_info(),
                **_module_status(self.config),
                'transport_security': certificate_status(self.config),
                'agent_security': self._refresh_security_report(),
                'countryBlockStatus': self._country_blocks.status(),
            }
            if self._cache_poison_detector:
                payload['dnsCachePoisonStatus'] = self._cache_poison_detector.status()
                payload['dnsCachePoisonEnabled'] = self._cache_poison_detector.enabled
                payload['dnsCachePoisonTelemetryEnabled'] = self._cache_poison_detector.telemetry_enabled
                payload['dnsCachePoisonPolicyVersion'] = self._cache_poison_detector.status().get('policyVersion', 0)
            if self._update_status:
                payload['update_status'] = self._update_status
                payload['update_error'] = self._update_error or ''
            if self._security_action_results:
                payload['security_action_results'] = self._security_action_results[:20]
            resp = secure_request(self.config, 'POST',
                url,
                json=payload,
                headers=signed_headers(self.config, payload),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if payload.get('security_action_results'):
                    self._security_action_results = self._security_action_results[
                        len(payload['security_action_results']):
                    ]
                if data.get('stop_monitoring') or not data.get('active', True):
                    reason = data.get('message', 'Subscription expired or inactive')
                    logger.warning(f'🔴 STOP_MONITORING received from server: {reason}')
                    logger.warning('Agent halting all monitoring. Renew subscription to resume.')
                    _STOP_MONITORING.set()

                    # Write a local flag file so service restart also sees it
                    try:
                        flag = os.path.join(os.path.dirname(__file__), '..', 'STOP_MONITORING')
                        with open(flag, 'w') as f:
                            f.write(reason)
                    except Exception:
                        pass

                elif _STOP_MONITORING.is_set():
                    # Previously stopped but server now says active → resume
                    logger.info('✅ Subscription reactivated — resuming monitoring')
                    _STOP_MONITORING.clear()
                    try:
                        flag = os.path.join(os.path.dirname(__file__), '..', 'STOP_MONITORING')
                        if os.path.exists(flag):
                            os.remove(flag)
                    except Exception:
                        pass

                # Log update availability (the actual update is driven by an 'update'
                # command queued from the dashboard, handled in _execute_pending_commands).
                if data.get('update_available'):
                    logger.info(f'ℹ️  Agent update available: v{data.get("new_version","?")}'
                                ' — click Update in the dashboard to push it')
                if isinstance(data.get('config_update'), dict):
                    changed = self.config.update_runtime(data['config_update'], persist=True)
                    if changed:
                        logger.info('✅ Runtime config updated from server heartbeat')
                        if self._cache_poison_detector:
                            self._cache_poison_detector.configure(data['config_update'])
                self._apply_security_policy(data.get('security_policy'))
                if 'country_blocks' in data:
                    self._country_blocks.submit(data['country_blocks'])
                self._sync_isolation_state(data)
                self._execute_pending_commands(data.get('commands', []))
            else:
                logger.debug(f'Heartbeat {resp.status_code}: {resp.text[:100]}')

        except requests.RequestException as e:
            # Fall back to legacy endpoint
            try:
                legacy = f'{self._server_url().rstrip("/")}/api/system/heartbeat'
                velociraptor_client_id = (
                    self.config.get('velociraptor_client_id', '')
                    or _detect_velociraptor_client_id()
                )
                payload = {
                    'agentKey':    self.config.get('agent_key', ''),
                    'agentVersion':self.config.get('agent_version', '0.1.13'),
                    'velociraptor_client_id': velociraptor_client_id,
                    **_system_info(),
                    **_module_status(self.config),
                }
                legacy_resp = secure_request(self.config, 'POST',
                    legacy,
                    json=payload,
                    headers=signed_headers(self.config, payload),
                    timeout=10,
                )
                if legacy_resp.status_code == 200:
                    legacy_data = legacy_resp.json()
                    self._sync_isolation_state(legacy_data)
                    self._execute_pending_commands(legacy_data.get('commands', []))
            except Exception:
                pass
            logger.debug(f'Heartbeat failed: {e}')

    def _loop(self):
        # Check for stop flag file left from a previous run
        flag = os.path.join(os.path.dirname(__file__), '..', 'STOP_MONITORING')
        if os.path.exists(flag):
            logger.warning('STOP_MONITORING flag found from previous run — starting halted')
            _STOP_MONITORING.set()

        # Initial ping immediately on start
        try:
            self._ping()
        except Exception:
            pass

        while True:
            time.sleep(self._interval)
            try:
                self._ping()
            except Exception as e:
                logger.debug(f'Heartbeat loop error: {e}')
