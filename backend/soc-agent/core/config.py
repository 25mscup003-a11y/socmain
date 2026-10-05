"""
Config loader — reads config/company_config.json.
Supports all fields including virustotal_api_key and IPS webhook v3.0.
"""

import json
import logging
import os
import platform
from pathlib import Path
from urllib.parse import urlparse

try:
    from .config_protection import config_key_password, is_encrypted_config, load_config, save_config
except ImportError:  # direct-file diagnostics/tests without a package context
    from core.config_protection import config_key_password, is_encrypted_config, load_config, save_config

logger = logging.getLogger('soc-agent.config')
RUNTIME_ONLY_KEYS = frozenset({
    'storage_encryption_key', 'gps_tracking_enabled', 'geolocation_forensics_enabled',
    'mtls_client_key_password',
})

def _default_config_path() -> Path:
    explicit = os.getenv('SOC_AGENT_CONFIG')
    if explicit:
        return Path(explicit)
    if platform.system() == 'Windows':
        data_root = str(
            os.getenv('AJNAT_DATA_DIR')
            or (os.getenv('ProgramData', r'C:\ProgramData').rstrip('\\/') + r'\AJNAT')
        ).rstrip('\\/')
        # Keep Windows separators even when packaging/tests execute on POSIX.
        installed_config = Path(f'{data_root}\\config\\company_config.json')
        if installed_config.exists():
            return installed_config
    return Path(__file__).parent.parent / 'config' / 'company_config.json'


CONFIG_PATH = _default_config_path()

DEFAULTS = {
    # ── Identity ──────────────────────────────────────────────────────────
    'company_id':               '',
    'company_name':             'unknown',
    'department_id':            '',
    'department_name':          '',
    'system_id':                '',
    'system_name':              'unknown',
    'velociraptor_client_id':   '',
    'agent_type':               'system',
    'expected_device_role':     'system',
    'agent_key':                '',
    'agent_version':            '0.1.13',
    'generated_at':             '',

    # ── Server connection ─────────────────────────────────────────────────
    'server_url':               '',
    'server_proto':             '',
    'server_ip':                '',
    'server_port':              None,
    'integration_secret':       '',
    'sender_spool_path':        '',
    'sender_max_attempts':      20,
    'sender_gzip_min_bytes':    1024,
    # Production packages must override server_url with HTTPS and provision
    # a tenant-approved CA plus a unique client certificate/private key.
    'require_tls':              False,
    'tls_ca_bundle':            '',
    'tls_server_sha256':        '',
    'mtls_client_cert':         '',
    'mtls_client_key':          '',
    'mtls_identity_dir':        '',
    'mtls_required':            False,
    'mtls_auto_enroll':         True,
    'mtls_auto_renew':          False,
    'mtls_renew_before_days':   30,

    # ── Intervals (seconds) ───────────────────────────────────────────────
    'heartbeat_interval_seconds':   60,
    'scan_interval_seconds':        300,
    'log_scan_interval_seconds':    30,
    # Change-only network summaries are additionally debounced so a busy
    # browser/server cannot flood the backend with short-lived socket churn.
    'network_summary_min_interval_seconds': 120,
    # Emit accumulated interface byte deltas periodically even when socket
    # topology is unchanged. This powers accurate total and VPN usage KPIs.
    'network_usage_report_interval_seconds': 300,

    # ── Security module flags ─────────────────────────────────────────────
    'edr_enabled':              True,
    'ids_enabled':              True,
    'ips_enabled':              True,
    'network_ids_sensors_enabled': True,
    'packet_ids_mode':          (
        'suricata-windivert-inline' if platform.system() == 'Windows'
        else 'suricata-passive' if platform.system() == 'Darwin'
        else 'suricata-nfqueue-inline'
    ),
    'ips_enforcement_mode':     (
        'suricata-inline-windivert+defender-firewall' if platform.system() == 'Windows'
        else 'suricata-detect+pf-source-block' if platform.system() == 'Darwin'
        else 'suricata-inline-nfqueue+native-firewall'
    ),
    # Set true by the Windows sensor installer only after the WinDivert-backed
    # Suricata service is running successfully.
    'inline_packet_verdict':    False,
    # Ship actionable Zeek notice/weird and Suricata alert/anomaly records.
    # Raw conn/dns/ssl flows remain in the local sensors to avoid CPU, memory,
    # network and database overload on normal busy endpoints.
    'send_ids_routine_telemetry': False,
    'ids_detection_window_seconds': 60,
    'ids_alert_cooldown_seconds': 900,
    'ids_sensor_dedupe_seconds': 900,
    'ids_port_scan_threshold': 15,
    'ids_brute_force_threshold': 10,
    'suricata_eve_path':        (
        r'C:\ProgramData\AJNAT\suricata\log\eve.json'
        if platform.system() == 'Windows'
        else '/opt/homebrew/var/log/suricata/eve.json'
        if platform.system() == 'Darwin' and platform.machine().lower() in ('arm64', 'aarch64')
        else '/usr/local/var/log/suricata/eve.json'
        if platform.system() == 'Darwin'
        else '/var/log/suricata/eve.json'
    ),
    'zeek_log_paths': [] if platform.system() == 'Windows' else [
        f'{root}/{name}.log'
        for root in ('/opt/zeek/logs/current', '/var/log/zeek/current')
        for name in ('conn', 'dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp', 'smb_files',
                     'dhcp', 'files', 'notice', 'weird', 'x509')
    ],
    'ids_sensor_mirror_to_agent_alerts': False,
    'firewall_enabled':         True,
    'yara_enabled':             True,
    'sandbox_analysis_enabled': True,
    'waf_enabled':              True,
    'waf_proxy_enabled':        False,  # explicit opt-in; monitoring never creates proxy ports
    'waf_intercept':            False,  # only applies when waf_proxy_enabled is true
    'waf_monitor_ports':        [],     # empty = auto-detect all; e.g. [3000] = only port 3000
    'waf_rescan_interval_seconds': 60,
    'waf_max_request_body_bytes': 10485760,
    'waf_rate_limit_per_minute': 300,
    'waf_login_attempts_per_minute': 20,
    'waf_allowed_methods': ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    'waf_blocked_upload_extensions': [
        'php', 'php3', 'php4', 'php5', 'phtml', 'phar', 'jsp', 'jspx',
        'asp', 'aspx', 'ashx', 'cgi', 'pl', 'exe', 'dll',
    ],
    'network_monitor_enabled':  True,
    'ransomware_enabled':       True,
    'ransomware_window_secs':   30,
    'mass_mod_threshold':       50,
    'mass_del_threshold':       30,
    'entropy_threshold':        7.0,
    'entropy_file_trigger':     10,
    'ransomware_alert_cooldown_seconds': 120,
    'ransomware_extensions':    [],
    'ransomware_protected_dirs': [],
    'ransomware_rule_overrides': {},
    'ransomware_policy_version': 0,
    'hash_monitoring_enabled':   True,
    'hash_sha256_enabled':       True,
    'hash_sha1_enabled':         True,
    'hash_md5_enabled':          False,
    'hash_signature_validation_enabled': True,
    'hash_threat_intel_enabled': True,
    'hash_baseline_monitoring_enabled': True,
    'hash_unsigned_alert_enabled': True,
    'hash_critical_file_monitoring_enabled': True,
    'hash_risk_threshold':       30,
    'hash_policy_version':       0,
    'cache_poison_enabled':     True,
    'cache_poison_telemetry_enabled': True,
    'cache_poison_watch_domains': [],
    'cache_poison_trusted_resolvers': [],
    'cache_poison_scan_interval_seconds': 300,
    'cache_poison_min_safe_ttl': 30,
    'cache_poison_max_safe_ttl': 86400,
    'cache_poison_baseline_window_seconds': 3600,
    'cache_poison_monitor_resolver_changes': True,
    'cache_poison_monitor_hosts_changes': True,
    'cache_poison_detect_private_answers': True,
    'cache_poison_detect_ttl_anomaly': True,
    'cache_poison_rule_severities': {
        'private-answer': 'critical', 'ttl-anomaly': 'high',
        'resolver-change': 'high', 'hosts-file-change': 'high',
    },
    'cache_poison_policy_version': 0,
    'dns_sinkhole_enabled':     True,
    'dns_sinkhole_ip':          '0.0.0.0',
    'dns_sinkhole_enforcement_mode': 'both',
    'dns_sinkhole_telemetry_enabled': True,
    'dns_sinkhole_report_interval_seconds': 300,
    'dns_sinkhole_sync_blocklist': True,
    'dns_sinkhole_policy_version': 0,
    'dns_sinkhole_default_severity': 'high',
    'dns_sinkhole_builtin_rule_ids': [],
    'dns_anomaly_detection_enabled': True,
    'beacon_detection_enabled': True,
    'beacon_enabled_rule_ids': [
        'exact-periodic-callback', 'jittered-c2-beacon', 'low-and-slow-beacon',
        'dns-periodic-beacon', 'http-https-beacon', 'suspicious-process-beacon',
    ],
    'beacon_custom_rules': [],
    'dns_beacon_detection_enabled': True,
    'beacon_min_connections': 6,
    'beacon_min_interval_seconds': 5,
    'beacon_max_interval_seconds': 3600,
    'beacon_min_observation_seconds': 60,
    'beacon_consistency_threshold': 75,
    'beacon_alert_threshold': 70,
    'dns_beacon_alert_threshold': 55,
    'beacon_alert_cooldown_seconds': 1800,
    'beacon_history_seconds': 86400,
    'beacon_policy_version': 0,
    'beacon_allow_destinations': [],
    'beacon_allow_processes': [],
    'network_snapshot_max_connections': 500,
    'network_snapshot_max_closed': 250,
    'network_behavior_window_seconds': 60,
    'port_scan_unique_ports': 20,
    'host_scan_unique_hosts': 15,
    'lateral_movement_unique_hosts': 8,
    'network_detection_cooldown_seconds': 900,
    'large_outbound_bytes': 104857600,
    'transfer_anomaly_multiplier': 4.0,
    'dns_anomaly_threshold': 45,
    'dns_anomaly_cooldown_seconds': 1800,
    # Listening-service protection.  An empty allowlist keeps discovery in
    # inventory/audit mode; enforcement is only possible when administrators
    # explicitly provide an allowlist and select mode "block".
    'port_policy_enabled':      True,
    'port_policy_mode':         'audit',  # audit | block
    'allowed_listening_ports':  [],       # ints, "tcp/443", or "udp/53"
    'allowed_port_processes':   {},       # e.g. {"tcp/443": ["nginx"]}
    'port_policy_exempt_loopback': True,
    'usb_monitor_enabled':      True,
    'fim_start_at':             '',
    'file_monitor_start_at':    '',
    'process_monitor_enabled':  True,
    'advanced_process_monitor_enabled': True,
    'kernel_monitoring_enabled': True,
    'kernel_monitor_interval_seconds': 300,
    'kernel_vulnerable_driver_hashes': [],
    'service_monitoring_enabled': True,
    'windows_event_poll_interval_seconds': 10,
    'process_asset_inventory_interval_seconds': 300,
    'persistence_monitoring_enabled': True,
    'system_changes_monitoring_enabled': True,
    'registry_monitor_enabled': True,
    'registry_monitor_interval_seconds': 60,
    'registry_monitor_paths': [],
    'configuration_monitor_paths': [],
    'container_monitor_enabled': True,
    'workload_activity_monitor_enabled': True,
    'input_behavior_monitoring_enabled': True,
    'input_behavior_retry_seconds': 60,
    'input_behavior_report_interval_seconds': 60,
    'workload_log_poll_interval_seconds': 15,
    'process_poll_interval_seconds': 30,
    'process_inventory_interval_seconds': 60,
    'process_connection_snapshot_interval_seconds': 60,
    'process_trust_worker_interval_seconds': 2,
    'file_monitor_poll_interval_seconds': 60,
    'file_monitor_poll_max_files': 3000,
    'file_monitor_hash_max_bytes': 16777216,
    'file_monitor_md5_enabled': False,
    'network_poll_interval_seconds': 20,
    'patch_inventory_enabled': True,
    'patch_inventory_interval_seconds': 21600,
    'lolbins_poll_interval': 30,
    'script_monitoring_enabled': True,
    'script_hashing_enabled': True,
    'script_hash_max_bytes': 16777216,
    'script_risk_threshold': 30,
    'script_alert_cooldown_seconds': 900,
    'script_detect_encoded_commands': True,
    'script_detect_obfuscation': True,
    'script_detect_download_execution': True,
    'script_detect_persistence': True,
    'script_detect_external_connections': True,
    'script_monitoring_rules': [],
    'script_trusted_paths': [],
    'script_trusted_hashes': [],
    'script_trusted_publishers': [],
    'time_anomaly_enabled': True,
    'time_anomaly_bypass_active': False,
    'time_anomaly_bypass_until': None,
    'time_anomaly_bypass_reason': '',
    'time_anomaly_bypass_id': '',
    'working_hours_start': 8,
    'working_hours_end': 20,
    'time_anomaly_weekends': True,
    'time_anomaly_weekend_days': [5, 6],
    'time_anomaly_holidays': [],
    'time_anomaly_exceptions': [],
    'time_anomaly_timezone': 'endpoint-local',
    'time_auth_failure_window_seconds': 300,
    'time_auth_failure_threshold': 5,
    'auth_password_spray_window_seconds': 300,
    'auth_password_spray_user_threshold': 5,
    'time_anomaly_risk_threshold': 45,
    'time_baseline_minimum_samples': 20,
    'time_anomaly_cooldown_seconds': 3600,
    'process_lifecycle_alerts_enabled': True,
    'process_cpu_threshold_percent': 90,
    'process_memory_threshold_percent': 15,
    'unauthorized_process_paths': [],
    'response_enabled':         True,
    'maintenance_mode':         False,
    'self_protection':          True,
    'erase_code_on_open':       False,
    'tamper_protection':        True,
    'integrity_verification':   True,
    'anti_debugging':           True,
    'anti_reverse_engineering': True,
    'anti_dump_protection':     True,
    'code_integrity_monitoring':True,
    'lockdown_mode':            True,
    'quarantine_exclude_paths': [],
    'memory_scanner_enabled':   True,   # EDR cap #5 — memory activity scanner (core/memory_scanner.py)
    'memory_scanner_interval_seconds': 60,
    'memory_overflow_enabled':  True,
    'memory_collection_interval_seconds': 30,
    'memory_high_usage_threshold': 90,
    'memory_high_usage_duration_seconds': 300,
    'memory_spike_percent_threshold': 25,
    'memory_spike_window_seconds': 60,
    'memory_leak_window_minutes': 30,
    'memory_leak_min_samples': 10,
    'memory_leak_growth_percent': 30,
    'memory_alert_cooldown_seconds': 300,
    'memory_process_sample_limit': 75,
    'memory_process_metric_top_n': 10,
    'memory_rwx_detection_enabled': True,
    'memory_process_access_detection_enabled': True,
    'memory_crash_correlation_enabled': True,
    'geo_enrichment_enabled':   True,
    'geo_fence_enabled':        False,
    'geo_fence_latitude':       None,
    'geo_fence_longitude':      None,
    'geo_fence_radius_meters':  200,
    'geo_fence_lock_on_violation': False,
    # Device GPS is explicitly enabled by a tenant Location-Based policy.
    # Geo-IP enrichment remains a fallback and is never represented as GPS.
    'gps_tracking_enabled':     False,
    'geolocation_forensics_enabled': False,
    'gps_collection_interval_seconds': 300,
    'gps_required_accuracy_meters': 50,
    'high_risk_geo_countries':  ['RU', 'CN', 'KP', 'IR', 'SY', 'BY', 'CU'],
    'allowed_geo_countries':    [],

    # ── VirusTotal ────────────────────────────────────────────────────────
    'virustotal_api_key':       '',

    # ── IPS Webhook Server v3.0 (DEPRECATED) ──────────────────────────────
    # pfSense/OPNsense webhook removed — IPS now blocks on the local host
    # firewall (UFW/nftables/Windows Defender). These keys are ignored.
    'ips_webhook_url':          '',       # e.g. http://localhost:5050
    'ips_webhook_secret':       '',       # Must match IPS_WEBHOOK_SECRET in ipsserver/.env
    'ips_auto_block':           True,     # Auto-block high/critical threats
    'network_attack_block_enabled': True,
    'ips_block_ttl_hours':      24,       # Hours before block auto-expires
    'ips_threat_threshold':     'medium', # low / medium / high / critical
    'waf_direct_block_enabled': True,     # Suricata web signature -> host firewall, no proxy
    'waf_direct_block_threshold': 'medium',
    'ids_ips_capabilities_enabled': True,
    # Native preset deployment. The agent service needs write permission to
    # these sensor-owned paths (normally it runs as root).
    'ids_policy_dir':            (
        os.path.join(os.getenv('ProgramData', r'C:\ProgramData'), 'AJNAT', 'state', 'ids-policies')
        if platform.system() == 'Windows' else '/var/lib/soc-agent/ids-policies'
    ),
    'suricata_config':           '/etc/suricata/suricata.yaml',
    'suricata_soc_rules':        (
        os.path.join(os.getenv('ProgramData', r'C:\ProgramData'), 'AJNAT', 'suricata', 'rules', 'soc-managed.rules')
        if platform.system() == 'Windows' else '/etc/suricata/rules/soc-managed.rules'
    ),
    'zeek_local_script':         '',  # auto-detect /opt, /usr/local, or /usr
    'zeek_soc_script':           '',  # defaults beside Zeek local.zeek
    'ids_packet_sensor_required': [
        'SYN Scan', 'FIN Scan', 'NULL Scan', 'XMAS Scan', 'ACK Scan',
        'ICMP Flood', 'Network Packets',
    ],

    # ── Plan ──────────────────────────────────────────────────────────────
    'plan_limit':               10,
}


class AgentConfig:
    def __init__(self, path: Path = CONFIG_PATH):
        self._data = dict(DEFAULTS)
        self._path = path
        self._load()

    def _load(self):
        if not self._path.exists():
            logger.critical(
                f'[config] ❌ Config NOT found at {self._path}. '
                'Download your config from SOC Dashboard → Download Agent page.'
            )
            self._apply_env_overrides()
            self._normalize_connection()
            return
        stored = ''
        encrypted = False
        try:
            stored = self._path.read_text(encoding='utf-8')
            encrypted = is_encrypted_config(stored)
            loaded = load_config(self._path)
            self._data.update(loaded)
            self._apply_env_overrides()
            self._normalize_connection()

            # Fresh packages contain bootstrap JSON so installers can select
            # the correct platform. The first agent start immediately migrates
            # it to authenticated AES-256-GCM ciphertext.
            if not is_encrypted_config(stored):
                save_config(self._path, {
                    key: value for key, value in self._data.items()
                    if key not in RUNTIME_ONLY_KEYS
                })
            if self._data.get('mtls_client_key'):
                self._data['mtls_client_key_password'] = config_key_password(self._path)

            # Log every key that was loaded so problems are easy to spot
            logger.info(
                f'[config] ✅ Loaded: company={self._data.get("company_name")} '
                f'| system={self._data.get("system_name")} '
                f'| server={self._data.get("server_url")} '
                f'| agent_key={"SET" if self._data.get("agent_key") else "MISSING"} '
                f'| edr={self._data.get("edr_enabled")} '
                f'| ids={self._data.get("ids_enabled")} '
                f'| ips={self._data.get("ips_enabled")} '
                f'| fw={self._data.get("firewall_enabled")} '
                f'| vt={"yes" if self._data.get("virustotal_api_key") else "no"} '
                f'| ips_webhook={"SET" if self._data.get("ips_webhook_url") else "NOT SET"}'
            )

            # Warn about critical missing fields
            for critical in ('agent_key', 'system_id', 'company_id', 'server_url'):
                if not self._data.get(critical):
                    logger.warning(f'[config] ⚠️  Field "{critical}" is empty — agent may not connect!')

        except json.JSONDecodeError as e:
            logger.error(f'[config] ❌ JSON parse error in {self._path}: {e}')
        except Exception as e:
            logger.error(f'[config] ❌ Unexpected error loading config: {e}')
            if encrypted:
                raise RuntimeError('AJNAT encrypted configuration authentication failed') from e

    def _apply_env_overrides(self):
        """Allow installer/service env vars to override generated JSON values."""
        env_map = {
            'SOC_AGENT_SERVER_URL': 'server_url',
            'SERVER_URL': 'server_url',
            'SOC_AGENT_SERVER_PROTO': 'server_proto',
            'SERVER_PROTO': 'server_proto',
            'SOC_AGENT_SERVER_IP': 'server_ip',
            'SERVER_IP': 'server_ip',
            'SOC_AGENT_SERVER_PORT': 'server_port',
            'SERVER_PORT': 'server_port',
            'SOC_AGENT_KEY': 'agent_key',
            'AGENT_KEY': 'agent_key',
            'SOC_AGENT_COMPANY_ID': 'company_id',
            'COMPANY_ID': 'company_id',
            'SOC_AGENT_SYSTEM_ID': 'system_id',
            'SYSTEM_ID': 'system_id',
            'SOC_AGENT_VELOCIRAPTOR_CLIENT_ID': 'velociraptor_client_id',
            'VELOCIRAPTOR_CLIENT_ID': 'velociraptor_client_id',
            'INTEGRATION_SECRET': 'integration_secret',
            'VIRUSTOTAL_API_KEY': 'virustotal_api_key',
            'IPS_WEBHOOK_URL': 'ips_webhook_url',
            'IPS_WEBHOOK_SECRET': 'ips_webhook_secret',
            'SOC_AGENT_QUARANTINE_EXCLUDE': 'quarantine_exclude_paths',
            'MEMORY_MONITORING_ENABLED': 'memory_overflow_enabled',
            'MEMORY_COLLECTION_INTERVAL_SECONDS': 'memory_collection_interval_seconds',
            'MEMORY_HIGH_USAGE_THRESHOLD': 'memory_high_usage_threshold',
            'MEMORY_HIGH_USAGE_DURATION_SECONDS': 'memory_high_usage_duration_seconds',
            'MEMORY_SPIKE_PERCENT_THRESHOLD': 'memory_spike_percent_threshold',
            'MEMORY_SPIKE_WINDOW_SECONDS': 'memory_spike_window_seconds',
            'MEMORY_LEAK_WINDOW_MINUTES': 'memory_leak_window_minutes',
            'MEMORY_LEAK_MIN_SAMPLES': 'memory_leak_min_samples',
            'MEMORY_LEAK_GROWTH_PERCENT': 'memory_leak_growth_percent',
            'MEMORY_RWX_DETECTION_ENABLED': 'memory_rwx_detection_enabled',
            'MEMORY_PROCESS_ACCESS_DETECTION_ENABLED': 'memory_process_access_detection_enabled',
            'MEMORY_CRASH_CORRELATION_ENABLED': 'memory_crash_correlation_enabled',
            'MEMORY_ALERT_COOLDOWN_SECONDS': 'memory_alert_cooldown_seconds',
        }
        for env_name, key in env_map.items():
            value = os.getenv(env_name)
            if value not in (None, ''):
                if key == 'quarantine_exclude_paths':
                    self._data[key] = [p for p in value.split(os.pathsep) if p.strip()]
                elif isinstance(DEFAULTS.get(key), bool):
                    self._data[key] = str(value).strip().lower() in {'1', 'true', 'yes', 'on'}
                elif isinstance(DEFAULTS.get(key), int):
                    try:
                        self._data[key] = int(value)
                    except ValueError:
                        logger.warning('[config] Ignoring invalid integer %s', env_name)
                elif isinstance(DEFAULTS.get(key), float):
                    try:
                        self._data[key] = float(value)
                    except ValueError:
                        logger.warning('[config] Ignoring invalid number %s', env_name)
                else:
                    self._data[key] = value

    def _normalize_connection(self):
        """Auto-compose server_url/server_ip/server_port when one side is missing."""
        server_url = (self._data.get('server_url') or '').strip().rstrip('/')
        server_ip = (self._data.get('server_ip') or '').strip()
        server_proto = (self._data.get('server_proto') or '').strip()
        server_port = self._data.get('server_port')

        if server_url:
            self._data['server_url'] = server_url
            parsed = urlparse(server_url if '://' in server_url else f'http://{server_url}')
            if parsed.scheme:
                self._data['server_proto'] = parsed.scheme
            if parsed.hostname and (not server_ip or server_ip == 'localhost'):
                self._data['server_ip'] = parsed.hostname
            if parsed.port:
                self._data['server_port'] = parsed.port
            return

        if server_proto and server_ip and server_port:
            self._data['server_url'] = f'{server_proto}://{server_ip}:{server_port}'

    def reload(self):
        """Re-read the JSON file from disk (useful after hot-update)."""
        self._data = dict(DEFAULTS)
        self._load()

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def all(self) -> dict:
        return dict(self._data)

    def is_configuration_encrypted(self) -> bool:
        """Return the on-disk state without exposing configuration contents."""
        try:
            return is_encrypted_config(self._path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError):
            return False

    def update_runtime(self, updates: dict, persist: bool = True, strict: bool = False):
        """Merge server-provided config updates and optionally persist JSON."""
        if not isinstance(updates, dict) or not updates:
            return False
        changed = False
        for key, value in updates.items():
            if value is not None and self._data.get(key) != value:
                self._data[key] = value
                changed = True
        if persist and (changed or strict):
            self._persist(strict=strict)
        return changed

    def _persist(self, strict=False):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            current = load_config(self._path) if self._path.exists() else {}
            for key in RUNTIME_ONLY_KEYS:
                current.pop(key, None)
            current.update({
                key: value for key, value in self._data.items()
                if key not in RUNTIME_ONLY_KEYS
            })
            save_config(self._path, current)
        except Exception as e:
            logger.warning(f'[config] ⚠️  Runtime config persist failed: {e}')
            if strict:
                raise

    def __repr__(self):
        return (
            f'<AgentConfig company={self._data.get("company_name")!r} '
            f'system={self._data.get("system_name")!r} '
            f'server={self._data.get("server_url")!r}>'
        )
