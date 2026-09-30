"""
IDS Module — Intrusion Detection System
Detects suspicious traffic/events and sends alerts to server.

Features:
  - Monitor network connections for known attack patterns
  - Detect port scans (many connections from single IP)
  - Detect brute-force login attempts (many failed logins)
  - Detect suspicious outbound connections (C2, DNS tunnelling)
  - Send real-time alerts to SOC dashboard
"""
import time
import logging
import threading
import platform
from collections import defaultdict
from datetime import datetime, timezone

try:
    from core.ids_ips_capabilities import IDS_IPS_ATTACK_TYPES
except Exception:
    IDS_IPS_ATTACK_TYPES = []

logger = logging.getLogger('soc-agent.ids')
SYSTEM = platform.system()
POLL_INTERVAL = 20  # seconds

# Detection defaults. Deployments can tune these in company_config.json.
PORT_SCAN_THRESHOLD    = 15   # unique dst ports from same src IP in 60s → port scan
BRUTE_FORCE_THRESHOLD  = 10   # failed auth events from same IP in 60s
DNS_TUNNEL_THRESHOLD   = 50   # DNS queries per minute → possible tunnelling
ALERT_COOLDOWN_SECONDS = 900  # one alert per fingerprint every 15 minutes

C2_PORTS = {
    4444, 4445, 4446, 5555, 6666, 6667, 6668, 6669,
    1337, 31337, 12345, 9999, 8888, 1234, 2222, 7777,
    1080, 9050, 9051,   # SOCKS / Tor
    4899,               # Radmin
}


class IDSModule:
    def __init__(self, sender, config=None, ips=None):
        self._sender         = sender
        self._config         = config or {}
        self._ips            = ips
        self._port_tracker   = defaultdict(set)    # src_ip → {dst_ports}
        self._brute_tracker  = defaultdict(int)    # src_ip → count
        self._alerted        = {}  # fingerprint → last emitted monotonic timestamp
        self._thread         = threading.Thread(target=self._loop, daemon=True, name='ids')
        self._last_reset     = time.monotonic()
        self._reset_interval = self._config_number('ids_detection_window_seconds', 60, 30, 600)
        self._alert_cooldown = self._config_number(
            'ids_alert_cooldown_seconds', ALERT_COOLDOWN_SECONDS, 60, 86400
        )
        self._port_scan_threshold = int(self._config_number(
            'ids_port_scan_threshold', PORT_SCAN_THRESHOLD, 10, 1000
        ))
        self._brute_force_threshold = int(self._config_number(
            'ids_brute_force_threshold', BRUTE_FORCE_THRESHOLD, 5, 1000
        ))

    def _config_number(self, key, default, minimum, maximum):
        try:
            value = float(self._config.get(key, default))
        except (TypeError, ValueError):
            value = float(default)
        return max(float(minimum), min(float(maximum), value))

    def _should_emit(self, fingerprint):
        """Return True once per fingerprint/cooldown without losing counters."""
        now = time.monotonic()
        last_emitted = self._alerted.get(fingerprint)
        if last_emitted is not None and now - last_emitted < self._alert_cooldown:
            return False
        self._alerted[fingerprint] = now
        return True

    def start(self):
        self._thread.start()
        logger.info('IDS module started')

    def set_ips(self, ips):
        """Attach the local IPS after agent modules finish initializing."""
        self._ips = ips

    def _auto_block_source(self, source_ip, severity, reason, port=None):
        """Apply the detected threat to the platform-native firewall."""
        if not self._ips or not self._config.get('ips_enabled', True):
            return
        if not self._config.get('ips_auto_block', True):
            return
        levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        minimum = str(self._config.get('ips_threat_threshold', 'high')).lower()
        if levels.get(severity, 0) < levels.get(minimum, levels['high']):
            return
        try:
            self._ips.block_ip(
                source_ip,
                reason=f'IDS: {reason}',
                port=port,
                protocol='tcp',
                threat_level=severity,
                attack_type=reason,
            )
        except Exception as exc:
            logger.error('IDS auto-block failed for %s: %s', source_ip, exc)

    def _loop(self):
        while True:
            try:
                self._scan()
                self._maybe_reset()
            except Exception as e:
                logger.error('IDS scan error: %s', e)
            time.sleep(POLL_INTERVAL)

    def _maybe_reset(self):
        now = time.monotonic()
        if now - self._last_reset > self._reset_interval:
            self._port_tracker.clear()
            self._brute_tracker.clear()
            # Counter windows reset frequently, but alert suppression has its
            # own longer lifecycle. Prune only expired fingerprints here.
            self._alerted = {
                key: emitted_at for key, emitted_at in self._alerted.items()
                if now - emitted_at < self._alert_cooldown
            }
            self._last_reset = now

    def _scan(self):
        try:
            import psutil
        except ImportError:
            return

        conns = psutil.net_connections(kind='inet')
        now_ts = datetime.now(timezone.utc).isoformat()

        for conn in conns:
            try:
                if conn.status != 'ESTABLISHED':
                    continue
                laddr = conn.laddr
                raddr = conn.raddr
                if not raddr:
                    continue

                remote_ip   = raddr.ip
                remote_port = raddr.port
                local_port  = laddr.port if laddr else 0

                # Skip private/loopback
                if self._is_private(remote_ip):
                    continue

                # ── C2 port detection ────────────────────────────────────────
                if remote_port in C2_PORTS or local_port in C2_PORTS:
                    key = f'ids_c2_{remote_ip}_{remote_port}'
                    if self._should_emit(key):
                        self._sender.enqueue({
                            'module':      'IDS',
                            'source_type': 'ids',
                            'event_category': 'ids_alert',
                            'source':      'IDS',
                            'rule_id':     'IDS_C2_PORT',
                            'category':    'network',
                            'severity':    'critical',
                            'description': f'Connection on known C2 port: {remote_ip}:{remote_port}',
                            'raw_log':     f'src={remote_ip}:{remote_port} local_port={local_port}',
                            'src_ip':      remote_ip,
                            'dst_port':    remote_port,
                            'protocol':    'tcp',
                            'type':        'IDS_ALERT',
                            'attackType':  'C2 Communication',
                            'action':      'Detected',
                            'status':      'Open',
                            'sensor':      'SOC Agent IDS',
                            'timestamp':   now_ts,
                        })
                        self._auto_block_source(
                            remote_ip, 'critical', 'C2 Communication', remote_port
                        )

                # ── Port scan tracking ───────────────────────────────────────
                self._port_tracker[remote_ip].add(remote_port)
                if len(self._port_tracker[remote_ip]) >= self._port_scan_threshold:
                    key = f'ids_scan_{remote_ip}'
                    if self._should_emit(key):
                        ports = list(self._port_tracker[remote_ip])[:20]
                        self._sender.enqueue({
                            'module':      'IDS',
                            'source_type': 'ids',
                            'event_category': 'ids_alert',
                            'source':      'IDS',
                            'rule_id':     'IDS_PORT_SCAN',
                            'category':    'network',
                            'severity':    'high',
                            'description': f'Port scan detected from {remote_ip} ({len(self._port_tracker[remote_ip])} ports)',
                            'raw_log':     f'src={remote_ip} ports={ports}',
                            'src_ip':      remote_ip,
                            'protocol':    'tcp',
                            'type':        'IDS_ALERT',
                            'attackType':  'Port Scan',
                            'action':      'Detected',
                            'status':      'Open',
                            'sensor':      'SOC Agent IDS',
                            'timestamp':   now_ts,
                        })
                        self._auto_block_source(remote_ip, 'high', 'Port Scan')

            except Exception:
                pass

    @staticmethod
    def _is_private(ip: str) -> bool:
        return ip.startswith((
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.', '::1', 'fc', 'fd', '169.254.',
        ))

    def report_brute_force(self, src_ip: str, service: str = 'ssh'):
        """Call this from log collector when auth failure lines are parsed."""
        self._brute_tracker[src_ip] += 1
        if self._brute_tracker[src_ip] >= self._brute_force_threshold:
            key = f'ids_brute_{src_ip}_{service}'
            if self._should_emit(key):
                self._sender.enqueue({
                    'module':      'IDS',
                    'source_type': 'ids',
                    'event_category': 'ids_alert',
                    'source':      'IDS',
                    'rule_id':     'IDS_BRUTE_FORCE',
                    'category':    'network',
                    'severity':    'high',
                    'description': f'Brute-force detected from {src_ip} on {service} ({self._brute_tracker[src_ip]} attempts)',
                    'raw_log':     f'src={src_ip} service={service} attempts={self._brute_tracker[src_ip]}',
                    'src_ip':      src_ip,
                    'user_action': 'brute_force',
                    'type':        'IDS_ALERT',
                    'attackType':  'Brute Force',
                    'action':      'Detected',
                    'status':      'Open',
                    'sensor':      'SOC Agent IDS',
                    'timestamp':   datetime.now(timezone.utc).isoformat(),
                })
                self._auto_block_source(src_ip, 'high', 'Brute Force')

    def supported_attack_types(self):
        return IDS_IPS_ATTACK_TYPES
