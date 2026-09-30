"""
Suricata/Zeek IDS Log Parser
Watches Suricata's eve.json and Zeek JSON logs,
parses alerts, and sends them to the SOC backend.

Features:
  - Tails eve.json (Suricata EVE format)
  - Parses Zeek JSON/TSV notice logs
  - Sends parsed alerts to /api/ids/suricata or /api/ids/zeek
  - Shows in dashboard with severity, signature, src/dst IP
"""
import json
import hashlib
import logging
import os
import platform
import re
import threading
import time

from core.network_sensor_normalizer import (
    is_suricata_informational_noise,
    is_zeek_informational_noise,
    normalize_suricata,
    normalize_zeek,
)
from core.secure_transport import secure_request

logger = logging.getLogger('soc-agent.suricata-parser')

DEFAULT_IGNORED_SENSOR_IPS = {'8.8.8.8', '1.1.1.1'}
WAF_ATTACK_PATTERN = re.compile(
    r'web[_ -]?(server|client|application)|http attack|sql.?injection|xss|cross.?site|'
    r'command injection|path traversal|directory traversal|rfi|lfi|xxe|ssrf|log4j|web shell',
    re.IGNORECASE,
)

# Common paths to search for Suricata logs
SURICATA_LOG_PATHS = [
    '/var/log/suricata/eve.json',
    '/var/log/suricata/fast.log',
    '/usr/local/var/log/suricata/eve.json',
    '/opt/suricata/var/log/eve.json',
    '/var/log/ids/eve.json',
    os.path.expandvars(r'%ProgramData%\AJNAT\suricata\log\eve.json'),
    os.path.expandvars(r'%ProgramData%\Suricata\log\eve.json'),
    os.path.expandvars(r'%ProgramFiles%\Suricata\log\eve.json'),
]

ZEEK_LOG_PATHS = [
    f'{root}/{name}.log'
    for root in ('/opt/zeek/logs/current', '/usr/local/zeek/logs/current',
                 '/var/log/zeek/current', '/var/log/zeek', '/var/log/bro/current')
    for name in ('conn', 'dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp', 'smb_files',
                 'dhcp', 'files', 'notice', 'weird', 'x509')
]


def _split_config_paths(value):
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [p.strip() for p in str(value).replace(',', os.pathsep).split(os.pathsep) if p.strip()]


class Parser:
    """
    Watches Suricata EVE JSON and Zeek JSON logs.
    Parses each alert event and sends to the SOC backend.
    """

    def __init__(self, sender, config=None, ips=None):
        self._sender = sender
        self._config = config or {}
        # The IPS module owns local firewall enforcement.  Keep it optional so
        # the parser can still operate in detection-only deployments.
        self._ips = ips
        self._eve_path = None
        self._suricata_candidates = []
        self._zeek_paths = []
        self._watched_paths = set()
        self._running = False
        self._threads = []
        self._recent_event_fingerprints = {}
        self._fingerprint_lock = threading.Lock()

    def _sensor_dedupe_seconds(self):
        try:
            configured = int(self._config.get('ids_sensor_dedupe_seconds', 900))
        except (TypeError, ValueError):
            configured = 900
        return max(60, min(86400, configured))

    @staticmethod
    def _normalized_event_fingerprint(event):
        """Build a semantic fingerprint independent of native ID/timestamp."""
        material = {
            'source': event.get('source'),
            'log_type': event.get('log_type'),
            'signature_id': event.get('signature_id'),
            'signature': event.get('signature'),
            'src_ip': event.get('src_ip'),
            'src_port': event.get('src_port'),
            'dest_ip': event.get('dest_ip'),
            'dest_port': event.get('dest_port'),
            'protocol': event.get('protocol'),
            'action': event.get('action'),
            'severity': event.get('severity'),
            'hostname': event.get('hostname'),
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')
        ).hexdigest()

    def _is_duplicate_normalized_event(self, event):
        """Check for a recently delivered, semantically identical event.

        Native event IDs and timestamps intentionally are not part of this
        fingerprint: sensors often assign a new ID to every packet even when
        it represents the same alert. Action/severity are included so an
        escalation or a detect→block state change is delivered immediately.
        """
        fingerprint = self._normalized_event_fingerprint(event)
        now = time.monotonic()
        cooldown = self._sensor_dedupe_seconds()
        with self._fingerprint_lock:
            previous = self._recent_event_fingerprints.get(fingerprint)
            return previous is not None and now - previous < cooldown

    def _remember_normalized_event(self, event):
        fingerprint = self._normalized_event_fingerprint(event)
        now = time.monotonic()
        cooldown = self._sensor_dedupe_seconds()
        with self._fingerprint_lock:
            self._recent_event_fingerprints[fingerprint] = now
            if len(self._recent_event_fingerprints) > 10000:
                self._recent_event_fingerprints = {
                    key: seen_at for key, seen_at in self._recent_event_fingerprints.items()
                    if now - seen_at < cooldown
                }

    def _mirror_to_agent_alerts(self):
        return bool(self._config.get('ids_sensor_mirror_to_agent_alerts', False))

    def _ignored_sensor_ips(self):
        configured = self._config.get('ids_sensor_ignored_ips', DEFAULT_IGNORED_SENSOR_IPS)
        if isinstance(configured, str):
            return {ip.strip() for ip in configured.split(',') if ip.strip()}
        return {str(ip).strip() for ip in configured if str(ip).strip()}

    def _drop_suricata_event(self, event):
        """Keep explicitly ignored traffic and routine DNS telemetry local."""
        ignored_ips = self._ignored_sensor_ips()
        if event.get('src_ip') in ignored_ips or event.get('dest_ip') in ignored_ips:
            return True
        if event.get('event_type') == 'dns' and self._config.get('send_suricata_dns_telemetry', False):
            return False
        if not self._config.get('send_ids_routine_telemetry', False):
            return event.get('event_type') not in {'alert', 'anomaly'}
        return event.get('event_type') == 'dns' and not event.get('alert')

    def start(self):
        if self._config.get('network_ids_sensors_enabled', True) is False:
            logger.info('Network IDS sensor parser disabled by config')
            return

        self._running = True

        # Find Suricata eve.json
        self._suricata_candidates = _split_config_paths(
            self._config.get('suricata_eve_path') or self._config.get('suricata_eve_paths')
        ) + SURICATA_LOG_PATHS
        for p in self._suricata_candidates:
            if os.path.exists(p):
                self._eve_path = p
                break

        zeek_candidates = _split_config_paths(self._config.get('zeek_log_path') or self._config.get('zeek_log_paths')) + ZEEK_LOG_PATHS

        # Find Zeek logs
        seen_zeek = set()
        for p in zeek_candidates:
            if p not in seen_zeek and os.path.exists(p):
                seen_zeek.add(p)
                self._zeek_paths.append(p)

        if self._eve_path:
            t = threading.Thread(target=self._watch_suricata, daemon=True, name='suricata-parser')
            t.start()
            self._threads.append(t)
            self._watched_paths.add(self._eve_path)
            logger.info('Suricata parser started: watching %s', self._eve_path)
        else:
            logger.info('Suricata: no eve.json found — skipping')

        if self._zeek_paths:
            for zeek_path in self._zeek_paths:
                t = threading.Thread(target=self._watch_zeek, args=(zeek_path,), daemon=True, name=f'zeek-parser-{os.path.basename(zeek_path)}')
                t.start()
                self._threads.append(t)
                self._watched_paths.add(zeek_path)
            logger.info('Zeek parser started: watching %d log file(s)', len(self._zeek_paths))
        else:
            logger.info('Zeek: no notice/conn log found — skipping')

        t = threading.Thread(
            target=self._discover_late_sensor_logs,
            args=(zeek_candidates,),
            daemon=True,
            name='ids-log-discovery',
        )
        t.start()
        self._threads.append(t)

        # Health check for local IDS sensor processes.
        self._http_thread = threading.Thread(target=self._http_sender_loop, daemon=True, name='ids-http-sender')
        self._http_thread.start()

    def _discover_late_sensor_logs(self, zeek_candidates):
        """Start Zeek watchers when log files are created after agent startup."""
        while self._running:
            try:
                if not self._eve_path:
                    for p in self._suricata_candidates:
                        if os.path.exists(p):
                            self._eve_path = p
                            t = threading.Thread(target=self._watch_suricata, daemon=True, name='suricata-parser')
                            t.start()
                            self._threads.append(t)
                            self._watched_paths.add(p)
                            logger.info('Suricata parser started late: watching %s', p)
                            break
                for p in zeek_candidates:
                    if os.path.exists(p) and p not in self._watched_paths:
                        t = threading.Thread(target=self._watch_zeek, args=(p,), daemon=True, name=f'zeek-parser-{os.path.basename(p)}')
                        t.start()
                        self._threads.append(t)
                        self._watched_paths.add(p)
                        logger.info('Zeek parser started late: watching %s', p)
            except Exception as e:
                logger.debug('IDS late log discovery error: %s', e)
            time.sleep(30)

    def _watch_suricata(self):
        """Tail Suricata's eve.json and parse alert events."""
        try:
            # Seek to end of file
            with open(self._eve_path, 'r') as f:
                f.seek(0, 2)  # Seek to end
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    try:
                        event = json.loads(line.strip())
                        if self._drop_suricata_event(event):
                            logger.debug('Routine Suricata DNS telemetry suppressed locally')
                            continue
                        if is_suricata_informational_noise(event):
                            logger.debug(
                                'Suricata self-generated threat-feed alert suppressed: SID=%s',
                                (event.get('alert') or {}).get('signature_id'),
                            )
                            continue
                        delivered = self._send_normalized(normalize_suricata(event, platform.node() or 'suricata'))
                        if event.get('event_type') == 'alert':
                            # Enforcement is local and must not depend on a
                            # successful backend delivery.  Previously it ran
                            # only when normalized delivery failed, so normal
                            # healthy agents merely reported attacks.
                            alert_data = event.get('alert', {})
                            severity_map = {1: 'critical', 2: 'high', 3: 'medium'}
                            severity = severity_map.get(alert_data.get('severity', 3), 'low')
                            self._auto_block_suricata_source(
                                event,
                                severity,
                                alert_data.get('signature', 'Unknown Suricata Alert'),
                            )
                            if not delivered:
                                # Preserve the legacy endpoint as a delivery
                                # fallback without enforcing the same event twice.
                                self._process_suricata_alert(event, enforce=False)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.debug('Suricata parse error: %s', e)
        except PermissionError:
            logger.warning('Suricata: no permission to read %s', self._eve_path)
        except Exception as e:
            logger.error('Suricata watcher error: %s', e)

    def _process_suricata_alert(self, event, enforce=True):
        """Convert a Suricata EVE alert event to SOC alert format."""
        alert_data = event.get('alert', {})
        severity_map = {1: 'critical', 2: 'high', 3: 'medium'}
        sev = severity_map.get(alert_data.get('severity', 3), 'low')

        signature = alert_data.get('signature', 'Unknown Suricata Alert')
        sig_id = alert_data.get('signature_id', 0)
        category = alert_data.get('category', 'network')

        description = f'[Suricata] {signature}'
        if alert_data.get('action') == 'blocked':
            description += ' [BLOCKED]'

        if enforce:
            self._auto_block_suricata_source(event, sev, signature)

        alert = {
            'module':      'IDS',
            'source_type': 'ids',
            'event_category': 'ids_alert',
            'rule_id':     f'SUR_{sig_id}',
            'category':    'network',
            'severity':    sev,
            'description': description,
            'raw_log':     json.dumps(event)[:2000],
            'src_ip':      event.get('src_ip', ''),
            'dst_ip':      event.get('dest_ip', ''),
            'src_port':    event.get('src_port'),
            'dst_port':    event.get('dest_port'),
            'protocol':    event.get('proto', ''),
            'blocked':     alert_data.get('action') == 'blocked',
            'source':      'suricata',
            'type':        'IDS_ALERT',
            'attackType':  signature,
            'signatureName': signature,
            'action':      'Blocked' if alert_data.get('action') == 'blocked' else 'Detected',
            'status':      'blocked' if alert_data.get('action') == 'blocked' else 'open',
            'sensor':      'Suricata',
            'packet_count': event.get('flow', {}).get('pkts_toserver') if isinstance(event.get('flow'), dict) else None,
            'timestamp':   event.get('timestamp'),
        }
        if self._mirror_to_agent_alerts():
            self._sender.enqueue(alert)

        logger.info(
            'Suricata alert: [%s] %s → %s:%s (severity: %s)',
            sig_id, event.get('src_ip', '?'),
            event.get('dest_ip', '?'), event.get('dest_port', '?'), sev
        )

        # Also send to backend IDS endpoint for proper dashboard visualization
        self._send_to_ids_endpoint('suricata', event)

    def _auto_block_suricata_source(self, event, severity, signature):
        """Block a malicious public source IP after a Suricata alert.

        Suricata's ``alert`` rules only detect traffic.  In agent-managed IPS
        mode, this bridges those alerts to the local firewall backend.  The IPS
        module retains ownership of whitelist/private-address safeguards and of
        reporting the resulting block event.
        """
        if not self._ips or not self._config.get('ips_enabled', True):
            return
        if not self._config.get('ips_auto_block', True):
            return
        levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        is_waf_attack = bool(WAF_ATTACK_PATTERN.search(str(signature or '')))
        if is_waf_attack and not self._config.get('waf_direct_block_enabled', True):
            return
        if not is_waf_attack and not self._config.get('network_attack_block_enabled', True):
            return
        minimum = str(
            self._config.get('waf_direct_block_threshold', 'medium')
            if is_waf_attack else self._config.get('ips_threat_threshold', 'high')
        ).lower()
        if levels.get(severity, 0) < levels.get(minimum, levels['high']):
            return

        src_ip = str(event.get('src_ip') or '').strip()
        if not src_ip:
            logger.warning('IPS auto-block skipped: Suricata alert has no source IP')
            return

        try:
            ok = self._ips.block_ip(
                src_ip,
                reason=f'{"AJNAT WAF direct" if is_waf_attack else "Suricata"}: {signature}',
                port=event.get('dest_port'),
                protocol=event.get('proto'),
                threat_level=severity,
                attack_type=signature,
            )
            if ok:
                logger.warning('IPS auto-blocked Suricata source %s (%s)', src_ip, signature)
            else:
                logger.info('IPS did not block Suricata source %s (already blocked, private, or whitelisted)', src_ip)
        except Exception as e:
            # An alert must still be delivered if firewall enforcement fails.
            logger.error('IPS auto-block failed for Suricata source %s: %s', src_ip, e)

    def _watch_zeek(self, path):
        """Tail Zeek JSON or TSV logs and convert notices/interesting connections."""
        first_open = True
        missing_logged = False
        while self._running:
            if not os.path.exists(path):
                if not missing_logged:
                    logger.warning('Zeek log unavailable; waiting for file: %s', path)
                    missing_logged = True
                time.sleep(30)
                continue
            try:
                with open(path, 'r', errors='replace') as f:
                    missing_logged = False
                    opened_inode = os.fstat(f.fileno()).st_ino
                # Zeek's default TSV format declares its columns near the start
                # of the file.  Capture them before tailing from EOF; otherwise
                # every row appended after agent startup is silently skipped.
                    fields = self._read_zeek_fields(f)
                    if first_open:
                        f.seek(0, 2)
                        first_open = False
                    else:
                        # After rotation, consume the new file from its start so
                        # events written between rotation and reopen are retained.
                        f.seek(0)
                    while self._running:
                        line = f.readline()
                        if not line:
                            try:
                                current = os.stat(path)
                                if current.st_ino != opened_inode or current.st_size < f.tell():
                                    logger.info('Zeek log rotation detected: reopening %s', path)
                                    break
                            except FileNotFoundError:
                                break
                            time.sleep(0.5)
                            continue
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith('#fields'):
                            fields = line.split('\t')[1:]
                            continue
                        if line.startswith('#'):
                            continue
                        try:
                            event = json.loads(line) if line.startswith('{') else self._parse_zeek_tsv(line, fields)
                            if event:
                                self._process_zeek_event(event, path)
                        except Exception as e:
                            logger.debug('Zeek parse error: %s', e)
            except PermissionError:
                logger.warning('Zeek: no permission to read %s', path)
                return
            except FileNotFoundError:
                if not missing_logged:
                    logger.warning('Zeek log rotated or unavailable; waiting for file: %s', path)
                    missing_logged = True
            except Exception as e:
                logger.error('Zeek watcher error (%s): %s', path, e)
            if self._running:
                time.sleep(5)

    @staticmethod
    def _read_zeek_fields(handle):
        handle.seek(0)
        for line in handle:
            if line.startswith('#fields'):
                return line.rstrip('\n').split('\t')[1:]
            if line and not line.startswith('#'):
                break
        return []

    def _parse_zeek_tsv(self, line, fields):
        if not fields:
            return None
        values = line.split('\t')
        return {field: values[i] if i < len(values) else '' for i, field in enumerate(fields)}

    def _process_zeek_event(self, event, path):
        log_type = os.path.basename(path).replace('.log', '')
        if is_zeek_informational_noise(event, log_type):
            logger.debug(
                'Zeek capture diagnostic suppressed locally: %s',
                event.get('name') or event.get('note'),
            )
            return
        src_ip = event.get('src') or event.get('id.orig_h') or event.get('orig_h') or event.get('local_orig') or ''
        dst_ip = event.get('dst') or event.get('id.resp_h') or event.get('resp_h') or ''
        if src_ip in self._ignored_sensor_ips() or dst_ip in self._ignored_sensor_ips():
            logger.debug('Ignored public DNS resolver Zeek telemetry suppressed locally')
            return
        try:
            normalized = normalize_zeek(event, log_type, platform.node() or 'zeek')
            if not normalized.get('actionable') and not self._config.get('send_ids_routine_telemetry', False):
                return
            if self._send_normalized(normalized):
                return
        except ValueError as exc:
            logger.debug('Zeek normalization skipped: %s', exc)
            return
        note = event.get('note') or event.get('notice') or ''
        msg = event.get('msg') or event.get('message') or ''
        proto = event.get('proto') or event.get('service') or ''
        src_port = self._safe_int(event.get('id.orig_p') or event.get('orig_p'))
        dst_port = self._safe_int(event.get('id.resp_p') or event.get('resp_p'))
        service = event.get('service') or ''
        history = event.get('history') or ''
        conn_state = event.get('conn_state') or ''

        text = ' '.join(str(v) for v in (note, msg, proto, path)).lower()
        interesting_notice = bool(note or msg)
        interesting_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587, 993, 995, 1433, 3306, 3389, 4444, 5900, 8080}
        interesting_conn = (
            any(token in text for token in (
                'scan', 'ssh', 'dns', 'tunnel', 'notice', 'weird', 'intel', 'tor',
                'c2', 'beacon', 'malware', 'exploit',
            ))
            or str(service).lower() in {'dns', 'ssh', 'http', 'ssl', 'rdp', 'smb', 'ftp', 'smtp', 'irc'}
            or dst_port in interesting_ports
            or str(conn_state).upper() in {'S0', 'REJ', 'RSTO', 'RSTR'}
        )
        if not interesting_notice and not interesting_conn:
            return

        severity = 'medium' if interesting_notice else 'low'
        if any(token in text for token in ('critical', 'malware', 'exploit', 'c2', 'beacon', 'tunnel', 'tor')):
            severity = 'high'
        elif dst_port in {22, 23, 3389, 445, 4444, 5900} or str(conn_state).upper() in {'S0', 'REJ'}:
            severity = 'medium'

        rule = (note or os.path.basename(path).replace('.', '_') or 'ZEEK_NOTICE').replace('::', '_')
        if msg or note:
            description = msg or note
        else:
            svc = service or proto or 'unknown protocol'
            port_desc = f':{dst_port}' if dst_port else ''
            state_desc = f' state={conn_state}' if conn_state else ''
            description = f'Zeek connection monitor: {svc}{port_desc}{state_desc}'
        alert = {
            'module':      'IDS',
            'source_type': 'ids',
            'event_category': 'ids_alert',
            'rule_id':     f'ZEEK_{rule}',
            'category':    'network',
            'severity':    severity,
            'description': f'[Zeek] {description}',
            'raw_log':     json.dumps(event)[:2000],
            'src_ip':      src_ip,
            'dst_ip':      dst_ip,
            'src_port':    src_port,
            'dst_port':    dst_port,
            'protocol':    proto,
            'source':      'zeek',
            'type':        'IDS_ALERT',
            'attackType':  note or description,
            'signatureName': note or description,
            'action':      'Detected',
            'status':      'open',
            'sensor':      'Zeek',
            'timestamp':   event.get('ts') or event.get('timestamp'),
        }
        if self._mirror_to_agent_alerts():
            self._sender.enqueue(alert)
        self._send_to_ids_endpoint('zeek', {
            **event,
            'note': note or rule,
            'msg': description,
            'src': src_ip,
            'dst': dst_ip,
            'id.orig_h': src_ip,
            'id.resp_h': dst_ip,
            'id.orig_p': src_port,
            'id.resp_p': dst_port,
            'proto': proto,
            'severity': severity,
            'attack_type': note or description,
        })

    @staticmethod
    def _safe_int(value):
        try:
            if value in (None, '', '-'):
                return None
            return int(float(value))
        except Exception:
            return None

    def _send_to_ids_endpoint(self, source, event_data):
        """Send parsed alert to the backend IDS endpoint for dashboard display."""
        try:
            import requests
        except ImportError:
            return

        server_url = (self._config.get('server_url') or
                      'http://{}:{}'.format(
                          self._config.get('server_ip', 'localhost'),
                          self._config.get('server_port', 5000)))
        company_id = self._config.get('company_id', '')
        secret = self._config.get('integration_secret', '')

        if not company_id:
            return

        url = f'{server_url.rstrip("/")}/api/ids/{source}'
        payload = {**event_data, 'company_id': company_id}

        try:
            secure_request(self._config, 'POST',
                url,
                json=payload,
                headers={'x-integration-secret': secret},
                timeout=10,
            )
        except Exception as e:
            logger.debug('IDS endpoint send failed: %s', e)

    def _send_normalized(self, event):
        """Deliver one validated event with bounded exponential retry.

        The backend accepts batches; a one-item batch here keeps memory bounded
        while the existing parser threads remain backward compatible.
        """
        if self._is_duplicate_normalized_event(event):
            logger.debug(
                'Duplicate IDS sensor event suppressed locally: %s %s',
                event.get('source'), event.get('signature_id') or event.get('signature'),
            )
            # Treat a suppressed duplicate as delivered so the legacy endpoint
            # fallback does not upload the same alert through another route.
            return True
        try:
            import requests
        except ImportError:
            return
        company_id = self._config.get('company_id', '')
        if not company_id:
            return
        server_url = self._config.get('server_url') or 'http://{}:{}'.format(
            self._config.get('server_ip', 'localhost'), self._config.get('server_port', 5000))
        url = f'{server_url.rstrip("/")}/api/ids/events'
        payload = {'company_id': company_id, 'events': [event]}
        headers = {'x-integration-secret': self._config.get('integration_secret', '')}
        for attempt in range(3):
            try:
                response = secure_request(self._config, 'POST', url, json=payload, headers=headers, timeout=10)
                if response.status_code < 500:
                    response.raise_for_status()
                    self._remember_normalized_event(event)
                    return True
            except Exception as exc:
                if attempt == 2:
                    logger.warning('Normalized sensor delivery failed: %s', exc)
                    return False
            time.sleep(0.5 * (2 ** attempt))
        return False

    def _http_sender_loop(self):
        """Periodic health check for local Suricata and Zeek processes."""
        while self._running:
            time.sleep(300)  # Check every 5 minutes
            try:
                import psutil
                names = {
                    str(proc.info.get('name') or '').lower()
                    for proc in psutil.process_iter(['name'])
                }
                suricata_running = any('suricata' in name for name in names)
                zeek_running = any(name in {'zeek', 'zeek.exe'} for name in names)

                if not suricata_running and self._eve_path:
                    logger.warning('Suricata process not running — alerts may be stale')
                if not zeek_running and self._zeek_paths:
                    logger.warning('Zeek process not running — alerts may be stale')

            except Exception:
                pass  # pgrep not available on all systems
