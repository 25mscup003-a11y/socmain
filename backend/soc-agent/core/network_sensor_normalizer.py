"""Strict Zeek/Suricata JSON normalization for the SOC ingestion API."""
import hashlib
import ipaddress
import json
from datetime import datetime, timezone

MAX_RAW_BYTES = 64 * 1024
ZEEK_TYPES = {
    'conn', 'dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp', 'smb_files', 'dhcp',
    'files', 'notice', 'weird', 'x509',
}
SURICATA_TYPES = {'alert', 'flow', 'dns', 'http', 'tls', 'stats', 'anomaly', 'fileinfo'}
SURICATA_INFORMATIONAL_NOISE_SIDS = {
    '2017926', '2017928', '2022082', '2054141', '2210044', '2210054',
    # Suricata decoder/stream diagnostics generated repeatedly by the local
    # NFQUEUE capture path. They remain available in eve.json, but are not
    # security detections and must not become SOC alerts.
    '2200003',  # SURICATA IPv4 truncated packet
    '2210045',  # SURICATA STREAM Packet with invalid ack
    '2210046',  # SURICATA STREAM SHUTDOWN RST invalid ack
}
SURICATA_DECODER_NOISE_SIDS = {'2200003', '2210045', '2210046'}
ZEEK_INFORMATIONAL_WEIRDS = {'truncated_tcp_payload'}


def is_suricata_informational_noise(event):
    """Recognize the SOC agent's own threat-intel and geo lookup traffic."""
    if not isinstance(event, dict) or event.get('event_type') != 'alert':
        return False
    alert = event.get('alert') if isinstance(event.get('alert'), dict) else {}
    signature_id = str(alert.get('signature_id') or '')
    signature = str(alert.get('signature') or '').lower()
    dns = event.get('dns') if isinstance(event.get('dns'), dict) else {}
    queries = dns.get('queries') if isinstance(dns.get('queries'), list) else []
    query = str(queries[0].get('rrname', '') if queries and isinstance(queries[0], dict) else '').lower()
    tls = event.get('tls') if isinstance(event.get('tls'), dict) else {}
    sni = str(tls.get('sni') or '').lower()
    observed_name = query.rstrip('.') or sni.rstrip('.')
    is_self_lookup = (
        'check.torproject.org' in signature
        or observed_name == 'check.torproject.org'
        or 'ip-api.com' in signature
        or observed_name == 'ip-api.com'
    )
    return signature_id in {'2210044', '2210054'} | SURICATA_DECODER_NOISE_SIDS or (
        signature_id in SURICATA_INFORMATIONAL_NOISE_SIDS and is_self_lookup
    )


def is_zeek_informational_noise(event, log_type=''):
    """Keep known packet-capture truncation diagnostics in local Zeek logs.

    This exact weird is emitted when the capture path supplies less TCP data
    than Zeek expected.  Notices and all other weird types remain actionable.
    """
    if not isinstance(event, dict):
        return False
    normalized_type = _text(log_type, 32).lower().replace('.log', '')
    if normalized_type != 'weird':
        return False
    name = _text(event.get('name') or event.get('note'), 256).lower()
    return name in ZEEK_INFORMATIONAL_WEIRDS


def _text(value, limit=2048):
    if value is None:
        return ''
    return str(value).replace('\x00', '')[:limit]


def _port(value):
    try:
        value = int(value)
        return value if 0 <= value <= 65535 else None
    except (TypeError, ValueError):
        return None


def _ip(value):
    value = _text(value, 64)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ''


def _timestamp(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    value = _text(value, 64)
    if value:
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()


def _raw(event):
    encoded = json.dumps(event, separators=(',', ':'), ensure_ascii=False, default=str)
    return encoded.encode('utf-8')[:MAX_RAW_BYTES].decode('utf-8', errors='ignore')


def _event_id(source, log_type, event, timestamp):
    native = event.get('event_id') or event.get('community_id') or event.get('uid') or event.get('flow_id')
    material = '|'.join(map(str, (source, log_type, native or '', timestamp,
        event.get('src_ip') or event.get('id.orig_h') or '',
        event.get('dest_ip') or event.get('id.resp_h') or '',
        event.get('alert', {}).get('signature_id') if isinstance(event.get('alert'), dict) else '')))
    return f'{source}:{hashlib.sha256(material.encode()).hexdigest()}'


def normalize_suricata(event, sensor='suricata'):
    if not isinstance(event, dict):
        raise ValueError('event must be a JSON object')
    log_type = _text(event.get('event_type'), 32).lower()
    if log_type not in SURICATA_TYPES:
        raise ValueError(f'unsupported Suricata event_type: {log_type}')
    alert = event.get('alert') if isinstance(event.get('alert'), dict) else {}
    severity = {1: 'critical', 2: 'high', 3: 'medium'}.get(alert.get('severity'), 'low')
    action = _text(alert.get('action') or 'observed', 32).lower()
    ts = _timestamp(event.get('timestamp'))
    signature = _text(alert.get('signature') or event.get('anomaly', {}).get('event') or log_type)
    hostname = _text((event.get('dns') or {}).get('rrname') or (event.get('http') or {}).get('hostname') or (event.get('tls') or {}).get('sni'), 253)
    result = {'event_id': _event_id('suricata', log_type, event, ts), 'timestamp': ts,
        'source': 'suricata', 'sensor': _text(sensor, 128), 'log_type': log_type,
        'severity': severity, 'category': _text(alert.get('category') or log_type, 128),
        'src_ip': _ip(event.get('src_ip')), 'src_port': _port(event.get('src_port')),
        'dest_ip': _ip(event.get('dest_ip')), 'dest_port': _port(event.get('dest_port')),
        'protocol': _text(event.get('proto'), 16).lower(), 'action': action,
        'signature': signature, 'signature_id': _text(alert.get('signature_id'), 64),
        'community_id': _text(event.get('community_id'), 128), 'hostname': hostname,
        'actionable': log_type in {'alert', 'anomaly'} or action in {'blocked', 'drop', 'dropped'},
        'raw_event': _raw(event)}
    return result


def normalize_zeek(event, log_type, sensor='zeek'):
    if not isinstance(event, dict):
        raise ValueError('event must be a JSON object')
    log_type = _text(log_type, 32).lower().replace('.log', '')
    if log_type not in ZEEK_TYPES:
        raise ValueError(f'unsupported Zeek log type: {log_type}')
    ts = _timestamp(event.get('ts') or event.get('timestamp'))
    signature = _text(event.get('note') or event.get('name') or event.get('msg') or log_type)
    hostname = _text(event.get('query') or event.get('host') or event.get('server_name') or event.get('domain'), 253)
    severity = 'high' if log_type == 'notice' else ('medium' if log_type == 'weird' else 'low')
    return {'event_id': _event_id('zeek', log_type, event, ts), 'timestamp': ts,
        'source': 'zeek', 'sensor': _text(sensor, 128), 'log_type': log_type,
        'severity': severity, 'category': log_type,
        'src_ip': _ip(event.get('src') or event.get('id.orig_h')),
        'src_port': _port(event.get('id.orig_p')), 'dest_ip': _ip(event.get('dst') or event.get('id.resp_h')),
        'dest_port': _port(event.get('id.resp_p')), 'protocol': _text(event.get('proto') or event.get('service'), 16).lower(),
        'action': 'observed', 'signature': signature, 'signature_id': _text(event.get('note'), 128),
        'community_id': _text(event.get('community_id'), 128), 'hostname': hostname,
        'actionable': log_type in {'notice', 'weird'}, 'raw_event': _raw(event)}
