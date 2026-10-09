"""Keep provider credentials and automatic network decisions on the backend."""
from datetime import datetime, timezone

from .security import signed_headers
from .secure_transport import secure_request

PROVIDERS = {'ipinfo', 'abuseipdb', 'otx', 'virustotal'}
POLICY = 'two-of-four'
PROOF_VERSION = 2


def proof_valid(proof, ip, action, company_id=None):
    try:
        now = datetime.now(timezone.utc).timestamp()
        checked = datetime.fromisoformat(proof['checkedAt'].replace('Z', '+00:00')).timestamp()
        expires = datetime.fromisoformat(proof['expiresAt'].replace('Z', '+00:00')).timestamp()
        matched = proof.get('matchedProviders')
        return (proof.get('version') == PROOF_VERSION and proof.get('policy') == POLICY
                and proof.get('ip') == ip and proof.get('action') == action
                and (not company_id or str(proof.get('companyId')) == str(company_id))
                and isinstance(matched, list) and len(matched) >= 2
                and len(set(matched)) == len(matched) and set(matched).issubset(PROVIDERS)
                and checked <= now < expires and 0 < expires - checked <= 60.001)
    except (TypeError, KeyError, ValueError, AttributeError, OverflowError):
        return False


def verify_network_action(config, ip, action):
    """Require backend approval with two distinct matches; unavailable providers may abstain."""
    base = config.get('server_url') or 'http://{}:{}'.format(config.get('server_ip', 'localhost'), config.get('server_port', 5000))
    payload = {'agent_key': config.get('agent_key', ''), 'ip': ip, 'action': action}
    if not payload['agent_key']:
        return False
    try:
        response = secure_request(config, 'POST', base.rstrip('/') + '/api/agent/network-response/check',
                                  json=payload, headers=signed_headers(config, payload), timeout=45)
        if response.status_code != 200:
            return False
        result = response.json()
        return result.get('allowed') is True and proof_valid(result.get('verification'), ip, action, config.get('company_id'))
    except Exception:
        return False


def automatic_network_error(command, payload):
    if command not in ('block_ip', 'isolate', 'isolate_agent', 'quarantine_endpoint'):
        return None
    automatic = payload.get('automatic') is True or payload.get('threatVerification') is not None or payload.get('autoIsolation') is not None
    automatic = automatic or str(payload.get('reason', '')).lower().startswith(
        ('ips auto-block', 'ti auto-block', 'automatic ips isolation', 'severity auto-block'))
    if not automatic:
        return None
    ip = payload.get('ip') or payload.get('srcIp') or (payload.get('params') or {}).get('ip')
    action = 'block_ip' if command == 'block_ip' else 'isolate'
    if not proof_valid(payload.get('threatVerification'), ip, action):
        prefix = 'Threat verification deferred: ' if action == 'block_ip' else 'Automatic isolation deferred: '
        return prefix + 'missing, expired or mismatched two-of-four threat verification'
    return None
