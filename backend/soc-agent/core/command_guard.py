"""Short-lived verification for automatic IPS isolation only."""
import time
from datetime import datetime, timezone


def _timestamp(value):
    parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def automatic_isolation_error(command, payload, now=None):
    from .network_verification import automatic_network_error
    denied = automatic_network_error(command, payload)
    if denied:
        return denied
    if command != 'isolate':
        return None
    proof = payload.get('autoIsolation')
    if proof is None and not str(payload.get('reason', '')).lower().startswith('automatic ips isolation'):
        return None  # explicit manual command or reapply confirmed isolation
    prefix = 'Automatic isolation deferred: '
    now = time.time() if now is None else now
    try:
        verified = _timestamp(proof['verifiedAt'])
        expires = _timestamp(proof['expiresAt'])
        started = _timestamp(proof['incidentStartedAt'])
        if (proof.get('version') != 1 or not proof.get('threatAlertId')
                or not isinstance(proof.get('requireUnconfirmedBlock'), bool)
                or started >= verified or verified > now or expires <= verified
                or expires - verified > 30.001):
            return prefix + 'invalid fresh-threat verification'
        if now >= expires:
            return prefix + 'fresh-threat verification expired'
    except (TypeError, KeyError, ValueError, AttributeError, OverflowError):
        return prefix + 'missing or invalid fresh-threat verification'
    return None
