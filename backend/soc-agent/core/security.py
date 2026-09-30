"""
Agent request signing helpers.
Uses per-system agent_key as the HMAC secret with timestamp + nonce to prevent
tampering and replay of heartbeat/alert requests.
"""

import json
import hmac
import time
import uuid
import hashlib
import math


def _normalize_for_javascript(value):
    """Match JSON.stringify's finite-number representation used by the API."""
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, dict):
        return {key: _normalize_for_javascript(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_for_javascript(item) for item in value]
    return value


def canonicalize(value):
    return json.dumps(_normalize_for_javascript(value), sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def signed_headers(config, payload):
    agent_key = config.get('agent_key', '') or ''
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    message = f'{timestamp}.{nonce}.{canonicalize(payload)}'.encode('utf-8')
    signature = hmac.new(agent_key.encode('utf-8'), message, hashlib.sha256).hexdigest()
    headers = {
        'Content-Type': 'application/json',
        'x-agent-timestamp': timestamp,
        'x-agent-nonce': nonce,
        'x-agent-signature': signature,
    }
    integration_secret = config.get('integration_secret', '') or ''
    if integration_secret:
        headers['x-integration-secret'] = integration_secret
    return headers
