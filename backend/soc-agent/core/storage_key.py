"""Retrieve the AES storage key from AJNAT server into process memory only."""

import base64

import requests

from .secure_transport import secure_request

from .security import signed_headers


def fetch_storage_key(config) -> str:
    server_url = str(config.get('server_url') or '').rstrip('/')
    agent_key = str(config.get('agent_key') or '')
    if not server_url or not agent_key:
        raise RuntimeError('server_url and agent_key are required for AES storage key')
    payload = {'agent_key': agent_key, 'purpose': 'durable-spool-v1'}
    response = secure_request(config, 'POST',
        f'{server_url}/api/agent/storage-key',
        json=payload,
        headers=signed_headers(config, payload),
        timeout=15,
    )
    response.raise_for_status()
    key = base64.b64decode(response.json().get('key', ''), validate=True)
    if len(key) != 32:
        raise RuntimeError('server returned an invalid AES-256 key')
    return base64.b64encode(key).decode('ascii')
