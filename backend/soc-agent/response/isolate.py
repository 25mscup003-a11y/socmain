"""Network isolation that preserves the SOC management connection.

Enforced on-host via core.fw_backend:
  Linux   → nftables (dedicated `soc_isolation` table, high-priority DROP)
  Windows → Windows Defender Firewall (netsh advfirewall)
  macOS   → PF (dedicated `com.soc.agent/isolation` anchor)
"""
import logging
import socket
from urllib.parse import urlparse

try:
    from core import fw_backend
except ImportError:                      # when imported as top-level package
    import fw_backend                     # type: ignore

logger = logging.getLogger('soc-agent.response.isolate')


def _management_target(management_url):
    parsed = urlparse(management_url or '')
    host = parsed.hostname
    if not host:
        return None, None
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        logger.error('Cannot resolve SOC management host %s; isolation aborted', host)
        return None, None
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    return ip, port


def isolate(management_url=None):
    management_ip, management_port = _management_target(management_url)
    if not management_ip or not management_port:
        raise RuntimeError('SOC management endpoint is required for safe isolation')

    logger.warning(
        'ISOLATION TRIGGERED; preserving SOC management %s:%s',
        management_ip, management_port,
    )
    fw_backend.isolate(management_ip, management_port)


def restore():
    logger.warning('REMOVING NETWORK ISOLATION')
    fw_backend.restore()
