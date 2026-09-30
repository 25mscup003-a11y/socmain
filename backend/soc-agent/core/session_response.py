"""Allow-listed local session response actions for explicit company policies."""

import getpass
import logging
import os
import platform
import re
import subprocess

try:
    import pwd
except ImportError:  # Windows
    pwd = None

logger = logging.getLogger('soc-agent.session-response')
_SAFE_USER = re.compile(r'^[A-Za-z0-9_.@-]{1,128}$')


def logout_user(username=''):
    """Force the interactive OS session closed without invoking a shell."""
    system = platform.system()
    user = str(username or '').strip()
    if system == 'Windows':
        command = ['shutdown.exe', '/l', '/f']
    elif system == 'Linux':
        user = user or getpass.getuser()
        if user and not _SAFE_USER.fullmatch(user):
            raise ValueError('unsafe username refused')
        if not user or user in {'root', 'soc-agent'}:
            raise RuntimeError('refusing to terminate service/root session')
        command = ['loginctl', 'terminate-user', user]
    elif system == 'Darwin':
        if pwd is None:
            raise RuntimeError('macOS account lookup is unavailable')
        if user and not _SAFE_USER.fullmatch(user):
            raise ValueError('unsafe username refused')
        try:
            account = pwd.getpwnam(user) if user else pwd.getpwuid(os.stat('/dev/console').st_uid)
        except (KeyError, OSError) as exc:
            raise RuntimeError('active macOS console user could not be resolved') from exc
        user = account.pw_name
        uid = int(account.pw_uid)
        if uid == 0 or user in {'root', 'soc-agent', '_soc-agent'}:
            raise RuntimeError('refusing to terminate service/root session')
        command = ['/bin/launchctl', 'bootout', f'gui/{uid}']
    else:
        raise RuntimeError(f'system logout is not supported on {system}')

    result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or 'logout failed').strip()[:300])
    logger.warning('Explicit geography policy logged out OS user %s', user or 'interactive-user')
    return {'ok': True, 'action': 'SYSTEM_LOGOUT', 'user': user or 'interactive-user'}
