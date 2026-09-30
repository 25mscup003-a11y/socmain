"""
Browser activity collector for safe login/signup/MFA portal visibility.

This collector reads browser history databases in read-only copied form and emits
authentication portal events. It never reads cookies, saved passwords, form
values, or page contents.
"""

import logging
import os
import platform
import shutil
import socket
import sqlite3
import tempfile
import threading
import time
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger('soc-agent.collector.browser_activity')
SYSTEM = platform.system()

POLL_INTERVAL = 30
LOOKBACK_SECONDS = 24 * 60 * 60
PENDING_AUTH_TTL_SECONDS = 30 * 60

LOGIN_PATH_HINTS = (
    'login', 'signin', 'sign-in', 'sign_in', 'session', 'sessions',
    'authenticate', 'authentication', 'oauth', 'sso', 'saml', 'authorize',
    'auth/login', 'api/login', 'api/auth', 'api/session', 'token',
)
SIGNUP_PATH_HINTS = (
    'signup', 'sign-up', 'sign_up', 'register', 'registration', 'create-account',
    'create_account', 'join', 'new-account', 'new_account', 'account/create',
    'users/sign_up', 'users/sign-up',
)
MFA_PATH_HINTS = (
    'mfa', '2fa', 'two-factor', 'two_factor', 'totp', 'otp', 'duo',
    'challenge', 'verify', 'verification', 'webauthn', 'u2f',
)
AUTH_FAILURE_HINTS = (
    'invalid', 'incorrect', 'wrong password', 'bad password', 'failed',
    'failure', 'denied', 'rejected', 'blocked', 'locked', 'expired',
    'error=', 'access_denied', 'login_error', 'signin_error',
    'authentication failed', 'verification failed', 'try again',
)
SESSION_SUCCESS_HINTS = (
    'dashboard', 'inbox', 'settings', 'profile', 'account', 'accounts',
    'programs', 'reports', 'activity', 'notifications', 'organizations',
    'opportunities', 'home', 'me', 'user', 'users', 'security-checkup',
    'mail', 'console', 'portal', 'workspace', 'admin', 'billing',
    'authenticated', 'welcome',
)
STATIC_RESOURCE_EXTENSIONS = (
    '.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.webp', '.ico', '.woff', '.woff2', '.ttf', '.mp4', '.webm', '.json',
)
KNOWN_AUTH_DOMAINS = {
    'hackerone.com': 'HackerOne Login',
    'duosecurity.com': 'Duo MFA',
    'duo.com': 'Duo MFA',
    'okta.com': 'Okta MFA/SSO',
    'login.microsoftonline.com': 'Microsoft Entra MFA',
    'accounts.google.com': 'Google MFA',
    'myaccount.google.com': 'Google MFA',
    'mail.google.com': 'Google MFA',
    'auth0.com': 'Auth0 MFA/SSO',
    'cloudflareaccess.com': 'Cloudflare Access',
    'onelogin.com': 'OneLogin MFA/SSO',
    'pingone.com': 'Ping Identity MFA/SSO',
    'proton.me': 'Proton Account MFA',
    'account.proton.me': 'Proton Account MFA',
}

AUTH_PORTAL_DOMAINS = (
    'duosecurity.com',
    'duo.com',
    'okta.com',
    'login.microsoftonline.com',
    'accounts.google.com',
    'auth0.com',
    'cloudflareaccess.com',
    'onelogin.com',
    'pingone.com',
    'account.proton.me',
)


def _utc_now():
    return datetime.now(timezone.utc)


def _chrome_time_to_unix(value):
    try:
        value = int(value or 0)
        if value <= 0:
            return 0
        # Chromium stores microseconds since 1601-01-01 UTC.
        return (value / 1000000) - 11644473600
    except Exception:
        return 0


def _firefox_time_to_unix(value):
    try:
        value = int(value or 0)
        if value <= 0:
            return 0
        return value / 1000000
    except Exception:
        return 0


def _domain_provider(hostname):
    host = (hostname or '').lower().strip('.')
    for suffix, provider in KNOWN_AUTH_DOMAINS.items():
        if host == suffix or host.endswith(f'.{suffix}'):
            return provider
    return 'Web Login'


def _site_key(hostname):
    host = (hostname or '').lower().strip('.')
    if host.startswith('www.'):
        host = host[4:]
    if host in ('accounts.google.com', 'myaccount.google.com', 'mail.google.com') or host.endswith('.google.com'):
        return 'google.com'
    if host.endswith('.hackerone.com') or host == 'hackerone.com':
        return 'hackerone.com'
    if host.endswith('.proton.me') or host == 'proton.me':
        return 'proton.me'
    parts = [part for part in host.split('.') if part]
    if len(parts) >= 3 and parts[-2] in ('co', 'com', 'net', 'org', 'gov', 'ac'):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def _url_text(url, title=''):
    try:
        parsed = urlparse(url)
    except Exception:
        return ''
    return f'{parsed.hostname or ""} {parsed.path or ""} {parsed.query or ""} {title or ""}'.lower()


def _has_auth_hint(text):
    return any(h in text for h in LOGIN_PATH_HINTS + SIGNUP_PATH_HINTS + MFA_PATH_HINTS)


def _has_mfa_hint(text):
    return any(h in text for h in MFA_PATH_HINTS)


def _is_static_resource(url):
    try:
        path = (urlparse(url).path or '').lower()
    except Exception:
        return True
    return any(path.endswith(ext) for ext in STATIC_RESOURCE_EXTENSIONS)


def _is_auth_related_url(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    host = (parsed.hostname or '').lower()
    path = f'{parsed.path or ""} {parsed.query or ""}'.lower()
    if any(host == suffix or host.endswith(f'.{suffix}') for suffix in AUTH_PORTAL_DOMAINS):
        return True
    return _has_auth_hint(path)


def _signal_for_url(url, title=''):
    text = f'{url} {title}'.lower()
    if any(h in text for h in MFA_PATH_HINTS):
        return {
            'status': 'Challenge observed',
            'action': 'mfa_portal_activity',
            'method': 'MFA',
            'rule_id': 'AUTH_WEB_LOGIN_PORTAL',
            'description': 'mfa challenge observed',
        }
    if any(h in text for h in SIGNUP_PATH_HINTS):
        return {
            'status': 'Signup portal observed',
            'action': 'signup_portal_activity',
            'method': 'Signup',
            'rule_id': 'AUTH_WEB_SIGNUP_PORTAL',
            'description': 'signup portal observed',
        }
    if any(h in text for h in LOGIN_PATH_HINTS):
        return {
            'status': 'Login portal observed',
            'action': 'web_login_portal',
            'method': 'Web Login',
            'rule_id': 'AUTH_WEB_LOGIN_PORTAL',
            'description': 'login portal observed',
        }
    return {
        'status': 'Portal observed',
        'action': 'auth_portal_activity',
        'method': 'Authentication Portal',
        'rule_id': 'AUTH_WEB_LOGIN_PORTAL',
        'description': 'authentication portal observed',
    }


def _is_login_failure_url(url, title=''):
    text = _url_text(url, title)
    return _has_auth_hint(text) and any(h in text for h in AUTH_FAILURE_HINTS)


def _is_session_success_url(url, title='', has_pending_auth=False):
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    host = (parsed.hostname or '').lower()
    if not host or '.' not in host or _is_static_resource(url):
        return False
    text = _url_text(url, title)
    if _has_auth_hint(text) or any(h in text for h in AUTH_FAILURE_HINTS):
        return False
    if any(word in text for word in SESSION_SUCCESS_HINTS):
        return True
    # After a login/signup/MFA page, many sites redirect to a clean root page.
    return has_pending_auth and (parsed.path in ('', '/') or bool(parsed.path))


def _profile_user(path):
    try:
        parts = Path(path).parts
        if SYSTEM == 'Linux':
            if len(parts) > 2 and parts[1] == 'home':
                return parts[2]
            if len(parts) > 1 and parts[1] == 'root':
                return 'root'
        if SYSTEM == 'Darwin':
            if len(parts) > 2 and parts[1] == 'Users':
                return parts[2]
        if SYSTEM == 'Windows':
            lowered = [p.lower() for p in parts]
            if 'users' in lowered:
                idx = lowered.index('users')
                if len(parts) > idx + 1:
                    return parts[idx + 1]
    except Exception:
        pass
    try:
        import psutil
        users = [u.name for u in psutil.users() if getattr(u, 'name', '')]
        for name in users:
            if name and name not in ('root', 'SYSTEM', 'LocalSystem'):
                return name
        if users:
            return users[0]
    except Exception:
        pass
    return os.environ.get('SUDO_USER') or os.environ.get('USER') or os.environ.get('USERNAME') or ''


def _browser_identity(path):
    value = str(path or '').lower()
    if 'brave' in value:
        return 'Brave', 'brave'
    if 'opera' in value:
        return 'Opera', 'opera'
    if 'edge' in value:
        return 'Edge', 'msedge'
    if 'firefox' in value or 'places.sqlite' in value:
        return 'Firefox', 'firefox'
    if 'chromium' in value:
        return 'Chromium', 'chromium'
    return 'Chrome', 'chrome'


def _safe_history_url(value):
    """Retain useful navigation evidence without query tokens/fragments."""
    try:
        parsed = urlparse(value or '')
        if not parsed.scheme or not parsed.netloc:
            return ''
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or '/', '', '', ''))[:2048]
    except Exception:
        return ''


def _local_source_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.connect(('8.8.8.8', 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return ''


def _user_home_roots(system_name=None):
    """Return real user profiles even when the agent runs as a system service."""
    system_name = system_name or SYSTEM
    roots = []
    if system_name == 'Linux':
        base = Path('/home')
        try:
            roots.extend(path for path in base.iterdir() if path.is_dir())
        except (OSError, PermissionError):
            pass
        if Path('/root').exists():
            roots.append(Path('/root'))
    elif system_name == 'Darwin':
        base = Path('/Users')
        try:
            roots.extend(path for path in base.iterdir() if path.is_dir())
        except (OSError, PermissionError):
            pass
        roots.append(Path.home())
    elif system_name == 'Windows':
        drive = os.environ.get('SystemDrive', 'C:').rstrip('\\/')
        base = Path(f'{drive}\\Users')
        try:
            roots.extend(path for path in base.iterdir() if path.is_dir())
        except (OSError, PermissionError):
            pass
        # Also retain the current profile for non-service/manual agent runs.
        for key in ('USERPROFILE',):
            if os.environ.get(key):
                roots.append(Path(os.environ[key]))

    excluded = {'all users', 'default', 'default user', 'public', 'defaultaccount', 'wdagutilityaccount'}
    unique = []
    seen = set()
    for root in roots:
        key = str(root).lower().rstrip('\\/')
        if not key or root.name.lower() in excluded or key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def _history_paths(home_roots=None, system_name=None):
    paths = []
    system_name = system_name or SYSTEM
    home_roots = list(home_roots) if home_roots is not None else _user_home_roots(system_name)
    if system_name == 'Linux':
        for home in home_roots:
            for rel in (
                '.config/google-chrome',
                '.config/chromium',
                '.config/microsoft-edge',
                '.config/BraveSoftware/Brave-Browser',
            ):
                base = home / rel
                if base.exists():
                    paths.extend(base.glob('*/History'))
            ff_base = home / '.mozilla/firefox'
            if ff_base.exists():
                paths.extend(ff_base.glob('*.default*/places.sqlite'))
            for opera_rel in ('.config/opera/History', '.config/opera-beta/History'):
                paths.append(home / opera_rel)
    elif system_name == 'Darwin':
        for home in home_roots:
            for rel in (
                'Library/Application Support/Google/Chrome',
                'Library/Application Support/Chromium',
                'Library/Application Support/BraveSoftware/Brave-Browser',
                'Library/Application Support/Microsoft Edge',
            ):
                base = home / rel
                if base.exists():
                    paths.extend(base.glob('*/History'))
            ff_base = home / 'Library/Application Support/Firefox/Profiles'
            if ff_base.exists():
                paths.extend(ff_base.glob('*.default*/places.sqlite'))
            paths.append(home / 'Library/Application Support/com.operasoftware.Opera/History')
    elif system_name == 'Windows':
        for home in home_roots:
            local = home / 'AppData/Local'
            roaming = home / 'AppData/Roaming'
            for rel in (
                'Google/Chrome/User Data',
                'Chromium/User Data',
                'Microsoft/Edge/User Data',
                'BraveSoftware/Brave-Browser/User Data',
            ):
                root = local / rel
                if root.exists():
                    paths.extend(root.glob('*/History'))
            ff_base = roaming / 'Mozilla/Firefox/Profiles'
            if ff_base.exists():
                paths.extend(ff_base.glob('*.default*/places.sqlite'))
            paths.append(roaming / 'Opera Software/Opera Stable/History')

    unique = []
    seen = set()
    for path in paths:
        key = str(path).lower()
        if key in seen or not path.exists() or not path.is_file():
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _copy_db(path):
    tmp_dir = ''
    try:
        # Chromium keeps recent navigations in History-wal while it is open.
        # Copy the database and its sidecars into one private directory so the
        # snapshot includes a Gmail tab opened moments ago.
        tmp_dir = tempfile.mkdtemp(prefix='soc-browser-history-')
        tmp = str(Path(tmp_dir) / 'history.sqlite')
        shutil.copyfile(path, tmp)
        for suffix in ('-wal', '-shm'):
            source = f'{path}{suffix}'
            if Path(source).exists():
                shutil.copyfile(source, f'{tmp}{suffix}')
        return tmp
    except Exception as exc:
        logger.debug('Browser history copy failed for %s: %s', path, exc)
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return ''


def _remove_db_copy(path):
    if path:
        shutil.rmtree(str(Path(path).parent), ignore_errors=True)


def _read_chromium(path, since_unix):
    tmp = _copy_db(path)
    if not tmp:
        return []
    try:
        since_chrome = int((since_unix + 11644473600) * 1000000)
        with closing(sqlite3.connect(tmp)) as conn:
            rows = conn.execute(
                'SELECT url, title, last_visit_time FROM urls '
                'WHERE last_visit_time >= ? ORDER BY last_visit_time DESC LIMIT 1000',
                (since_chrome,),
            ).fetchall()
        return [
            {'url': url, 'title': title or '', 'visited': _chrome_time_to_unix(last_visit)}
            for url, title, last_visit in rows
        ]
    except Exception as exc:
        logger.debug('Chromium history read failed for %s: %s', path, exc)
        return []
    finally:
        _remove_db_copy(tmp)


def _read_firefox(path, since_unix):
    tmp = _copy_db(path)
    if not tmp:
        return []
    try:
        since_firefox = int(since_unix * 1000000)
        with closing(sqlite3.connect(tmp)) as conn:
            rows = conn.execute(
                'SELECT url, title, last_visit_date FROM moz_places '
                'WHERE last_visit_date >= ? ORDER BY last_visit_date DESC LIMIT 1000',
                (since_firefox,),
            ).fetchall()
        return [
            {'url': url, 'title': title or '', 'visited': _firefox_time_to_unix(last_visit)}
            for url, title, last_visit in rows
        ]
    except Exception as exc:
        logger.debug('Firefox history read failed for %s: %s', path, exc)
        return []
    finally:
        _remove_db_copy(tmp)


class BrowserActivityCollector:
    def __init__(self, sender):
        self._sender = sender
        self._seen = set()
        self._web_seen = set()
        self._pending_auth = {}
        self._thread = threading.Thread(target=self._loop, daemon=True, name='browser-activity-monitor')

    def start(self):
        self._thread.start()

    def _pending_key(self, source_path, hostname):
        return f'{source_path}|{_site_key(hostname)}'

    def _remember_auth_attempt(self, source_path, domain, signal, visited, username, source_ip, provider):
        key = self._pending_key(source_path, domain)
        existing = self._pending_auth.get(key, {})
        action = signal.get('action') or ''
        self._pending_auth[key] = {
            'domain': domain,
            'provider': provider,
            'username': username,
            'source_ip': source_ip,
            'started': existing.get('started') or visited,
            'last_seen': visited,
            'mfa_seen': bool(existing.get('mfa_seen')) or action == 'mfa_portal_activity',
            'signup_seen': bool(existing.get('signup_seen')) or action == 'signup_portal_activity',
        }

    def _prune_pending_auth(self):
        cutoff = time.time() - PENDING_AUTH_TTL_SECONDS
        self._pending_auth = {
            key: value
            for key, value in self._pending_auth.items()
            if value.get('last_seen', 0) >= cutoff
        }

    def _emit(self, item, source_path):
        url = item.get('url') or ''
        if not _is_auth_related_url(url):
            return
        parsed = urlparse(url)
        domain = (parsed.hostname or '').lower()
        visited = item.get('visited') or time.time()
        key = f'{domain}|{parsed.path}|{int(visited)}'
        if key in self._seen:
            return
        self._seen.add(key)
        if len(self._seen) > 2000:
            self._seen = set(list(self._seen)[-1000:])

        signal = _signal_for_url(url, item.get('title') or '')
        status = signal['status']
        action = signal['action']
        is_mfa = action == 'mfa_portal_activity'
        is_signup = action == 'signup_portal_activity'
        provider = _domain_provider(domain)
        timestamp = datetime.fromtimestamp(visited, timezone.utc).isoformat()
        username = _profile_user(source_path)
        browser, process_name = _browser_identity(source_path)
        safe_url = _safe_history_url(url)
        source_ip = _local_source_ip()
        self._remember_auth_attempt(source_path, domain, signal, visited, username, source_ip, provider)
        self._sender.enqueue({
            'rule_id': signal['rule_id'],
            'capabilityId': 4,
            'capabilityIds': [4, 9],
            'category': 'edr',
            'severity': 'low',
            'description': f'{provider} {signal["description"]}',
            'source': 'browser-history',
            'username': username,
            'src_ip': source_ip,
            'domain': domain,
            'url': safe_url,
            'http_method': 'GET',
            'browser': browser,
            'process_name': process_name,
            'query': domain,
            'dnsQuery': domain,
            'user_action': action,
            'raw_log': f'AUTH:WEB_AUTH_PORTAL domain={domain} action={action} status={status} title={item.get("title") or ""}',
            'raw': {
                'auth_method': signal['method'],
                'auth_action': action,
                'log_type': 'authentication',
                'mfa_portal_activity': is_mfa,
                'signup_portal_activity': is_signup,
                'mfa_result_known': False,
                'mfa_status': status,
                'username': username,
                'src_ip': source_ip,
                'source_ip': source_ip,
                'domain': domain,
                'url': safe_url,
                'http_method': 'GET',
                'browser': browser,
                'process_name': process_name,
                'website': domain,
                'providers': [provider],
                'browser_history_path': str(source_path),
                'note': 'Browser history URL signal only; no passwords, cookies, form fields, account names entered in websites, or MFA result were read.',
            },
            'timestamp': timestamp,
        })

    def _emit_login_result(self, item, source_path):
        url = item.get('url') or ''
        parsed = urlparse(url)
        domain = (parsed.hostname or '').lower()
        if not domain:
            return
        pending_key = self._pending_key(source_path, domain)
        pending = self._pending_auth.get(pending_key)
        title = item.get('title') or ''
        is_failure = _is_login_failure_url(url, title)
        is_success = _is_session_success_url(url, title, has_pending_auth=bool(pending))
        if not is_failure and not is_success:
            return
        visited = item.get('visited') or time.time()
        result = 'Fail' if is_failure else 'Pass'
        key = f'login-result|{_site_key(domain)}|{result}|{parsed.path}|{int(visited)}'
        if key in self._seen:
            return
        self._seen.add(key)
        provider = (pending or {}).get('provider') or _domain_provider(domain)
        timestamp = datetime.fromtimestamp(visited, timezone.utc).isoformat()
        username = (pending or {}).get('username') or _profile_user(source_path)
        browser, process_name = _browser_identity(source_path)
        safe_url = _safe_history_url(url)
        source_ip = (pending or {}).get('source_ip') or _local_source_ip()
        text = _url_text(url, title)
        mfa_was_seen = bool((pending or {}).get('mfa_seen')) or _has_mfa_hint(text)
        mfa_result = result if mfa_was_seen else 'Not Captured'
        action = 'web_login_result' if not (pending or {}).get('signup_seen') else 'web_signup_result'
        self._sender.enqueue({
            'rule_id': 'AUTH_WEB_LOGIN_RESULT',
            'capabilityId': 4,
            'capabilityIds': [4, 9],
            'category': 'edr',
            'severity': 'low',
            'description': f'{provider} {"authentication failed" if result == "Fail" else "authenticated session page observed"}',
            'source': 'browser-history',
            'username': username,
            'src_ip': source_ip,
            'domain': domain,
            'url': safe_url,
            'http_method': 'GET',
            'browser': browser,
            'process_name': process_name,
            'query': domain,
            'dnsQuery': domain,
            'user_action': action,
            'raw_log': f'AUTH:WEB_LOGIN_RESULT domain={domain} login_result={result} mfa_result={mfa_result} title={title}',
            'raw': {
                'auth_method': 'Web Login',
                'auth_action': action,
                'log_type': 'authentication',
                'login_result': result,
                'auth_result': 'success' if result == 'Pass' else 'failed',
                'mfa_result': mfa_result,
                'mfa_result_known': mfa_was_seen,
                'username': username,
                'src_ip': source_ip,
                'source_ip': source_ip,
                'domain': domain,
                'url': safe_url,
                'http_method': 'GET',
                'browser': browser,
                'process_name': process_name,
                'website': domain,
                'site_key': _site_key(domain),
                'providers': [provider],
                'browser_history_path': str(source_path),
                'note': 'Browser history URL transition signal only; no passwords, cookies, form fields, or page contents were read.',
            },
            'timestamp': timestamp,
        })
        if result == 'Pass' and pending_key in self._pending_auth:
            self._pending_auth.pop(pending_key, None)

    def _scan_once(self):
        since = time.time() - LOOKBACK_SECONDS
        activity = []
        for path in _history_paths():
            name = path.name.lower()
            rows = _read_firefox(path, since) if name == 'places.sqlite' else _read_chromium(path, since)
            for item in sorted(rows, key=lambda row: row.get('visited') or 0):
                url = item.get('url') or ''
                parsed = urlparse(url)
                domain = (parsed.hostname or '').lower()
                visited = item.get('visited') or 0
                activity_key = f'{path}|{url}|{int(visited)}'
                if domain and not _is_static_resource(url) and activity_key not in self._web_seen:
                    self._web_seen.add(activity_key)
                    browser, process_name = _browser_identity(path)
                    activity.append({
                        'domain': domain, 'url': _safe_history_url(url), 'browser': browser,
                        'process_name': process_name, 'username': _profile_user(path),
                        'visited': visited,
                    })
                self._emit(item, path)
                self._emit_login_result(item, path)
        if len(self._web_seen) > 10000:
            self._web_seen = set(list(self._web_seen)[-5000:])
        if activity:
            domains = Counter(row['domain'] for row in activity)
            browsers = Counter(row['browser'] for row in activity)
            latest = max(activity, key=lambda row: row['visited'])
            self._sender.enqueue({
                'rule_id': 'WEB_BROWSER_ACTIVITY_SUMMARY',
                'capabilityId': 9,
                'capabilityIds': [9],
                'category': 'network',
                'severity': 'low',
                'source': 'browser-history',
                'description': f'Browser activity observed: {len(activity)} navigation(s) across {len(domains)} domain(s)',
                'eventType': 'Browser Activity Summary',
                'protocol': 'https' if latest['url'].startswith('https://') else 'http',
                'domain': latest['domain'],
                'url': latest['url'],
                'http_method': 'GET',
                'browser': latest['browser'],
                'process_name': latest['process_name'],
                'username': latest['username'],
                'src_ip': _local_source_ip(),
                'raw': {
                    'web_request_count': len(activity),
                    'top_domains': domains.most_common(20),
                    'browser_counts': dict(browsers),
                    'recent_urls': [row['url'] for row in sorted(activity, key=lambda row: row['visited'], reverse=True)[:20]],
                    'collection_scope': 'browser history metadata; query strings, cookies, credentials and page content excluded',
                },
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
        self._prune_pending_auth()

    def _loop(self):
        logger.info('Browser login/signup/MFA portal monitor started')
        while True:
            try:
                self._scan_once()
            except Exception as exc:
                logger.debug('Browser activity scan failed: %s', exc)
            time.sleep(POLL_INTERVAL)
