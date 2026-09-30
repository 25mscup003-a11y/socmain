"""
VirusTotal Scanner — checks file hashes and IPs against VT API.
- Caches results to avoid duplicate API calls (rate limit: 4/min free tier)
- Only scans if VT API key is set in config
- Returns score 0–100 and engine list
"""

from typing import Optional, List, Dict, Any

import os
import json
import time
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta

from core.secure_file import load_json, save_json

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger('soc-agent.virustotal')

# ─── Cache file ──────────────────────────────────────────────────────────────
CACHE_FILE = Path(os.path.join(os.path.dirname(__file__), '..', 'config', 'vt_cache.json'))
CACHE_TTL_HOURS = 24       # cached result is valid for 24 hours
RATE_LIMIT_DELAY = 15      # seconds between VT calls (free tier: 4/min)


class VirusTotalScanner:
    def __init__(self, api_key: str, encryption_key: str = ''):
        self.api_key = api_key
        self._encryption_key = encryption_key
        self.enabled = bool(api_key) and HAS_REQUESTS
        self._cache: dict = {}
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._load_cache()
        if not HAS_REQUESTS:
            logger.warning('requests library not installed — VirusTotal disabled')
        elif not api_key:
            logger.info('No VT API key in config — VirusTotal disabled')
        else:
            logger.info('VirusTotal scanner enabled')

    # ─── Cache helpers ────────────────────────────────────────────────────────
    def _load_cache(self):
        try:
            if CACHE_FILE.exists():
                raw = load_json(
                    CACHE_FILE, self._encryption_key, 'virustotal-cache', {}
                )
                # Purge expired entries
                cutoff = datetime.utcnow().isoformat()
                self._cache = {k: v for k, v in raw.items() if v.get('expires', '') > cutoff}
        except Exception:
            self._cache = {}

    def _save_cache(self):
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            save_json(
                CACHE_FILE, self._cache, self._encryption_key, 'virustotal-cache'
            )
        except Exception as e:
            logger.debug(f'Cache save error: {e}')

    def _get_cached(self, key: str):
        with self._lock:
            entry = self._cache.get(key)
            if entry and entry.get('expires', '') > datetime.utcnow().isoformat():
                return entry.get('result')
        return None

    def _set_cached(self, key: str, result: dict):
        expires = (datetime.utcnow() + timedelta(hours=CACHE_TTL_HOURS)).isoformat()
        with self._lock:
            self._cache[key] = {'result': result, 'expires': expires}
        self._save_cache()

    # ─── Rate limiter ─────────────────────────────────────────────────────────
    def _wait_rate_limit(self):
        elapsed = time.time() - self._last_call
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_call = time.time()

    # ─── VT API calls ─────────────────────────────────────────────────────────
    def _vt_get(self, url: str) -> Optional[dict]:
        self._wait_rate_limit()
        try:
            resp = requests.get(
                url,
                headers={'x-apikey': self.api_key},
                timeout=10
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return None   # not found — clean
            else:
                logger.warning(f'VT API returned {resp.status_code}: {resp.text[:200]}')
                return None
        except requests.RequestException as e:
            logger.warning(f'VT request failed: {e}')
            return None

    def _parse_stats(self, data: dict) -> dict:
        """Convert VT response to our score format."""
        try:
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            score = round(((malicious + suspicious) / max(total, 1)) * 100, 1)
            engines = [
                name
                for name, result in data['data']['attributes'].get('last_analysis_results', {}).items()
                if result.get('category') in ('malicious', 'suspicious')
            ]
            return {
                'score': score,
                'malicious': malicious,
                'suspicious': suspicious,
                'total_engines': total,
                'engines_triggered': engines[:10],
                'detection_ratio': f'{malicious + suspicious}/{total}',
                'verdict': 'malicious' if malicious > 0 else ('suspicious' if suspicious > 0 else 'clean')
            }
        except (KeyError, TypeError):
            return {'score': 0, 'verdict': 'unknown', 'detection_ratio': '0/0', 'engines_triggered': []}

    # ─── Public API ───────────────────────────────────────────────────────────
    def scan_hash(self, file_hash: str, file_path: str = '') -> Optional[dict]:
        """Scan a file hash (MD5/SHA1/SHA256). Returns result dict or None."""
        if not self.enabled:
            return None
        key = f'hash:{file_hash}'
        cached = self._get_cached(key)
        if cached:
            logger.debug(f'VT cache hit for hash {file_hash[:16]}')
            return cached
        logger.info(f'VT scanning hash: {file_hash[:16]}… ({file_path})')
        data = self._vt_get(f'https://www.virustotal.com/api/v3/files/{file_hash}')
        if data is None:
            result = {'score': 0, 'verdict': 'not_found', 'detection_ratio': '0/0', 'engines_triggered': []}
        else:
            result = self._parse_stats(data)
        self._set_cached(key, result)
        return result

    def scan_ip(self, ip: str) -> Optional[dict]:
        """Scan an IP address. Returns result dict or None."""
        if not self.enabled:
            return None
        if ip.startswith(('127.', '10.', '192.168.', '172.')):
            return None  # skip private IPs
        key = f'ip:{ip}'
        cached = self._get_cached(key)
        if cached:
            return cached
        logger.info(f'VT scanning IP: {ip}')
        data = self._vt_get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')
        if data is None:
            result = {'score': 0, 'verdict': 'not_found', 'detection_ratio': '0/0', 'engines_triggered': []}
        else:
            result = self._parse_stats(data)
        self._set_cached(key, result)
        return result

    def cached_ip(self, ip: str) -> Optional[dict]:
        """Return cached IP reputation without performing network I/O."""
        if not ip:
            return None
        return self._get_cached(f'ip:{ip}')

    def scan_url(self, url: str) -> Optional[dict]:
        """Scan a URL. Returns result dict or None."""
        if not self.enabled:
            return None
        import base64
        key = f'url:{hashlib.md5(url.encode()).hexdigest()}'
        cached = self._get_cached(key)
        if cached:
            return cached
        logger.info(f'VT scanning URL: {url[:60]}')
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        data = self._vt_get(f'https://www.virustotal.com/api/v3/urls/{url_id}')
        if data is None:
            result = {'score': 0, 'verdict': 'not_found', 'detection_ratio': '0/0', 'engines_triggered': []}
        else:
            result = self._parse_stats(data)
        self._set_cached(key, result)
        return result

    def scan_file(self, file_path: str) -> Optional[dict]:
        """Compute SHA256 of file then scan hash."""
        if not self.enabled:
            return None
        try:
            sha256 = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()
            return self.scan_hash(sha256, file_path)
        except (OSError, IOError) as e:
            logger.debug(f'Cannot read file for VT scan: {e}')
            return None


# ─── Module-level singleton (lazy init) ──────────────────────────────────────
_scanner: Optional[VirusTotalScanner] = None

def get_scanner(api_key: str = '') -> VirusTotalScanner:
    global _scanner
    if _scanner is None:
        _scanner = VirusTotalScanner(api_key)
    return _scanner
