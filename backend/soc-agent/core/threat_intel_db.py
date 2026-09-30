"""
core/threat_intel_db.py
Threat Intelligence IP Database — local offline reputation database.

Sources supported:
  - Feodo Tracker (C2 botnet IPs)
  - Emerging Threats (known bad IPs)
  - AbuseIPDB bulk feed
  - Local custom IOC list

MITRE ATT&CK: T1071, T1566, T1105
"""

import os
import json
import time
import ipaddress
import logging
import requests
from typing import Dict, Optional, List, Set
from pathlib import Path

from .secure_file import load_json, save_json

logger = logging.getLogger(__name__)

# Free open-source threat intel feeds
FEEDS = {
    'feodo_tracker': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
    'emerging_threats': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    'tor_exit_nodes': 'https://check.torproject.org/torbulkexitlist',
}

DB_PATH = Path(__file__).parent.parent / 'data' / 'threat_intel.json'
REFRESH_INTERVAL = 3600 * 6  # refresh every 6 hours


class ThreatIntelDB:
    """Local IP reputation database built from open-source feeds."""

    def __init__(self, config=None):
        self.config   = config
        self._encryption_key = config.get('storage_encryption_key', '') if config else ''
        self._db: Dict[str, dict] = {}   # ip → {source, severity, category, ts}
        self._custom_iocs: Set[str] = set()
        self._last_refresh = 0
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._load_from_disk()

    # ─── Persistence ─────────────────────────────────────────────────────────
    def _load_from_disk(self):
        if DB_PATH.exists():
            try:
                data = load_json(
                    DB_PATH, self._encryption_key, 'threat-intel-cache', {}
                )
                self._db = data.get('ips', {})
                self._last_refresh = data.get('last_refresh', 0)
                logger.info(f'[ThreatIntelDB] Loaded {len(self._db)} IPs from disk')
            except Exception as e:
                logger.warning(f'[ThreatIntelDB] Load error: {e}')

    def _save_to_disk(self):
        try:
            save_json(
                DB_PATH,
                {'ips': self._db, 'last_refresh': self._last_refresh},
                self._encryption_key,
                'threat-intel-cache',
            )
        except Exception as e:
            logger.warning(f'[ThreatIntelDB] Save error: {e}')

    # ─── Feed Fetching ───────────────────────────────────────────────────────
    def _fetch_feodo(self):
        """Fetch Feodo Tracker C2 blocklist."""
        try:
            r = requests.get(FEEDS['feodo_tracker'], timeout=15)
            for line in r.text.splitlines():
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.split(',')
                if parts:
                    ip = parts[0].strip().strip('"')
                    self._add(ip, 'feodo_tracker', 'critical', 'c2_botnet')
        except Exception as e:
            logger.warning(f'[ThreatIntelDB] Feodo fetch error: {e}')

    def _fetch_emerging(self):
        """Fetch Emerging Threats compromised IPs."""
        try:
            r = requests.get(FEEDS['emerging_threats'], timeout=15)
            for line in r.text.splitlines():
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                self._add(line, 'emerging_threats', 'high', 'compromised_host')
        except Exception as e:
            logger.warning(f'[ThreatIntelDB] ET fetch error: {e}')

    def _fetch_tor(self):
        """Fetch Tor exit node list."""
        try:
            r = requests.get(FEEDS['tor_exit_nodes'], timeout=15)
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    self._add(line, 'tor_project', 'medium', 'tor_exit_node')
        except Exception as e:
            logger.warning(f'[ThreatIntelDB] Tor fetch error: {e}')

    def _add(self, ip: str, source: str, severity: str, category: str):
        """Add an IP to the database after validation."""
        try:
            ipaddress.ip_address(ip)
            self._db[ip] = {'source': source, 'severity': severity,
                            'category': category, 'ts': time.time()}
        except ValueError:
            pass

    # ─── Public API ──────────────────────────────────────────────────────────
    def refresh(self, force: bool = False):
        """Refresh all feeds if interval has passed."""
        if not force and time.time() - self._last_refresh < REFRESH_INTERVAL:
            return
        logger.info('[ThreatIntelDB] Refreshing feeds…')
        self._fetch_feodo()
        self._fetch_emerging()
        self._fetch_tor()
        self._last_refresh = time.time()
        self._save_to_disk()
        logger.info(f'[ThreatIntelDB] Database updated: {len(self._db)} IPs')

    def add_custom(self, ip: str, severity: str = 'high', category: str = 'custom_ioc'):
        """Add a custom IOC IP."""
        self._add(ip, 'custom', severity, category)
        self._custom_iocs.add(ip)
        self._save_to_disk()

    def remove_custom(self, ip: str):
        """Remove a custom IOC IP."""
        self._db.pop(ip, None)
        self._custom_iocs.discard(ip)
        self._save_to_disk()

    def lookup(self, ip: str) -> Optional[dict]:
        """Look up an IP. Returns reputation info or None if clean."""
        self.refresh()
        return self._db.get(ip)

    def bulk_lookup(self, ips: List[str]) -> Dict[str, dict]:
        """Bulk lookup — returns only malicious IPs."""
        self.refresh()
        return {ip: self._db[ip] for ip in ips if ip in self._db}

    def stats(self) -> dict:
        """Return database statistics."""
        categories: Dict[str, int] = {}
        for entry in self._db.values():
            cat = entry.get('category', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
        return {
            'total_ips':    len(self._db),
            'custom_iocs':  len(self._custom_iocs),
            'categories':   categories,
            'last_refresh': self._last_refresh,
            'feeds':        list(FEEDS.keys()),
        }

    def check_alert(self, alert: dict, sender=None) -> Optional[dict]:
        """Check alert srcip against DB and optionally fire an alert."""
        ip = alert.get('srcip', '')
        if not ip:
            return None
        hit = self.lookup(ip)
        if not hit:
            return None
        finding = {
            'ip':       ip,
            'source':   hit['source'],
            'severity': hit['severity'],
            'category': hit['category'],
            'description': f'Known malicious IP detected: {ip} [{hit["category"]} via {hit["source"]}]',
            'mitre': 'T1071',
        }
        if sender:
            try:
                sender.send_alert({
                    'ruleId':         'THREAT_INTEL_HIT',
                    'eventCategory':  'network',
                    'severity':       hit['severity'],
                    'description':    finding['description'],
                    'srcip':          ip,
                    'userAction':     'threat_intel_match',
                    'mitreTechnique': 'T1071',
                    'raw':            finding,
                })
            except Exception as e:
                logger.error(f'[ThreatIntelDB] Send error: {e}')
        return finding


# Singleton
_instance: Optional[ThreatIntelDB] = None

def get_db(config=None) -> ThreatIntelDB:
    global _instance
    if _instance is None:
        _instance = ThreatIntelDB(config)
    return _instance
