"""
core/geo_enrichment.py
Geolocation Anomaly Detection — CAP #23
Enriches alert source IPs and raises account/location anomalies.

MITRE ATT&CK: T1078, T1133
"""

import time
import logging
import requests
import ipaddress
import math
from datetime import datetime, timezone
from typing import Dict, Optional, List, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

GEO_API = 'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,proxy,hosting'
CACHE: Dict[str, dict] = {}
CACHE_TTL = 3600  # 1 hour
_cache_time: Dict[str, float] = {}

HIGH_RISK_COUNTRIES = set()  # organization policy only; never infer geopolitical risk
IMPOSSIBLE_TRAVEL_WINDOW = 3600
DEFAULT_MAX_TRAVEL_SPEED_KMH = 900
DEFAULT_MIN_TRAVEL_DISTANCE_KM = 500
MULTI_GEO_WINDOW = 3600
FAILED_LOGIN_WINDOW = 900
FAILED_LOGIN_THRESHOLD = 5
UNUSUAL_LOCATION_GRACE = 3


def _as_list(value) -> List[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip().upper() for v in value if str(v).strip()]
    return [v.strip().upper() for v in str(value).replace(';', ',').split(',') if v.strip()]


def _is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return not (
            parsed.is_private or parsed.is_loopback or parsed.is_link_local
            or parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified
        )
    except ValueError:
        return False


def _float(value) -> Optional[float]:
    try:
        if value in (None, ''):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371000.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _event_time(alert: dict) -> float:
    raw = alert.get('timestamp') or alert.get('createdAt') or alert.get('observedAt')
    if isinstance(raw, (int, float)):
        return float(raw / 1000 if raw > 10_000_000_000 else raw)
    if raw:
        try:
            return datetime.fromisoformat(str(raw).replace('Z', '+00:00')).astimezone(timezone.utc).timestamp()
        except (TypeError, ValueError):
            pass
    return time.time()


def lookup_ip(ip: str) -> Optional[Dict]:
    """Return geo info for an IP. Cached for 1 hour."""
    if not ip or not _is_public_ip(ip):
        return None  # skip private IPs
    now = time.time()
    if ip in CACHE and now - _cache_time.get(ip, 0) < CACHE_TTL:
        return CACHE[ip]
    try:
        r = requests.get(GEO_API.format(ip=ip), timeout=4)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'fail':
                return None
            CACHE[ip] = data
            _cache_time[ip] = now
            return data
    except Exception as e:
        logger.debug(f'[GeoEnrich] Lookup failed for {ip}: {e}')
    return None


def enrich_alert(alert: dict) -> dict:
    """Add geoCountry/geoCity fields to an alert dict in-place."""
    src_ip = alert.get('srcip') or alert.get('src_ip') or alert.get('source_ip') or ''
    if not src_ip:
        return alert
    geo = lookup_ip(src_ip)
    if geo:
        alert['geoCountry'] = geo.get('country', '') or geo.get('countryCode', '')
        alert['geoCountryCode'] = geo.get('countryCode', '')
        alert['geoCity']    = geo.get('city', '')
        alert['geoLat']     = geo.get('lat')
        alert['geoLon']     = geo.get('lon')
        alert['geoISP']     = geo.get('isp', '')
        alert['geoProxy']   = geo.get('proxy', False)
        alert['geoHosting'] = geo.get('hosting', False)
        alert['geoStatus']  = 'enriched'
        capability_ids = alert.get('capabilityIds') or alert.get('capability_ids') or []
        if not isinstance(capability_ids, list):
            capability_ids = [capability_ids]
        alert['capabilityIds'] = list(dict.fromkeys([*capability_ids, 23]))
        if geo.get('countryCode') in HIGH_RISK_COUNTRIES:
            alert['highRiskCountry'] = True
    return alert


class GeoEnrichment:
    """Batch geo-enrichment and account/location anomaly detection."""

    def __init__(self, config=None):
        self.config = config
        self.high_risk_countries: Set[str] = set(_as_list(self._cfg('high_risk_geo_countries')))
        self.allowed_countries: Set[str] = set(_as_list(
            self._cfg('allowed_geo_countries') or self._cfg('geo_allowed_countries')
        ))
        self.geo_fence_enabled = bool(self._cfg('geo_fence_enabled', False))
        self.geo_fence_lat = _float(self._cfg('geo_fence_latitude'))
        self.geo_fence_lon = _float(self._cfg('geo_fence_longitude'))
        self.geo_fence_radius_m = max(1, int(_float(self._cfg('geo_fence_radius_meters')) or 200))
        self.gps_required_accuracy_m = min(50, max(5, _float(self._cfg('gps_required_accuracy_meters')) or 50))
        self.geo_fence_lock = bool(self._cfg('geo_fence_lock_on_violation', False))
        self.geo_fence_action = str(self._cfg('geo_fence_action', 'ALERT')).upper()
        self.policies = self._cfg('geolocation_policies', []) or []
        self.max_travel_speed_kmh = max(1, _float(self._cfg('geo_max_travel_speed_kmh')) or DEFAULT_MAX_TRAVEL_SPEED_KMH)
        self.min_travel_distance_km = max(0, _float(self._cfg('geo_min_travel_distance_km')) or DEFAULT_MIN_TRAVEL_DISTANCE_KM)
        self._user_locs: Dict[str, list] = defaultdict(list)
        self._user_baseline: Dict[str, Set[str]] = defaultdict(set)
        self._user_devices: Dict[str, Set[str]] = defaultdict(set)
        self._failed_logins: Dict[str, list] = defaultdict(list)
        self._dedup: Dict[str, float] = {}

    def _cfg(self, key, default=None):
        if hasattr(self.config, 'get'):
            return self.config.get(key, default)
        if isinstance(self.config, dict):
            return self.config.get(key, default)
        return default

    def _refresh_config(self):
        self.high_risk_countries = set(_as_list(self._cfg('high_risk_geo_countries')))
        self.allowed_countries = set(_as_list(
            self._cfg('allowed_geo_countries') or self._cfg('geo_allowed_countries')
        ))
        self.geo_fence_enabled = bool(self._cfg('geo_fence_enabled', False))
        self.geo_fence_lat = _float(self._cfg('geo_fence_latitude'))
        self.geo_fence_lon = _float(self._cfg('geo_fence_longitude'))
        self.geo_fence_radius_m = max(1, int(_float(self._cfg('geo_fence_radius_meters')) or 200))
        self.gps_required_accuracy_m = min(50, max(5, _float(self._cfg('gps_required_accuracy_meters')) or 50))
        self.geo_fence_lock = bool(self._cfg('geo_fence_lock_on_violation', False))
        self.geo_fence_action = str(self._cfg('geo_fence_action', 'ALERT')).upper()
        self.policies = self._cfg('geolocation_policies', []) or []
        self.max_travel_speed_kmh = max(1, _float(self._cfg('geo_max_travel_speed_kmh')) or DEFAULT_MAX_TRAVEL_SPEED_KMH)
        self.min_travel_distance_km = max(0, _float(self._cfg('geo_min_travel_distance_km')) or DEFAULT_MIN_TRAVEL_DISTANCE_KM)

    def enrich(self, alert: dict) -> dict:
        return enrich_alert(alert)

    def _dedup_ok(self, key: str, ttl: int = 1800) -> bool:
        now = time.time()
        if now - self._dedup.get(key, 0) < ttl:
            return False
        self._dedup[key] = now
        return True

    def _policy_for(self, category: str) -> Optional[dict]:
        wanted = str(category or '').strip().lower()
        return next((policy for policy in self.policies
                     if str(policy.get('category') or '').strip().lower() == wanted), None)

    @staticmethod
    def _category_for_rule(rule_id: str) -> Optional[str]:
        return {
            'GEO_HIGH_RISK_COUNTRY': 'Country-Based',
            'GEO_FENCE_VIOLATION': 'Country-Based',
            'GEO_FENCE_RADIUS_VIOLATION': 'Location-Based',
            'GEO_LOCATION_MISMATCH': 'Location-Based',
            'GEO_UNUSUAL_LOGIN_LOCATION': 'User-Based',
            'GEO_MULTIPLE_GEOLOGINS': 'User-Based',
            'GEO_NEW_DEVICE_LOCATION': 'User-Based',
            'GEO_FAILED_LOGIN_SPRAY': 'Authentication',
            'GEO_IMPOSSIBLE_TRAVEL': 'Impossible Travel',
            'GEO_PROXY_OR_HOSTING': 'VPN / Proxy / Tor',
            'GEO_CORPORATE_NETWORK_VIOLATION': 'Corporate Network',
            'GEO_RISK_SCORE_POLICY': 'Risk Score Matrix',
            'GEO_TIME_LOCATION_POLICY': 'Time + Location',
        }.get(str(rule_id or '').upper())

    def _finalize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Bind each detection to the enabled policy that authorizes it."""
        finalized = []
        for finding in findings:
            category = self._category_for_rule(finding.get('ruleId'))
            policy = self._policy_for(category)
            if not policy:
                continue
            conditions = policy.get('conditions') or {}
            cutoff = _float(conditions.get('riskCutoff')) or 0
            if _float(finding.get('riskScore')) is not None and _float(finding.get('riskScore')) < cutoff:
                continue
            action = str(policy.get('action') or 'LOG & MONITOR').strip().upper()
            finding.update({
                'policyId': str(policy.get('id') or policy.get('_id') or ''),
                'policyName': str(policy.get('name') or category),
                'policyCategory': category,
                'policyAction': action,
                'policyTriggered': True,
                'policyActionStatus': 'triggered',
                'systemLogoutRequested': 'LOGOUT' in action or 'SESSION REVOKE' in action,
                'geoFenceLockRequested': action == 'ENDPOINT ISOLATION',
                'lockRecommended': action == 'ENDPOINT ISOLATION',
                'ipBlockRequested': 'IP BAN' in action or 'CRITICAL BLOCK' in action,
            })
            finding['severity'] = str(policy.get('severity') or finding.get('severity') or 'medium').lower()
            finding['raw'] = {**(finding.get('raw') or {}), **{
                key: finding[key] for key in (
                    'policyId', 'policyName', 'policyCategory', 'policyAction',
                    'policyTriggered', 'policyActionStatus', 'systemLogoutRequested',
                    'geoFenceLockRequested', 'lockRecommended', 'ipBlockRequested',
                )
            }}
            finalized.append(finding)
        return finalized

    def _finding(self, rule_id: str, severity: str, description: str, alert: dict, **extra) -> Dict:
        return {
            'ruleId': rule_id,
            'rule_id': rule_id,
            'eventCategory': 'edr',
            'category': 'edr',
            'capabilityId': 23,
            'capabilityIds': [23],
            'severity': severity,
            'description': description,
            'userAction': extra.get('userAction') or rule_id.lower(),
            'mitreTechnique': 'T1078',
            'username': alert.get('username') or alert.get('user'),
            'src_ip': alert.get('src_ip') or alert.get('srcip'),
            'srcip': alert.get('srcip') or alert.get('src_ip'),
            'geoCountry': alert.get('geoCountry'),
            'geoCountryCode': alert.get('geoCountryCode'),
            'geoCity': alert.get('geoCity'),
            'geoLat': alert.get('geoLat'),
            'geoLon': alert.get('geoLon'),
            'geoISP': alert.get('geoISP'),
            'geoProxy': alert.get('geoProxy'),
            'geoHosting': alert.get('geoHosting'),
            'highRiskCountry': alert.get('highRiskCountry', False),
            'riskScore': extra.get('riskScore', {'critical': 90, 'high': 75, 'medium': 50, 'low': 25}.get(severity, 20)),
            'gpsLat': alert.get('gpsLat') if alert.get('gpsLat') is not None else alert.get('gps_lat'),
            'gpsLon': alert.get('gpsLon') if alert.get('gpsLon') is not None else alert.get('gps_lon'),
            'gpsAccuracyMeters': alert.get('gpsAccuracyMeters') or alert.get('gps_accuracy_meters'),
            'gpsAltitudeMeters': alert.get('gpsAltitudeMeters') or alert.get('gps_altitude_meters'),
            'gpsProvider': alert.get('gpsProvider') or alert.get('gps_provider'),
            'gpsStatus': alert.get('gpsStatus') or alert.get('gps_status'),
            'gpsObservedAt': alert.get('gpsObservedAt') or alert.get('gps_observed_at'),
            'geoFenceDistanceMeters': extra.get('geoFenceDistanceMeters'),
            'geoFenceRadiusMeters': extra.get('geoFenceRadiusMeters'),
            'geoFenceLockRequested': extra.get('geoFenceLockRequested', False),
            'lockRecommended': extra.get('geoFenceLockRequested', False),
            'device': alert.get('device') or alert.get('device_id') or alert.get('hostname') or alert.get('system_name'),
            'raw': {'sourceAlert': alert, **extra},
        }

    def check_impossible_travel(self, username: str, country: str, ts: float, alert: Optional[dict] = None) -> Optional[Dict]:
        """Detect physically implausible travel using distance, elapsed time and policy speed."""
        if not username or not country:
            return None
        alert = alert or {}
        lat = _float(alert.get('geoLat'))
        lon = _float(alert.get('geoLon'))
        locs = self._user_locs[username]
        one_hour_ago = ts - IMPOSSIBLE_TRAVEL_WINDOW
        recent = [item for item in locs if item['timestamp'] >= one_hour_ago]
        locs.clear()
        locs.extend(recent)
        previous = next((item for item in reversed(locs) if item['country'] != country), None)
        locs.append({'country': country, 'city': alert.get('geoCity'), 'lat': lat, 'lon': lon, 'timestamp': ts})
        countries = {item['country'] for item in locs}
        if not previous:
            return None

        elapsed_hours = max((ts - previous['timestamp']) / 3600, 1 / 3600)
        distance_km = None
        required_speed = None
        if None not in (previous.get('lat'), previous.get('lon'), lat, lon):
            distance_km = _distance_meters(previous['lat'], previous['lon'], lat, lon) / 1000
            required_speed = distance_km / elapsed_hours
            impossible = distance_km >= self.min_travel_distance_km and required_speed > self.max_travel_speed_kmh
        else:
            # When a provider omitted coordinates, retain the conservative
            # legacy signal but only inside the configured one-hour window.
            impossible = len(countries) >= 2

        if impossible and self._dedup_ok(f'impossible:{username}:{previous["country"]}:{country}'):
            evidence = f'{previous["country"]} → {country} in {round(elapsed_hours * 60)} minutes'
            if distance_km is not None:
                evidence += f' ({round(distance_km)} km, {round(required_speed)} km/h required)'
            return self._finding(
                'GEO_IMPOSSIBLE_TRAVEL',
                'critical' if required_speed and required_speed >= self.max_travel_speed_kmh * 2 else 'high',
                f'Impossible travel: {username} {evidence}',
                alert,
                countries=sorted(countries),
                previousCountry=previous['country'], currentCountry=country,
                previousCity=previous.get('city'), currentCity=alert.get('geoCity'),
                previousLoginAt=datetime.fromtimestamp(previous['timestamp'], timezone.utc).isoformat(),
                currentLoginAt=datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                distanceKm=round(distance_km, 2) if distance_km is not None else None,
                elapsedMinutes=round(elapsed_hours * 60, 2),
                requiredSpeedKmh=round(required_speed, 2) if required_speed is not None else None,
                maxTravelSpeedKmh=self.max_travel_speed_kmh,
                riskScore=95 if required_speed and required_speed >= self.max_travel_speed_kmh * 2 else 80,
                userAction='impossible_travel',
            )
        return None

    def analyze(self, alert: dict) -> List[Dict]:
        self._refresh_config()
        alert = self.enrich(alert)
        # Geo-IP enrichment may continue for evidence, but anomaly findings and
        # response actions require an explicit enabled organization policy.
        if not self.policies:
            return []
        username = alert.get('username') or alert.get('user')
        country = alert.get('geoCountryCode') or alert.get('geoCountry')
        city = alert.get('geoCity')
        ts = _event_time(alert)
        findings = []

        gps_accuracy = _float(alert.get('gpsAccuracyMeters') if alert.get('gpsAccuracyMeters') is not None else alert.get('gps_accuracy_meters'))
        gps_usable = (alert.get('gpsStatus') or alert.get('gps_status') or 'available') == 'available' \
            and gps_accuracy is not None and gps_accuracy <= self.gps_required_accuracy_m
        # A geo-fence is a physical-device control. Never fall back to IP or
        # other inferred coordinates when native GPS accuracy is insufficient.
        coordinate_keys = ('gpsLat', 'gps_lat') if gps_usable else ()
        longitude_keys = ('gpsLon', 'gps_lon') if gps_usable else ()
        current_lat = _float(next((alert.get(key) for key in coordinate_keys if alert.get(key) is not None), None))
        current_lon = _float(next((alert.get(key) for key in longitude_keys if alert.get(key) is not None), None))
        if self.geo_fence_enabled and self.geo_fence_lat is not None and self.geo_fence_lon is not None and current_lat is not None and current_lon is not None:
            distance = _distance_meters(self.geo_fence_lat, self.geo_fence_lon, current_lat, current_lon)
            if distance > self.geo_fence_radius_m and self._dedup_ok(f'fenceradius:{username}:{int(distance)}', 900):
                findings.append(self._finding(
                    'GEO_FENCE_RADIUS_VIOLATION',
                    'critical' if (self.geo_fence_lock or self.geo_fence_action in {'SESSION_REVOKE', 'SYSTEM_LOGOUT'}) else 'high',
                    f'Login/location outside allowed radius: {int(distance)}m from allowed place; limit {self.geo_fence_radius_m}m',
                    alert,
                    geoFenceDistanceMeters=round(distance, 2),
                    geoFenceRadiusMeters=self.geo_fence_radius_m,
                    geoFenceLockRequested=self.geo_fence_lock,
                    policyAction=self.geo_fence_action,
                    sessionRevokeRequested=self.geo_fence_action in {'SESSION_REVOKE', 'SYSTEM_LOGOUT'},
                    systemLogoutRequested=self.geo_fence_action == 'SYSTEM_LOGOUT',
                    userAction='geo_fence_radius_violation',
                ))

        if not country:
            return self._finalize_findings(findings)

        if country in self.high_risk_countries and self._dedup_ok(f'highrisk:{country}:{alert.get("srcip") or alert.get("src_ip")}'):
            findings.append(self._finding(
                'GEO_HIGH_RISK_COUNTRY',
                'high',
                f'High-risk geography access from {country}{(" / " + city) if city else ""}',
                alert,
                userAction='high_risk_geography',
            ))

        if alert.get('geoProxy') or alert.get('geoHosting'):
            label = 'proxy/VPN/hosting' if alert.get('geoHosting') else 'proxy/VPN'
            if self._dedup_ok(f'proxy:{username}:{alert.get("srcip") or alert.get("src_ip")}'):
                findings.append(self._finding(
                    'GEO_PROXY_OR_HOSTING',
                    'medium',
                    f'Suspicious location masking detected via {label}',
                    alert,
                    userAction='proxy_or_vpn',
                ))

        if self.allowed_countries and country not in self.allowed_countries:
            if self._dedup_ok(f'fence:{username}:{country}'):
                findings.append(self._finding(
                    'GEO_FENCE_VIOLATION',
                    'high',
                    f'Geo-fencing violation: access from {country}, allowed: {", ".join(sorted(self.allowed_countries))}',
                    alert,
                    userAction='geo_fence_violation',
                ))

        gps_country = alert.get('gpsCountry') or alert.get('gps_country')
        if gps_country and str(gps_country).upper() != country:
            if self._dedup_ok(f'gps:{username}:{gps_country}:{country}'):
                findings.append(self._finding(
                    'GEO_LOCATION_MISMATCH',
                    'medium',
                    f'Location mismatch: GPS={gps_country}, IP={country}',
                    alert,
                    userAction='location_mismatch',
                ))

        if username:
            baseline = self._user_baseline[username]
            is_new_country = country not in baseline
            if is_new_country and len(baseline) >= UNUSUAL_LOCATION_GRACE:
                if self._dedup_ok(f'unusual:{username}:{country}', 86400):
                    findings.append(self._finding(
                        'GEO_UNUSUAL_LOGIN_LOCATION',
                        'medium',
                        f'Unusual login location for {username}: {country}{(" / " + city) if city else ""}',
                        alert,
                        userAction='unusual_login_location',
                    ))
            impossible = self.check_impossible_travel(username, country, ts, alert)
            if impossible:
                findings.append(impossible)

            locs = [item for item in self._user_locs[username] if item['timestamp'] >= ts - MULTI_GEO_WINDOW]
            if len({item['country'] for item in locs}) >= 3 and self._dedup_ok(f'multigeo:{username}', 1800):
                findings.append(self._finding(
                    'GEO_MULTIPLE_GEOLOGINS',
                    'high',
                    f'Multiple geolocation logins for {username}: {", ".join(sorted({item["country"] for item in locs}))}',
                    alert,
                    userAction='multiple_geolocations',
                ))

            device = alert.get('device') or alert.get('device_id') or alert.get('hostname') or alert.get('system_name')
            devices = self._user_devices[username]
            if device and device not in devices and is_new_country and devices:
                if self._dedup_ok(f'devloc:{username}:{device}:{country}', 86400):
                    findings.append(self._finding(
                        'GEO_NEW_DEVICE_LOCATION',
                        'high',
                        f'New device plus unusual location for {username}: {device} from {country}',
                        alert,
                        userAction='device_location_anomaly',
                    ))
            if device:
                devices.add(str(device))
            baseline.add(country)

            action = str(alert.get('userAction') or alert.get('user_action') or alert.get('event') or '').lower()
            text = str(alert.get('description') or alert.get('raw_log') or '').lower()
            if 'fail' in action or 'failed login' in text or 'authentication failure' in text:
                recent = [(c, t) for c, t in self._failed_logins[username] if t >= ts - FAILED_LOGIN_WINDOW]
                recent.append((country, ts))
                self._failed_logins[username] = recent
                if len(recent) >= FAILED_LOGIN_THRESHOLD and len({c for c, _ in recent}) >= 2:
                    if self._dedup_ok(f'failed:{username}', 1800):
                        findings.append(self._finding(
                            'GEO_FAILED_LOGIN_SPRAY',
                            'high',
                            f'Repeated failed logins for {username} from multiple geolocations',
                            alert,
                            userAction='failed_login_geo_spray',
                        ))

        risk_policy = self._policy_for('Risk Score Matrix')
        source_risk = _float(alert.get('riskScore') if alert.get('riskScore') is not None else alert.get('risk_score'))
        if risk_policy and source_risk is not None:
            cutoff = _float((risk_policy.get('conditions') or {}).get('riskCutoff')) or 0
            if source_risk >= cutoff and self._dedup_ok(f'risk:{username}:{country}:{int(source_risk)}', 900):
                findings.append(self._finding(
                    'GEO_RISK_SCORE_POLICY',
                    'critical' if source_risk >= 90 else 'high',
                    f'Geolocation risk score {int(source_risk)} met policy cutoff {int(cutoff)}',
                    alert,
                    riskScore=source_risk,
                    userAction='geolocation_risk_score',
                ))

        time_policy = self._policy_for('Time + Location')
        outside_time = alert.get('afterHours') is True or alert.get('outsideWorkingHours') is True \
            or str(alert.get('ruleId') or alert.get('rule_id') or '').upper().startswith('TIME_')
        if time_policy and outside_time and self._dedup_ok(f'time-location:{username}:{country}', 900):
            findings.append(self._finding(
                'GEO_TIME_LOCATION_POLICY', 'high',
                f'Location activity outside the configured time window: {country}',
                alert, userAction='time_location_policy',
            ))

        return self._finalize_findings(findings)

    def run_and_report(self, alerts: list, sender=None) -> list:
        """Enrich a batch of alerts and report geo anomalies."""
        findings = []
        for alert in alerts:
            for finding in self.analyze(alert):
                findings.append(finding)
                if sender:
                    try:
                        sender.send_alert(finding)
                    except Exception as e:
                        logger.error(f'[GeoEnrich] Send error: {e}')
        return findings


Enrichment = GeoEnrichment
Enricher = GeoEnrichment
