"""Policy-gated endpoint location collection using native OS providers.

This module never derives or guesses GPS coordinates from an IP address.  A
position is reported only when Windows Location Services or Linux GeoClue
returns one and the company policy has explicitly enabled device tracking.
"""

import json
import getpass
import logging
import math
import os
import platform
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger('soc-agent.gps-location')

FORENSIC_SCHEMA_VERSION = 1


WINDOWS_LOCATION_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.Devices.Geolocation.Geolocator,Windows.Devices.Geolocation,ContentType=WindowsRuntime] | Out-Null
[Windows.Devices.Geolocation.Geoposition,Windows.Devices.Geolocation,ContentType=WindowsRuntime] | Out-Null
function Await-WinRT($Operation, $ResultType) {
  $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 } |
    Select-Object -First 1
  $task = $method.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
  $task.Wait()
  $task.Result
}
$locator = New-Object Windows.Devices.Geolocation.Geolocator
$locator.DesiredAccuracy = [Windows.Devices.Geolocation.PositionAccuracy]::High
$locator.DesiredAccuracyInMeters = 50
$operation = $locator.GetGeopositionAsync()
$position = Await-WinRT $operation ([Windows.Devices.Geolocation.Geoposition])
$coordinate = $position.Coordinate
$point = $coordinate.Point.Position
[pscustomobject]@{
  latitude = $point.Latitude
  longitude = $point.Longitude
  altitude = $point.Altitude
  accuracy = $coordinate.Accuracy
  timestamp = $coordinate.Timestamp.ToUniversalTime().ToString('o')
} | ConvertTo-Json -Compress
""".strip()

GEOCLUE_CANDIDATES = (
    '/usr/lib/geoclue-2.0/demos/where-am-i',
    '/usr/libexec/geoclue-2.0/demos/where-am-i',
)


def geoclue_command(executable, runtime_root=Path('/run/user')):
    """Run GeoClue in the active desktop session when the agent runs as root.

    GeoClue authorizes location access per desktop user.  A system service has
    no session bus of its own, so calling ``where-am-i`` directly as root can
    time out even while Location Services are enabled for the signed-in user.
    """
    # Ask GeoClue for its highest (Exact) accuracy tier explicitly.  This does
    # not falsify the provider-reported uncertainty: machines without a GNSS
    # sensor may still return a coarse Wi-Fi/network fix, which the 50m policy
    # rejects below.
    command = [executable, '--accuracy-level=8', '--timeout=20']
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return command
    runuser = shutil.which('runuser')
    if not runuser:
        return command
    try:
        runtime_dirs = sorted(
            (path for path in runtime_root.iterdir() if path.name.isdigit() and int(path.name) >= 1000),
            key=lambda path: int(path.name),
        )
    except OSError:
        return command
    for runtime_dir in runtime_dirs:
        bus = runtime_dir / 'bus'
        if not bus.exists():
            continue
        try:
            username = pwd.getpwuid(int(runtime_dir.name)).pw_name
        except (KeyError, ValueError):
            continue
        return [
            runuser, '-u', username, '--', 'env',
            f'XDG_RUNTIME_DIR={runtime_dir}',
            f'DBUS_SESSION_BUS_ADDRESS=unix:path={bus}',
            *command,
        ]
    return command


def _number(value):
    try:
        number = float(value)
        return number if number == number else None
    except (TypeError, ValueError):
        return None


def _text(value):
    return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else str(value or '')


def _distance_meters(lat1, lon1, lat2, lon2):
    """Return great-circle distance for policy evidence without reverse geocoding."""
    values = [_number(value) for value in (lat1, lon1, lat2, lon2)]
    if any(value is None for value in values):
        return None
    first_lat, first_lon, second_lat, second_lon = map(math.radians, values)
    dlat, dlon = second_lat - first_lat, second_lon - first_lon
    haversine = math.sin(dlat / 2) ** 2 + math.cos(first_lat) * math.cos(second_lat) * math.sin(dlon / 2) ** 2
    return 6371000 * 2 * math.asin(min(1, math.sqrt(haversine)))


def _active_username():
    """Best-effort local session identity; never reads credentials or tokens."""
    if platform.system() == 'Windows':
        return os.environ.get('USERNAME') or getpass.getuser() or 'unknown'
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        try:
            for entry in sorted(Path('/run/user').iterdir(), key=lambda path: path.name):
                if entry.name.isdigit() and int(entry.name) >= 1000 and (entry / 'bus').exists():
                    return pwd.getpwuid(int(entry.name)).pw_name
        except (OSError, KeyError, ValueError):
            pass
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except (AttributeError, KeyError):
        return getpass.getuser() or 'unknown'


def _network_context():
    """Collect bounded endpoint interface metadata without contacting the Internet."""
    hostname = socket.gethostname()
    addresses = []
    interface_name = 'unknown'
    try:
        import psutil
        for name, items in psutil.net_if_addrs().items():
            for item in items:
                address = str(item.address or '')
                if item.family in (socket.AF_INET, socket.AF_INET6) and address and not address.startswith(('127.', '::1', 'fe80:')):
                    addresses.append(address.split('%', 1)[0])
                    if interface_name == 'unknown':
                        interface_name = name
    except (ImportError, OSError):
        try:
            addresses.extend(item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM))
        except OSError:
            pass
    addresses = list(dict.fromkeys(address for address in addresses if address))[:8]
    return {
        'hostname': hostname,
        'fqdn': socket.getfqdn(),
        'localIp': next((address for address in addresses if ':' not in address), addresses[0] if addresses else 'unavailable'),
        'localAddresses': addresses,
        'interface': interface_name,
        'publicIpCollection': 'not_performed_by_location_collector',
    }


def parse_windows_location(output):
    """Parse the fixed PowerShell helper JSON and validate its coordinates."""
    data = json.loads(_text(output).strip())
    latitude = _number(data.get('latitude'))
    longitude = _number(data.get('longitude'))
    if latitude is None or longitude is None or not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError('Windows Location Services returned invalid coordinates')
    return {
        'latitude': latitude,
        'longitude': longitude,
        'altitudeMeters': _number(data.get('altitude')),
        'accuracyMeters': _number(data.get('accuracy')),
        'timestamp': data.get('timestamp') or datetime.now(timezone.utc).isoformat(),
    }


def parse_geoclue_location(output):
    """Parse GeoClue's stable `where-am-i` labels without locale guessing."""
    text = _text(output)
    patterns = {
        'latitude': r'(?im)^\s*Latitude\s*:\s*([-+]?\d+(?:\.\d+)?)',
        'longitude': r'(?im)^\s*Longitude\s*:\s*([-+]?\d+(?:\.\d+)?)',
        'altitudeMeters': r'(?im)^\s*Altitude\s*:\s*([-+]?\d+(?:\.\d+)?)',
        'accuracyMeters': r'(?im)^\s*Accuracy\s*:\s*([-+]?\d+(?:\.\d+)?)',
    }
    matches = {
        key: [_number(value) for value in re.findall(pattern, text)]
        for key, pattern in patterns.items()
    }
    candidates = []
    for index in range(min(len(matches['latitude']), len(matches['longitude']))):
        candidates.append({
            'latitude': matches['latitude'][index],
            'longitude': matches['longitude'][index],
            'altitudeMeters': matches['altitudeMeters'][index] if index < len(matches['altitudeMeters']) else None,
            'accuracyMeters': matches['accuracyMeters'][index] if index < len(matches['accuracyMeters']) else None,
        })
    # GeoClue can emit an initial stale GeoIP position followed by a fresher
    # Wi-Fi-derived position with the same declared accuracy. Prefer the most
    # recent candidate when accuracy ties so the agent is not pinned to the
    # older city-level estimate.
    values = min(
        enumerate(candidates),
        key=lambda pair: (
            pair[1]['accuracyMeters'] if pair[1]['accuracyMeters'] is not None else float('inf'),
            -pair[0],
        ),
    )[1] if candidates else {}
    latitude, longitude = values.get('latitude'), values.get('longitude')
    if latitude is None or longitude is None or not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError('GeoClue returned no valid coordinates')
    values['timestamp'] = datetime.now(timezone.utc).isoformat()
    return values


def parse_gpsd_tpv(payload):
    """Validate one gpsd TPV report and normalize its uncertainty."""
    data = json.loads(_text(payload).strip()) if not isinstance(payload, dict) else payload
    if data.get('class') != 'TPV' or int(_number(data.get('mode')) or 0) < 2:
        raise ValueError('gpsd has no two-dimensional GNSS fix')
    latitude = _number(data.get('lat'))
    longitude = _number(data.get('lon'))
    if latitude is None or longitude is None or not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError('gpsd returned invalid coordinates')
    horizontal_error = _number(data.get('eph'))
    if horizontal_error is None:
        axis_errors = [_number(data.get('epx')), _number(data.get('epy'))]
        known_errors = [value for value in axis_errors if value is not None]
        horizontal_error = max(known_errors) if known_errors else None
    return {
        'latitude': latitude,
        'longitude': longitude,
        'altitudeMeters': _number(data.get('altHAE') if data.get('altHAE') is not None else data.get('alt')),
        'accuracyMeters': horizontal_error,
        'timestamp': data.get('time') or datetime.now(timezone.utc).isoformat(),
    }


def collect_macos_corelocation(timeout_seconds=20):
    """Request a native CoreLocation fix through PyObjC.

    macOS owns the authorization decision. The collector never changes TCC or
    falls back to IP-derived coordinates when permission/sensors are absent.
    """
    try:
        import objc
        from CoreLocation import CLLocationManager, kCLLocationAccuracyBest
        from Foundation import NSDate, NSObject, NSRunLoop
    except ImportError as error:
        return {'status': 'unsupported', 'provider': 'macos-corelocation', 'reason': f'CoreLocation bridge is unavailable: {error}'}

    class LocationDelegate(NSObject):
        def init(self):
            self = objc.super(LocationDelegate, self).init()
            if self is not None:
                self.location = None
                self.error = None
            return self

        def locationManager_didUpdateLocations_(self, _manager, locations):
            if locations and locations.count():
                self.location = locations.lastObject()

        def locationManager_didFailWithError_(self, _manager, error):
            self.error = str(error)

    if not CLLocationManager.locationServicesEnabled():
        return {'status': 'permission_denied', 'provider': 'macos-corelocation', 'reason': 'macOS Location Services are disabled'}
    manager = CLLocationManager.alloc().init()
    delegate = LocationDelegate.alloc().init()
    manager.setDelegate_(delegate)
    manager.setDesiredAccuracy_(kCLLocationAccuracyBest)
    try:
        manager.startUpdatingLocation()
        deadline = time.monotonic() + max(1, timeout_seconds)
        while delegate.location is None and delegate.error is None and time.monotonic() < deadline:
            NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.2))
    finally:
        manager.stopUpdatingLocation()
    if delegate.location is None:
        reason = delegate.error or 'macOS returned no CoreLocation fix; allow Location Services for AJNAT/Python'
        return {'status': 'sensor_unavailable', 'provider': 'macos-corelocation', 'reason': reason}
    coordinate = delegate.location.coordinate()
    accuracy = _number(delegate.location.horizontalAccuracy())
    if accuracy is not None and accuracy < 0:
        accuracy = None
    return {
        'status': 'available',
        'provider': 'macos-corelocation',
        'latitude': _number(coordinate.latitude),
        'longitude': _number(coordinate.longitude),
        'altitudeMeters': _number(delegate.location.altitude()),
        'accuracyMeters': accuracy,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


class GPSLocationCollector:
    """Collect and format GPS events while reading mutable runtime policy."""

    def __init__(self, config, state=None):
        self.config = config
        self.state = state
        persisted = state.gps_location_state() if state and hasattr(state, 'gps_location_state') else None
        self._last_reported_state = tuple(persisted) if persisted else None
        self._observation_confirmed = False

    @property
    def enabled(self):
        return self.config.get('gps_tracking_enabled', False) is True

    @property
    def interval_seconds(self):
        try:
            return max(30, min(3600, int(self.config.get('gps_collection_interval_seconds', 300))))
        except (TypeError, ValueError):
            return 300

    @property
    def required_accuracy_meters(self):
        try:
            # Policies may demand tighter fixes, but never accept a location
            # whose reported horizontal uncertainty exceeds 50 metres.
            return max(5.0, min(50.0, float(self.config.get('gps_required_accuracy_meters', 50))))
        except (TypeError, ValueError):
            return 50.0

    @staticmethod
    def _status_from_error(message):
        lowered = str(message or '').lower()
        if any(token in lowered for token in ('access is denied', 'permission denied', 'unauthorized', 'disabled by policy')):
            return 'permission_denied'
        if any(token in lowered for token in ('not available', 'no location', 'position unavailable', 'element not found')):
            return 'sensor_unavailable'
        return 'provider_error'

    def _collect_windows(self):
        executable = shutil.which('powershell.exe') or shutil.which('powershell')
        if not executable:
            return {'status': 'unsupported', 'provider': 'windows-location-services', 'reason': 'PowerShell is unavailable'}
        try:
            completed = subprocess.run(
                [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass', '-Command', WINDOWS_LOCATION_SCRIPT],
                capture_output=True, text=True, timeout=30, check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            return {'status': 'provider_timeout', 'provider': 'windows-location-services', 'reason': 'Windows Location Services timed out'}
        except OSError as error:
            return {'status': 'provider_error', 'provider': 'windows-location-services', 'reason': str(error)}
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or 'Windows Location Services failed').strip()
            return {'status': self._status_from_error(message), 'provider': 'windows-location-services', 'reason': message[:500]}
        try:
            return {'status': 'available', 'provider': 'windows-location-services', **parse_windows_location(completed.stdout)}
        except (ValueError, json.JSONDecodeError) as error:
            return {'status': 'provider_error', 'provider': 'windows-location-services', 'reason': str(error)}

    @staticmethod
    def _geoclue_executable():
        discovered = shutil.which('where-am-i')
        if discovered:
            return discovered
        return next((candidate for candidate in GEOCLUE_CANDIDATES if Path(candidate).is_file()), None)

    def _collect_linux(self):
        gpsd_result = self._collect_gpsd()
        if gpsd_result.get('status') == 'available':
            return gpsd_result
        executable = self._geoclue_executable()
        if not executable:
            return gpsd_result if gpsd_result.get('status') != 'unsupported' else {
                'status': 'unsupported', 'provider': 'linux-native-location',
                'reason': 'Neither a gpsd GNSS fix nor the GeoClue helper is available',
            }
        try:
            completed = subprocess.run(
                geoclue_command(executable), capture_output=True, text=True, timeout=30, check=False, shell=False,
            )
        except subprocess.TimeoutExpired as error:
            # Some GeoClue demo builds keep watching after printing the first
            # fix. Preserve that real fix instead of misreporting a timeout.
            try:
                return {'status': 'available', 'provider': 'geoclue', **parse_geoclue_location(error.stdout)}
            except ValueError:
                return {'status': 'provider_timeout', 'provider': 'geoclue', 'reason': 'GeoClue timed out'}
        except OSError as error:
            return {'status': 'provider_error', 'provider': 'geoclue', 'reason': str(error)}
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or 'GeoClue failed').strip()
            return {'status': self._status_from_error(message), 'provider': 'geoclue', 'reason': message[:500]}
        try:
            return {'status': 'available', 'provider': 'geoclue', **parse_geoclue_location(completed.stdout)}
        except ValueError as error:
            return {'status': 'provider_error', 'provider': 'geoclue', 'reason': str(error)}

    @staticmethod
    def _collect_gpsd(host='127.0.0.1', port=2947):
        """Read a real hardware GNSS fix from the local gpsd daemon."""
        try:
            connection = socket.create_connection((host, port), timeout=2)
        except OSError as error:
            return {'status': 'unsupported', 'provider': 'gpsd-gnss', 'reason': f'gpsd is unavailable: {error}'}
        try:
            connection.settimeout(2)
            connection.sendall(b'?WATCH={"enable":true,"json":true};\n')
            stream = connection.makefile('r', encoding='utf-8', errors='replace')
            deadline = time.monotonic() + 8
            last_reason = 'gpsd reported no hardware GNSS fix'
            while time.monotonic() < deadline:
                try:
                    line = stream.readline()
                except OSError:
                    continue
                if not line:
                    break
                try:
                    return {'status': 'available', 'provider': 'gpsd-gnss', **parse_gpsd_tpv(line)}
                except (ValueError, json.JSONDecodeError) as error:
                    last_reason = str(error)
            return {'status': 'sensor_unavailable', 'provider': 'gpsd-gnss', 'reason': last_reason}
        except OSError as error:
            return {'status': 'provider_error', 'provider': 'gpsd-gnss', 'reason': str(error)}
        finally:
            connection.close()

    def collect(self):
        if not self.enabled:
            return {'status': 'disabled', 'provider': 'none', 'reason': 'GPS tracking is disabled by company policy'}
        system = platform.system()
        if system == 'Windows':
            result = self._collect_windows()
        elif system == 'Linux':
            result = self._collect_linux()
        elif system == 'Darwin':
            result = collect_macos_corelocation()
        else:
            result = {'status': 'unsupported', 'provider': system.lower() or 'unknown', 'reason': 'Native GPS provider is unsupported on this operating system'}

        if result.get('status') == 'available':
            accuracy = _number(result.get('accuracyMeters'))
            if accuracy is None:
                result.update(status='accuracy_unknown', reason='Location provider did not report accuracy')
            elif accuracy > self.required_accuracy_meters:
                result.update(status='inaccurate', reason=f'GPS accuracy {accuracy:.0f}m exceeds policy limit {self.required_accuracy_meters:.0f}m')
        return result

    def _reportable_state(self, result):
        """Return stable local state, excluding the always-changing timestamp.

        Coordinates are rounded to roughly 10 metres and accuracy is bucketed
        so harmless provider jitter remains local. A real location, provider,
        status, or material accuracy change produces a new server event.
        """
        status = result.get('status', 'provider_error')
        provider = str(result.get('provider') or '')
        latitude = _number(result.get('latitude'))
        longitude = _number(result.get('longitude'))
        position_qualified = status == 'available'
        reason = '' if status in ('available', 'inaccurate') else str(result.get('reason') or '')[:200]
        state = (
            status,
            provider,
            round(latitude, 4) if position_qualified and latitude is not None else None,
            round(longitude, 4) if position_qualified and longitude is not None else None,
            reason,
            str(self.config.get('gps_policy_id') or ''),
            int(self.config.get('gps_policy_version') or 0),
            str(self.config.get('gps_policy_action') or ''),
        )
        return state + ((FORENSIC_SCHEMA_VERSION,) if self.config.get('geolocation_forensics_enabled', False) is True else ())

    def _remember_reported_state(self, reportable_state):
        self._last_reported_state = reportable_state
        if self.state and hasattr(self.state, 'set_gps_location_state'):
            self.state.set_gps_location_state(reportable_state)

    def _forensic_context(self, result, observed_at):
        """Build the privacy-bounded evidence used by every forensic-panel tab."""
        status = str(result.get('status') or 'provider_error')
        latitude = _number(result.get('latitude'))
        longitude = _number(result.get('longitude'))
        accuracy = _number(result.get('accuracyMeters'))
        policy_latitude = _number(self.config.get('geo_fence_latitude'))
        policy_longitude = _number(self.config.get('geo_fence_longitude'))
        radius = _number(self.config.get('geo_fence_radius_meters'))
        policy_eligible = status == 'available' and accuracy is not None and accuracy <= self.required_accuracy_meters
        distance = _distance_meters(policy_latitude, policy_longitude, latitude, longitude) if policy_eligible else None
        username = _active_username()
        network = _network_context()
        process_name = Path(sys.argv[0]).name or 'soc-agent'
        queued_at = datetime.now(timezone.utc).isoformat()
        category = str(self.config.get('gps_policy_category') or 'Device GPS Tracking')
        action = str(self.config.get('gps_policy_action') or 'LOG & MONITOR')
        return {
            'schemaVersion': FORENSIC_SCHEMA_VERSION,
            'evidenceOrigin': 'AJNAT endpoint agent',
            'overview': {
                'detectionTrigger': 'Native endpoint location observation',
                'observationStatus': status,
                'riskScore': 0,
                'evidenceSource': 'agent-native-location',
                'collectedAt': observed_at,
            },
            'network': {
                **network,
                'locationProvider': result.get('provider') or 'unknown',
                'locationStatus': status,
                'locationReason': result.get('reason') or '',
                'internetGeoIp': 'not_collected_by_gps_sensor',
            },
            'travel': {
                'currentLatitude': latitude,
                'currentLongitude': longitude,
                'accuracyMeters': accuracy,
                'requiredAccuracyMeters': self.required_accuracy_meters,
                'allowedLatitude': policy_latitude,
                'allowedLongitude': policy_longitude,
                'allowedRadiusMeters': radius,
                'distanceFromAllowedMeters': round(distance, 2) if distance is not None else None,
                'insideAllowedRadius': distance <= radius if distance is not None and radius is not None else None,
                'policyEligible': policy_eligible,
                'evaluation': 'evaluated' if distance is not None else 'not_evaluated_without_qualified_fix_or_geofence',
            },
            'authentication': {
                'username': username,
                'authType': 'local endpoint session',
                'mfaStatus': 'not_observable_by_endpoint_location_sensor',
                'identityProvider': 'operating-system',
                'sessionEvidence': 'active desktop/service context',
            },
            'endpoint': {
                'hostname': network['hostname'],
                'systemId': str(self.config.get('system_id') or ''),
                'agentId': str(self.config.get('agent_id') or self.config.get('system_id') or ''),
                'agentVersion': str(self.config.get('agent_version') or ''),
                'operatingSystem': platform.system(),
                'osRelease': platform.release(),
                'osVersion': platform.version(),
                'architecture': platform.machine(),
                'processName': process_name,
                'processId': os.getpid(),
                'parentProcessId': os.getppid(),
            },
            'data': {
                'eventType': 'location sensor telemetry',
                'dataClassification': 'Internal',
                'transferBytes': 0,
                'exfiltrationObserved': False,
                'transferChannel': 'AJNAT authenticated telemetry',
                'scope': 'metadata only; no file or content collection',
            },
            'mitre': {
                'mapped': False,
                'techniqueId': 'not_applicable',
                'techniqueName': 'Operational location telemetry',
                'tactic': 'not_applicable',
                'reason': 'GPS status is sensor evidence, not an ATT&CK behavior by itself',
            },
            'policy': {
                'policyId': str(self.config.get('gps_policy_id') or ''),
                'policyName': str(self.config.get('gps_policy_name') or 'AJNAT Device GPS Tracking'),
                'category': category,
                'action': action,
                'version': int(self.config.get('gps_policy_version') or 0),
                'requiredAccuracyMeters': self.required_accuracy_meters,
                'triggered': True,
            },
            'timeline': {
                'observedAt': observed_at,
                'collectedAt': observed_at,
                'queuedAt': queued_at,
                'stage': 'agent_collection_complete',
            },
            'actions': {
                'agentDisposition': 'allowed' if action.upper() == 'ALLOW & AUDIT' else 'logged',
                'recommendedAction': 'Verify location permission and GNSS/Wi-Fi availability' if status != 'available' else 'Continue monitoring',
                'responseExecution': 'server_managed_approval_workflow',
                'responseStatus': 'not_requested',
            },
        }

    def event_for(self, result):
        status = result.get('status', 'provider_error')
        reportable_state = self._reportable_state(result)
        if reportable_state == self._last_reported_state:
            logger.debug('GPS state unchanged; retaining local observation without server upload')
            return None
        self._remember_reported_state(reportable_state)

        observed_at = result.get('timestamp') or datetime.now(timezone.utc).isoformat()
        policy_action = str(self.config.get('gps_policy_action') or 'LOG & MONITOR')
        event = {
            'rule_id': 'GPS_LOCATION_TELEMETRY' if status == 'available' else 'GEO_GPS_STATUS',
            'ruleId': 'GPS_LOCATION_TELEMETRY' if status == 'available' else 'GEO_GPS_STATUS',
            'capabilityId': 23,
            'capabilityIds': [23],
            'eventCategory': 'edr',
            'category': 'edr',
            'severity': 'low',
            'riskScore': 0,
            'source': 'gps-location',
            'gpsProvider': result.get('provider'),
            'gpsStatus': status,
            'gpsObservedAt': observed_at,
            'timestamp': observed_at,
            'description': 'Device GPS position collected from the native OS location provider' if status == 'available' else f'Device GPS unavailable: {result.get("reason") or status}',
            'policyId': str(self.config.get('gps_policy_id') or ''),
            'policyName': str(self.config.get('gps_policy_name') or 'AJNAT Device GPS Tracking'),
            'policyCategory': str(self.config.get('gps_policy_category') or 'Device GPS Tracking'),
            'policyAction': policy_action,
            'policyTriggered': True,
            'policyActionStatus': 'allowed' if policy_action.upper() == 'ALLOW & AUDIT' else 'logged',
        }
        if self.config.get('geolocation_forensics_enabled', False) is True:
            forensic_context = self._forensic_context(result, observed_at)
            event.update({
                'username': forensic_context['authentication']['username'],
                'device': forensic_context['endpoint']['hostname'],
                'process_name': forensic_context['endpoint']['processName'],
                'pid': forensic_context['endpoint']['processId'],
                'authType': forensic_context['authentication']['authType'],
                'mfaStatus': forensic_context['authentication']['mfaStatus'],
                'dataEventType': forensic_context['data']['eventType'],
                'dataClassification': forensic_context['data']['dataClassification'],
                'bytes_transferred': forensic_context['data']['transferBytes'],
                'raw': {'geoForensics': forensic_context},
            })
        # Coarse provider coordinates are useful as an explicitly approximate
        # map location. Enforcement remains gated by status=available and the
        # configured accuracy limit in geo_enrichment.py.
        if status in ('available', 'inaccurate') and result.get('latitude') is not None:
            event['gpsLat'] = result['latitude']
            event['geoLat'] = result['latitude']
        if status in ('available', 'inaccurate') and result.get('longitude') is not None:
            event['gpsLon'] = result['longitude']
            event['geoLon'] = result['longitude']
        event['gpsCoordinateQuality'] = 'precise' if status == 'available' else 'approximate'
        if result.get('accuracyMeters') is not None:
            event['gpsAccuracyMeters'] = result['accuracyMeters']
        if result.get('altitudeMeters') is not None:
            event['gpsAltitudeMeters'] = result['altitudeMeters']
        if result.get('reason'):
            event['gpsReason'] = result['reason']
        return event

    def run_and_report(self, sender=None):
        if not self.enabled:
            return None
        result = self.collect()
        event = self.event_for(result)
        if not self._observation_confirmed:
            upload_state = 'queued_changed_state' if event else 'suppressed_unchanged_state'
            logger.info(
                'GPS observation active: status=%s provider=%s upload=%s',
                result.get('status', 'provider_error'),
                result.get('provider', 'unknown'),
                upload_state,
            )
            self._observation_confirmed = True
        if event and sender:
            sender.send_alert(event)
        return event
