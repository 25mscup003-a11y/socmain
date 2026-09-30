"""
USB Collector — detects USB device plug/unplug events.
Sends eventCategory='usb' alerts with device name, vendor, action.

Linux:   pyudev (preferred) real-time udev events
         → /sys/bus/usb polling (if pyudev fails or permission denied)
         → /proc/bus/usb alternative
Windows: WMI
macOS:   ioreg polling

Note: When running as root (systemd service) pyudev should work. If not,
the /sys poll fallback runs every USB_POLL_INTERVAL seconds.
"""

import os
import time
import logging
import threading
import platform
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger('soc-agent.collector.usb')
SYSTEM = platform.system()

USB_POLL_INTERVAL = 3   # seconds between /sys polling


class USBCollector:
    def __init__(self, sender):
        self._sender = sender
        self._thread = threading.Thread(target=self._run, daemon=True, name='usb-monitor')
        self._mount_watch_lock = threading.Lock()
        self._watched_mounts = set()
        self._event_lock = threading.Lock()
        self._recent_device_events = {}
        self._recent_policy_events = {}

    def start(self):
        self._thread.start()

    def _emit(self, device: str, vendor: str, action: str, mount_path: str = '', username: str = '',
              serial_number: str = '', vid: str = '', pid: str = '', device_type: str = ''):
        device  = device.strip()  or 'Unknown Device'
        vendor  = vendor.strip()  or ''
        # Linux emits both add/bind (and remove/unbind) for one physical action.
        # Suppress only identical device transitions inside a short window.
        event_key = (serial_number or f'{vid}:{pid}:{device}').strip().lower()
        now = time.monotonic()
        with self._event_lock:
            previous = self._recent_device_events.get(event_key)
            if previous and previous[0] == action and now - previous[1] < 5:
                return
            self._recent_device_events[event_key] = (action, now)
        severity = 'high' if action == 'connected' else 'medium'
        desc = f'USB device {action}: {device}'
        if vendor:
            desc += f' ({vendor})'
        if mount_path:
            desc += f' → mounted at {mount_path}'

        alert = {
            'rule_id':     'USB_DEVICE_EVENT',
            'capabilityId': 10,
            'category':    'usb',
            'severity':    severity,
            'description': desc,
            'device':      device,
            'device_name': device,
            'vendor':      vendor or None,
            'serial_number': serial_number or None,
            'vid':         vid or None,
            'product_id':  pid or None,
            'device_type': device_type or 'USB Device',
            'mount_path':  mount_path or None,
            'username':    username   or None,
            'user_action': action,          # 'connected' or 'disconnected'
            'source':      'usb',
            'raw_log':     f'USB:{action}|{device}|{vendor}|mount={mount_path}|user={username}',
            'timestamp':   datetime.now(timezone.utc).isoformat(),
        }
        self._sender.enqueue(alert)
        logger.info('🔌 USB %s: %s %s mount=%s user=%s',
                    action, device, f'({vendor})' if vendor else '',
                    mount_path or '—', username or '—')

        # Trigger file scan on mounted path when USB is connected (Rule 4)
        if action == 'connected' and mount_path and os.path.isdir(mount_path):
            self._start_mount_watch(mount_path, device, username)
            if _mount_is_read_only(mount_path):
                self._sender.enqueue({
                    'rule_id': 'USB_WRITE_BLOCKED', 'capabilityId': 10, 'category': 'usb', 'severity': 'medium',
                    'description': f'USB write blocked by read-only mount policy: {device}',
                    'device': device, 'device_name': device, 'mount_path': mount_path,
                    'username': username or None, 'user_action': 'write_blocked',
                    'blocked': True, 'policy_name': 'Read-only removable media',
                    'action_taken': 'Blocked', 'source': 'usb',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
        elif action == 'connected':
            threading.Thread(target=self._discover_mount, args=(device, username), daemon=True).start()

        allowed = {s.strip().lower() for s in os.getenv('USB_ALLOWED_SERIALS', '').split(',') if s.strip()}
        if action == 'connected' and allowed and (serial_number or '').lower() not in allowed:
            self._sender.enqueue({
                'rule_id': 'USB_POLICY_VIOLATION', 'capabilityId': 10, 'category': 'usb', 'severity': 'high',
                'description': f'Unauthorized USB device connected: {device}',
                'device': device, 'device_name': device, 'vendor': vendor or None,
                'serial_number': serial_number or None, 'vid': vid or None, 'product_id': pid or None,
                'device_type': device_type or 'USB Device', 'mount_path': mount_path or None,
                'username': username or None, 'user_action': 'policy_violation',
                'blocked': False, 'policy_name': 'USB serial allowlist',
                'action_taken': 'None', 'source': 'usb',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
        if action == 'connected':
            self._apply_connection_policies(device, vendor, serial_number, vid, pid, device_type, mount_path, username)
            self._detect_hid_threat(device, vendor, serial_number, vid, pid, device_type)

    def _policies(self):
        config = getattr(self._sender, 'config', None)
        policies = config.get('usb_policies', []) if config else []
        return policies if isinstance(policies, list) else []

    def _policy_alert(self, policy, description, device, username='', blocked=False,
                      enforcement_status='audit', enforcement_error='', **extra):
        policy_id = str(policy.get('id') or policy.get('name') or 'usb-policy')
        dedup_key = (policy_id, str(device).lower(), str(extra.get('file_path') or '').lower(), enforcement_status)
        now = time.monotonic()
        with self._event_lock:
            if now - self._recent_policy_events.get(dedup_key, 0) < 30:
                return
            self._recent_policy_events[dedup_key] = now
        self._sender.enqueue({
            'rule_id': 'USB_POLICY_BLOCKED' if blocked else ('USB_POLICY_ENFORCEMENT_FAILED' if enforcement_status == 'failed' else 'USB_POLICY_VIOLATION'),
            'capabilityId': 10, 'category': 'usb', 'severity': 'high' if blocked else 'medium',
            'description': description, 'device': device, 'device_name': device,
            'username': username or None, 'user_action': 'policy_blocked' if blocked else 'policy_violation',
            'blocked': blocked, 'policy_name': policy.get('name') or 'USB policy',
            'action_taken': 'Blocked' if blocked else ('Enforcement Failed' if enforcement_status == 'failed' else 'Audit'),
            'enforcement_status': enforcement_status,
            'enforcement_error': enforcement_error or None,
            'source': 'usb-policy',
            'policy_id': policy.get('id'), 'policy_rule_type': policy.get('rule_type'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            **extra,
        })

    def _apply_connection_policies(self, device, vendor, serial, vid, pid, device_type, mount_path, username):
        serial_l = (serial or '').lower()
        vendor_l = (vendor or '').lower()
        type_l = (device_type or '').lower()
        for policy in self._policies():
            rule_type = policy.get('rule_type')
            values = {str(value).strip().lower() for value in policy.get('values', []) if str(value).strip()}
            violation = False
            if rule_type == 'allow_serials':
                violation = bool(values) and serial_l not in values
            elif rule_type == 'block_serials':
                violation = serial_l in values
            elif rule_type == 'block_vendor':
                violation = any(value in vendor_l for value in values)
            elif rule_type == 'block_device_type':
                violation = any(value in type_l for value in values)
            elif rule_type == 'read_only' and mount_path:
                violation = True
            if not violation:
                continue
            should_block = policy.get('action') == 'block'
            enforced = False
            enforcement_error = ''
            if should_block:
                if rule_type == 'read_only' and mount_path:
                    enforced = _remount_read_only(mount_path)
                else:
                    enforced = _block_usb_storage()
                if not enforced:
                    enforcement_error = 'Endpoint enforcement command failed or is unsupported on this host'
            enforcement_status = 'enforced' if enforced else ('failed' if should_block else 'audit')
            self._policy_alert(
                policy, f"USB policy {'blocked' if enforced else 'violated'}: {policy.get('name')} — {device}",
                device, username, blocked=enforced, enforcement_status=enforcement_status,
                enforcement_error=enforcement_error,
                vendor=vendor or None, serial_number=serial or None, vid=vid or None,
                product_id=pid or None, device_type=device_type or None, mount_path=mount_path or None,
            )

    def _detect_hid_threat(self, device, vendor, serial, vid, pid, device_type):
        """Emit only defensible HID/BadUSB indicators, not every keyboard/mouse."""
        text = f'{device} {vendor} {device_type}'.lower()
        known_attack_tokens = ('rubber ducky', 'usb rubber ducky', 'bash bunny', 'badusb', 'digispark', 'teensy')
        if not any(token in text for token in known_attack_tokens):
            return
        rubber_ducky = 'rubber ducky' in text
        self._sender.enqueue({
            'rule_id': 'USB_RUBBER_DUCKY_SUSPECTED' if rubber_ducky else 'USB_HID_ANOMALY',
            'capabilityId': 10, 'category': 'usb', 'severity': 'critical' if rubber_ducky else 'high',
            'description': f"Suspicious HID device signature detected: {device}",
            'device': device, 'device_name': device, 'vendor': vendor or None,
            'serial_number': serial or None, 'vid': vid or None, 'product_id': pid or None,
            'device_type': device_type or 'HID Device', 'user_action': 'hid_anomaly',
            'source': 'usb', 'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _discover_mount(self, device: str, username: str):
        """udev's USB-device event can arrive before the block device is mounted."""
        for _ in range(10):
            time.sleep(2)
            mount_path = _get_mount_path_by_name(device)
            if mount_path:
                self._sender.enqueue({
                    'rule_id': 'USB_STORAGE_MOUNTED', 'capabilityId': 10, 'category': 'usb', 'severity': 'low',
                    'description': f'USB storage mounted: {device} at {mount_path}',
                    'device': device, 'device_name': device, 'device_type': 'USB Storage',
                    'mount_path': mount_path, 'username': username or None,
                    'user_action': 'storage_mounted', 'source': 'usb',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
                for policy in self._policies():
                    if policy.get('rule_type') != 'read_only':
                        continue
                    should_block = policy.get('action') == 'block'
                    enforced = _remount_read_only(mount_path) if should_block else False
                    status = 'enforced' if enforced else ('failed' if should_block else 'audit')
                    self._policy_alert(
                        policy,
                        f"USB read-only policy {'enforced' if enforced else 'violated'}: {policy.get('name')} — {device}",
                        device,
                        username,
                        blocked=enforced,
                        enforcement_status=status,
                        enforcement_error='' if status != 'failed' else 'Unable to remount removable volume as read-only',
                        mount_path=mount_path,
                        device_type='USB Storage',
                    )
                self._start_mount_watch(mount_path, device, username)
                return

    def _start_mount_watch(self, mount_path: str, device: str, username: str):
        """Start exactly one bounded file watcher for each mounted volume."""
        mount_key = os.path.realpath(mount_path)
        with self._mount_watch_lock:
            if mount_key in self._watched_mounts:
                return False
            self._watched_mounts.add(mount_key)

        def run():
            try:
                self._scan_mount(mount_path, device)
                self._watch_mount(mount_path, device, username)
            finally:
                with self._mount_watch_lock:
                    self._watched_mounts.discard(mount_key)

        threading.Thread(
            target=run,
            daemon=True,
            name=f'usb-files-{os.path.basename(mount_path)[:24]}',
        ).start()
        return True

    def _emit_driver_event(self, device, driver, vendor='', serial='', vid='', pid='', device_type='USB Device'):
        if not driver:
            return
        self._sender.enqueue({
            'rule_id': 'USB_DRIVER_LOADED', 'capabilityId': 10, 'category': 'usb', 'severity': 'low',
            'description': f'USB driver loaded: {driver} for {device}',
            'device': device, 'device_name': device, 'vendor': vendor or None,
            'serial_number': serial or None, 'vid': vid or None, 'product_id': pid or None,
            'device_type': device_type, 'driver_name': driver,
            'user_action': 'driver_loaded', 'source': 'usb',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _watch_mount(self, mount_path: str, device: str, username: str):
        """Emit real copy/transfer events for files created or modified after mount."""
        def snapshot():
            state = {}
            try:
                for root, dirs, files in os.walk(mount_path):
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    for name in files:
                        path = os.path.join(root, name)
                        try:
                            stat = os.stat(path)
                            state[path] = (stat.st_mtime_ns, stat.st_size)
                        except OSError:
                            pass
                        if len(state) >= 10000:
                            return state
            except OSError:
                pass
            return state

        previous = snapshot()
        observed_reads = set()
        while os.path.isdir(mount_path) and os.path.ismount(mount_path):
            time.sleep(2)
            current = snapshot()
            for path, (mtime, size) in current.items():
                old = previous.get(path)
                if old is not None and old == (mtime, size):
                    continue
                name = os.path.basename(path)
                sensitive = _sensitive_file(path)
                sha256 = _sha256(path)
                matched_policy = self._matching_file_policy(path, size, sensitive)
                blocked_by_policy = False
                enforcement_failed = False
                should_block = bool(matched_policy and matched_policy.get('action') == 'block')
                if should_block:
                    try:
                        os.remove(path)
                        blocked_by_policy = True
                    except OSError:
                        enforcement_failed = True
                policy_rule = (
                    'USB_POLICY_BLOCKED' if blocked_by_policy else
                    'USB_POLICY_ENFORCEMENT_FAILED' if enforcement_failed else
                    'USB_POLICY_VIOLATION' if matched_policy else
                    'USB_SENSITIVE_FILE_COPIED' if sensitive else
                    'USB_FILE_COPIED'
                )
                self._sender.enqueue({
                    'rule_id': policy_rule,
                    'capabilityId': 10, 'capabilityIds': [10, 12], 'category': 'usb', 'severity': 'high' if sensitive or matched_policy else 'medium',
                    'data_event_type': 'usb_transfer',
                    'data_classification': 'Restricted' if sensitive else 'Internal',
                    'transfer_channel': 'usb', 'transfer_protocol': 'removable-storage',
                    'description': f"{'Blocked file copy' if blocked_by_policy else ('Sensitive file' if sensitive else 'File')} to USB: {name} on {device}",
                    'device': device, 'device_name': device, 'device_type': 'USB Storage',
                    'mount_path': mount_path, 'file_path': path, 'file_name': name,
                    'file_size': size, 'bytes_transferred': size, 'file_hash': sha256,
                    'file_action': 'copied_to_usb', 'sensitivity_type': 'sensitive' if sensitive else 'standard',
                    'username': username or None, 'user_action': 'file_copied_to_usb',
                    'blocked': blocked_by_policy, 'policy_name': matched_policy.get('name') if matched_policy else None,
                    'policy_id': matched_policy.get('id') if matched_policy else None,
                    'policy_rule_type': matched_policy.get('rule_type') if matched_policy else None,
                    'action_taken': 'Blocked' if blocked_by_policy else ('Enforcement Failed' if enforcement_failed else ('Audit' if matched_policy else 'None')),
                    'enforcement_status': 'enforced' if blocked_by_policy else ('failed' if enforcement_failed else ('audit' if matched_policy else 'not_applicable')),
                    'enforcement_error': 'Unable to remove the prohibited file from removable media' if enforcement_failed else None,
                    'source': 'usb', 'raw_log': f'USB_COPY:{path}|bytes={size}|device={device}',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
            # On Linux, an open descriptor beneath the removable mount is
            # direct evidence of a read/open operation. Values/content are
            # never collected. Keep one event per PID/path while it is open.
            if SYSTEM == 'Linux':
                active_reads = _linux_open_files(mount_path)
                for pid, path, process_name in active_reads - observed_reads:
                    try:
                        size = os.path.getsize(path)
                    except OSError:
                        size = 0
                    self._sender.enqueue({
                        'rule_id': 'USB_FILE_READ', 'capabilityId': 10, 'category': 'usb', 'severity': 'low',
                        'description': f'File opened from USB: {os.path.basename(path)} on {device}',
                        'device': device, 'device_name': device, 'device_type': 'USB Storage',
                        'mount_path': mount_path, 'file_path': path, 'file_name': os.path.basename(path),
                        'file_size': size, 'bytes_transferred': size,
                        'file_action': 'read_from_usb', 'username': username or None,
                        'process_name': process_name or None, 'pid': int(pid),
                        'user_action': 'file_read_from_usb', 'source': 'usb',
                        'raw_log': f'USB_READ:{path}|pid={pid}|device={device}',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                    })
                observed_reads = active_reads
            previous = current

    def _matching_file_policy(self, path: str, size: int, sensitive: bool):
        extension = os.path.splitext(path)[1].lower()
        for policy in self._policies():
            rule_type = policy.get('rule_type')
            values = {str(value).strip().lower() for value in policy.get('values', []) if str(value).strip()}
            if rule_type == 'block_sensitive_files' and sensitive:
                return policy
            if rule_type == 'block_extensions' and extension in {value if value.startswith('.') else f'.{value}' for value in values}:
                return policy
            if rule_type == 'max_file_size' and int(policy.get('max_bytes') or 0) > 0 and size > int(policy.get('max_bytes')):
                return policy
        return None

    # ── Scan USB mount for suspicious files ──────────────────────────────────
    def _scan_mount(self, mount_path: str, device: str):
        """Walk the mounted USB path and enqueue file events for suspicious files."""
        import hashlib
        from pathlib import Path

        SUSPICIOUS_EXT = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.hta',
                          '.sh', '.py', '.rb', '.pl', '.elf',
                          '.locked', '.encrypted', '.crypt', '.wncry'}
        count = 0
        logger.info('🔍 USB scan started: %s', mount_path)
        try:
            for root, _dirs, files in os.walk(mount_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    ext   = os.path.splitext(fname)[1].lower()
                    if ext not in SUSPICIOUS_EXT:
                        continue
                    count += 1
                    if count > 500:
                        logger.warning('USB scan capped at 500 files for %s', mount_path)
                        break
                    # Compute hash
                    try:
                        h = hashlib.sha256()
                        with open(fpath, 'rb') as f:
                            for chunk in iter(lambda: f.read(65536), b''):
                                h.update(chunk)
                        fhash = h.hexdigest()
                    except Exception:
                        fhash = ''

                    self._sender.enqueue({
                        'rule_id':     'USB_FILE_FOUND',
                        'capabilityId': 10,
                        'category':    'usb',
                        'severity':    'high' if ext in {'.exe','.dll','.ps1','.sh','.elf'} else 'medium',
                        'description': f'USB file found: {fname} on {device}',
                        'device':      device,
                        'mount_path':  mount_path,
                        'file_path':   fpath,
                        'file_name':   fname,
                        'file_hash':   fhash,
                        'file_size':   os.path.getsize(fpath) if os.path.exists(fpath) else 0,
                        'file_action': 'found_on_usb',
                        'device_type': 'USB Storage',
                        'source':      'usb',
                        'raw_log':     f'USB_FILE:{fpath}|hash={fhash}',
                        'timestamp':   datetime.now(timezone.utc).isoformat(),
                    })
        except Exception as e:
            logger.warning('USB scan error on %s: %s', mount_path, e)
        logger.info('🔍 USB scan complete: %d suspicious files on %s', count, mount_path)

    def _run(self):
        if SYSTEM == 'Linux':
            self._linux()
        elif SYSTEM == 'Windows':
            self._windows()
        elif SYSTEM == 'Darwin':
            self._macos()
        else:
            logger.info('USB monitoring not supported on this OS')

    # ── Linux: pyudev real-time (preferred) ───────────────────────────────────
    def _linux(self):
        # Try pyudev first
        try:
            import pyudev
            ctx     = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(ctx)
            monitor.filter_by(subsystem='usb', device_type='usb_device')
            monitor.start()
            logger.info('USB monitor started (Linux/udev real-time)')

            while True:
                try:
                    device = monitor.poll(timeout=5)
                    if device is None:
                        continue
                    name   = (device.get('ID_MODEL')
                              or device.get('ID_MODEL_ID')
                              or device.device_path.split('/')[-1])
                    vendor = (device.get('ID_VENDOR')
                              or device.get('ID_VENDOR_FROM_DATABASE') or '')
                    action = device.action or ''

                    # Resolve mount path via /proc/mounts (Rule 4)
                    mount_path = ''
                    dev_node   = device.device_node or ''
                    if dev_node:
                        mount_path = _get_mount_path(dev_node)

                    # Get current user
                    username = _get_current_user()
                    serial_number = device.get('ID_SERIAL_SHORT') or device.get('ID_SERIAL') or ''
                    vid = device.get('ID_VENDOR_ID') or ''
                    pid = device.get('ID_MODEL_ID') or ''
                    driver = device.get('ID_USB_DRIVER') or device.driver or ''
                    device_type = _classify_device_type(device.get('ID_TYPE') or '', driver, name)

                    if action in ('add', 'bind'):
                        self._emit(name, vendor, 'connected', mount_path, username, serial_number, vid, pid, device_type)
                        self._emit_driver_event(name, driver, vendor, serial_number, vid, pid, device_type)
                    elif action in ('remove', 'unbind'):
                        self._emit(name, vendor, 'disconnected', mount_path, username, serial_number, vid, pid, device_type)
                except Exception as inner:
                    logger.debug('pyudev poll error: %s', inner)
                    time.sleep(1)

        except ImportError:
            logger.warning('pyudev not installed — falling back to /sys/bus polling')
            logger.warning('Fix: pip3 install pyudev  OR  sudo apt install python3-pyudev')
            self._linux_sys_poll()

        except PermissionError:
            logger.warning('pyudev: permission denied (not root?) — falling back to /sys poll')
            self._linux_sys_poll()

        except Exception as e:
            logger.error('pyudev error: %s — falling back to /sys poll', e)
            self._linux_sys_poll()

    # ── Linux: /sys/bus/usb polling fallback ──────────────────────────────────
    def _linux_sys_poll(self):
        """Polls /sys/bus/usb/devices every USB_POLL_INTERVAL seconds.
        Works without root/udev. Detects connect and disconnect events.
        """
        logger.info('USB monitor started (Linux/sys-poll every %ds)', USB_POLL_INTERVAL)
        seen: dict = {}   # device_id → device metadata

        def _read(path):
            try:
                with open(path) as f:
                    return f.read().strip()
            except Exception:
                return ''

        def _scan_sys():
            """Scan /sys/bus/usb/devices and return dict of id→(name,vendor)."""
            found = {}
            usb_path = '/sys/bus/usb/devices'
            if not os.path.isdir(usb_path):
                return found
            try:
                for entry in os.listdir(usb_path):
                    dev_path = os.path.join(usb_path, entry)
                    # Only real USB devices have idProduct
                    idproduct = _read(os.path.join(dev_path, 'idProduct'))
                    if not idproduct:
                        continue
                    idvendor  = _read(os.path.join(dev_path, 'idVendor'))
                    name   = (_read(os.path.join(dev_path, 'product'))
                               or f'USB Device {idproduct}')
                    vendor = (_read(os.path.join(dev_path, 'manufacturer'))
                               or idvendor or '')
                    found[entry] = {
                        'name': name,
                        'vendor': vendor,
                        'serial': _read(os.path.join(dev_path, 'serial')),
                        'vid': idvendor,
                        'pid': idproduct,
                        'driver': os.path.basename(os.path.realpath(os.path.join(dev_path, 'driver'))) if os.path.exists(os.path.join(dev_path, 'driver')) else '',
                        'type': _classify_device_type(_read(os.path.join(dev_path, 'bDeviceClass')), '', name),
                    }
            except Exception as e:
                logger.debug('USB sys scan error: %s', e)
            return found

        # Also check /proc/bus/usb as alternative
        def _scan_proc():
            found = {}
            proc_path = '/proc/bus/usb/devices'
            if not os.path.isfile(proc_path):
                return found
            try:
                with open(proc_path) as f:
                    content = f.read()
                # Parse Vendor/Product from USBInfo format
                import re
                for m in re.finditer(r'P:\s+Vendor=(\w+)\s+ProdID=(\w+)', content):
                    vid, pid = m.group(1), m.group(2)
                    found[f'{vid}:{pid}'] = {'name': f'USB Device {pid}', 'vendor': vid, 'serial': '', 'vid': vid, 'pid': pid, 'type': 'USB Device'}
            except Exception:
                pass
            return found

        first_run = True
        while True:
            current = _scan_sys()
            if not current:
                current = _scan_proc()

            if not first_run:
                username = _get_current_user()
                # Connected
                for dev_id, meta in current.items():
                    if dev_id not in seen:
                        # Try to find mount path
                        mount_path = _get_mount_path_by_name(meta['name'])
                        self._emit(meta['name'], meta['vendor'], 'connected', mount_path, username,
                                   meta['serial'], meta['vid'], meta['pid'], meta['type'])
                        self._emit_driver_event(meta['name'], meta.get('driver', ''), meta['vendor'],
                                                meta['serial'], meta['vid'], meta['pid'], meta['type'])

                # Disconnected
                for dev_id, meta in seen.items():
                    if dev_id not in current:
                        self._emit(meta['name'], meta['vendor'], 'disconnected', '', username,
                                   meta['serial'], meta['vid'], meta['pid'], meta['type'])

            seen = current
            first_run = False
            time.sleep(USB_POLL_INTERVAL)

    # ── Windows WMI ───────────────────────────────────────────────────────────
    def _windows(self):
        try:
            import wmi
        except ImportError:
            logger.warning('wmi not installed — enable USB monitoring with: pip install wmi pywin32')
            return
        client = wmi.WMI()
        creation = client.Win32_PnPEntity.watch_for('creation')
        deletion = client.Win32_PnPEntity.watch_for('deletion')

        def watch(watcher, action):
            while True:
                try:
                    dev = watcher(timeout_ms=3000)
                    pnp_id = str(getattr(dev, 'PNPDeviceID', '') or '')
                    if dev and ('USB' in pnp_id.upper() or 'REMOVABLE' in str(getattr(dev, 'Description', '')).upper()):
                        vid, pid = _vid_pid_from_id(pnp_id)
                        serial = pnp_id.rsplit('\\', 1)[-1] if '\\' in pnp_id else ''
                        mount_path = _get_mount_path_by_name(str(getattr(dev, 'Name', '') or 'USB Device')) if action == 'connected' else ''
                        self._emit(str(getattr(dev, 'Name', '') or 'USB Device'),
                                   str(getattr(dev, 'Manufacturer', '') or ''), action, mount_path, _get_current_user(),
                                   serial, vid, pid, str(getattr(dev, 'Description', '') or 'USB Device'))
                        if action == 'connected':
                            self._emit_driver_event(str(getattr(dev, 'Name', '') or 'USB Device'),
                                                    str(getattr(dev, 'Service', '') or ''),
                                                    str(getattr(dev, 'Manufacturer', '') or ''), serial, vid, pid,
                                                    _classify_device_type(str(getattr(dev, 'Description', '') or ''), '', str(getattr(dev, 'Name', '') or '')))
                except Exception:
                    time.sleep(1)
        threading.Thread(target=watch, args=(creation, 'connected'), daemon=True).start()
        threading.Thread(target=watch, args=(deletion, 'disconnected'), daemon=True).start()
        while True:
            time.sleep(60)

    # ── macOS ioreg polling ───────────────────────────────────────────────────
    def _macos(self):
        import subprocess
        import re
        seen = {}
        logger.info('USB monitor started (macOS/ioreg polling)')
        while True:
            try:
                out = subprocess.check_output(['ioreg', '-r', '-c', 'IOUSBHostDevice', '-l'], text=True, timeout=8)
                blocks = re.split(r'\n\s*\+-o ', out)
                current = {}
                for block in blocks:
                    name = _ioreg_value(block, 'USB Product Name') or _ioreg_value(block, 'kUSBProductString')
                    if not name:
                        continue
                    meta = {
                        'vendor': _ioreg_value(block, 'USB Vendor Name') or _ioreg_value(block, 'kUSBVendorString'),
                        'serial': _ioreg_value(block, 'USB Serial Number'),
                        'vid': _ioreg_number(block, 'idVendor'),
                        'pid': _ioreg_number(block, 'idProduct'),
                    }
                    current[f"{name}:{meta['serial']}:{meta['vid']}:{meta['pid']}"] = (name, meta)
                for key, (name, meta) in current.items():
                    if key not in seen:
                        mount_path = _get_mount_path_by_name(name)
                        self._emit(name, meta['vendor'], 'connected', mount_path, _get_current_user(), meta['serial'], meta['vid'], meta['pid'], _classify_device_type('', '', name))
                for key, (name, meta) in seen.items():
                    if key not in current:
                        self._emit(name, meta['vendor'], 'disconnected', '', _get_current_user(), meta['serial'], meta['vid'], meta['pid'], 'USB Device')
                seen = current
            except Exception as exc:
                logger.debug('macOS USB poll error: %s', exc)
            time.sleep(5)


# ── USB helper functions ──────────────────────────────────────────────────────

def _get_mount_path(dev_node: str) -> str:
    """Find where dev_node (e.g. /dev/sdb1) is mounted via /proc/mounts."""
    if not dev_node or not os.path.exists('/proc/mounts'):
        return ''
    try:
        with open('/proc/mounts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == dev_node:
                    return parts[1]
    except Exception:
        pass
    return ''


def _get_mount_path_by_name(device_name: str) -> str:
    """Resolve a removable-volume mount path on Linux, macOS, or Windows."""
    if SYSTEM == 'Windows':
        try:
            import ctypes
            for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
                root = f'{letter}:\\'
                if os.path.isdir(root) and ctypes.windll.kernel32.GetDriveTypeW(root) == 2:
                    return root
        except (AttributeError, OSError):
            return ''

    bases = ['/Volumes'] if SYSTEM == 'Darwin' else ['/media', '/mnt', '/run/media']
    normalized_name = ''.join(char.lower() for char in device_name if char.isalnum())
    candidates = []
    for base in bases:
        if os.path.isdir(base):
            try:
                for entry in os.listdir(base):
                    full = os.path.join(base, entry)
                    if os.path.isdir(full):
                        # Search user subdirs (e.g. /media/user/DriveName)
                        try:
                            for sub in os.listdir(full):
                                sfull = os.path.join(full, sub)
                                if os.path.isdir(sfull) and os.path.ismount(sfull):
                                    candidates.append(sfull)
                        except Exception:
                            pass
                        if os.path.ismount(full):
                            candidates.append(full)
            except Exception:
                pass
    if not candidates:
        return ''
    for candidate in candidates:
        label = ''.join(char.lower() for char in os.path.basename(candidate) if char.isalnum())
        if normalized_name and (label in normalized_name or normalized_name in label):
            return candidate
    return candidates[0]


def _get_current_user() -> str:
    """Return the currently logged-in username (best effort)."""
    if SYSTEM == 'Windows':
        try:
            import ctypes
            size = ctypes.c_ulong(256)
            buffer = ctypes.create_unicode_buffer(size.value)
            if ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
                value = buffer.value.strip()
                if value and value.upper() not in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                    return value
        except (AttributeError, OSError):
            pass
    if SYSTEM == 'Darwin':
        try:
            value = subprocess.check_output(
                ['stat', '-f%Su', '/dev/console'], text=True, timeout=2,
                stderr=subprocess.DEVNULL,
            ).strip()
            if value and value not in ('root', 'loginwindow'):
                return value
        except (OSError, subprocess.SubprocessError):
            pass
    if SYSTEM == 'Linux':
        try:
            output = subprocess.check_output(['who'], text=True, timeout=2, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                value = line.split()[0] if line.split() else ''
                if value and value != 'root':
                    return value
        except (OSError, subprocess.SubprocessError):
            pass
    for var in ('SUDO_USER', 'USER', 'LOGNAME', 'USERNAME'):
        u = os.environ.get(var, '')
        if u and u.lower() not in ('root', 'system'):
            return u
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return ''


def _linux_open_files(mount_path: str):
    """Return privacy-safe (pid, path, process) evidence for open USB files."""
    result = set()
    mount_real = os.path.realpath(mount_path).rstrip(os.sep) + os.sep
    try:
        proc_entries = os.listdir('/proc')
    except OSError:
        return result
    for pid in proc_entries:
        if not pid.isdigit():
            continue
        fd_dir = os.path.join('/proc', pid, 'fd')
        try:
            process_name = ''
            try:
                with open(os.path.join('/proc', pid, 'comm'), encoding='utf-8', errors='replace') as handle:
                    process_name = handle.read(128).strip()
            except OSError:
                pass
            for fd_name in os.listdir(fd_dir)[:256]:
                try:
                    target = os.path.realpath(os.readlink(os.path.join(fd_dir, fd_name)))
                except OSError:
                    continue
                if target.startswith(mount_real) and os.path.isfile(target):
                    result.add((pid, target, process_name))
                    if len(result) >= 1000:
                        return result
        except OSError:
            continue
    return result

def _vid_pid_from_id(value: str):
    """Extract VID/PID from a Windows PNP identifier."""
    import re
    vid = re.search(r'VID_([0-9A-F]{4})', value or '', re.I)
    pid = re.search(r'PID_([0-9A-F]{4})', value or '', re.I)
    return (vid.group(1).lower() if vid else '', pid.group(1).lower() if pid else '')


def _ioreg_value(block: str, key: str) -> str:
    import re
    match = re.search(rf'"{re.escape(key)}"\s*=\s*"([^"]*)"', block or '')
    return match.group(1) if match else ''


def _ioreg_number(block: str, key: str) -> str:
    import re
    match = re.search(rf'"{re.escape(key)}"\s*=\s*(\d+)', block or '')
    return f'{int(match.group(1)):04x}' if match else ''


def _classify_device_type(kind: str, driver: str, name: str) -> str:
    text = f'{kind} {driver} {name}'.lower()
    if any(token in text for token in ('rndis', 'cdc_ether', 'ethernet', 'network', 'wifi', 'wireless')):
        return 'USB Network Adapter'
    if any(token in text for token in ('mtp', 'android', 'iphone', 'mobile', 'phone')):
        return 'Mobile Device (MTP)'
    if any(token in text for token in ('storage', 'usb-storage', 'mass', 'disk', 'flash', 'hdd', 'ssd')):
        return 'USB Storage'
    if any(token in text for token in ('hid', 'keyboard', 'mouse')):
        return 'HID Device'
    return 'USB Device'


def _mount_is_read_only(mount_path: str) -> bool:
    try:
        with open('/proc/mounts') as mounts:
            for line in mounts:
                parts = line.split()
                if len(parts) >= 4 and parts[1] == mount_path:
                    return 'ro' in parts[3].split(',')
    except OSError:
        pass
    return False


def _remount_read_only(mount_path: str) -> bool:
    import subprocess
    try:
        result = subprocess.run(['mount', '-o', 'remount,ro', mount_path], capture_output=True, timeout=20, check=False)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _block_usb_storage() -> bool:
    try:
        from response.usb_block import block
        return block() is not False
    except Exception:
        return False


def _sensitive_file(path: str) -> bool:
    name = os.path.basename(path).lower()
    sensitive_tokens = ('password', 'credential', 'secret', 'confidential', 'private', 'payroll',
                        'customer', 'database', 'backup', 'id_rsa', '.env', 'passwd', 'shadow')
    sensitive_ext = ('.pem', '.key', '.p12', '.pfx', '.kdbx', '.sql', '.dump', '.bak')
    return any(token in name for token in sensitive_tokens) or name.endswith(sensitive_ext)


def _sha256(path: str) -> str:
    import hashlib
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as stream:
            for chunk in iter(lambda: stream.read(65536), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ''


# agent.py imports collectors by the common `Collector` contract.
Collector = USBCollector
