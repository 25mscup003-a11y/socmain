"""OS socket counters and bounded, asynchronous peer metadata (no payloads)."""
import ipaddress
import queue
import re
import subprocess
import sys
import threading
import time


def normalized_ip(value):
    try:
        address = ipaddress.ip_address(str(value).strip('[]').split('%', 1)[0])
        return str(address.ipv4_mapped or address) if address.version == 6 else str(address)
    except ValueError:
        return ''


def socket_key(local_ip, local_port, remote_ip, remote_port):
    return normalized_ip(local_ip), int(local_port or 0), normalized_ip(remote_ip), int(remote_port or 0)


def parse_tcp_counters(output):
    """Parse ss TCP_INFO; queue sizes are never treated as byte counters."""
    counters = {}
    current = None
    for line in output.splitlines():
        if line and not line[0].isspace():
            current = None
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                local_ip, local_port = parts[3].rsplit(':', 1)
                remote_ip, remote_port = parts[4].rsplit(':', 1)
                current = socket_key(local_ip, local_port, remote_ip, remote_port)
                if not current[0] or not current[2]:
                    current = None
            except (ValueError, TypeError):
                continue
        elif current:
            values = {key: int(value) for key, value in re.findall(r'\b(bytes_sent|bytes_received):(\d+)\b', line)}
            if values:
                counters.setdefault(current, {}).update(values)
    return counters


def linux_tcp_counters():
    if not sys.platform.startswith('linux'):
        return {}
    try:
        result = subprocess.run(['ss', '-tinH'], capture_output=True, text=True, timeout=3, check=False)
        return parse_tcp_counters(result.stdout) if result.returncode == 0 else {}
    except (OSError, subprocess.SubprocessError):
        return {}


def reverse_dns(ip):
    """Bound libc/NSS DNS time without changing global socket timeouts."""
    try:
        result = subprocess.run(
            [sys.executable, '-c', 'import socket,sys; print(socket.gethostbyaddr(sys.argv[1])[0])', ip],
            capture_output=True, text=True, timeout=2, check=False,
        )
        return result.stdout.strip().rstrip('.')[:253] if result.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        return ''


class PeerMetadataCache:
    """Resolve all observed public peers over time without stalling a scan."""
    def __init__(self, lookup, capacity=1024, ttl=3600, retry_seconds=300, interval=2):
        self.lookup = lookup
        self.capacity = capacity
        self.ttl = ttl
        self.retry_seconds = retry_seconds
        self.interval = interval
        self.cache = {}
        self.pending = set()
        self.queue = queue.Queue(maxsize=min(capacity, 256))
        self.lock = threading.Lock()
        self.worker = None
        self.stopped = threading.Event()

    def get(self, ip):
        ip = normalized_ip(ip)
        if not ip or not ipaddress.ip_address(ip).is_global:
            return {}
        with self.lock:
            value, expires = self.cache.get(ip, ({}, 0))
            if time.monotonic() < expires:
                return dict(value)
            if ip not in self.pending and not self.stopped.is_set():
                try:
                    self.queue.put_nowait(ip)
                    self.pending.add(ip)
                    if self.worker is None:
                        self.worker = threading.Thread(target=self._run, daemon=True, name='network-peer-metadata')
                        self.worker.start()
                except queue.Full:
                    pass
            return {}  # Expired metadata is not presented as current evidence.

    def _run(self):
        while not self.stopped.is_set():
            try:
                ip = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                value = self.lookup(ip) or {}
            except Exception:
                value = {}
            complete = bool(value.get('geo')) and bool(value.get('domain'))
            with self.lock:
                self.cache.pop(ip, None)
                self.cache[ip] = (value, time.monotonic() + (self.ttl if complete else self.retry_seconds))
                while len(self.cache) > self.capacity:
                    self.cache.pop(next(iter(self.cache)))
                self.pending.discard(ip)
            self.queue.task_done()
            self.stopped.wait(self.interval)

    def close(self):
        self.stopped.set()
