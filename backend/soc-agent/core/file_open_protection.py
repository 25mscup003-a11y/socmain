"""Opt-in Linux response to external opens of manifested Python source files.

Only a kernel permission event with an identified external process can clear a
file. No inotify fallback, process-name allowlist, recursive deletion or secure
erasure claim. Existing descriptors, copies and privileged OS administrators are
outside this protection. Enable maintenance before backups or local inspection.
"""
import ctypes
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import select
import stat
import struct
import sys
import threading

from .self_protection import _load_manifest

_OPEN_PERM = 0x10000
_OVERFLOW = 0x4000
_ALLOW, _DENY = 1, 2
_METADATA = struct.Struct('=IBBHQii')
_RESPONSE = struct.Struct('=iI')


def _kernel_group():
    if not sys.platform.startswith('linux'):
        raise OSError('File-open protection requires Linux fanotify permission events.')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    libc.fanotify_init.restype = ctypes.c_int
    libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    libc.fanotify_mark.restype = ctypes.c_int
    # CONTENT | NONBLOCK | CLOEXEC; event FDs must support ftruncate without
    # reopening a protected path (which could deadlock this permission listener).
    fd = libc.fanotify_init(0x07, os.O_RDWR | os.O_CLOEXEC | getattr(os, 'O_LARGEFILE', 0))
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'Linux fanotify requires CAP_SYS_ADMIN and kernel support')
    return libc, fd


class FileOpenProtection:
    def __init__(self, root=None):
        self.root = Path(root or Path(__file__).resolve().parent.parent).absolute()
        self._pid = os.getpid()
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._inventory = {}
        self._findings = []
        self._supported = None
        self._support_detail = ''
        self._state = 'disabled'
        self._detail = 'Clearing source files on external open is off.'
        self._updating = False

    def _probe(self):
        if self._supported is not None:
            return
        try:
            _, fd = _kernel_group()
            os.close(fd)
            self._supported = True
        except (OSError, AttributeError) as error:
            self._supported = False
            self._support_detail = str(error)[:300]

    def _protected_inventory(self):
        # Do all source reads before installing marks. Untrusted writable paths,
        # symlinks and hardlinks must never become destructive targets.
        manifest, error = _load_manifest(self.root)
        if not manifest:
            raise ValueError(error)
        inventory = {}
        for relative, digest in manifest['files'].items():
            path = self.root / relative
            for parent in (path, *path.parents):
                info = parent.lstat()
                if stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022 or info.st_uid != os.geteuid():
                    raise ValueError('Protected code requires owned, non-writable, non-symlink paths: ' + relative)
                if parent == self.root:
                    break
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Protected code must be a regular file without hardlinks: ' + relative)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('Protected code does not match the package manifest: ' + relative)
            inventory[(info.st_dev, info.st_ino)] = (relative, path)
        return inventory

    def apply(self, config):
        self._probe()
        enabled = config.get('erase_code_on_open', False) is True
        if not enabled or not config.get('self_protection', True) or config.get('maintenance_mode', False) or self._updating:
            self.stop()
            with self._lock:
                self._state = 'disabled'
                self._detail = ('Clearing source files on external open is off.' if not enabled
                                else 'File-open response is suspended by Self Protection, maintenance or an authorized update.')
                if not self._supported:
                    self._detail += ' ' + self._support_detail
            return
        if not self._supported:
            self._state, self._detail = 'unsupported', self._support_detail
            return
        if self._thread and self._thread.is_alive():
            return
        # A failed listener is not silently rearmed on each heartbeat.
        if self._state == 'error':
            return
        fd = None
        try:
            inventory = self._protected_inventory()
            libc, fd = _kernel_group()
            for _, path in inventory.values():
                if libc.fanotify_mark(fd, 0x05, _OPEN_PERM, -100, os.fsencode(path)) < 0:  # ADD | DONT_FOLLOW
                    raise OSError(ctypes.get_errno(), 'Cannot protect package source: ' + path.name)
            self._inventory = inventory
            self._stop.clear()
            self._state = 'enforced'
            self._detail = (f'External opens clear only the opened manifested Python source file ({len(inventory)} files). '
                            'Agent-process reads are allowed. Copies and privileged administrators are outside this protection.')
            self._thread = threading.Thread(target=self._listen, args=(fd,), name='agent-file-open', daemon=True)
            self._thread.start()
            fd = None  # listener owns the group
        except Exception as error:
            self._state, self._detail = 'error', str(error)[:300]
        finally:
            if fd is not None:
                os.close(fd)

    def stop(self):
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                raise RuntimeError('File-open listener did not stop; update/maintenance cannot proceed')
        self._thread = None

    def suspend_for_update(self):
        self.stop()
        self._updating = True
        self._state, self._detail = 'disabled', 'Suspended for an authorized package update; resumes in the restarted agent.'

    def update_failed(self, config):
        self._updating = False
        self.apply(config)

    def _respond_to_open(self, event_fd, pid):
        """Return a permission decision; never resolve a caller-supplied target."""
        if pid == self._pid or self._stop.is_set():
            return _ALLOW
        with self._lock:
            if self._state != 'enforced':
                return _DENY
            relative = ''
            try:
                if pid <= 0:
                    raise ValueError('Unidentified reader; access denied without clearing data')
                info = os.fstat(event_fd)
                target = self._inventory.get((info.st_dev, info.st_ino))
                if not target:
                    raise ValueError('Unrecognized inode; access denied without clearing data')
                relative, path = target
                current = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.geteuid() or info.st_mode & 0o022
                        or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                        or stat.S_ISLNK(current.st_mode) or path.resolve() != path):
                    raise ValueError('Protected path changed; access denied without clearing data')
                os.ftruncate(event_fd, 0)
                os.fsync(event_fd)
                self._findings.append({
                    'type': 'source_cleared_on_open', 'file': relative,
                    'detail': f'Source content cleared after external open by PID {pid} at {datetime.now(timezone.utc).isoformat()}; reinstall required.',
                })
                self._findings = self._findings[-10:]
                # Deny the triggering request as well as clearing the exact file.
                return _DENY
            except Exception as error:
                self._state, self._detail = 'error', str(error)[:300]
                self._findings.append({'type': 'file_open_error', 'file': relative, 'detail': self._detail})
                self._findings = self._findings[-10:]
                return _DENY

    def _listen(self, fd):
        try:
            while not self._stop.is_set():
                if not select.select([fd], [], [], .2)[0]:
                    continue
                try:
                    # No extended-report flags are enabled: read one metadata
                    # record at a time so an error cannot leak later event FDs.
                    data = os.read(fd, _METADATA.size)
                except BlockingIOError:
                    continue
                if not data:
                    raise RuntimeError('File-open event stream closed')
                offset = 0
                while offset + _METADATA.size <= len(data):
                    length, version, _, metadata_length, mask, event_fd, pid = _METADATA.unpack_from(data, offset)
                    try:
                        if version != 3 or length < _METADATA.size or metadata_length < _METADATA.size or offset + length > len(data):
                            raise RuntimeError('Invalid kernel file-open event')
                        if mask & _OVERFLOW:
                            raise RuntimeError('File-open event queue overflow; protection is no longer complete')
                        if event_fd >= 0 and mask & _OPEN_PERM:
                            response = self._respond_to_open(event_fd, pid)
                            os.write(fd, _RESPONSE.pack(event_fd, response))
                    finally:
                        if event_fd >= 0:
                            os.close(event_fd)
                    offset += length
        except Exception as error:
            with self._lock:
                self._state, self._detail = 'error', str(error)[:300]
        finally:
            # Closing the group releases pending permission requests; a failed
            # listener must never be shown as protection active.
            os.close(fd)

    def report(self, config):
        with self._lock:
            if self._state == 'enforced':
                try:
                    for identity, (_, path) in self._inventory.items():
                        info = path.lstat()
                        if ((info.st_dev, info.st_ino) != identity or info.st_nlink != 1 or stat.S_ISLNK(info.st_mode)
                                or info.st_uid != os.geteuid() or info.st_mode & 0o022):
                            raise ValueError('Protected source was replaced or linked; disable the response and reinstall before rearming.')
                except (OSError, ValueError) as error:
                    self._state, self._detail = 'error', str(error)[:300]
            return {'enabled': config.get('erase_code_on_open', False) is True,
                    'supported': self._supported is True, 'state': self._state,
                    'detail': self._detail, 'protectedFiles': len(self._inventory) if self._state == 'enforced' else 0}

    def findings(self):
        with self._lock:
            return [dict(item) for item in self._findings]
