"""
Log Collector — tails system logs in real-time.
- Linux/macOS: tail from end of file on first run, track byte position
- Windows: track RecordNumber per channel, only new events
- NEVER re-reads old lines after restart
"""

from typing import Optional, List, Dict, Any

import os
import time
import platform
import logging
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from core.state import StateManager

logger = logging.getLogger('soc-agent.collector.logs')

SYSTEM = platform.system()
POLL_INTERVAL = 2   # seconds between file polls


# ─── Linux/macOS log files to tail ───────────────────────────────────────────
LINUX_LOG_FILES = [
    '/var/log/syslog',
    '/var/log/auth.log',
    '/var/log/kern.log',
    '/var/log/messages',
    '/var/log/secure',     # RHEL/CentOS
    '/var/log/audit/audit.log',
]

MACOS_LOG_FILES = [
    '/var/log/system.log',
    '/var/log/install.log',
]

WINDOWS_CHANNELS = [
    'Security',
    'System',
    'Application',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-HelloForBusiness/Operational',
    'Microsoft-Windows-Biometrics/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
]


class LogCollector:
    def __init__(self, state: StateManager, on_line):
        """
        state: StateManager instance for position tracking
        on_line: callback(line: str, source: str) called for each new log line
        """
        self._state = state
        self._on_line = on_line
        self._threads: List[threading.Thread] = []

    def start(self):
        if SYSTEM == 'Windows':
            t = threading.Thread(target=self._tail_windows, daemon=True, name='log-win')
            t.start()
            self._threads.append(t)
        elif SYSTEM == 'Darwin':
            self._start_file_tailers(MACOS_LOG_FILES)
            self._start_macos_stream()
        else:  # Linux
            self._start_file_tailers(LINUX_LOG_FILES)
            # Some modern distributions keep authentication events only in
            # journald. Avoid a duplicate stream when auth.log/secure exists.
            if not any(Path(path).exists() for path in ('/var/log/auth.log', '/var/log/secure')):
                self._start_linux_auth_journal()

    # ─── File tail (Linux/macOS) ──────────────────────────────────────────────
    def _start_file_tailers(self, paths: list):
        for path in paths:
            if Path(path).exists():
                t = threading.Thread(
                    target=self._tail_file,
                    args=(path,),
                    daemon=True,
                    name=f'log-{Path(path).name}'
                )
                t.start()
                self._threads.append(t)

    def _tail_file(self, path: str):
        logger.info(f'Tailing {path}')
        try:
            with open(path, 'r', errors='replace') as f:
                # First run: seek to end (skip historical logs)
                saved_pos = self._state.get_file_position(path)
                if saved_pos == -1:
                    f.seek(0, 2)   # seek to end of file
                    self._state.set_file_position(path, f.tell())
                else:
                    # Check if file was rotated (inode changed / file smaller)
                    try:
                        if f.seek(0, 2) < saved_pos:
                            # File rotated. Start at end so pre-install or
                            # archived lines are not replayed as new alerts.
                            self._state.set_file_position(path, f.tell())
                        else:
                            f.seek(saved_pos)
                    except Exception:
                        f.seek(0, 2)

                while True:
                    line = f.readline()
                    if line:
                        self._state.set_file_position(path, f.tell())
                        self._on_line(line.rstrip(), path)
                    else:
                        time.sleep(POLL_INTERVAL)
                        # Re-open if file rotated
                        try:
                            if not Path(path).exists():
                                time.sleep(5)
                                return self._tail_file(path)
                            if Path(path).stat().st_size < f.tell():
                                f.seek(0, 2)
                                self._state.set_file_position(path, f.tell())
                        except OSError:
                            pass
        except PermissionError:
            logger.warning(f'Permission denied: {path}')
        except Exception as e:
            logger.error(f'Log tailer error ({path}): {e}')
            time.sleep(10)
            self._tail_file(path)   # restart on error

    # ─── macOS log stream ─────────────────────────────────────────────────────
    def _start_macos_stream(self):
        def _stream():
            try:
                proc = subprocess.Popen(
                    ['log', 'stream', '--style', 'syslog', '--level', 'info', '--predicate',
                     'process == "loginwindow" OR process == "authd" OR process == "SecurityAgent" OR subsystem CONTAINS[c] "authentication"'],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
                )
                for line in proc.stdout:
                    self._on_line(line.rstrip(), 'macos-log-stream')
            except Exception as e:
                logger.warning(f'macOS log stream error: {e}')
        t = threading.Thread(target=_stream, daemon=True, name='log-macos-stream')
        t.start()
        self._threads.append(t)

    def _start_linux_auth_journal(self):
        if not shutil.which('journalctl'):
            logger.info('No auth.log/secure or journalctl authentication source is available')
            return

        def _stream():
            command = [
                'journalctl', '--follow', '--no-pager', '--lines=0', '--output=short-iso',
                '--unit=ssh.service', '--unit=sshd.service', '--unit=systemd-logind.service',
            ]
            while True:
                try:
                    proc = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                    )
                    if proc.stdout is not None:
                        for line in proc.stdout:
                            self._on_line(line.rstrip(), 'linux/journald-auth')
                    proc.wait()
                except Exception as exc:
                    logger.warning('Linux authentication journal stream error: %s', exc)
                time.sleep(5)

        thread = threading.Thread(target=_stream, daemon=True, name='log-linux-journald-auth')
        thread.start()
        self._threads.append(thread)

    # ─── Windows event log ────────────────────────────────────────────────────
    def _tail_windows(self):
        try:
            import win32evtlog
            import win32con
            try:
                import win32evtlogutil
            except ImportError:
                win32evtlogutil = None
        except ImportError:
            logger.warning('pywin32 not installed — Windows event log unavailable')
            return

        handles = {}
        for channel in WINDOWS_CHANNELS:
            try:
                handles[channel] = win32evtlog.OpenEventLog(None, channel)
            except Exception:
                pass

        logger.info(f'Windows event log monitoring: {list(handles.keys())}')

        while True:
            for channel, handle in handles.items():
                try:
                    last_record = self._state.get_win_cursor(channel)
                    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    if last_record is None:
                        try:
                            oldest = win32evtlog.GetOldestEventLogRecord(handle)
                            count = win32evtlog.GetNumberOfEventLogRecords(handle)
                            newest = oldest + count - 1 if count else 0
                            if newest:
                                self._state.set_win_cursor(channel, newest)
                            continue
                        except Exception:
                            pass

                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        continue
                    new_cursor = last_record
                    for ev in events:
                        rec_no = ev.RecordNumber
                        # Skip events we've already seen
                        if last_record is not None and rec_no <= last_record:
                            continue
                        new_cursor = max(new_cursor or 0, rec_no)
                        ts = ev.TimeGenerated.isoformat() if ev.TimeGenerated else ''
                        if win32evtlogutil:
                            try:
                                msg = win32evtlogutil.SafeFormatMessage(ev, channel)
                            except Exception:
                                msg = str(ev.StringInserts or '')
                        else:
                            msg = str(ev.StringInserts or '')
                        # Security event messages do not contain the submitted
                        # password/PIN. Preserve enough structured text to parse
                        # logon type, target account, status and failure reason.
                        event_id = int(ev.EventID) & 0xFFFF
                        line = f'{ts} [{channel}] EventID={event_id} {msg[:4000]}'
                        self._on_line(line, f'windows/{channel}')
                    if new_cursor and new_cursor != last_record:
                        self._state.set_win_cursor(channel, new_cursor)
                except Exception as e:
                    logger.debug(f'Windows log read error ({channel}): {e}')
            time.sleep(POLL_INTERVAL)
