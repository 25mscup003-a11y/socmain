"""Restart-safe SQLite spool for alert delivery.

Pending events are committed before entering the in-memory priority queue. Failed
events receive a bounded retry count and are moved to a local dead-letter table
instead of disappearing when the process exits or the queue is saturated.
"""

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable, List

from .aes256 import AES256GCM


class DurableSpool:
    def __init__(self, path, max_attempts: int = 20, encryption_key: str = ''):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_attempts = max(1, int(max_attempts))
        self._cipher = AES256GCM(encryption_key, 'durable-spool')
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute('PRAGMA journal_mode=WAL')
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('PRAGMA busy_timeout=10000')
            self._db.executescript('''
                CREATE TABLE IF NOT EXISTS pending_events (
                    event_id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    last_error TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS pending_due_idx
                    ON pending_events(next_attempt_at, created_at);
                CREATE TABLE IF NOT EXISTS dead_letter_events (
                    event_id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    failed_at REAL NOT NULL,
                    last_error TEXT NOT NULL
                );
            ''')
            columns = {row[1] for row in self._db.execute('PRAGMA table_info(pending_events)').fetchall()}
            if 'coalesce_key' not in columns:
                self._db.execute("ALTER TABLE pending_events ADD COLUMN coalesce_key TEXT NOT NULL DEFAULT ''")
            self._db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS pending_coalesce_idx
                                ON pending_events(coalesce_key)
                                WHERE coalesce_key != '' ''')
            self._db.commit()

    def put(self, alert: dict, coalesce_key: str = '') -> bool:
        event_id = str(alert.get('event_id') or '')
        if not event_id:
            raise ValueError('event_id is required for durable delivery')
        encoded = self._encode(alert)
        with self._lock:
            key = str(coalesce_key or '')
            if key:
                existing = self._db.execute(
                    'SELECT event_id FROM pending_events WHERE coalesce_key = ?', (key,)
                ).fetchone()
                if existing:
                    event_id = str(existing['event_id'])
                    alert['event_id'] = event_id
                    encoded = self._encode(alert)
                    self._db.execute(
                        '''UPDATE pending_events
                           SET severity = ?, payload = ?, attempts = 0,
                               next_attempt_at = 0, created_at = ?, last_error = ''
                           WHERE event_id = ?''',
                        (str(alert.get('severity') or 'medium'), encoded, time.time(), event_id),
                    )
                    self._db.commit()
                    return True
            cursor = self._db.execute(
                '''INSERT OR IGNORE INTO pending_events
                   (event_id, severity, payload, created_at, coalesce_key)
                   VALUES (?, ?, ?, ?, ?)''',
                (event_id, str(alert.get('severity') or 'medium'), encoded, time.time(), key),
            )
            self._db.commit()
            return cursor.rowcount == 1

    def collapse_rule(self, rule_id: str, coalesce_key: str) -> int:
        """Collapse legacy periodic snapshots, preserving individual state changes."""
        with self._lock:
            candidates = self._db.execute(
                'SELECT event_id, payload FROM pending_events ORDER BY created_at DESC'
            ).fetchall()
            rows = []
            for row in candidates:
                alert = self._decode(row['payload'])
                raw = alert.get('raw') if isinstance(alert.get('raw'), dict) else {}
                if alert.get('rule_id') == str(rule_id) and raw.get('reporting_mode') != 'on_change':
                    rows.append(row)
            if not rows:
                return 0
            keep = str(rows[0]['event_id'])
            stale = [str(row['event_id']) for row in rows[1:]]
            if stale:
                placeholders = ','.join('?' for _ in stale)
                self._db.execute(f'DELETE FROM pending_events WHERE event_id IN ({placeholders})', stale)
            self._db.execute(
                'UPDATE pending_events SET coalesce_key = ? WHERE event_id = ?',
                (str(coalesce_key), keep),
            )
            self._db.commit()
            return len(stale)

    def due(self, limit: int = 100, now: float = None) -> List[dict]:
        at = time.time() if now is None else float(now)
        with self._lock:
            rows = self._db.execute(
                '''SELECT payload FROM pending_events
                   WHERE next_attempt_at <= ?
                   ORDER BY CASE severity
                       WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                       WHEN 'medium' THEN 2 ELSE 3 END, created_at
                   LIMIT ?''',
                (at, max(1, int(limit))),
            ).fetchall()
        return [self._decode(row['payload']) for row in rows]

    def _encode(self, alert: dict) -> str:
        plaintext = json.dumps(alert, separators=(',', ':'), sort_keys=True, default=str)
        return self._cipher.encrypt(plaintext)

    def _decode(self, payload: str) -> dict:
        return json.loads(self._cipher.decrypt(payload))

    def acknowledge(self, event_ids: Iterable[str]) -> int:
        ids = [str(value) for value in event_ids if value]
        if not ids:
            return 0
        placeholders = ','.join('?' for _ in ids)
        with self._lock:
            cursor = self._db.execute(
                f'DELETE FROM pending_events WHERE event_id IN ({placeholders})', ids
            )
            self._db.commit()
            return cursor.rowcount

    def fail(self, event_id: str, error: str, delay_seconds: float) -> str:
        """Record a failure and return ``pending``, ``dead_letter`` or ``missing``."""
        with self._lock:
            row = self._db.execute(
                'SELECT * FROM pending_events WHERE event_id = ?', (str(event_id),)
            ).fetchone()
            if not row:
                return 'missing'
            attempts = int(row['attempts']) + 1
            message = str(error or 'delivery failed')[:1000]
            if attempts >= self.max_attempts:
                self._db.execute(
                    '''INSERT OR REPLACE INTO dead_letter_events
                       (event_id, severity, payload, attempts, failed_at, last_error)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (row['event_id'], row['severity'], row['payload'], attempts, time.time(), message),
                )
                self._db.execute('DELETE FROM pending_events WHERE event_id = ?', (row['event_id'],))
                self._db.commit()
                return 'dead_letter'
            self._db.execute(
                '''UPDATE pending_events
                   SET attempts = ?, next_attempt_at = ?, last_error = ?
                   WHERE event_id = ?''',
                (attempts, time.time() + max(0, float(delay_seconds)), message, row['event_id']),
            )
            self._db.commit()
            return 'pending'

    def counts(self) -> dict:
        with self._lock:
            pending = self._db.execute('SELECT COUNT(*) FROM pending_events').fetchone()[0]
            dead = self._db.execute('SELECT COUNT(*) FROM dead_letter_events').fetchone()[0]
        return {'pending': pending, 'dead_letter': dead}

    def close(self):
        with self._lock:
            self._db.close()
