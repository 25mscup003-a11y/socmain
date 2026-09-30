package com.soc.agent;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Build;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/** Crash-safe bounded queue. Rows are removed only after a positive server ACK. */
public final class EventQueue extends SQLiteOpenHelper {
    private static final String DATABASE = "ajnat-telemetry.db";
    private static final int VERSION = 2;
    private static final int MAX_EVENTS = 10000;

    public static final class Entry {
        public final String id;
        public final JSONObject payload;
        public final int attempts;

        Entry(String id, JSONObject payload, int attempts) {
            this.id = id;
            this.payload = payload;
            this.attempts = attempts;
        }
    }

    public EventQueue(Context context) {
        super(storageContext(context), DATABASE, null, VERSION);
        setWriteAheadLoggingEnabled(true);
    }

    private static Context storageContext(Context context) {
        Context app = context.getApplicationContext();
        return Build.VERSION.SDK_INT >= 24 ? app.createDeviceProtectedStorageContext() : app;
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_ms INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_ms INTEGER NOT NULL DEFAULT 0)");
        db.execSQL("CREATE INDEX events_due ON events(next_attempt_ms, created_ms)");
        db.execSQL("CREATE TABLE queue_meta (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 2) {
            db.execSQL("CREATE TABLE IF NOT EXISTS queue_meta (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)");
        }
    }

    public synchronized boolean enqueue(NormalizedEvent event) {
        ContentValues values = new ContentValues();
        values.put("event_id", event.id());
        values.put("payload", event.json().toString());
        values.put("created_ms", System.currentTimeMillis());
        long inserted = getWritableDatabase().insertWithOnConflict("events", null, values, SQLiteDatabase.CONFLICT_IGNORE);
        trimToBound();
        // A duplicate event ID is already durable, so collectors may safely ACK
        // their upstream spool instead of getting permanently stuck on replay.
        return inserted != -1 || contains(event.id());
    }

    public synchronized List<Entry> ready(int limit, long now) {
        ArrayList<Entry> result = new ArrayList<>();
        try (Cursor cursor = getReadableDatabase().query(
                "events", new String[]{"event_id", "payload", "attempts"},
                "next_attempt_ms<=?", new String[]{String.valueOf(now)},
                null, null, "created_ms ASC", String.valueOf(Math.max(1, Math.min(50, limit))))) {
            while (cursor.moveToNext()) {
                try {
                    result.add(new Entry(cursor.getString(0), new JSONObject(cursor.getString(1)), cursor.getInt(2)));
                } catch (Exception malformed) {
                    getWritableDatabase().delete("events", "event_id=?", new String[]{cursor.getString(0)});
                }
            }
        }
        return result;
    }

    public synchronized void acknowledge(List<Entry> entries) {
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            for (Entry entry : entries) db.delete("events", "event_id=?", new String[]{entry.id});
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized void retry(List<Entry> entries) {
        SQLiteDatabase db = getWritableDatabase();
        long now = System.currentTimeMillis();
        db.beginTransaction();
        try {
            for (Entry entry : entries) {
                int attempts = Math.min(20, entry.attempts + 1);
                long base = Math.min(15L * 60L * 1000L, 5000L * (1L << Math.min(8, attempts - 1)));
                long jitter = ThreadLocalRandom.current().nextLong(Math.max(1L, base / 4L));
                ContentValues values = new ContentValues();
                values.put("attempts", attempts);
                values.put("next_attempt_ms", now + base + jitter);
                db.update("events", values, "event_id=?", new String[]{entry.id});
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized int depth() {
        return (int) android.database.DatabaseUtils.queryNumEntries(getReadableDatabase(), "events");
    }

    public synchronized long oldestAgeMs() {
        try (Cursor cursor = getReadableDatabase().rawQuery("SELECT MIN(created_ms) FROM events", null)) {
            if (cursor.moveToFirst() && !cursor.isNull(0)) return Math.max(0L, System.currentTimeMillis() - cursor.getLong(0));
        }
        return 0L;
    }

    public synchronized long droppedCount() {
        try (Cursor cursor = getReadableDatabase().query(
                "queue_meta", new String[]{"value"}, "name='dropped'",
                null, null, null, null, "1")) {
            return cursor.moveToFirst() ? cursor.getLong(0) : 0L;
        }
    }

    private boolean contains(String eventId) {
        try (Cursor cursor = getReadableDatabase().query(
                "events", new String[]{"event_id"}, "event_id=?",
                new String[]{eventId}, null, null, null, "1")) {
            return cursor.moveToFirst();
        }
    }

    private void trimToBound() {
        long overflow = android.database.DatabaseUtils.queryNumEntries(getReadableDatabase(), "events") - MAX_EVENTS;
        if (overflow <= 0) return;
        SQLiteDatabase db = getWritableDatabase();
        db.execSQL(
                "DELETE FROM events WHERE event_id IN (SELECT event_id FROM events ORDER BY created_ms ASC LIMIT ?)",
                new Object[]{overflow});
        db.execSQL("INSERT OR IGNORE INTO queue_meta(name, value) VALUES('dropped', 0)");
        db.execSQL("UPDATE queue_meta SET value=value+? WHERE name='dropped'", new Object[]{overflow});
    }
}
