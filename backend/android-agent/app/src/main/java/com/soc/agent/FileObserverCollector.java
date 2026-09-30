package com.soc.agent;

import android.content.Context;
import android.os.Environment;
import android.os.FileObserver;

import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/** Event-driven monitoring limited to storage paths legitimately visible to this app. */
public final class FileObserverCollector {
    private final Context context;
    private final TelemetryPipeline pipeline;
    private final List<FileObserver> observers = new ArrayList<>();

    public FileObserverCollector(Context context, TelemetryPipeline pipeline) {
        this.context = context.getApplicationContext();
        this.pipeline = pipeline;
    }

    public synchronized int start() {
        stop();
        ArrayList<File> roots = new ArrayList<>();
        File appExternal = context.getExternalFilesDir(null);
        if (appExternal != null) roots.add(appExternal);
        if (android.os.Build.VERSION.SDK_INT < 30 || Environment.isExternalStorageManager()) {
            roots.add(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS));
        }
        for (File root : roots) {
            if (root == null) continue;
            if (!root.exists()) root.mkdirs();
            if (!root.isDirectory() || !root.canRead()) continue;
            FileObserver observer = createObserver(root);
            observer.startWatching();
            observers.add(observer);
        }
        return observers.size();
    }

    public synchronized void stop() {
        for (FileObserver observer : observers) observer.stopWatching();
        observers.clear();
    }

    @SuppressWarnings("deprecation")
    private FileObserver createObserver(final File root) {
        // CLOSE_WRITE represents a completed write. Listening to MODIFY as well
        // creates many duplicate database rows while an application is writing.
        int mask = FileObserver.CREATE | FileObserver.DELETE
                | FileObserver.MOVED_FROM | FileObserver.MOVED_TO | FileObserver.CLOSE_WRITE;
        return new FileObserver(root.getAbsolutePath(), mask) {
            @Override
            public void onEvent(int rawEvent, String relativePath) {
                int event = rawEvent & FileObserver.ALL_EVENTS;
                String operation = operation(event);
                if (operation == null) return;
                File target = relativePath == null ? root : new File(root, relativePath);
                JSONObject payload = new JSONObject();
                try {
                    payload.put("event_type", "file");
                    payload.put("event_subtype", operation);
                    payload.put("file_action", operation);
                    payload.put("file_path", target.getAbsolutePath());
                    payload.put("file_name", target.getName());
                    payload.put("file_size", target.isFile() ? target.length() : 0L);
                    payload.put("event_time", System.currentTimeMillis());
                } catch (Exception ignored) { }
                pipeline.enqueue("ANDROID_FILE_" + operation.toUpperCase(), "file", "low",
                        "Android visible file " + operation + ": " + target.getName(), payload);
            }
        };
    }

    private static String operation(int event) {
        if (event == FileObserver.CREATE) return "create";
        if (event == FileObserver.DELETE) return "delete";
        if (event == FileObserver.MOVED_FROM) return "move_from";
        if (event == FileObserver.MOVED_TO) return "move_to";
        if (event == FileObserver.CLOSE_WRITE) return "close_write";
        return null;
    }
}
