package com.soc.agent;

import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.hardware.usb.UsbManager;
import android.net.TrafficStats;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Coordinates event-driven Android collectors and optional native AOSP telemetry. */
public final class CollectorManager {
    private static final String PREFS = "ajnat_collector_state";
    private static final String APP_PREFIX = "app:";
    private static final String APP_BASELINE_COMPLETE = "app_baseline_complete_v1";
    private static final long INVENTORY_INTERVAL_MS = 60L * 60L * 1000L;
    private static final long HEALTH_INTERVAL_MS = 5L * 60L * 1000L;

    private final Context context;
    private final TelemetryPipeline pipeline;
    private final NativeDaemonClient daemon;
    private final CapabilityDetector capabilities;
    private final FileObserverCollector fileObserver;
    private final UsbEventReceiver usbReceiver;
    private long lastInventoryMs;
    private long lastHealthMs;
    private int fileWatchCount;
    private boolean usbRegistered;
    private volatile String inventoryStatus = "not_started";
    private volatile String nativeStatus = "not_started";

    public CollectorManager(Context context, TelemetryPipeline pipeline,
                            NativeDaemonClient daemon, CapabilityDetector capabilities) {
        this.context = context.getApplicationContext();
        this.pipeline = pipeline;
        this.daemon = daemon;
        this.capabilities = capabilities;
        this.fileObserver = new FileObserverCollector(context, pipeline);
        this.usbReceiver = new UsbEventReceiver((action, payload) -> pipeline.enqueue(
                "ANDROID_USB_DEVICE_EVENT", "usb", "low",
                "Android USB device " + payload.optString("event_subtype", "change"), payload));
    }

    public void start() {
        try {
            fileWatchCount = fileObserver.start();
        } catch (Exception ignored) {
            fileWatchCount = 0;
        }
        try {
            IntentFilter usb = new IntentFilter();
            usb.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
            usb.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
            if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(usbReceiver, usb, Context.RECEIVER_NOT_EXPORTED);
            else context.registerReceiver(usbReceiver, usb);
            usbRegistered = true;
        } catch (Exception ignored) {
            usbRegistered = false;
        }
    }

    public void stop() {
        fileObserver.stop();
        if (usbRegistered) {
            try { context.unregisterReceiver(usbReceiver); } catch (Exception ignored) { }
        }
        usbRegistered = false;
    }

    public void collectPeriodic() {
        long now = System.currentTimeMillis();
        if (now - lastInventoryMs >= INVENTORY_INTERVAL_MS) {
            try {
                collectApplicationDeltas();
                inventoryStatus = "running";
            } catch (Exception error) {
                inventoryStatus = "failed:" + error.getClass().getSimpleName();
            }
            lastInventoryMs = now;
        }
        try {
            collectNativeEvents();
            nativeStatus = daemon.isAvailable() ? "running" : "capability_unavailable";
        } catch (Exception error) {
            nativeStatus = "failed:" + error.getClass().getSimpleName();
        }
        if (now - lastHealthMs >= HEALTH_INTERVAL_MS) {
            emitHealth();
            lastHealthMs = now;
        }
    }

    private void collectApplicationDeltas() {
        PackageManager manager = context.getPackageManager();
        Context storage = Build.VERSION.SDK_INT >= 24
                ? context.createDeviceProtectedStorageContext() : context;
        SharedPreferences prefs = storage.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        boolean baselineComplete = prefs.getBoolean(APP_BASELINE_COMPLETE, false);
        Map<String, String> current = new HashMap<>();
        List<PackageInfo> packages = manager.getInstalledPackages(0);
        for (PackageInfo info : packages) {
            long version = Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode;
            String fingerprint = version + ":" + info.lastUpdateTime;
            current.put(info.packageName, fingerprint);
            String old = prefs.getString(APP_PREFIX + info.packageName, null);
            if (fingerprint.equals(old)) continue;
            String operation = old == null ? (baselineComplete ? "install" : "inventory") : "update";
            JSONObject payload = packagePayload(manager, info, operation);
            payload = withEventId(payload, "android-app-" + operation + "-" + info.packageName
                    + "-" + fingerprint);
            pipeline.enqueue("inventory".equals(operation) ? "ANDROID_APP_INVENTORY"
                            : (old == null ? "ANDROID_APP_INSTALLED" : "ANDROID_APP_UPDATED"),
                    "edr", "low", "Android application " + payload.optString("event_subtype")
                            + ": " + info.packageName, payload);
        }

        Set<String> previous = new HashSet<>();
        for (String key : prefs.getAll().keySet()) if (key.startsWith(APP_PREFIX)) previous.add(key.substring(APP_PREFIX.length()));
        SharedPreferences.Editor editor = prefs.edit();
        for (String removed : previous) {
            if (current.containsKey(removed)) continue;
            JSONObject payload = new JSONObject();
            try {
                payload.put("event_type", "application");
                payload.put("event_subtype", "remove");
                payload.put("package_name", removed);
                payload.put("event_time", System.currentTimeMillis());
                payload.put("event_id", "android-app-remove-" + removed + "-"
                        + String.valueOf(prefs.getString(APP_PREFIX + removed, "unknown")).hashCode());
            } catch (Exception ignored) { }
            pipeline.enqueue("ANDROID_APP_REMOVED", "edr", "low", "Android application removed: " + removed, payload);
            editor.remove(APP_PREFIX + removed);
        }
        for (Map.Entry<String, String> entry : current.entrySet()) editor.putString(APP_PREFIX + entry.getKey(), entry.getValue());
        editor.putBoolean(APP_BASELINE_COMPLETE, true);
        editor.apply();
    }

    private JSONObject packagePayload(PackageManager manager, PackageInfo info, String operation) {
        JSONObject payload = new JSONObject();
        try {
            ApplicationInfo app = info.applicationInfo;
            payload.put("event_type", "application");
            payload.put("event_subtype", operation);
            payload.put("package_name", info.packageName);
            payload.put("application_label", app == null ? info.packageName : manager.getApplicationLabel(app));
            payload.put("version_name", info.versionName);
            payload.put("version_code", Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode);
            payload.put("system_application", app != null && (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
            payload.put("event_time", System.currentTimeMillis());
        } catch (Exception ignored) { }
        return payload;
    }

    private static JSONObject withEventId(JSONObject payload, String eventId) {
        try { payload.put("event_id", eventId); } catch (Exception ignored) { }
        return payload;
    }

    private void collectNativeEvents() {
        JSONArray events = daemon.peek(50);
        if (events == null) return;
        int accepted = 0;
        for (int i = 0; i < events.length(); i++) {
            JSONObject nativeEvent = events.optJSONObject(i);
            if (nativeEvent == null) break;
            enrichUidPackages(nativeEvent);
            String type = nativeEvent.optString("event_type", "security");
            if (!pipeline.enqueue("ANDROID_NATIVE_" + type.toUpperCase(), type, "low",
                    "Authorized AOSP native telemetry: " + nativeEvent.optString("event_subtype", type), nativeEvent)) break;
            accepted++;
        }
        if (accepted > 0) daemon.acknowledge(accepted);
    }

    private void enrichUidPackages(JSONObject nativeEvent) {
        try {
            JSONObject payload = nativeEvent.optJSONObject("payload");
            if (payload == null) return;
            int uid = payload.optInt("uid", -1);
            if (uid < 0) return;
            String[] packages = context.getPackageManager().getPackagesForUid(uid);
            if (packages == null || packages.length == 0) return;
            JSONArray names = new JSONArray();
            for (String packageName : packages) names.put(packageName);
            payload.put("packages", names);
            if (packages.length == 1) payload.put("package_name", packages[0]);
        } catch (Exception ignored) { }
    }

    private void emitHealth() {
        JSONObject payload = new JSONObject();
        try {
            payload.put("event_type", "agent_health");
            payload.put("event_subtype", "collector_status");
            payload.put("event_time", System.currentTimeMillis());
            payload.put("capability", capabilities.report());
            payload.put("file_watch_roots", fileWatchCount);
            payload.put("queue", pipeline.health());
            payload.put("agent_uid_tx_bytes", TrafficStats.getUidTxBytes(android.os.Process.myUid()));
            payload.put("agent_uid_rx_bytes", TrafficStats.getUidRxBytes(android.os.Process.myUid()));
        } catch (Exception ignored) { }
        pipeline.enqueue("ANDROID_AGENT_HEALTH", "system", "low", "Android agent health report", payload);
    }

    public JSONObject health() {
        JSONObject result = new JSONObject();
        try {
            result.put("file_observer", fileWatchCount > 0 ? "running" : "capability_unavailable");
            result.put("application_inventory", inventoryStatus);
            result.put("usb_receiver", usbRegistered ? "running" : "capability_unavailable");
            result.put("native_daemon", nativeStatus);
        } catch (Exception ignored) { }
        return result;
    }
}
