package com.soc.agent;

import android.Manifest;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

/** Policy-gated Android GPS telemetry. Never substitutes IP geolocation. */
public final class GpsLocationCollector implements LocationListener {
    private static final String GPS_STATE_PREFERENCES = "ajnat_gps_state";
    private static final float MIN_MOVEMENT_METERS = 10.0f;
    private final Context context;
    private final JSONObject config;
    private final TelemetryPipeline pipeline;
    private final LocationManager manager;
    private final SharedPreferences state;
    private volatile Location latest;
    private volatile boolean listening;
    private double lastLatitude = Double.NaN;
    private double lastLongitude = Double.NaN;
    private String lastStatus;
    private String lastProvider;
    private String lastPolicyId;
    private int lastPolicyVersion;
    private String lastPolicyAction;

    public GpsLocationCollector(Context context, JSONObject config, TelemetryPipeline pipeline) {
        this.context = context.getApplicationContext();
        this.config = config;
        this.pipeline = pipeline;
        this.manager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        this.state = this.context.getSharedPreferences(GPS_STATE_PREFERENCES, Context.MODE_PRIVATE);
        this.lastStatus = state.getString("status", "");
        this.lastProvider = state.getString("provider", "");
        this.lastPolicyId = state.getString("policy_id", "");
        this.lastPolicyVersion = state.getInt("policy_version", 0);
        this.lastPolicyAction = state.getString("policy_action", "");
        if (state.contains("latitude") && state.contains("longitude")) {
            this.lastLatitude = Double.longBitsToDouble(state.getLong("latitude", 0L));
            this.lastLongitude = Double.longBitsToDouble(state.getLong("longitude", 0L));
        }
    }

    public void applyHeartbeatPolicy(JSONObject heartbeat) {
        JSONObject runtime = heartbeat == null ? null : heartbeat.optJSONObject("config");
        if (runtime == null) runtime = heartbeat;
        if (runtime == null) return;
        try {
            if (runtime.has("gps_tracking_enabled")) {
                config.put("gps_tracking_enabled", runtime.optBoolean("gps_tracking_enabled", false));
            }
            if (runtime.has("gps_collection_interval_seconds")) {
                config.put("gps_collection_interval_seconds", runtime.optInt("gps_collection_interval_seconds", 300));
            }
            if (runtime.has("gps_required_accuracy_meters")) {
                config.put("gps_required_accuracy_meters", runtime.optDouble("gps_required_accuracy_meters", 50));
            }
            for (String key : new String[]{"gps_policy_id", "gps_policy_name", "gps_policy_category", "gps_policy_action", "gps_policy_version"}) {
                if (runtime.has(key)) config.put(key, runtime.get(key));
            }
        } catch (Exception ignored) { }
    }

    public synchronized void collectAndQueue() {
        if (!config.optBoolean("gps_tracking_enabled", false)) {
            stop();
            return;
        }
        if (manager == null || context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            reportStatus("permission_denied", "Android precise-location permission is not granted", null);
            return;
        }
        startListening();
        Location candidate = bestLocation();
        if (candidate == null) {
            reportStatus("sensor_unavailable", "Android GPS/network provider has no location fix", null);
            return;
        }
        double required = Math.max(5.0, Math.min(50.0,
                config.optDouble("gps_required_accuracy_meters", 50.0)));
        if (!candidate.hasAccuracy() || candidate.getAccuracy() > required) {
            reportStatus("inaccurate", "Android location accuracy exceeds the policy limit", candidate);
            return;
        }
        if (!locationChanged(candidate) && !policyChanged()) return;
        JSONObject event = baseEvent("GPS_LOCATION_TELEMETRY", "available", candidate);
        if (pipeline.enqueue("GPS_LOCATION_TELEMETRY", "edr", "low",
                "Device GPS position collected from Android Location Services", event)) {
            rememberState("available", candidate.getProvider(), candidate);
        }
    }

    private void startListening() {
        if (listening) return;
        try {
            long interval = Math.max(30000L, config.optLong("gps_collection_interval_seconds", 300L) * 1000L);
            if (manager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                manager.requestLocationUpdates(LocationManager.GPS_PROVIDER, interval, 0f, this, Looper.getMainLooper());
            }
            if (manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                manager.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, interval, 0f, this, Looper.getMainLooper());
            }
            listening = true;
        } catch (SecurityException denied) {
            listening = false;
        }
    }

    public synchronized void stop() {
        if (!listening || manager == null) return;
        try { manager.removeUpdates(this); } catch (SecurityException ignored) { }
        listening = false;
    }

    private Location bestLocation() {
        Location best = latest;
        for (String provider : new String[]{LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER}) {
            try {
                if (!manager.isProviderEnabled(provider)) continue;
                Location value = manager.getLastKnownLocation(provider);
                if (isBetter(value, best)) best = value;
            } catch (Exception ignored) { }
        }
        if (best != null && System.currentTimeMillis() - best.getTime() > 10L * 60L * 1000L) return null;
        return best;
    }

    private static boolean isBetter(Location candidate, Location current) {
        if (candidate == null) return false;
        if (current == null) return true;
        if (candidate.getTime() > current.getTime() + 120000L) return true;
        return candidate.hasAccuracy() && (!current.hasAccuracy() || candidate.getAccuracy() < current.getAccuracy());
    }

    private void reportStatus(String status, String reason, Location location) {
        String provider = location == null ? "android-location-services" : location.getProvider();
        if (status.equals(lastStatus) && provider.equals(lastProvider) && !policyChanged()) return;
        JSONObject event = baseEvent("GEO_GPS_STATUS", status, location);
        try { event.put("gpsReason", reason); } catch (Exception ignored) { }
        if (pipeline.enqueue("GEO_GPS_STATUS", "edr", "low", "Device GPS unavailable: " + reason, event)) {
            rememberState(status, provider, null);
        }
    }

    private boolean locationChanged(Location location) {
        if (!"available".equals(lastStatus)) return true;
        String provider = location.getProvider() == null ? "android-location-services" : location.getProvider();
        if (!provider.equals(lastProvider)) return true;
        if (!Double.isFinite(lastLatitude) || !Double.isFinite(lastLongitude)) return true;
        float[] distance = new float[1];
        Location.distanceBetween(lastLatitude, lastLongitude,
                location.getLatitude(), location.getLongitude(), distance);
        return distance[0] >= MIN_MOVEMENT_METERS;
    }

    private boolean policyChanged() {
        return !config.optString("gps_policy_id", "").equals(lastPolicyId)
                || config.optInt("gps_policy_version", 0) != lastPolicyVersion
                || !config.optString("gps_policy_action", "").equals(lastPolicyAction);
    }

    private void rememberState(String status, String provider, Location location) {
        lastStatus = status;
        lastProvider = provider == null ? "android-location-services" : provider;
        SharedPreferences.Editor editor = state.edit()
                .putString("status", lastStatus)
                .putString("provider", lastProvider)
                .putString("policy_id", config.optString("gps_policy_id", ""))
                .putInt("policy_version", config.optInt("gps_policy_version", 0))
                .putString("policy_action", config.optString("gps_policy_action", ""));
        lastPolicyId = config.optString("gps_policy_id", "");
        lastPolicyVersion = config.optInt("gps_policy_version", 0);
        lastPolicyAction = config.optString("gps_policy_action", "");
        if (location != null && "available".equals(status)) {
            lastLatitude = location.getLatitude();
            lastLongitude = location.getLongitude();
            editor.putLong("latitude", Double.doubleToRawLongBits(lastLatitude));
            editor.putLong("longitude", Double.doubleToRawLongBits(lastLongitude));
        } else {
            lastLatitude = Double.NaN;
            lastLongitude = Double.NaN;
            editor.remove("latitude").remove("longitude");
        }
        editor.apply();
    }

    private JSONObject baseEvent(String ruleId, String status, Location location) {
        JSONObject event = new JSONObject();
        try {
            long now = System.currentTimeMillis();
            event.put("event_id", "android-gps-" + ruleId + "-" + now);
            event.put("event_time", now);
            event.put("event_type", "device_location");
            event.put("capability_id", 23);
            event.put("capability_ids", new JSONArray().put(23));
            event.put("gpsProvider", location == null ? "android-location-services" : location.getProvider());
            event.put("gpsStatus", status);
            event.put("gpsObservedAt", now);
            event.put("policyId", config.optString("gps_policy_id", ""));
            event.put("policyName", config.optString("gps_policy_name", "AJNAT Device GPS Tracking"));
            event.put("policyCategory", config.optString("gps_policy_category", "Device GPS Tracking"));
            String policyAction = config.optString("gps_policy_action", "LOG & MONITOR");
            event.put("policyAction", policyAction);
            event.put("policyTriggered", true);
            event.put("policyActionStatus", "ALLOW & AUDIT".equalsIgnoreCase(policyAction) ? "allowed" : "logged");
            if (location != null && ("available".equals(status) || "inaccurate".equals(status))) {
                event.put("gpsLat", location.getLatitude());
                event.put("gpsLon", location.getLongitude());
                event.put("geoLat", location.getLatitude());
                event.put("geoLon", location.getLongitude());
                if (location.hasAltitude()) event.put("gpsAltitudeMeters", location.getAltitude());
            }
            event.put("gpsCoordinateQuality", "available".equals(status) ? "precise" : "approximate");
            if (location != null && location.hasAccuracy()) {
                event.put("gpsAccuracyMeters", location.getAccuracy());
            }
        } catch (Exception ignored) { }
        return event;
    }

    @Override public void onLocationChanged(Location location) {
        if (isBetter(location, latest)) {
            latest = location;
            collectAndQueue();
        }
    }
    @Override public void onProviderEnabled(String provider) { }
    @Override public void onProviderDisabled(String provider) { }
    @Override public void onStatusChanged(String provider, int status, Bundle extras) { }
}
