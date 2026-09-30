package com.soc.agent;

import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

/** Canonical event envelope with legacy alert fields retained for backend compatibility. */
public final class NormalizedEvent {
    public static final int SCHEMA_VERSION = 1;
    private final JSONObject value;

    private NormalizedEvent(JSONObject value) {
        this.value = value;
    }

    public static NormalizedEvent fromLegacy(
            JSONObject config,
            String deviceId,
            String agentVersion,
            String ruleId,
            String category,
            String severity,
            String description,
            JSONObject payload) {
        JSONObject safePayload = payload == null ? new JSONObject() : sanitizeObject(payload);
        long eventTime = safePayload.optLong("event_time", System.currentTimeMillis());
        String eventId = safePayload.optString("event_id", "");
        if (eventId.isEmpty()) eventId = "android-" + UUID.randomUUID();
        String eventType = normalizeType(safePayload.optString("event_type", category));
        String eventSubtype = safePayload.optString("event_subtype", ruleId);

        JSONObject event = new JSONObject();
        try {
            event.put("event_id", eventId);
            event.put("schema_version", SCHEMA_VERSION);
            event.put("event_type", eventType);
            event.put("event_subtype", eventSubtype);
            event.put("timestamp", iso8601(eventTime));
            event.put("event_time", eventTime);
            event.put("device_id", deviceId);
            event.put("agent_id", deviceId);
            event.put("agent_version", agentVersion == null ? "unknown" : agentVersion);
            event.put("agentVersion", agentVersion == null ? "unknown" : agentVersion);
            event.put("company_id", config.optString("company_id", ""));
            event.put("system_id", config.optString("system_id", ""));
            event.put("system_name", config.optString("system_name", Build.MODEL));
            event.put("source", "android-agent");
            event.put("severity", normalizeSeverity(severity));
            event.put("payload", new JSONObject(safePayload.toString()));

            // Existing AJNAT alert ingestion fields remain unchanged.
            event.put("rule_id", ruleId);
            event.put("type", ruleId);
            event.put("category", category);
            event.put("description", description);
            event.put("raw_log", safePayload.toString());
            event.put("os", "Android");
            Iterator<String> keys = safePayload.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                if (!isSensitive(key)) event.put(key, safePayload.opt(key));
            }
        } catch (Exception error) {
            throw new IllegalArgumentException("Unable to normalize Android event", error);
        }
        return new NormalizedEvent(event);
    }

    public JSONObject json() {
        try {
            return new JSONObject(value.toString());
        } catch (org.json.JSONException impossibleForExistingObject) {
            throw new IllegalStateException("Unable to copy normalized event", impossibleForExistingObject);
        }
    }

    public String id() {
        return value.optString("event_id", "");
    }

    private static String normalizeType(String value) {
        String lower = String.valueOf(value).toLowerCase(Locale.US);
        if (lower.contains("file")) return "file";
        if (lower.contains("network") || lower.contains("connection")) return "network";
        if (lower.contains("process")) return "process";
        if (lower.contains("app") || lower.contains("package")) return "application";
        if (lower.contains("usb")) return "usb";
        if (lower.contains("health")) return "agent_health";
        if (lower.contains("device") || lower.contains("snapshot")) return "device";
        return "security";
    }

    private static String normalizeSeverity(String value) {
        String severity = String.valueOf(value).toLowerCase(Locale.US);
        return new JSONArray().put("low").put("medium").put("high").put("critical").toString().contains("\"" + severity + "\"")
                ? severity : "low";
    }

    private static boolean isSensitive(String key) {
        String lower = key == null ? "" : key.toLowerCase(Locale.US);
        return lower.contains("password") || lower.contains("secret") || lower.contains("token")
                || lower.contains("private_key") || lower.contains("authorization");
    }

    private static JSONObject sanitizeObject(JSONObject input) {
        JSONObject result = new JSONObject();
        Iterator<String> keys = input.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (isSensitive(key)) continue;
            try {
                result.put(key, sanitizeValue(input.opt(key)));
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static Object sanitizeValue(Object value) {
        if (value instanceof JSONObject) return sanitizeObject((JSONObject) value);
        if (value instanceof JSONArray) {
            JSONArray input = (JSONArray) value;
            JSONArray result = new JSONArray();
            for (int i = 0; i < input.length(); i++) result.put(sanitizeValue(input.opt(i)));
            return result;
        }
        return value;
    }

    private static String iso8601(long timestamp) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(timestamp));
    }
}
