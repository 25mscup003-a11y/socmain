package com.soc.agent;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/** Persistent queue -> batch transport -> positive ACK -> deletion. */
public final class TelemetryPipeline {
    private final JSONObject config;
    private final EventQueue queue;
    private final SecureTransport transport;
    private final String deviceId;
    private final String agentVersion;
    private final AtomicBoolean flushing = new AtomicBoolean(false);
    private volatile long lastSuccessfulUploadMs;
    private volatile long lastUploadAttemptMs;
    private volatile String lastError = "";

    public TelemetryPipeline(JSONObject config, EventQueue queue, SecureTransport transport,
                             String deviceId, String agentVersion) {
        this.config = config;
        this.queue = queue;
        this.transport = transport;
        this.deviceId = deviceId;
        this.agentVersion = agentVersion;
    }

    public boolean enqueue(String ruleId, String category, String severity, String description, JSONObject payload) {
        return queue.enqueue(NormalizedEvent.fromLegacy(
                config, deviceId, agentVersion, ruleId, category, severity, description, payload));
    }

    public boolean flush() {
        if (!flushing.compareAndSet(false, true)) return false;
        try {
            // Bound each wake cycle while still draining bursts faster than one
            // batch per heartbeat.
            for (int batchNumber = 0; batchNumber < 4; batchNumber++) {
                List<EventQueue.Entry> batch = queue.ready(50, System.currentTimeMillis());
                if (batch.isEmpty()) return true;
                lastUploadAttemptMs = System.currentTimeMillis();
                JSONArray alerts = new JSONArray();
                for (EventQueue.Entry entry : batch) {
                    JSONObject alert = new JSONObject(entry.payload.toString());
                    alert.put("agent_key", config.optString("agent_key", ""));
                    alerts.put(alert);
                }
                JSONObject envelope = new JSONObject().put("alerts", alerts);
                SecureTransport.Response response = transport.post("/api/alerts/batch", envelope);
                JSONObject acknowledgement = response.json();
                if (response.status != 207 && response.successful() && acknowledgement.optBoolean("ok", false)) {
                    queue.acknowledge(batch);
                    lastSuccessfulUploadMs = System.currentTimeMillis();
                    lastError = "";
                    continue;
                }
                lastError = "HTTP " + response.status;
                queue.retry(batch);
                return false;
            }
            return true;
        } catch (Exception error) {
            lastError = error.getClass().getSimpleName() + ": " + String.valueOf(error.getMessage());
            List<EventQueue.Entry> due = queue.ready(50, System.currentTimeMillis());
            if (!due.isEmpty()) queue.retry(due);
            return false;
        } finally {
            flushing.set(false);
        }
    }

    public JSONObject health() {
        JSONObject health = new JSONObject();
        try {
            health.put("queue_depth", queue.depth());
            health.put("queue_oldest_age_ms", queue.oldestAgeMs());
            health.put("queue_dropped_events", queue.droppedCount());
            health.put("last_successful_upload", lastSuccessfulUploadMs);
            health.put("last_upload_attempt", lastUploadAttemptMs);
            health.put("connection_state", lastError.isEmpty() ? "ready" : "retrying");
            health.put("last_transport_error", lastError);
        } catch (Exception ignored) {
        }
        return health;
    }
}
