package com.soc.agent;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/** Narrow line-oriented IPC client for the AOSP ajnatd init service. */
public final class NativeDaemonClient {
    private static final String SOCKET_NAME = "ajnatd";
    private static final int MAX_RESPONSE_CHARS = 1024 * 1024;

    public boolean isAvailable() {
        JSONObject response = request("PING");
        return response != null && response.optBoolean("ok", false);
    }

    public JSONObject capabilities() {
        JSONObject response = request("CAPABILITIES");
        if (response == null) return null;
        JSONObject capabilities = response.optJSONObject("capabilities");
        if (capabilities == null) return null;
        try {
            capabilities.put("native_queue_depth", response.optLong("queue_depth", 0L));
            capabilities.put("native_queue_dropped", response.optLong("dropped", 0L));
        } catch (Exception ignored) { }
        return capabilities;
    }

    public JSONArray peek(int limit) {
        JSONObject response = request("PEEK " + Math.max(1, Math.min(100, limit)));
        return response == null ? new JSONArray() : response.optJSONArray("events");
    }

    public boolean acknowledge(int count) {
        JSONObject response = request("ACKCOUNT " + Math.max(0, Math.min(100, count)));
        return response != null && response.optBoolean("ok", false);
    }

    private JSONObject request(String command) {
        LocalSocket socket = new LocalSocket();
        try {
            socket.connect(new LocalSocketAddress(SOCKET_NAME, LocalSocketAddress.Namespace.RESERVED));
            socket.setSoTimeout(2000);
            OutputStreamWriter writer = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8);
            writer.write(command);
            writer.write('\n');
            writer.flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String line = reader.readLine();
            if (line == null || line.length() > MAX_RESPONSE_CHARS) return null;
            return new JSONObject(line);
        } catch (Exception ignored) {
            return null;
        } finally {
            try { socket.close(); } catch (Exception ignored) { }
        }
    }
}
