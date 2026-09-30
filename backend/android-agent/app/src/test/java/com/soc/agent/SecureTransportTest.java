package com.soc.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

public class SecureTransportTest {
    @Test
    public void canonicalJsonMatchesBackendOrderingAndNumberRules() throws Exception {
        JSONObject payload = new JSONObject()
                .put("z", new JSONArray().put(3).put("x"))
                .put("risk", 80.0)
                .put("a", new JSONObject().put("b", true).put("a", JSONObject.NULL));

        assertEquals("{\"a\":{\"a\":null,\"b\":true},\"risk\":80,\"z\":[3,\"x\"]}",
                SecureTransport.canonicalize(payload));
    }

    @Test
    public void normalizedEventKeepsBackendFieldsAndRemovesNestedSecretsFromTopLevel() throws Exception {
        JSONObject config = new JSONObject()
                .put("company_id", "company-1")
                .put("system_id", "system-1")
                .put("system_name", "managed-phone");
        JSONObject payload = new JSONObject()
                .put("event_id", "event-1")
                .put("event_type", "process")
                .put("event_time", 1234L)
                .put("password", "must-not-be-flattened");

        JSONObject event = NormalizedEvent.fromLegacy(config, "device-1", "0.1.1", "PROCESS_START",
                "edr", "medium", "process started", payload).json();

        assertEquals("event-1", event.getString("event_id"));
        assertEquals("PROCESS_START", event.getString("rule_id"));
        assertEquals("process", event.getString("event_type"));
        assertEquals("company-1", event.getString("company_id"));
        assertEquals("0.1.1", event.getString("agent_version"));
        assertEquals("0.1.1", event.getString("agentVersion"));
        assertFalse(event.has("password"));
        assertFalse(event.getJSONObject("payload").has("password"));
    }

    @Test
    public void canonicalJsonPreservesAndroidLongVersionCodes() throws Exception {
        JSONObject payload = new JSONObject().put("version_code", Long.MAX_VALUE);

        assertEquals("{\"version_code\":9223372036854775807}", SecureTransport.canonicalize(payload));
    }

    @Test
    public void apiPayloadUsesAes256GcmEnvelope() throws Exception {
        String key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        // android.util.Base64 is a framework API and cannot execute in a plain
        // local JVM test. Verify the protocol and 256-bit KDF here; request
        // envelope interoperability is covered by the backend/Python tests.
        assertEquals("aes-256-gcm-v1", SecureTransport.TRANSPORT_VERSION);
        assertEquals("x-ajnat-payload-encryption", SecureTransport.TRANSPORT_HEADER);
        assertTrue(SecureTransport.transportKey(key).length == 32);
    }
}
