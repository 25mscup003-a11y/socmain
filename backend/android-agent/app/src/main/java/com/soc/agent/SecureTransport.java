package com.soc.agent;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.Date;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

/** HTTPS transport compatible with backend canonical HMAC request authentication. */
public final class SecureTransport {
    static final String TRANSPORT_VERSION = "aes-256-gcm-v1";
    static final String TRANSPORT_HEADER = "x-ajnat-payload-encryption";
    static final String SYSTEM_HEADER = "x-agent-system-id";
    private static final byte[] KEY_DOMAIN = "AJNAT-AGENT-API-AES-256-GCM-V1\u0000".getBytes(StandardCharsets.UTF_8);
    private static final byte[] REQUEST_AAD = "AJNAT-AGENT-API-REQUEST-V1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE_AAD = "AJNAT-AGENT-API-RESPONSE-V1".getBytes(StandardCharsets.UTF_8);

    public static final class Response {
        public final int status;
        public final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public boolean successful() {
            return status >= 200 && status < 300;
        }

        public JSONObject json() {
            try {
                return body == null || body.isEmpty() ? new JSONObject() : new JSONObject(body);
            } catch (Exception ignored) {
                return new JSONObject();
            }
        }
    }

    private final Context context;
    private final JSONObject config;
    private final javax.net.ssl.SSLSocketFactory sslSocketFactory;
    private String clientCertificateFingerprint = "";

    public SecureTransport(Context context, JSONObject config) {
        this.context = context.getApplicationContext();
        this.config = config;
        this.sslSocketFactory = createSocketFactory();
    }

    public Response post(String path, JSONObject body) throws Exception {
        JSONObject envelope = encryptPayload(body, config.optString("agent_key", ""));
        byte[] payload = envelope.toString().getBytes(StandardCharsets.UTF_8);
        HttpURLConnection connection = open(path, "POST", envelope, payload);
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");
        try (OutputStream output = connection.getOutputStream()) {
            output.write(payload);
        }
        return readResponse(connection);
    }

    public HttpURLConnection openDownload(String absoluteUrl) throws Exception {
        return openAbsolute(absoluteUrl, "GET", new JSONObject(), null);
    }

    public boolean enrollClientCertificate() throws Exception {
        if (!config.optBoolean("mtls_auto_enroll", false)) return false;
        String base = config.optString("server_url", "").replaceAll("/+$", "");
        if (!base.toLowerCase(java.util.Locale.ROOT).startsWith("https://")) {
            if (config.optBoolean("mtls_required", false)) {
                throw new SecurityException("AJNAT mTLS requires HTTPS");
            }
            return false;
        }
        if (clientCertificateFingerprint.isEmpty()) {
            throw new SecurityException("AJNAT Android client certificate is unavailable");
        }
        JSONObject body = new JSONObject()
                .put("agent_key", config.optString("agent_key", ""))
                .put("system_id", config.optString("system_id", ""))
                .put("certificate_fingerprint256", clientCertificateFingerprint);
        Response response = post("/api/agent/certificate/enroll", body);
        if (!response.successful()) {
            throw new SecurityException("AJNAT mTLS enrollment rejected with HTTP " + response.status);
        }
        String confirmed = response.json().optString("fingerprint256", "");
        if (!clientCertificateFingerprint.equalsIgnoreCase(confirmed)) {
            throw new SecurityException("AJNAT server confirmed a different client certificate");
        }
        return true;
    }

    private HttpURLConnection open(String path, String method, JSONObject body, byte[] wirePayload) throws Exception {
        String base = config.optString("server_url", "").replaceAll("/+$", "");
        if (base.isEmpty()) throw new IllegalStateException("AJNAT server_url is not configured");
        return openAbsolute(base + path, method, body, wirePayload);
    }

    private HttpURLConnection openAbsolute(String value, String method, JSONObject body, byte[] wirePayload) throws Exception {
        URL url = new URL(value);
        boolean tlsRequired = config.optBoolean("require_tls", true);
        if (tlsRequired && !"https".equalsIgnoreCase(url.getProtocol())) {
            throw new SecurityException("Refusing plaintext AJNAT transport");
        }
        if ("http".equalsIgnoreCase(url.getProtocol())
                && (!config.optBoolean("allow_cleartext_test", false) || !isLocalTestHost(url.getHost()))) {
            throw new SecurityException("Plaintext AJNAT transport is restricted to local test hosts");
        }
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(30000);
        connection.setUseCaches(false);
        connection.setRequestProperty("Accept", "application/json");
        String systemId = config.optString("system_id", "").trim();
        if (systemId.isEmpty()) throw new IllegalStateException("AJNAT system_id is required for encrypted API transport");
        connection.setRequestProperty(TRANSPORT_HEADER, TRANSPORT_VERSION);
        connection.setRequestProperty(SYSTEM_HEADER, systemId);
        sign(connection, body == null ? new JSONObject() : body, wirePayload);
        if (connection instanceof HttpsURLConnection && sslSocketFactory != null) {
            ((HttpsURLConnection) connection).setSSLSocketFactory(sslSocketFactory);
        }
        return connection;
    }

    private static boolean isLocalTestHost(String host) {
        String value = host == null ? "" : host.trim().toLowerCase(java.util.Locale.ROOT);
        if ("localhost".equals(value)) return true;
        String[] parts = value.split("\\.");
        if (parts.length != 4) return false;
        int[] octets = new int[4];
        try {
            for (int i = 0; i < parts.length; i++) {
                octets[i] = Integer.parseInt(parts[i]);
                if (octets[i] < 0 || octets[i] > 255) return false;
            }
        } catch (NumberFormatException invalidAddress) {
            return false;
        }
        return octets[0] == 127 || octets[0] == 10
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168);
    }

    private void sign(HttpURLConnection connection, JSONObject body, byte[] wirePayload) throws Exception {
        String key = config.optString("agent_key", "");
        if (key.isEmpty()) throw new IllegalStateException("AJNAT agent_key is not configured");
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
        String nonce = UUID.randomUUID().toString().replace("-", "");
        // V2 authenticates the exact UTF-8 bytes sent on the wire. The original
        // canonical JSON scheme could reject legitimate Android inventory batches
        // when a 64-bit longVersionCode was rounded by JavaScript's Number parser.
        // Keep V1 for body-less GET requests so existing download endpoints remain
        // compatible while the backend accepts both signature versions.
        boolean rawBodySignature = wirePayload != null;
        String signedBody = rawBodySignature
                ? new String(wirePayload, StandardCharsets.UTF_8)
                : canonicalize(body);
        String message = timestamp + "." + nonce + "." + signedBody;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        connection.setRequestProperty("x-agent-timestamp", timestamp);
        connection.setRequestProperty("x-agent-nonce", nonce);
        connection.setRequestProperty("x-agent-signature", hex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8))));
        if (rawBodySignature) connection.setRequestProperty("x-agent-signature-version", "2");
    }

    private Response readResponse(HttpURLConnection connection) throws Exception {
        try {
            int status = connection.getResponseCode();
            InputStream stream = status >= 200 && status < 300
                    ? connection.getInputStream() : connection.getErrorStream();
            byte[] responseBody = readAllBytes(stream);
            if (TRANSPORT_VERSION.equalsIgnoreCase(connection.getHeaderField(TRANSPORT_HEADER))) {
                JSONObject envelope = new JSONObject(new String(responseBody, StandardCharsets.UTF_8));
                responseBody = decryptPayload(envelope, config.optString("agent_key", ""), RESPONSE_AAD);
            }
            return new Response(status, new String(responseBody, StandardCharsets.UTF_8));
        } finally {
            connection.disconnect();
        }
    }

    static JSONObject encryptPayload(JSONObject payload, String agentKey) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(transportKey(agentKey), "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(REQUEST_AAD);
        byte[] sealed = cipher.doFinal(payload.toString().getBytes(StandardCharsets.UTF_8));
        int ciphertextLength = sealed.length - 16;
        byte[] ciphertext = java.util.Arrays.copyOfRange(sealed, 0, ciphertextLength);
        byte[] tag = java.util.Arrays.copyOfRange(sealed, ciphertextLength, sealed.length);
        return new JSONObject()
                .put("v", 1)
                .put("alg", "A256GCM")
                .put("nonce", Base64.encodeToString(nonce, Base64.NO_WRAP))
                .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .put("tag", Base64.encodeToString(tag, Base64.NO_WRAP));
    }

    static byte[] decryptPayload(JSONObject envelope, String agentKey, byte[] aad) throws Exception {
        if (envelope.optInt("v", 0) != 1 || !"A256GCM".equals(envelope.optString("alg"))) {
            throw new SecurityException("Unsupported encrypted AJNAT API response");
        }
        byte[] nonce = Base64.decode(envelope.getString("nonce"), Base64.DEFAULT);
        byte[] ciphertext = Base64.decode(envelope.getString("ciphertext"), Base64.DEFAULT);
        byte[] tag = Base64.decode(envelope.getString("tag"), Base64.DEFAULT);
        if (nonce.length != 12 || tag.length != 16) throw new SecurityException("Invalid AJNAT encryption nonce or tag");
        byte[] sealed = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, sealed, 0, ciphertext.length);
        System.arraycopy(tag, 0, sealed, ciphertext.length, tag.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(transportKey(agentKey), "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(sealed);
    }

    static byte[] transportKey(String agentKey) throws Exception {
        if (agentKey == null || agentKey.isEmpty()) throw new IllegalStateException("AJNAT agent_key is required for encrypted API transport");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(KEY_DOMAIN);
        digest.update(agentKey.getBytes(StandardCharsets.UTF_8));
        return digest.digest();
    }

    private javax.net.ssl.SSLSocketFactory createSocketFactory() {
        try {
            String assetName = config.optString("tls_ca_bundle_asset", "").trim();
            String pin = config.optString("tls_server_sha256", "").replace(":", "").trim().toLowerCase();
            X509TrustManager trustManager = assetName.isEmpty()
                    ? defaultTrustManager()
                    : assetTrustManager(assetName);
            if (!pin.isEmpty()) {
                if (!pin.matches("^[a-f0-9]{64}$")) throw new SecurityException("Invalid AJNAT TLS certificate pin");
                trustManager = new PinningTrustManager(trustManager, pin);
            }
            KeyManager[] clientManagers = createClientKeyManagers();
            if (assetName.isEmpty() && pin.isEmpty() && clientManagers == null) return null;
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(clientManagers, new TrustManager[]{trustManager}, new SecureRandom());
            return ssl.getSocketFactory();
        } catch (Exception error) {
            throw new IllegalStateException("Unable to initialize AJNAT TLS trust", error);
        }
    }

    private KeyManager[] createClientKeyManagers() throws Exception {
        if (!config.optBoolean("mtls_auto_enroll", false)) return null;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            if (config.optBoolean("mtls_required", false)) {
                throw new SecurityException("Android 6 or newer is required for non-exportable AJNAT mTLS keys");
            }
            return null;
        }
        String systemId = config.optString("system_id", "").trim();
        if (systemId.isEmpty()) throw new SecurityException("AJNAT system_id is required for mTLS");
        String alias = "ajnat-mtls-" + hex(MessageDigest.getInstance("SHA-256")
                .digest(systemId.getBytes(StandardCharsets.UTF_8))).substring(0, 24);
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(alias)) {
            Date notBefore = new Date(System.currentTimeMillis() - 5L * 60L * 1000L);
            Date notAfter = new Date(System.currentTimeMillis() + 825L * 24L * 60L * 60L * 1000L);
            BigInteger serial = new BigInteger(159, new SecureRandom()).add(BigInteger.ONE);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setCertificateSubject(new X500Principal(
                            "CN=AJNAT-" + systemId + ",OU=Endpoint Agent,O=AJNAT SOC"))
                    .setCertificateSerialNumber(serial)
                    .setCertificateNotBefore(notBefore)
                    .setCertificateNotAfter(notAfter)
                    .setUserAuthenticationRequired(false)
                    .build());
            generator.generateKeyPair();
        }
        Certificate certificate = store.getCertificate(alias);
        if (!(certificate instanceof X509Certificate)) {
            throw new SecurityException("AJNAT Android client certificate was not created");
        }
        clientCertificateFingerprint = hex(MessageDigest.getInstance("SHA-256")
                .digest(certificate.getEncoded()));
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, null);
        return factory.getKeyManagers();
    }

    private X509TrustManager assetTrustManager(String assetName) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null);
        try (InputStream input = context.getAssets().open(assetName)) {
            int index = 0;
            for (Certificate certificate : factory.generateCertificates(input)) {
                store.setCertificateEntry("ajnat-ca-" + index++, certificate);
            }
            if (index == 0) throw new SecurityException("AJNAT CA asset is empty");
        }
        TrustManagerFactory managerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managerFactory.init(store);
        return firstTrustManager(managerFactory.getTrustManagers());
    }

    private X509TrustManager defaultTrustManager() throws Exception {
        TrustManagerFactory managerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managerFactory.init((KeyStore) null);
        return firstTrustManager(managerFactory.getTrustManagers());
    }

    private static X509TrustManager firstTrustManager(TrustManager[] managers) {
        for (TrustManager manager : managers) {
            if (manager instanceof X509TrustManager) return (X509TrustManager) manager;
        }
        throw new IllegalStateException("No X509 trust manager is available");
    }

    static String canonicalize(Object value) {
        if (value == null || value == JSONObject.NULL) return "null";
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value;
            List<String> keys = new ArrayList<>();
            Iterator<String> iterator = object.keys();
            while (iterator.hasNext()) keys.add(iterator.next());
            Collections.sort(keys);
            StringBuilder result = new StringBuilder("{");
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) result.append(',');
                String key = keys.get(i);
                result.append(JSONObject.quote(key)).append(':').append(canonicalize(object.opt(key)));
            }
            return result.append('}').toString();
        }
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            StringBuilder result = new StringBuilder("[");
            for (int i = 0; i < array.length(); i++) {
                if (i > 0) result.append(',');
                result.append(canonicalize(array.opt(i)));
            }
            return result.append(']').toString();
        }
        if (value instanceof String) return JSONObject.quote((String) value);
        if (value instanceof Number) {
            try {
                return JSONObject.numberToString((Number) value);
            } catch (org.json.JSONException invalidNumber) {
                throw new IllegalArgumentException("Non-finite number in signed JSON payload", invalidNumber);
            }
        }
        if (value instanceof Boolean) return value.toString();
        return JSONObject.quote(String.valueOf(value));
    }

    private static byte[] readAllBytes(InputStream input) throws Exception {
        if (input == null) return new byte[0];
        try (InputStream stream = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = stream.read(buffer)) > 0) output.write(buffer, 0, count);
            return output.toByteArray();
        }
    }

    private static String readAll(InputStream input) throws Exception {
        return new String(readAllBytes(input), StandardCharsets.UTF_8);
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }

    private static final class PinningTrustManager implements X509TrustManager {
        private final X509TrustManager delegate;
        private final String pin;

        PinningTrustManager(X509TrustManager delegate, String pin) {
            this.delegate = delegate;
            this.pin = pin;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            delegate.checkServerTrusted(chain, authType);
            if (chain == null || chain.length == 0) throw new java.security.cert.CertificateException("AJNAT server certificate is missing");
            try {
                String actual = hex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));
                if (!MessageDigest.isEqual(actual.getBytes(StandardCharsets.US_ASCII), pin.getBytes(StandardCharsets.US_ASCII))) {
                    throw new java.security.cert.CertificateException("AJNAT server certificate pin mismatch");
                }
            } catch (java.security.cert.CertificateException error) {
                throw error;
            } catch (Exception error) {
                throw new java.security.cert.CertificateException("Unable to verify AJNAT certificate pin", error);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }
}
