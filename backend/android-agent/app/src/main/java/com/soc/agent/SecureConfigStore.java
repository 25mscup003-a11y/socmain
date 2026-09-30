package com.soc.agent;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Encrypts runtime enrollment credentials with a non-exportable Android Keystore key. */
public final class SecureConfigStore {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS = "ajnat-agent-config-v1";
    private static final String PREFS = "ajnat_secure_config";
    private static final String AGENT_KEY = "agent_key";

    private SecureConfigStore() { }

    public static JSONObject resolve(Context context, JSONObject packaged) {
        JSONObject result;
        try {
            result = new JSONObject(packaged.toString());
        } catch (Exception invalid) {
            return packaged;
        }
        try {
            SharedPreferences preferences = preferences(context);
            String encrypted = preferences.getString(AGENT_KEY, "");
            String agentKey;
            if (!encrypted.isEmpty()) {
                agentKey = decrypt(encrypted);
            } else {
                agentKey = result.optString(AGENT_KEY, "");
                if (!agentKey.isEmpty()) {
                    preferences.edit().putString(AGENT_KEY, encrypt(agentKey)).commit();
                }
            }
            if (!agentKey.isEmpty()) result.put(AGENT_KEY, agentKey);
            // Legacy fleet-wide secrets are deliberately never persisted here.
            result.remove("integration_secret");
        } catch (Exception unavailableBeforeUnlock) {
            // Some devices do not expose Android Keystore until first unlock.
            // The packaged per-device key remains usable for that boot only.
        }
        return result;
    }

    private static SharedPreferences preferences(Context context) {
        Context app = context.getApplicationContext();
        Context storage = Build.VERSION.SDK_INT >= 24 ? app.createDeviceProtectedStorageContext() : app;
        return storage.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance(KEYSTORE);
        store.load(null);
        java.security.Key existing = store.getKey(ALIAS, null);
        if (existing instanceof SecretKey) return (SecretKey) existing;
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }

    private static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP) + "."
                + Base64.encodeToString(ciphertext, Base64.NO_WRAP);
    }

    private static String decrypt(String encoded) throws Exception {
        String[] parts = encoded.split("\\.", 2);
        if (parts.length != 2) throw new IllegalArgumentException("Invalid encrypted AJNAT config");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(),
                new GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)));
        return new String(cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP)), StandardCharsets.UTF_8);
    }
}
