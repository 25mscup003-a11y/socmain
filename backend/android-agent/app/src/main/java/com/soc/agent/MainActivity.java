package com.soc.agent;

import android.Manifest;
import android.app.Activity;
import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.Environment;
import android.provider.Settings;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.InputType;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Iterator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import android.util.Base64;

public class MainActivity extends Activity {
    private static final String PREFS = "soc_agent_prefs";
    private static final String PASSWORD_HASH = "password_hash";
    private static final int PASSWORD_ITERATIONS = 210000;
    private static final int VPN_PERMISSION_REQUEST = 101;
    private static final int REMOVE_ADMIN_REQUEST = 103;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Button startButton;
    private Button firewallButton;
    private TextView statusView;
    private boolean controlsVisible = false;
    private boolean uninstallAuthorized = false;
    private boolean uninstallIntentLaunched = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestNotificationPermission();
        if (Build.VERSION.SDK_INT < 33
                || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            handler.postDelayed(this::requestPreciseLocationAccess, 500L);
        }
        startAgentService();
        if (LocalFirewallVpnService.hasConsent(this)) {
            LocalFirewallVpnService.start(this);
        }
        if (hasPassword()) {
            showLoginScreen();
        } else {
            showSetPasswordScreen();
        }
    }

    private void showSetPasswordScreen() {
        LinearLayout root = baseRoot();
        addTitle(root, "SOC Agent");
        addMessage(root, "Set protection password.\nThis password is required to open this page and control the agent.");

        EditText pass1 = passwordInput("Enter password");
        EditText pass2 = passwordInput("Confirm password");
        root.addView(pass1);
        root.addView(pass2);

        TextView error = messageText("", 0xfff87171, 13);
        root.addView(error);

        Button save = primaryButton("SAVE PASSWORD");
        save.setOnClickListener(v -> {
            String p1 = pass1.getText().toString();
            String p2 = pass2.getText().toString();
            if (p1.length() < 8) {
                error.setText("Password must be at least 8 characters.");
            } else if (!p1.equals(p2)) {
                error.setText("Passwords do not match.");
            } else {
                save.setEnabled(false);
                save.setText("SAVING...");
                new Thread(() -> {
                    String record = passwordRecord(p1);
                    getPrefs().edit().putString(PASSWORD_HASH, record).commit();
                    runOnUiThread(() -> {
                        enforceManagedUninstallBlock();
                        showProtectedPage("Password saved. Agent protection is active.");
                    });
                }, "ajnat-password-save").start();
            }
        });
        root.addView(save);
        setContentView(root);
    }

    private void showLoginScreen() {
        LinearLayout root = baseRoot();
        addTitle(root, "SOC Agent");
        addMessage(root, "Enter protection password to open agent controls.");

        EditText pass = passwordInput("Password");
        root.addView(pass);

        TextView error = messageText("", 0xfff87171, 13);
        root.addView(error);

        Button unlock = primaryButton("UNLOCK");
        unlock.setOnClickListener(v -> {
            String value = pass.getText().toString();
            unlock.setEnabled(false);
            unlock.setText("CHECKING...");
            new Thread(() -> {
                boolean valid = verifyPassword(value);
                runOnUiThread(() -> {
                    if (valid) showProtectedPage("Unlocked. Agent controls are protected.");
                    else {
                        unlock.setEnabled(true);
                        unlock.setText("UNLOCK");
                        error.setText("Incorrect password.");
                    }
                });
            }, "ajnat-password-check").start();
        });
        root.addView(unlock);
        setContentView(root);
    }

    private void showProtectedPage(String status) {
        controlsVisible = true;
        uninstallAuthorized = false;
        requestNotificationPermission();

        JSONObject config = readConfig();
        boolean firewallRunning = LocalFirewallVpnService.hasConsent(this)
                && LocalFirewallVpnService.isRunning(this);
        LinearLayout root = baseRoot();
        root.setGravity(Gravity.START);
        root.setPadding(dp(20), dp(32), dp(20), dp(32));

        TextView eyebrow = messageText("AJNAT MOBILE SECURITY", 0xff38bdf8, 12);
        eyebrow.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        eyebrow.setLetterSpacing(0.12f);
        root.addView(eyebrow);
        TextView title = messageText("Device protection", 0xfff8fafc, 30);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(title);
        statusView = messageText(status, 0xff94a3b8, 14);
        statusView.setPadding(0, dp(4), 0, dp(18));
        root.addView(statusView);

        LinearLayout hero = card();
        LinearLayout heroTop = horizontalRow();
        TextView shield = messageText("✓", 0xff052e16, 22);
        shield.setGravity(Gravity.CENTER);
        shield.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        shield.setBackground(roundRect(0xff22c55e, 18));
        heroTop.addView(shield, new LinearLayout.LayoutParams(dp(42), dp(42)));
        LinearLayout heroCopy = new LinearLayout(this);
        heroCopy.setOrientation(LinearLayout.VERTICAL);
        heroCopy.setPadding(dp(14), 0, 0, 0);
        TextView protectedTitle = messageText("Protection is running", 0xfff8fafc, 18);
        protectedTitle.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        heroCopy.addView(protectedTitle);
        heroCopy.addView(messageText("Heartbeat and endpoint monitoring are active", 0xff94a3b8, 13));
        heroTop.addView(heroCopy, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        hero.addView(heroTop);
        hero.addView(statusRow("Agent service", true, "Active"));
        hero.addView(statusRow("Firewall / IPS", firewallRunning,
                firewallRunning ? "Enabled" : "Setup required"));
        hero.addView(statusRow("App usage monitoring", hasUsageAccess(), hasUsageAccess() ? "Enabled" : "Permission required"));
        hero.addView(statusRow("Shared file monitoring", hasFileAccess(), hasFileAccess() ? "Enabled" : "Permission required"));
        hero.addView(statusRow("Precise device location", hasPreciseLocationAccess(),
                hasPreciseLocationAccess() ? "Enabled" : "Permission required"));
        root.addView(hero);

        addSectionTitle(root, "DEVICE");
        LinearLayout identity = card();
        identity.addView(infoRow("Device", valueOr(config, "system_name", Build.MODEL)));
        identity.addView(infoRow("Company", valueOr(config, "company_name", "Not assigned")));
        identity.addView(infoRow("Department", valueOr(config, "department_name", "Not assigned")));
        identity.addView(infoRow("Server", valueOr(config, "server_url", "Not configured")));
        identity.addView(infoRow("Agent version", "v" + AgentVersion.current(this)));
        root.addView(identity);

        addSectionTitle(root, "CONTROLS");
        startButton = actionButton("Restart agent", "Refresh connection and send heartbeat", 0xff0284c7);
        startButton.setOnClickListener(v -> startAgentWithLoader());
        root.addView(startButton);

        firewallButton = actionButton(firewallRunning
                ? "Restart Firewall / IPS" : "Enable Firewall / IPS", "Inspect and block policy-matched connections", 0xff0f766e);
        firewallButton.setOnClickListener(v -> requestVpnFirewallPermission());
        root.addView(firewallButton);

        Button usageButton = actionButton("App usage monitoring", "See which applications are used", 0xff4338ca);
        usageButton.setOnClickListener(v -> {
            startActivity(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS));
            statusView.setText("Allow Usage Access for AJNAT, then return here.");
        });
        root.addView(usageButton);

        Button filesButton = actionButton("File monitoring", "Monitor shared-storage file activity", 0xff7c3aed);
        filesButton.setOnClickListener(v -> requestFileMonitoringAccess());
        root.addView(filesButton);

        Button locationButton = actionButton("Precise device location",
                "Use this device's GPS only when AJNAT location policy is enabled", 0xff0369a1);
        locationButton.setOnClickListener(v -> requestPreciseLocationAccess());
        root.addView(locationButton);

        Button adminButton = actionButton("Device administration", "Strengthen agent removal protection", 0xff334155);
        adminButton.setOnClickListener(v -> requestDeviceAdmin());
        root.addView(adminButton);

        DevicePolicyManager dpm = devicePolicyManager();
        LinearLayout protectionCard = card();
        protectionCard.addView(messageText(dpm.isDeviceOwnerApp(getPackageName())
                ? "Removal protection active"
                : "Standard removal protection", dpm.isDeviceOwnerApp(getPackageName()) ? 0xff86efac : 0xfffbbf24, 14));
        protectionCard.addView(messageText(dpm.isDeviceOwnerApp(getPackageName())
                ? "AJNAT is provisioned as Device Owner."
                : "Device Owner provisioning is required to prevent removal from Android Settings.", 0xff94a3b8, 12));
        root.addView(protectionCard);

        Button uninstallButton = actionButton("Uninstall agent", "Password authorization required", 0xff7f1d1d);
        uninstallButton.setOnClickListener(v -> showUninstallAuthorization());
        root.addView(uninstallButton);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(0xff020617);
        scroll.addView(root);
        setContentView(scroll);
    }

    private void startAgentWithLoader() {
        startButton.setEnabled(false);
        startButton.setText("STARTING AGENT...");
        statusView.setText("Please wait 15 seconds. Starting service and sending heartbeat...");
        startAgentService();
        handler.postDelayed(() -> {
            startButton.setEnabled(true);
            startButton.setText("Restart agent\nRefresh connection and send heartbeat");
            statusView.setText("SOC Agent service started. Heartbeat will continue in background.");
        }, 15000);
    }

    private LinearLayout baseRoot() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(36, 48, 36, 36);
        root.setBackgroundColor(0xff06111f);
        return root;
    }

    private void addTitle(LinearLayout root, String text) {
        TextView title = messageText(text, 0xffe0f2fe, 30);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 18);
        root.addView(title);
    }

    private void addMessage(LinearLayout root, String text) {
        TextView msg = messageText(text, 0xff93c5fd, 15);
        msg.setGravity(Gravity.CENTER);
        msg.setPadding(0, 0, 0, 26);
        root.addView(msg);
    }

    private TextView messageText(String text, int color, int size) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(size);
        view.setPadding(0, 8, 0, 8);
        return view;
    }

    private EditText passwordInput(String hint) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setSingleLine(true);
        input.setTextColor(0xffe0f2fe);
        input.setHintTextColor(0xff64748b);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        input.setPadding(18, 10, 18, 10);
        input.setBackgroundColor(0xff0c1a2e);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
        lp.setMargins(0, 8, 0, 8);
        input.setLayoutParams(lp);
        return input;
    }

    private Button primaryButton(String text) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextColor(0xfff8fafc);
        button.setTextSize(14);
        button.setAllCaps(false);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setBackground(roundRect(0xff0369a1, 14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
        lp.setMargins(0, 16, 0, 18);
        button.setLayoutParams(lp);
        return button;
    }

    private Button actionButton(String title, String subtitle, int color) {
        Button button = primaryButton(title + "\n" + subtitle);
        button.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        button.setPadding(dp(18), dp(12), dp(18), dp(12));
        button.setMinHeight(dp(64));
        button.setBackground(roundRect(color, 14));
        LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams)button.getLayoutParams();
        lp.setMargins(0, dp(6), 0, dp(6));
        return button;
    }

    private LinearLayout card() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        card.setBackground(roundRect(0xff0f172a, 18));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(7), 0, dp(7));
        card.setLayoutParams(lp);
        return card;
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, 0, 0, dp(12));
        return row;
    }

    private LinearLayout statusRow(String label, boolean enabled, String value) {
        LinearLayout row = horizontalRow();
        row.setPadding(0, dp(9), 0, dp(9));
        TextView left = messageText(label, 0xffcbd5e1, 14);
        row.addView(left, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        TextView right = messageText((enabled ? "●  " : "○  ") + value, enabled ? 0xff4ade80 : 0xfffbbf24, 12);
        right.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        row.addView(right);
        return row;
    }

    private LinearLayout infoRow(String label, String value) {
        LinearLayout row = horizontalRow();
        row.setPadding(0, dp(7), 0, dp(7));
        row.addView(messageText(label, 0xff64748b, 13), new LinearLayout.LayoutParams(dp(110), LinearLayout.LayoutParams.WRAP_CONTENT));
        TextView text = messageText(value, 0xffe2e8f0, 14);
        text.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        row.addView(text, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        return row;
    }

    private void addSectionTitle(LinearLayout root, String title) {
        TextView text = messageText(title, 0xff64748b, 12);
        text.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        text.setLetterSpacing(0.12f);
        text.setPadding(0, dp(20), 0, dp(4));
        root.addView(text);
    }

    private GradientDrawable roundRect(int color, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radiusDp));
        return drawable;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private String valueOr(JSONObject config, String key, String fallback) {
        String value = config.optString(key, "").trim();
        return value.isEmpty() ? fallback : value;
    }

    private boolean hasUsageAccess() {
        try {
            AppOpsManager ops = (AppOpsManager)getSystemService(Context.APP_OPS_SERVICE);
            return ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), getPackageName()) == AppOpsManager.MODE_ALLOWED;
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean hasFileAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) return Environment.isExternalStorageManager();
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.M || checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    private void startAgentService() {
        Intent intent = new Intent(this, AgentService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
        }
    }

    private boolean hasPreciseLocationAccess() {
        boolean foreground = Build.VERSION.SDK_INT < Build.VERSION_CODES.M
                || checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        boolean background = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
                || checkSelfPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED;
        return foreground && background;
    }

    private void requestPreciseLocationAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                && checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION
            }, 104);
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                && checkSelfPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            try {
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:" + getPackageName()));
                startActivity(intent);
                if (statusView != null) {
                    statusView.setText("Location > Allow all the time and Precise location enable karein.");
                }
            } catch (Exception ignored) { }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == 100) handler.postDelayed(this::requestPreciseLocationAccess, 300L);
    }

    private void requestFileMonitoringAccess() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE}, 102);
            }
            if (statusView != null) statusView.setText("Grant file access so AJNAT can monitor shared-storage file changes.");
        } catch (Exception ignored) {
            startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
        }
    }

    private void requestBatteryOptimizationExemption() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return;
        PowerManager power = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (power != null && power.isIgnoringBatteryOptimizations(getPackageName())) return;
        try {
            Intent intent = new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            intent.setData(Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } catch (Exception ignored) {
            startActivity(new Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
        }
    }

    private void requestVpnFirewallPermission() {
        Intent permission = VpnService.prepare(this);
        if (permission != null) {
            startActivityForResult(permission, VPN_PERMISSION_REQUEST);
            statusView.setText("Approve the Android VPN prompt to enable Firewall / IPS.");
        } else {
            LocalFirewallVpnService.start(this);
            firewallButton.setText("RESTART FIREWALL / IPS");
            statusView.setText("SOC Firewall / IPS is enabled.");
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REMOVE_ADMIN_REQUEST) {
            if (!devicePolicyManager().isAdminActive(adminComponent())) {
                launchSystemUninstaller();
            } else {
                uninstallAuthorized = false;
                showProtectedPage("Android did not disable Device administration; uninstall cancelled.");
            }
            return;
        }
        if (requestCode != VPN_PERMISSION_REQUEST) return;
        if (resultCode == RESULT_OK) {
            LocalFirewallVpnService.start(this);
            if (firewallButton != null) firewallButton.setText("RESTART FIREWALL / IPS");
            if (statusView != null) statusView.setText("SOC Firewall / IPS is enabled.");
        } else if (statusView != null) {
            statusView.setText("VPN permission was denied; network IDS remains active without blocking.");
        }
    }

    private SharedPreferences getPrefs() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    private boolean hasPassword() {
        return getPrefs().contains(PASSWORD_HASH);
    }

    private boolean verifyPassword(String value) {
        String record = getPrefs().getString(PASSWORD_HASH, "");
        boolean valid = verifyPasswordRecord(value, record);
        if (valid && !record.startsWith("pbkdf2-sha256:")) {
            getPrefs().edit().putString(PASSWORD_HASH, passwordRecord(value)).apply();
        }
        return valid;
    }

    private String passwordRecord(String value) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), salt, PASSWORD_ITERATIONS, 256);
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            spec.clearPassword();
            return "pbkdf2-sha256:" + PASSWORD_ITERATIONS + ":"
                    + Base64.encodeToString(salt, Base64.NO_WRAP) + ":"
                    + Base64.encodeToString(hash, Base64.NO_WRAP);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to protect uninstall password", e);
        }
    }

    private boolean verifyPasswordRecord(String value, String record) {
        try {
            if (record != null && record.startsWith("pbkdf2-sha256:")) {
                String[] parts = record.split(":", 4);
                int iterations = Integer.parseInt(parts[1]);
                byte[] salt = Base64.decode(parts[2], Base64.NO_WRAP);
                byte[] expected = Base64.decode(parts[3], Base64.NO_WRAP);
                PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), salt, iterations, expected.length * 8);
                byte[] actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
                spec.clearPassword();
                return MessageDigest.isEqual(actual, expected);
            }
            return MessageDigest.isEqual(
                    sha256(value).getBytes(StandardCharsets.US_ASCII),
                    String.valueOf(record).getBytes(StandardCharsets.US_ASCII)
            );
        } catch (Exception e) {
            return false;
        }
    }

    private DevicePolicyManager devicePolicyManager() {
        return (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
    }

    private ComponentName adminComponent() {
        return new ComponentName(this, AgentDeviceAdminReceiver.class);
    }

    private void requestDeviceAdmin() {
        DevicePolicyManager dpm = devicePolicyManager();
        if (dpm.isAdminActive(adminComponent())) {
            enforceManagedUninstallBlock();
            showProtectedPage("Device administrator is enabled.");
            return;
        }
        Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
        intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent());
        intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Required for managed SOC Agent removal protection.");
        startActivity(intent);
    }

    private void enforceManagedUninstallBlock() {
        DevicePolicyManager dpm = devicePolicyManager();
        if (dpm.isDeviceOwnerApp(getPackageName())) {
            dpm.setUninstallBlocked(adminComponent(), getPackageName(), true);
        }
    }

    private void showUninstallAuthorization() {
        controlsVisible = false;
        LinearLayout root = baseRoot();
        addTitle(root, "Authorize uninstall");
        addMessage(root, "Enter the protection password. Wrong or cancelled passwords will not remove the agent.");
        EditText password = passwordInput("Uninstall password");
        root.addView(password);
        TextView error = messageText("", 0xfff87171, 13);
        root.addView(error);
        Button authorize = primaryButton("AUTHORIZE UNINSTALL");
        authorize.setOnClickListener(v -> {
            String value = password.getText().toString();
            authorize.setEnabled(false);
            authorize.setText("CHECKING PASSWORD...");
            new Thread(() -> {
                boolean valid = verifyPassword(value);
                runOnUiThread(() -> {
                    if (!valid) {
                        authorize.setEnabled(true);
                        authorize.setText("AUTHORIZE UNINSTALL");
                        error.setText("Incorrect password.");
                        return;
                    }
                    authorize.setText("PREPARING UNINSTALL...");
                    authorizeManagedUninstall(error);
                });
            }, "ajnat-uninstall-password").start();
        });
        root.addView(authorize);
        Button cancel = primaryButton("CANCEL");
        cancel.setOnClickListener(v -> showProtectedPage("Uninstall cancelled."));
        root.addView(cancel);
        setContentView(root);
    }

    @SuppressWarnings("deprecation")
    private void authorizeManagedUninstall(TextView error) {
        uninstallAuthorized = true;
        DevicePolicyManager dpm = devicePolicyManager();
        try {
            if (dpm.isDeviceOwnerApp(getPackageName())) {
                dpm.setUninstallBlocked(adminComponent(), getPackageName(), false);
                dpm.clearDeviceOwnerApp(getPackageName());
            }
            if (dpm.isAdminActive(adminComponent())) {
                dpm.removeActiveAdmin(adminComponent());
            }
        } catch (SecurityException policyError) {
            uninstallAuthorized = false;
            error.setText("Android policy did not allow removal. Remove Device Owner management first.");
            return;
        }
        stopService(new Intent(this, AgentService.class));
        stopService(new Intent(this, LocalFirewallVpnService.class));
        waitForAdminRemoval(0, error);
    }

    private void waitForAdminRemoval(int attempt, TextView error) {
        DevicePolicyManager dpm = devicePolicyManager();
        if (!dpm.isDeviceOwnerApp(getPackageName()) && !dpm.isAdminActive(adminComponent())) {
            launchSystemUninstaller();
            return;
        }
        if (attempt < 12) {
            handler.postDelayed(() -> waitForAdminRemoval(attempt + 1, error), 250L);
            return;
        }
        if (dpm.isDeviceOwnerApp(getPackageName())) {
            uninstallAuthorized = false;
            error.setText("Device Owner removal is still active. Ask the administrator to deprovision this phone.");
            return;
        }
        Intent removeAdmin = new Intent("android.app.action.REMOVE_DEVICE_ADMIN");
        removeAdmin.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent());
        startActivityForResult(removeAdmin, REMOVE_ADMIN_REQUEST);
    }

    private void launchSystemUninstaller() {
        uninstallIntentLaunched = true;
        Intent uninstall = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + getPackageName()));
        uninstall.putExtra(Intent.EXTRA_RETURN_RESULT, true);
        startActivity(uninstall);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (uninstallIntentLaunched) {
            uninstallIntentLaunched = false;
            uninstallAuthorized = false;
            if (hasPassword()) enforceManagedUninstallBlock();
            showProtectedPage("Uninstall was cancelled or did not complete.");
            return;
        }
        if (hasPassword() && !uninstallAuthorized) enforceManagedUninstallBlock();
        if (controlsVisible) showProtectedPage("Security controls refreshed.");
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private JSONObject readConfig() {
        try {
            return new JSONObject(readAsset("company_config.json"));
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    private String prettyConfig(JSONObject config) {
        try {
            return config.toString(2);
        } catch (Exception e) {
            return config.toString();
        }
    }

    private JSONObject safeConfigForDisplay(JSONObject config) {
        JSONObject safe = new JSONObject();
        try {
            Iterator<String> keys = config.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                safe.put(key, safeDisplayValue(key, config.opt(key)));
            }
        } catch (Exception ignored) {
            return config;
        }
        return safe;
    }

    private Object safeDisplayValue(String key, Object value) {
        if (value instanceof JSONObject) {
            return safeConfigForDisplay((JSONObject) value);
        }
        if (value instanceof JSONArray) {
            JSONArray source = (JSONArray) value;
            JSONArray safe = new JSONArray();
            for (int i = 0; i < source.length(); i++) {
                safe.put(safeDisplayValue(key, source.opt(i)));
            }
            return safe;
        }
        if (isSensitiveKey(key)) {
            return maskValue(String.valueOf(value));
        }
        return value;
    }

    private boolean isSensitiveKey(String key) {
        String lower = key == null ? "" : key.toLowerCase();
        return lower.contains("key")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("password")
                || lower.endsWith("_id")
                || lower.equals("id");
    }

    private String maskValue(String value) {
        if (value == null || value.isEmpty()) return "";
        if (value.length() <= 8) return "****";
        return value.substring(0, 4) + "****" + value.substring(value.length() - 4);
    }

    private String readAsset(String name) {
        try (InputStream in = getAssets().open(name)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toString(StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            return "{}";
        }
    }
}
