package com.soc.agent;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.app.AppOpsManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.content.ContentResolver;
import android.database.Cursor;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.StatFs;
import android.os.SystemClock;
import android.provider.Settings;
import android.provider.MediaStore;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import com.soc.agent.BootReceiver;
import com.soc.agent.LocalFirewallVpnService;
import com.soc.agent.R;
import com.soc.agent.UpdateFileProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

public class AgentService
extends Service {
    public static final String ACTION_APP_EVENT = "com.soc.agent.APP_EVENT";
    public static final String ACTION_NETWORK_EVENT = "com.soc.agent.NETWORK_EVENT";
    public static final String ACTION_HEARTBEAT = "com.soc.agent.HEARTBEAT";
    public static final String ACTION_IDS_EVENT = "com.soc.agent.IDS_EVENT";
    private static final String CHANNEL_ID = "soc_agent";
    private static final String PREFS = "soc_agent_service";
    // Version this preference when snapshot delivery semantics change so an
    // upgraded agent retries telemetry that an older build may have dropped.
    private static final String SNAPSHOT_SENT = "snapshot_sent_v2";
    private static final String LAST_NETWORK = "last_network";
    private static final String FALLBACK_AGENT_ID = "fallback_agent_id";
    private static final String TELEMETRY_CURSOR = "telemetry_cursor_v1";
    private static final String FILE_CURSOR = "file_cursor_v1";
    private static final String NETWORK_TELEMETRY_CURSOR = "network_telemetry_cursor_v1";
    private static final String COMMAND_RESULTS = "command_results_v1";
    private static final String DEVICE_PREFS_MIGRATED = "device_prefs_migrated_v1";
    private static final long NETWORK_TELEMETRY_INTERVAL_MS = 5L * 60L * 1000L;
    private static final long EDR_TELEMETRY_INTERVAL_MS = 5L * 60L * 1000L;
    private static final String EDR_COLLECTION_CURSOR = "edr_collection_cursor_v1";
    private final Handler handler = new Handler(Looper.getMainLooper());
    private JSONObject config;
    private int intervalSeconds = 60;
    private volatile boolean rootFirewallEnabled = false;
    private volatile boolean vpnFirewallEnabled = false;
    private volatile boolean monitoringSuspended = false;
    private volatile String activeUpdateRequestId = "";
    private int consecutiveHeartbeatFailures = 0;
    private volatile long lastHeartbeatAttemptMs = 0L;
    private volatile long lastSuccessfulHeartbeatMs = 0L;
    private volatile String lastHeartbeatError = "";
    private final AtomicBoolean heartbeatInFlight = new AtomicBoolean(false);
    private ConnectivityManager.NetworkCallback networkCallback;
    private final JSONArray commandResults = new JSONArray();
    private EventQueue eventQueue;
    private SecureTransport secureTransport;
    private TelemetryPipeline telemetryPipeline;
    private NativeDaemonClient nativeDaemon;
    private CapabilityDetector capabilityDetector;
    private CollectorManager collectorManager;
    private GpsLocationCollector gpsLocationCollector;
    private final Runnable heartbeatLoop = new Runnable(){

        @Override
        public void run() {
            if (!AgentService.this.heartbeatInFlight.compareAndSet(false, true)) {
                return;
            }
            new Thread(() -> {
                int nextDelaySeconds;
                PowerManager.WakeLock wakeLock = null;
                try {
                    PowerManager power = (PowerManager)AgentService.this.getSystemService(Context.POWER_SERVICE);
                    if (power != null) {
                        wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "AJNAT:Heartbeat");
                        wakeLock.acquire(45000L);
                    }
                    AgentService.this.collectorManager.collectPeriodic();
                    AgentService.this.collectAndSendEdrTelemetry();
                    AgentService.this.collectAndSendNetworkTelemetry();
                    // Queue delivery is independent from heartbeat health. A rejected or
                    // temporarily unavailable heartbeat must not starve telemetry retries.
                    AgentService.this.telemetryPipeline.flush();
                    AgentService.this.lastHeartbeatAttemptMs = System.currentTimeMillis();
                    HeartbeatResult result = AgentService.this.sendHeartbeat();
                    AgentService.this.lastSuccessfulHeartbeatMs = System.currentTimeMillis();
                    AgentService.this.lastHeartbeatError = "";
                    AgentService.this.monitoringSuspended = result.stopMonitoring;
                    AgentService.this.consecutiveHeartbeatFailures = 0;
                    if (result.intervalSeconds > 0) {
                        AgentService.this.intervalSeconds = Math.max(30, Math.min(300, result.intervalSeconds));
                    }
                    nextDelaySeconds = AgentService.this.monitoringSuspended ? 300 : AgentService.this.intervalSeconds;
                    AgentService.this.updateNotification(AgentService.this.monitoringSuspended ? "Monitoring paused by server; checking subscription" : "Protected \u2022 connected");
                }
                catch (Exception error) {
                    AgentService.this.consecutiveHeartbeatFailures++;
                    AgentService.this.lastHeartbeatError = error.getClass().getSimpleName()
                            + ": " + String.valueOf(error.getMessage());
                    nextDelaySeconds = Math.min(120, 15 * (1 << Math.min(3, AgentService.this.consecutiveHeartbeatFailures - 1)));
                    AgentService.this.updateNotification("Connection interrupted \u2022 retrying");
                }
                finally {
                    AgentService.this.heartbeatInFlight.set(false);
                    if (wakeLock != null && wakeLock.isHeld()) {
                        wakeLock.release();
                    }
                }
                AgentService.this.scheduleHeartbeat((long)nextDelaySeconds * 1000L);
                AgentService.this.scheduleWatchdog();
            }, "ajnat-heartbeat").start();
        }
    };

    public void onCreate() {
        super.onCreate();
        this.config = this.readConfig();
        this.restoreCommandResults();
        this.eventQueue = new EventQueue(this);
        this.secureTransport = new SecureTransport(this, this.config);
        this.nativeDaemon = new NativeDaemonClient();
        this.capabilityDetector = new CapabilityDetector(this, this.nativeDaemon);
        this.telemetryPipeline = new TelemetryPipeline(
                this.config, this.eventQueue, this.secureTransport, this.getStableAgentId(),
                AgentVersion.current(this));
        this.collectorManager = new CollectorManager(
                this, this.telemetryPipeline, this.nativeDaemon, this.capabilityDetector);
        this.gpsLocationCollector = new GpsLocationCollector(this, this.config, this.telemetryPipeline);
        this.intervalSeconds = this.config.optInt("heartbeat_interval_seconds", 60);
        this.startForeground(1001, this.buildNotification("SOC Agent running"));
        new Thread(() -> {
            try {
                this.secureTransport.enrollClientCertificate();
            } catch (Exception enrollmentError) {
                if (this.config.optBoolean("mtls_required", false)) {
                    this.stopSelf();
                    return;
                }
            }
            this.rootFirewallEnabled = this.initializeRootFirewall();
            this.vpnFirewallEnabled = LocalFirewallVpnService.hasConsent((Context)this);
            if (!this.rootFirewallEnabled && this.vpnFirewallEnabled) {
                LocalFirewallVpnService.start((Context)this);
            }
            this.requestHeartbeat(0L);
        }, "ajnat-firewall-init").start();
        this.registerNetworkCallback();
        this.collectorManager.start();
        this.sendStartupSnapshotOnce();
    }

    public int onStartCommand(Intent intent, int flags, int startId) {
        // Retry Keystore migration after credential-encrypted storage becomes
        // available at normal BOOT_COMPLETED without restarting the service.
        SecureConfigStore.resolve(this, this.config);
        if (intent != null && ACTION_APP_EVENT.equals(intent.getAction())) {
            String action = intent.getStringExtra("event_action");
            String packageName = intent.getStringExtra("package_name");
            JSONObject appEvent = this.extra("package_name", packageName, "user_action", action, "capability_id", 7);
            try {
                long now = System.currentTimeMillis();
                appEvent.put("capability_ids", new JSONArray().put(1).put(7).put(8).put(17).put(24));
                appEvent.put("event_type", "application_package_change");
                appEvent.put("event_time", now);
                appEvent.put("event_id", "android-package-" + Integer.toHexString((packageName + action).hashCode()) + "-" + now);
                appEvent.put("process_name", packageName);
                appEvent.put("process_status", Intent.ACTION_PACKAGE_REMOVED.equals(action) ? "removed" : "installed");
            } catch (Exception ignored) {}
            this.sendAlertAsync("android_app_change", "edr", "medium", "Android app package event: " + action + " package=" + packageName, appEvent);
        } else if (intent != null && ACTION_NETWORK_EVENT.equals(intent.getAction())) {
            String network = this.getNetworkType();
            this.sendAlertAsync("android_network_change", "network", "low", "Android network connectivity changed: " + network, this.networkEvent("connectivity_change", null));
            this.requestHeartbeat(1000L);
        } else if (intent != null && ACTION_IDS_EVENT.equals(intent.getAction())) {
            String remoteIp = intent.getStringExtra("remote_ip");
            JSONObject event = this.networkEvent("blocked_connection", remoteIp);
            try {
                event.put("protocol", intent.getStringExtra("protocol"));
                event.put("src_port", intent.getIntExtra("src_port", 0));
                event.put("dst_port", intent.getIntExtra("dst_port", 0));
            } catch (Exception ignored) { }
            this.sendAlertAsync("android_ips_block", "network", "high", "Android VPN firewall blocked traffic to " + remoteIp, event);
        } else if (intent != null && ACTION_HEARTBEAT.equals(intent.getAction())) {
            this.requestHeartbeat(0L);
        }
        this.scheduleWatchdog();
        return Service.START_STICKY;
    }

    public void onDestroy() {
        this.handler.removeCallbacksAndMessages(null);
        this.unregisterNetworkCallback();
        if (this.collectorManager != null) this.collectorManager.stop();
        if (this.gpsLocationCollector != null) this.gpsLocationCollector.stop();
        this.scheduleRestart(15000L);
        super.onDestroy();
    }

    public void onTaskRemoved(Intent rootIntent) {
        this.scheduleRestart(5000L);
        super.onTaskRemoved(rootIntent);
    }

    private void requestHeartbeat(long delayMs) {
        this.handler.removeCallbacks(this.heartbeatLoop);
        this.handler.postDelayed(this.heartbeatLoop, delayMs);
    }

    private void scheduleHeartbeat(long delayMs) {
        this.handler.removeCallbacks(this.heartbeatLoop);
        this.handler.postDelayed(this.heartbeatLoop, Math.max(15000L, delayMs));
    }

    private void scheduleWatchdog() {
        this.scheduleRestart(240000L);
    }

    private void scheduleRestart(long delayMs) {
        Intent restart = new Intent((Context)this, BootReceiver.class);
        restart.setAction("com.soc.agent.RESTART_AGENT");
        PendingIntent pending = PendingIntent.getBroadcast(this, 1002, restart,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        AlarmManager alarm = (AlarmManager)this.getSystemService(Context.ALARM_SERVICE);
        if (alarm == null) {
            return;
        }
        long triggerAt = SystemClock.elapsedRealtime() + delayMs;
        if (Build.VERSION.SDK_INT >= 23) {
            alarm.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pending);
        } else {
            alarm.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pending);
        }
    }

    private void registerNetworkCallback() {
        if (Build.VERSION.SDK_INT < 24) {
            return;
        }
        ConnectivityManager manager = (ConnectivityManager)this.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) {
            return;
        }
        this.networkCallback = new ConnectivityManager.NetworkCallback(){

            public void onAvailable(Network network) {
                AgentService.this.requestHeartbeat(1000L);
            }
        };
        try {
            manager.registerDefaultNetworkCallback(this.networkCallback);
        }
        catch (Exception exception) {
            // empty catch block
        }
    }

    private void unregisterNetworkCallback() {
        if (this.networkCallback == null) {
            return;
        }
        ConnectivityManager manager = (ConnectivityManager)this.getSystemService(Context.CONNECTIVITY_SERVICE);
        try {
            if (manager != null) {
                manager.unregisterNetworkCallback(this.networkCallback);
            }
        }
        catch (Exception exception) {
            // empty catch block
        }
        this.networkCallback = null;
    }

    public IBinder onBind(Intent intent) {
        return null;
    }

    private Notification buildNotification(String text) {
        NotificationManager manager = (NotificationManager)this.getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "SOC Agent",
                    NotificationManager.IMPORTANCE_LOW);
            manager.createNotificationChannel(channel);
        }
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder((Context)this, CHANNEL_ID) : new Notification.Builder((Context)this);
        return builder.setContentTitle((CharSequence)"SOC Agent").setContentText((CharSequence)text).setSmallIcon(R.drawable.ic_launcher).setOngoing(true).build();
    }

    private void updateNotification(String text) {
        NotificationManager manager = (NotificationManager)this.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager != null) {
            manager.notify(1001, this.buildNotification(text));
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private HeartbeatResult sendHeartbeat() throws Exception {
        JSONObject json;
        String serverUrl = this.config.optString("server_url", "").replaceAll("/+$", "");
        String agentKey = this.config.optString("agent_key", "");
        if (serverUrl.isEmpty() || agentKey.isEmpty()) {
            throw new IllegalStateException("AJNAT enrollment configuration is incomplete");
        }
        JSONObject body = new JSONObject();
        body.put("agent_key", (Object)agentKey);
        // Report the installed binary version, never a stale packaged config value.
        body.put("agent_version", AgentVersion.current(this));
        body.put("status", (Object)"active");
        body.put("hostname", (Object)Build.MODEL);
        body.put("os", (Object)"Android");
        body.put("osType", (Object)"android");
        body.put("os_version", (Object)Build.VERSION.RELEASE);
        body.put("arch", (Object)(Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "unknown"));
        body.put("agentId", (Object)this.getStableAgentId());
        body.put("edrEnabled", true);
        this.vpnFirewallEnabled = LocalFirewallVpnService.isRunning((Context)this);
        boolean firewallEnabled = this.rootFirewallEnabled || this.vpnFirewallEnabled;
        body.put("idsEnabled", true);
        body.put("ipsEnabled", firewallEnabled);
        body.put("firewallEnabled", firewallEnabled);
        body.put("yaraEnabled", false);
        body.put("wafEnabled", false);
        body.put("networkMonitorEnabled", true);
        body.put("usbMonitorEnabled", true);
        body.put("processMonitorEnabled", this.hasUsageAccess() || this.nativeDaemon.isAvailable());
        body.put("memoryMonitorEnabled", false);
        body.put("responseEnabled", firewallEnabled);
        body.put("geoEnrichmentEnabled", false);
        body.put("network_type", (Object)this.getNetworkType());
        String localIp = this.getLocalIpv4Address();
        if (!localIp.isEmpty()) {
            body.put("ip", (Object)localIp);
        }
        body.put("android_capabilities", (Object)this.getCapabilities());
        body.put("device_health", (Object)this.getDeviceHealth());
        body.put("capability_mode", this.capabilityDetector.mode().name());
        body.put("telemetry_queue", this.telemetryPipeline.health());
        body.put("installed_app_count", this.getInstalledAppCount());
        JSONArray jSONArray = this.commandResults;
        synchronized (jSONArray) {
            if (this.commandResults.length() > 0) {
                body.put("security_action_results", (Object)new JSONArray(this.commandResults.toString()));
            }
        }
        this.maybeSendNetworkChangeAlert(body.optString("network_type"));
        SecureTransport.Response heartbeatResponse = this.secureTransport.post("/api/agent/heartbeat", body);
        int code = heartbeatResponse.status;
        String response = heartbeatResponse.body;
        if (!heartbeatResponse.successful()) throw new java.io.IOException("Heartbeat failed with HTTP " + code);
        JSONObject jSONObject = json = response.isEmpty() ? new JSONObject() : new JSONObject(response);
        if (code >= 200 && code < 300 && body.has("security_action_results")) {
            JSONArray jSONArray2 = this.commandResults;
            synchronized (jSONArray2) {
                while (this.commandResults.length() > 0) {
                    this.commandResults.remove(0);
                }
                this.persistCommandResultsLocked();
            }
        }
        // Apply the allow-list before queued block commands so a stale/offline
        // command can never override a newer dashboard whitelist entry.
        LocalFirewallVpnService.replaceWhitelist((Context)this, json.optJSONArray("ips_whitelist"));
        // Reconcile the durable server state before processing this response's
        // commands. A pending isolate/reconnect command below remains the final
        // authority for this heartbeat and prevents stale-state reversal.
        if (json.has("is_isolated")) {
            LocalFirewallVpnService.setIsolation((Context)this, json.optBoolean("is_isolated", false));
        }
        this.handleCommands(json.optJSONArray("commands"));
        this.syncFirewallPolicy(json.optJSONArray("firewall_rules"));
        this.gpsLocationCollector.applyHeartbeatPolicy(json);
        this.gpsLocationCollector.collectAndQueue();
        return new HeartbeatResult(json.optBoolean("stop_monitoring", false), json.optInt("heartbeat_interval_seconds", this.intervalSeconds));
    }

    private void syncFirewallPolicy(JSONArray rules) {
        if (rules == null) {
            return;
        }
        JSONArray blockedIps = new JSONArray();
        JSONArray blockedDomains = new JSONArray();
        JSONArray blockedApplications = new JSONArray();
        for (int i = 0; i < rules.length(); ++i) {
            JSONObject conditions;
            JSONObject rule = rules.optJSONObject(i);
            if (rule == null || !"block".equalsIgnoreCase(rule.optString("action", "block")) || (conditions = rule.optJSONObject("conditions")) == null) continue;
            String ip = conditions.optString("ipAddress", "").trim();
            String domain = conditions.optString("domain", conditions.optString("host", "")).trim();
            String application = conditions.optString("application", "").trim();
            if (LocalFirewallVpnService.isValidIp(ip)) {
                blockedIps.put((Object)ip);
            }
            if (!domain.isEmpty()) {
                blockedDomains.put((Object)domain);
            }
            if (application.isEmpty()) continue;
            blockedApplications.put((Object)application);
        }
        LocalFirewallVpnService.replacePolicyRules((Context)this, blockedIps, blockedDomains, blockedApplications);
        this.vpnFirewallEnabled = LocalFirewallVpnService.isRunning((Context)this);
    }

    private String getLocalIpv4Address() {
        try {
            String address;
            String name;
            ArrayList<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface network : interfaces) {
                String string = name = network.getName() == null ? "" : network.getName().toLowerCase();
                if (!name.startsWith("wlan") && !name.contains("wifi") || (address = this.usableIpv4(network)).isEmpty()) continue;
                return address;
            }
            for (NetworkInterface network : interfaces) {
                name = network.getName() == null ? "" : network.getName().toLowerCase();
                if (name.startsWith("tun") || name.startsWith("vpn") || name.startsWith("dummy") || (address = this.usableIpv4(network)).isEmpty()) continue;
                return address;
            }
        }
        catch (Exception exception) {
            // empty catch block
        }
        return "";
    }

    private String getStableAgentId() {
        String androidId = Settings.Secure.getString((ContentResolver)this.getContentResolver(), (String)"android_id");
        if (androidId != null && !androidId.isEmpty()) {
            return "android-device-" + androidId;
        }
        SharedPreferences prefs = this.servicePreferences();
        String fallback = prefs.getString(FALLBACK_AGENT_ID, "");
        if (fallback.isEmpty()) {
            fallback = UUID.randomUUID().toString();
            prefs.edit().putString(FALLBACK_AGENT_ID, fallback).apply();
        }
        return "android-device-" + fallback;
    }

    private String usableIpv4(NetworkInterface network) {
        try {
            if (!network.isUp() || network.isLoopback()) {
                return "";
            }
            for (InetAddress address : Collections.list(network.getInetAddresses())) {
                if (!(address instanceof Inet4Address) || address.isLoopbackAddress() || address.isLinkLocalAddress()) continue;
                return address.getHostAddress();
            }
        }
        catch (Exception exception) {
            // empty catch block
        }
        return "";
    }

    private void handleCommands(JSONArray commands) {
        if (commands == null) {
            return;
        }
        for (int i = 0; i < commands.length(); ++i) {
            JSONObject cmd = commands.optJSONObject(i);
            if (cmd == null) continue;
            String command = cmd.optString("command", "").toLowerCase();
            String commandId = cmd.optString("id", cmd.optString("commandId", ""));
            if ("update".equals(command)) {
                boolean ok = this.performSelfUpdate(commandId);
                this.queueCommandResult(commandId, command, ok, ok ? "Android update installer launched; user confirmation required" : "Android update failed");
                continue;
            }
            if ("isolate".equals(command) || "reconnect".equals(command)) {
                boolean isolate = "isolate".equals(command);
                boolean ok = LocalFirewallVpnService.setIsolation((Context)this, isolate);
                this.vpnFirewallEnabled = LocalFirewallVpnService.isRunning((Context)this) || isolate;
                this.queueCommandResult(commandId, command, ok, ok
                        ? (isolate
                            ? "Android network isolation persisted; AJNAT management channel retained"
                            : "Android network isolation removed; normal firewall policy restored")
                        : "Android isolation unavailable: grant AJNAT VPN permission");
                continue;
            }
            if ("block_ip".equals(command) || "unblock_ip".equals(command)) {
                String ip = cmd.optString("ip", "").trim();
                if ("block_ip".equals(command) && LocalFirewallVpnService.isWhitelisted((Context)this, ip, "ip")) {
                    this.queueCommandResult(commandId, command, false, "Block skipped: target is whitelisted", ip);
                    continue;
                }
                boolean ok = this.applyFirewallRule(command, ip);
                this.queueCommandResult(commandId, command, ok, ok ? "Android firewall rule applied for " + ip : "Firewall unavailable: grant VPN permission or root access", ip);
                continue;
            }
            if ("block_domain".equals(command) || "unblock_domain".equals(command)) {
                String domain = cmd.optString("domain", "").trim();
                if ("block_domain".equals(command) && LocalFirewallVpnService.isWhitelisted((Context)this, domain, "domain")) {
                    this.queueCommandResult(commandId, command, false, "Block skipped: target is whitelisted");
                    continue;
                }
                boolean ok = LocalFirewallVpnService.updateDomainRule((Context)this, domain, "block_domain".equals(command));
                this.queueCommandResult(commandId, command, ok, ok ? "Android domain firewall rule applied for " + domain : "Domain firewall unavailable or invalid");
                continue;
            }
            if ("block_application".equals(command) || "unblock_application".equals(command)) {
                String application = cmd.optString("application", "").trim();
                boolean ok = LocalFirewallVpnService.updateApplicationRule((Context)this, application, "block_application".equals(command));
                this.queueCommandResult(commandId, command, ok, ok ? "Android application firewall rule applied for " + application : "Application firewall unavailable or invalid");
                continue;
            }
            if ("ips_whitelist_add".equals(command) || "ips_whitelist_remove".equals(command)) {
                String value = cmd.optString("value", "").trim();
                String type = cmd.optString("type", "ip").trim().toLowerCase();
                boolean ok = LocalFirewallVpnService.updateWhitelist(
                    (Context)this, value, type, "ips_whitelist_add".equals(command));
                this.queueCommandResult(commandId, command, ok, ok ? "Android IPS whitelist updated" : "Invalid Android whitelist entry");
                continue;
            }
            this.queueCommandResult(commandId, command, false, "Unsupported on Android agent: " + command);
        }
    }

    private boolean initializeRootFirewall() {
        // Never probe for or invoke `su`. Standard and managed installations use
        // Android's consented VpnService. AOSP enforcement must be implemented as
        // a separately reviewed, SELinux-confined platform component.
        return false;
    }

    private boolean applyFirewallRule(String command, String ip) {
        boolean updated = LocalFirewallVpnService.updateRule((Context)this, ip, "block_ip".equals(command));
        this.vpnFirewallEnabled = updated || LocalFirewallVpnService.isRunning((Context)this);
        return updated;
    }

    private void queueCommandResult(String commandId, String command, boolean ok, String message) {
        this.queueCommandResult(commandId, command, ok, message, null);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private void queueCommandResult(String commandId, String command, boolean ok, String message, String ip) {
        if (commandId == null || commandId.isEmpty()) {
            return;
        }
        try {
            JSONObject result = new JSONObject();
            result.put("commandId", (Object)commandId);
            result.put("command", (Object)command);
            result.put("ok", ok);
            result.put("message", (Object)message);
            if (ip != null && !ip.isEmpty()) {
                result.put("ip", (Object)ip);
            }
            JSONArray jSONArray = this.commandResults;
            synchronized (jSONArray) {
                if (this.commandResults.length() >= 100) this.commandResults.remove(0);
                this.commandResults.put((Object)result);
                this.persistCommandResultsLocked();
            }
        }
        catch (Exception exception) {
            // empty catch block
        }
    }

    private boolean performSelfUpdate(String updateRequestId) {
        File apk;
        this.activeUpdateRequestId = updateRequestId == null ? "" : updateRequestId;
        this.sendUpdateStatus("downloading", null);
        try {
            apk = this.downloadUpdateApk(this.activeUpdateRequestId);
        }
        catch (Exception e) {
            this.sendUpdateStatus("failed", "download failed: " + e.getMessage());
            return false;
        }
        this.sendUpdateStatus("installing", null);
        try {
            this.launchInstaller(apk);
            return true;
        }
        catch (Exception e) {
            this.sendUpdateStatus("failed", "install launch failed: " + e.getMessage());
            return false;
        }
    }

    private File downloadUpdateApk(String updateRequestId) throws Exception {
        String serverUrl = this.config.optString("server_url", "").replaceAll("/+$", "");
        String agentKey = this.config.optString("agent_key", "");
        if (serverUrl.isEmpty() || agentKey.isEmpty()) {
            throw new Exception("agent not configured");
        }
        String updateQuery = updateRequestId == null || updateRequestId.isEmpty()
                ? ""
                : "?update_request_id=" + URLEncoder.encode(updateRequestId, "UTF-8");
        String updateUrl = serverUrl + "/api/agent/self-update/package/apk" + updateQuery;
        HttpURLConnection conn = this.secureTransport.openDownload(updateUrl);
        conn.setConnectTimeout(20000);
        conn.setReadTimeout(180000);
        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            String err = this.readAll(conn.getErrorStream());
            conn.disconnect();
            throw new Exception("HTTP " + code + " " + err);
        }
        File out = new File(this.getFilesDir(), "soc-agent-update.apk");
        try (InputStream in = conn.getInputStream();
             FileOutputStream fos = new FileOutputStream(out);){
            int n;
            byte[] buf = new byte[65536];
            while ((n = in.read(buf)) > 0) {
                ((OutputStream)fos).write(buf, 0, n);
            }
        }
        conn.disconnect();
        return out;
    }

    private void launchInstaller(File apk) {
        Uri uri = UpdateFileProvider.uriFor(apk);
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setDataAndType(uri, "application/vnd.android.package-archive");
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        this.startActivity(intent);
    }

    private void sendUpdateStatus(String status, String error) {
        try {
            String serverUrl = this.config.optString("server_url", "").replaceAll("/+$", "");
            String agentKey = this.config.optString("agent_key", "");
            if (serverUrl.isEmpty() || agentKey.isEmpty()) {
                return;
            }
            JSONObject body = new JSONObject();
            body.put("agent_key", (Object)agentKey);
            body.put("agent_version", AgentVersion.current(this));
            body.put("status", (Object)"active");
            body.put("update_status", (Object)status);
            if (!this.activeUpdateRequestId.isEmpty()) {
                body.put("update_request_id", (Object)this.activeUpdateRequestId);
            }
            if (error != null) {
                body.put("update_error", (Object)error);
            }
            body.put("os", (Object)"Android");
            body.put("osType", (Object)"android");
            this.secureTransport.post("/api/agent/heartbeat", body);
        }
        catch (Exception exception) {
            // empty catch block
        }
    }

    private void sendStartupSnapshotOnce() {
        SharedPreferences prefs = this.servicePreferences();
        if (prefs.getBoolean(SNAPSHOT_SENT, false)) {
            return;
        }
        new Thread(() -> {
            try {
                JSONObject snapshot = this.extra("device_health", this.getDeviceHealth(),
                        "installed_app_count", this.getInstalledAppCount(),
                        "capabilities", this.getCapabilities());
                snapshot.put("event_id", "android-startup-snapshot-" + this.getStableAgentId());
                if (this.telemetryPipeline.enqueue("android_forensic_snapshot", "system", "low",
                        "Android forensic snapshot collected: device health and installed app inventory summary",
                        snapshot)) {
                    // The durable queue now owns delivery and ACK retries.
                    prefs.edit().putBoolean(SNAPSHOT_SENT, true).apply();
                }
            }
            catch (Exception error) {
                // Leave the flag unset. The service restart/watchdog will retry enqueueing.
            }
        }, "ajnat-startup-snapshot").start();
    }

    private void maybeSendNetworkChangeAlert(String currentNetwork) {
        SharedPreferences prefs = this.servicePreferences();
        String last = prefs.getString(LAST_NETWORK, "");
        if (!last.isEmpty() && !last.equals(currentNetwork)) {
            JSONObject event = this.networkEvent("connectivity_change", null);
            try { event.put("previous_network", last); } catch (Exception ignored) {}
            this.sendAlertAsync("android_network_change", "network", "low", "Android network changed: " + last + " -> " + currentNetwork, event);
        }
        prefs.edit().putString(LAST_NETWORK, currentNetwork).apply();
    }

    private void sendAlertAsync(String ruleId, String category, String severity, String description, JSONObject extras) {
        new Thread(() -> {
            try {
                this.sendAlert(ruleId, category, severity, description, extras);
            }
            catch (Exception exception) {
                // empty catch block
            }
        }).start();
    }

    private void sendAlert(String ruleId, String category, String severity, String description, JSONObject extras) throws Exception {
        this.telemetryPipeline.enqueue(ruleId, category, severity, description, extras);
    }

    private void collectAndSendEdrTelemetry() {
        if (this.monitoringSuspended) return;
        SharedPreferences prefs = this.servicePreferences();
        long now = System.currentTimeMillis();
        long lastCollection = prefs.getLong(EDR_COLLECTION_CURSOR, 0L);
        if (lastCollection > 0L && now - lastCollection < EDR_TELEMETRY_INTERVAL_MS) return;
        long from = Math.max(now - 3600000L, prefs.getLong(TELEMETRY_CURSOR, now - 300000L));
        try {
            JSONArray events = this.collectUsageEvents(from, now);
            for (int i = 0; i < events.length(); i++) {
                JSONObject event = events.getJSONObject(i);
                this.sendAlert("ANDROID_APP_ACTIVITY", "edr", "low",
                        "Android application used: " + event.optString("process_name"), event);
            }
            prefs.edit().putLong(TELEMETRY_CURSOR, now).apply();
        } catch (Exception ignored) {
            // Keep the old cursor so a temporary upload failure is retried.
        }

        long fileFrom = Math.max(now - 3600000L, prefs.getLong(FILE_CURSOR, now - 300000L));
        try {
            JSONArray files = this.collectRecentFiles(fileFrom, now);
            for (int i = 0; i < files.length(); i++) {
                JSONObject event = files.getJSONObject(i);
                this.sendAlert("ANDROID_FILE_CREATED", "file", "low",
                        "Android shared-storage file observed: " + event.optString("file_name"), event);
            }
            prefs.edit().putLong(FILE_CURSOR, now).apply();
        } catch (Exception ignored) {
            // Keep the cursor for retry.
        }
        prefs.edit().putLong(EDR_COLLECTION_CURSOR, now).apply();
    }

    private void collectAndSendNetworkTelemetry() {
        if (this.monitoringSuspended) return;
        SharedPreferences prefs = this.servicePreferences();
        long now = System.currentTimeMillis();
        long previous = prefs.getLong(NETWORK_TELEMETRY_CURSOR, 0L);
        if (previous > 0L && now - previous < NETWORK_TELEMETRY_INTERVAL_MS) return;
        try {
            JSONObject event = this.networkEvent("network_status", null);
            this.sendAlert("ANDROID_NETWORK_STATUS", "network", "low",
                    "Android network monitor active: " + event.optString("network_type"), event);
            prefs.edit().putLong(NETWORK_TELEMETRY_CURSOR, now).apply();
        } catch (Exception ignored) {
            // Do not advance the cursor; retry after the next heartbeat.
        }
    }

    private JSONObject networkEvent(String eventType, String remoteIp) {
        JSONObject event = new JSONObject();
        try {
            long now = System.currentTimeMillis();
            String localIp = this.getLocalIpv4Address();
            event.put("capability_id", 3);
            event.put("capability_ids", new JSONArray().put(3).put(9).put(30).put(31));
            event.put("event_type", eventType);
            event.put("event_time", now);
            String eventTarget = remoteIp == null ? "status" : remoteIp;
            event.put("event_id", "android-network-" + eventType + "-"
                    + Integer.toHexString(eventTarget.hashCode()) + "-" + (now / 60000L));
            event.put("network_type", this.getNetworkType());
            event.put("protocol", "IP");
            event.put("direction", "outbound");
            event.put("inbound", false);
            event.put("action", remoteIp == null ? "observed" : "blocked");
            event.put("blocked", remoteIp != null);
            if (!localIp.isEmpty()) event.put("src_ip", localIp);
            if (remoteIp != null && !remoteIp.isEmpty()) {
                event.put("remote_ip", remoteIp);
                event.put("dst_ip", remoteIp);
            }
        } catch (Exception ignored) {}
        return event;
    }

    private JSONArray collectUsageEvents(long from, long to) throws Exception {
        JSONArray result = new JSONArray();
        if (!this.hasUsageAccess()) return result;
        UsageStatsManager manager = (UsageStatsManager)this.getSystemService(Context.USAGE_STATS_SERVICE);
        if (manager == null) return result;
        UsageEvents stream = manager.queryEvents(from, to);
        UsageEvents.Event event = new UsageEvents.Event();
        java.util.HashSet<String> seen = new java.util.HashSet<>();
        while (stream != null && stream.hasNextEvent() && result.length() < 50) {
            stream.getNextEvent(event);
            int type = event.getEventType();
            if (type != UsageEvents.Event.MOVE_TO_FOREGROUND
                    && (Build.VERSION.SDK_INT < 29 || type != UsageEvents.Event.ACTIVITY_RESUMED)) continue;
            String packageName = event.getPackageName();
            String key = packageName + ":" + (event.getTimeStamp() / 60000L);
            if (packageName == null || packageName.equals(this.getPackageName()) || !seen.add(key)) continue;
            JSONObject data = new JSONObject();
            data.put("capability_id", 1);
            data.put("capability_ids", new JSONArray().put(1).put(7).put(11).put(24));
            data.put("event_type", "application_foreground");
            data.put("process_name", packageName);
            data.put("package_name", packageName);
            data.put("process_status", "foreground");
            data.put("user_action", "application_used");
            data.put("event_time", event.getTimeStamp());
            data.put("event_id", "android-app-" + Integer.toHexString(key.hashCode()) + "-" + event.getTimeStamp());
            try {
                ApplicationInfo app = this.getPackageManager().getApplicationInfo(packageName, 0);
                data.put("application_label", this.getPackageManager().getApplicationLabel(app).toString());
                data.put("system_application", (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
            } catch (Exception ignored) {}
            result.put(data);
        }
        return result;
    }

    private boolean hasUsageAccess() {
        try {
            AppOpsManager ops = (AppOpsManager)this.getSystemService(Context.APP_OPS_SERVICE);
            int mode = ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
                    android.os.Process.myUid(), this.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception ignored) {
            return false;
        }
    }

    private JSONArray collectRecentFiles(long from, long to) throws Exception {
        JSONArray result = new JSONArray();
        if (Build.VERSION.SDK_INT >= 30 && !Environment.isExternalStorageManager()) return result;
        Uri uri = MediaStore.Files.getContentUri("external");
        String[] projection = new String[]{MediaStore.Files.FileColumns.DISPLAY_NAME,
                MediaStore.Files.FileColumns.DATA, MediaStore.Files.FileColumns.SIZE,
                MediaStore.Files.FileColumns.DATE_ADDED, MediaStore.Files.FileColumns.DATE_MODIFIED};
        String selection = MediaStore.Files.FileColumns.DATE_ADDED + ">=? OR "
                + MediaStore.Files.FileColumns.DATE_MODIFIED + ">=?";
        String seconds = String.valueOf(from / 1000L);
        try (Cursor cursor = this.getContentResolver().query(uri, projection, selection,
                new String[]{seconds, seconds}, MediaStore.Files.FileColumns.DATE_MODIFIED + " ASC")) {
            while (cursor != null && cursor.moveToNext() && result.length() < 100) {
                long changed = Math.max(cursor.getLong(3), cursor.getLong(4)) * 1000L;
                if (changed > to) continue;
                JSONObject data = new JSONObject();
                data.put("capability_id", 2);
                data.put("capability_ids", new JSONArray().put(2).put(7).put(12).put(25).put(27));
                data.put("event_type", "shared_storage_file_observed");
                data.put("file_name", cursor.getString(0));
                data.put("file_path", cursor.getString(1));
                data.put("file_size", cursor.getLong(2));
                data.put("file_action", cursor.getLong(3) == cursor.getLong(4) ? "created" : "modified");
                data.put("event_time", changed);
                data.put("event_id", "android-file-" + Integer.toHexString((String.valueOf(cursor.getString(1)) + changed).hashCode()) + "-" + changed);
                result.put(data);
            }
        }
        return result;
    }

    private JSONObject getCapabilities() {
        JSONObject caps = new JSONObject();
        try {
            boolean vpnConsent = LocalFirewallVpnService.hasConsent((Context)this);
            boolean firewallEnabled = this.rootFirewallEnabled || this.vpnFirewallEnabled;
            caps.put("edr_device_health", true);
            caps.put("edr_app_inventory", true);
            caps.put("edr_app_install_uninstall_alerts", true);
            caps.put("edr_app_usage_monitoring", this.hasUsageAccess());
            caps.put("edr_shared_storage_file_monitoring", Build.VERSION.SDK_INT < 30 || Environment.isExternalStorageManager());
            caps.put("android_supported_capability_ids", new JSONArray().put(1).put(2).put(3).put(7).put(8).put(9).put(11).put(12).put(17).put(22).put(23).put(24).put(25).put(26).put(27).put(30).put(31));
            caps.put("ids_network_change_detection", true);
            caps.put("forensic_device_snapshot", true);
            caps.put("heartbeat_subscription_control", true);
            caps.put("ids_mode", (Object)(this.vpnFirewallEnabled ? "vpn_blocked_flow_monitor" : "network_change_monitor"));
            caps.put("ips_blocking", firewallEnabled);
            caps.put("firewall_rules", firewallEnabled);
            caps.put("root_firewall", this.rootFirewallEnabled);
            caps.put("vpn_firewall", this.vpnFirewallEnabled);
            caps.put("vpn_permission_granted", vpnConsent);
            caps.put("capability_mode", this.capabilityDetector.mode().name());
            caps.put("runtime_detection", this.capabilityDetector.report());
            caps.put("native_process_telemetry", this.nativeDaemon.isAvailable());
            caps.put("native_network_telemetry", this.nativeDaemon.isAvailable());
            caps.put("usb_telemetry", true);
            caps.put("yara_scan", false);
            caps.put("note", (Object)(this.rootFirewallEnabled ? "Root iptables firewall and Android network IDS are active." : (this.vpnFirewallEnabled ? "Local VPN malicious-IP firewall and blocked-flow IDS are active." : "Network-change IDS is active; open AJNAT once to grant VPN firewall permission.")));
        }
        catch (Exception exception) {
            // empty catch block
        }
        return caps;
    }

    private JSONObject getDeviceHealth() {
        JSONObject health = new JSONObject();
        try {
            BatteryManager battery = (BatteryManager)this.getSystemService(Context.BATTERY_SERVICE);
            int pct = battery != null
                    ? battery.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) : -1;
            health.put("battery_percent", pct);
            health.put("manufacturer", (Object)Build.MANUFACTURER);
            health.put("model", (Object)Build.MODEL);
            health.put("android_version", (Object)Build.VERSION.RELEASE);
            health.put("sdk", Build.VERSION.SDK_INT);
            health.put("storage", (Object)this.getStorageInfo());
            health.put("network_type", (Object)this.getNetworkType());
            health.put("capability_mode", this.capabilityDetector.mode().name());
            health.put("telemetry_queue", this.telemetryPipeline.health());
            health.put("collectors", this.collectorManager.health());
            health.put("last_heartbeat_attempt", this.lastHeartbeatAttemptMs);
            health.put("last_successful_heartbeat", this.lastSuccessfulHeartbeatMs);
            health.put("heartbeat_state", this.lastHeartbeatError.isEmpty() ? "ready" : "retrying");
            health.put("last_heartbeat_error", this.lastHeartbeatError);
        }
        catch (Exception exception) {
            // empty catch block
        }
        return health;
    }

    private JSONObject getStorageInfo() {
        JSONObject storage = new JSONObject();
        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
            long total = stat.getBlockCountLong() * stat.getBlockSizeLong();
            long free = stat.getAvailableBlocksLong() * stat.getBlockSizeLong();
            storage.put("total_bytes", total);
            storage.put("free_bytes", free);
            storage.put("used_percent", total > 0L ? Math.round((double)(total - free) * 100.0 / (double)total) : 0L);
        }
        catch (Exception exception) {
            // empty catch block
        }
        return storage;
    }

    private int getInstalledAppCount() {
        try {
            List packages = this.getPackageManager().getInstalledPackages(0);
            return packages != null ? packages.size() : 0;
        }
        catch (Exception e) {
            return -1;
        }
    }

    private JSONObject extra(String k1, Object v1, String k2, Object v2) {
        JSONObject obj = new JSONObject();
        try {
            obj.put(k1, v1);
            obj.put(k2, v2);
        }
        catch (Exception exception) {
            // empty catch block
        }
        return obj;
    }

    private JSONObject extra(String k1, Object v1) {
        JSONObject obj = new JSONObject();
        try {
            obj.put(k1, v1);
        }
        catch (Exception exception) {
            // empty catch block
        }
        return obj;
    }

    private JSONObject extra(String k1, Object v1, String k2, Object v2, String k3, Object v3) {
        JSONObject obj = this.extra(k1, v1, k2, v2);
        try {
            obj.put(k3, v3);
        }
        catch (Exception exception) {
            // empty catch block
        }
        return obj;
    }

    private SharedPreferences servicePreferences() {
        if (Build.VERSION.SDK_INT < 24) {
            return this.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        }
        Context deviceContext = this.createDeviceProtectedStorageContext();
        // Preserve pre-upgrade state when the user has unlocked at least once.
        SharedPreferences devicePreferences = deviceContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (!devicePreferences.getBoolean(DEVICE_PREFS_MIGRATED, false)) {
            try {
                deviceContext.moveSharedPreferencesFrom(this, PREFS);
                devicePreferences = deviceContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                devicePreferences.edit().putBoolean(DEVICE_PREFS_MIGRATED, true).apply();
            } catch (Exception ignored) {
                // Retry migration after user unlock.
            }
        }
        return devicePreferences;
    }

    private void restoreCommandResults() {
        String encoded = this.servicePreferences().getString(COMMAND_RESULTS, "[]");
        try {
            JSONArray saved = new JSONArray(encoded);
            synchronized (this.commandResults) {
                for (int i = 0; i < saved.length(); i++) {
                    JSONObject item = saved.optJSONObject(i);
                    if (item != null) this.commandResults.put(item);
                }
            }
        } catch (Exception ignored) {
            this.servicePreferences().edit().remove(COMMAND_RESULTS).apply();
        }
    }

    /** Caller must hold commandResults' monitor. */
    private void persistCommandResultsLocked() {
        this.servicePreferences().edit()
                .putString(COMMAND_RESULTS, this.commandResults.toString())
                .apply();
    }

    private JSONObject readConfig() {
        try {
            return SecureConfigStore.resolve(this,
                    new JSONObject(this.readAsset("company_config.json")));
        }
        catch (Exception e) {
            return new JSONObject();
        }
    }

    private String readAsset(String name) throws Exception {
        try (InputStream in = this.getAssets().open(name);){
            String string = this.readAll(in);
            return string;
        }
    }

    private String readAll(InputStream in) throws Exception {
        int n;
        if (in == null) {
            return "";
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toString(StandardCharsets.UTF_8.name());
    }

    private String getNetworkType() {
        try {
            ConnectivityManager cm = (ConnectivityManager)this.getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo info = cm.getActiveNetworkInfo();
            if (info == null || !info.isConnected()) {
                return "offline";
            }
            return info.getTypeName();
        }
        catch (Exception e) {
            return "unknown";
        }
    }

    private static class HeartbeatResult {
        final boolean stopMonitoring;
        final int intervalSeconds;

        HeartbeatResult(boolean stopMonitoring, int intervalSeconds) {
            this.stopMonitoring = stopMonitoring;
            this.intervalSeconds = intervalSeconds;
        }
    }
}
