package com.soc.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import com.soc.agent.AgentService;
import com.soc.agent.MainActivity;
import com.soc.agent.R;
import java.io.FileInputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

public class LocalFirewallVpnService
extends VpnService {
    public static final String ACTION_RELOAD = "com.soc.agent.VPN_RELOAD";
    private static final String CHANNEL_ID = "soc_agent_firewall";
    private static final String PREFS = "soc_agent_firewall";
    private static final String BLOCKED_IPS = "blocked_ips";
    private static final String POLICY_IPS = "policy_ips";
    private static final String BLOCKED_DOMAINS = "blocked_domains";
    private static final String BLOCKED_APPLICATIONS = "blocked_applications";
    private static final String COMMAND_DOMAINS = "command_domains";
    private static final String COMMAND_APPLICATIONS = "command_applications";
    private static final String WHITELIST_ENTRIES = "whitelist_entries";
    private static final String ISOLATED = "isolated";
    private static final Set<String> DEFAULT_WHITELIST = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "ip|127.0.0.1", "ip|::1", "ip|8.8.8.8", "ip|8.8.4.4",
            "ip|1.1.1.1", "ip|1.0.0.1", "ip|9.9.9.9", "ip|9.9.9.11",
            "ip|149.112.112.112", "ip|149.112.112.11", "ip|0.0.0.0")));
    private static final String RUNNING = "running";
    private static final int NOTIFICATION_ID = 1003;
    private final Map<String, Long> lastAlertAt = Collections.synchronizedMap(new HashMap());
    private final Handler handler = new Handler(Looper.getMainLooper());
    private ParcelFileDescriptor tunnel;
    private Thread packetThread;
    private final Runnable refreshRules = new Runnable(){

        @Override
        public void run() {
            new Thread(() -> LocalFirewallVpnService.this.establishTunnel(), "ajnat-vpn-refresh").start();
            LocalFirewallVpnService.this.handler.postDelayed((Runnable)this, 600000L);
        }
    };

    public static boolean hasConsent(Context context) {
        return VpnService.prepare((Context)context) == null;
    }

    public static boolean isRunning(Context context) {
        return context.getSharedPreferences("soc_agent_firewall", 0).getBoolean(RUNNING, false);
    }

    public static boolean isIsolated(Context context) {
        return context.getSharedPreferences(PREFS, 0).getBoolean(ISOLATED, false);
    }

    /**
     * Persist isolation intent before rebuilding the VPN. Android may stop and
     * recreate either service, so this flag is deliberately not in memory.
     * The AJNAT application itself is excluded from the full-tunnel drop route
     * in establishTunnel(), preserving its heartbeat/reconnect control path.
     */
    public static boolean setIsolation(Context context, boolean isolated) {
        if (isolated && !LocalFirewallVpnService.hasConsent(context)) return false;
        boolean current = LocalFirewallVpnService.isIsolated(context);
        if (current == isolated) {
            if (isolated && !LocalFirewallVpnService.isRunning(context)) LocalFirewallVpnService.reload(context);
            return true;
        }
        if (!context.getSharedPreferences(PREFS, 0).edit().putBoolean(ISOLATED, isolated).commit()) return false;
        if (LocalFirewallVpnService.hasConsent(context)) LocalFirewallVpnService.reload(context);
        return true;
    }

    static boolean requiresFullTunnel(boolean isolated, boolean applicationMode) {
        return isolated || applicationMode;
    }

    public static void start(Context context) {
        if (!LocalFirewallVpnService.hasConsent(context)) {
            return;
        }
        Intent intent = new Intent(context, LocalFirewallVpnService.class);
        intent.setAction("com.soc.agent.VPN_START");
        startServiceCompat(context, intent);
    }

    private static void reload(Context context) {
        if (!LocalFirewallVpnService.hasConsent(context)) return;
        Intent intent = new Intent(context, LocalFirewallVpnService.class);
        intent.setAction(ACTION_RELOAD);
        startServiceCompat(context, intent);
    }

    private static void startServiceCompat(Context context, Intent intent) {
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    public static boolean updateRule(Context context, String ip, boolean block) {
        if (!LocalFirewallVpnService.isValidIp(ip) || !LocalFirewallVpnService.hasConsent(context)
                || (block && LocalFirewallVpnService.isWhitelisted(context, ip, "ip"))) {
            return false;
        }
        SharedPreferences prefs = context.getSharedPreferences("soc_agent_firewall", 0);
        HashSet<String> rules = new HashSet<String>(prefs.getStringSet(BLOCKED_IPS, Collections.emptySet()));
        if (block) {
            rules.add(ip);
        } else {
            rules.remove(ip);
        }
        prefs.edit().putStringSet(BLOCKED_IPS, rules).apply();
        LocalFirewallVpnService.reload(context);
        return true;
    }

    public static boolean updateDomainRule(Context context, String domain, boolean block) {
        String normalized = LocalFirewallVpnService.normalizeDomain(domain);
        if (normalized.isEmpty() || !LocalFirewallVpnService.hasConsent(context)
                || (block && LocalFirewallVpnService.isWhitelisted(context, normalized, "domain"))) {
            return false;
        }
        SharedPreferences prefs = context.getSharedPreferences("soc_agent_firewall", 0);
        HashSet<String> rules = new HashSet<String>(prefs.getStringSet(COMMAND_DOMAINS, Collections.emptySet()));
        if (block) rules.add(normalized); else rules.remove(normalized);
        prefs.edit().putStringSet(COMMAND_DOMAINS, rules).apply();
        LocalFirewallVpnService.reload(context);
        return true;
    }

    public static boolean updateApplicationRule(Context context, String application, boolean block) {
        HashSet<String> requested = new HashSet<String>();
        if (application != null && !application.trim().isEmpty()) requested.add(application);
        Set<String> packages = LocalFirewallVpnService.applicationPackages(requested);
        if (packages.isEmpty() || !LocalFirewallVpnService.hasConsent(context)) return false;
        SharedPreferences prefs = context.getSharedPreferences("soc_agent_firewall", 0);
        HashSet<String> rules = new HashSet<String>(prefs.getStringSet(COMMAND_APPLICATIONS, Collections.emptySet()));
        if (block) rules.addAll(packages); else rules.removeAll(packages);
        prefs.edit().putStringSet(COMMAND_APPLICATIONS, rules).apply();
        LocalFirewallVpnService.reload(context);
        return true;
    }

    public static void replaceWhitelist(Context context, JSONArray entries) {
        if (entries == null) return;
        HashSet<String> normalized = new HashSet<String>();
        for (int i = 0; i < entries.length(); ++i) {
            JSONObject entry = entries.optJSONObject(i);
            if (entry == null) continue;
            String encoded = LocalFirewallVpnService.normalizeWhitelistEntry(
                    entry.optString("value", ""), entry.optString("type", "ip"));
            if (!encoded.isEmpty()) normalized.add(encoded);
        }
        SharedPreferences prefs = context.getSharedPreferences("soc_agent_firewall", 0);
        Set<String> old = prefs.getStringSet(WHITELIST_ENTRIES, Collections.emptySet());
        boolean changed = !normalized.equals(old);
        SharedPreferences.Editor editor = prefs.edit().putStringSet(WHITELIST_ENTRIES, normalized);
        LocalFirewallVpnService.removeWhitelistedCommandBlocks(prefs, editor, normalized);
        editor.apply();
        if (changed && LocalFirewallVpnService.hasConsent(context)) LocalFirewallVpnService.reload(context);
    }

    public static boolean updateWhitelist(Context context, String value, String type, boolean add) {
        String encoded = LocalFirewallVpnService.normalizeWhitelistEntry(value, type);
        if (encoded.isEmpty()) return false;
        SharedPreferences prefs = context.getSharedPreferences("soc_agent_firewall", 0);
        HashSet<String> entries = new HashSet<String>(prefs.getStringSet(WHITELIST_ENTRIES, Collections.emptySet()));
        if (add) entries.add(encoded); else entries.remove(encoded);
        SharedPreferences.Editor editor = prefs.edit().putStringSet(WHITELIST_ENTRIES, entries);
        if (add) LocalFirewallVpnService.removeWhitelistedCommandBlocks(prefs, editor, entries);
        editor.apply();
        if (LocalFirewallVpnService.hasConsent(context)) LocalFirewallVpnService.reload(context);
        return true;
    }

    public static boolean isWhitelisted(Context context, String value, String type) {
        HashSet<String> entries = new HashSet<String>(DEFAULT_WHITELIST);
        entries.addAll(context.getSharedPreferences("soc_agent_firewall", 0)
                .getStringSet(WHITELIST_ENTRIES, Collections.emptySet()));
        return LocalFirewallVpnService.whitelistMatches(entries, value, type);
    }

    static boolean whitelistMatches(Set<String> entries, String value, String type) {
        String normalizedType = type == null ? "ip" : type.trim().toLowerCase();
        if ("domain".equals(normalizedType)) {
            String host = LocalFirewallVpnService.normalizeDomain(value);
            for (String encoded : entries) {
                if (!encoded.startsWith("domain|")) continue;
                String allowed = encoded.substring(7);
                if (host.equals(allowed) || host.endsWith("." + allowed)) return true;
            }
            return false;
        }
        for (String encoded : entries) {
            int separator = encoded.indexOf('|');
            if (separator < 1) continue;
            String kind = encoded.substring(0, separator);
            String candidate = encoded.substring(separator + 1);
            if ("ip".equals(kind) && LocalFirewallVpnService.sameIp(value, candidate)) return true;
            if ("cidr".equals(kind) && LocalFirewallVpnService.ipv4InCidr(value, candidate)) return true;
        }
        return false;
    }

    private static String normalizeWhitelistEntry(String value, String type) {
        String kind = type == null ? "ip" : type.trim().toLowerCase();
        String candidate = value == null ? "" : value.trim().toLowerCase();
        if ("domain".equals(kind)) candidate = LocalFirewallVpnService.normalizeDomain(candidate);
        if ("ip".equals(kind) && !LocalFirewallVpnService.isValidIp(candidate)) return "";
        if ("cidr".equals(kind) && !LocalFirewallVpnService.validIpCidr(candidate)) return "";
        if ("domain".equals(kind) && candidate.isEmpty()) return "";
        if (!"ip".equals(kind) && !"cidr".equals(kind) && !"domain".equals(kind)) return "";
        return kind + "|" + candidate;
    }

    private static void removeWhitelistedCommandBlocks(SharedPreferences prefs, SharedPreferences.Editor editor, Set<String> whitelist) {
        HashSet<String> ips = new HashSet<String>(prefs.getStringSet(BLOCKED_IPS, Collections.emptySet()));
        HashSet<String> keptIps = new HashSet<String>();
        for (String ip : ips) if (!LocalFirewallVpnService.whitelistMatches(whitelist, ip, "ip")) keptIps.add(ip);
        HashSet<String> domains = new HashSet<String>(prefs.getStringSet(COMMAND_DOMAINS, Collections.emptySet()));
        HashSet<String> keptDomains = new HashSet<String>();
        for (String domain : domains) if (!LocalFirewallVpnService.whitelistMatches(whitelist, domain, "domain")) keptDomains.add(domain);
        editor.putStringSet(BLOCKED_IPS, keptIps).putStringSet(COMMAND_DOMAINS, keptDomains);
    }

    public static void replacePolicyRules(Context context, JSONArray ips, JSONArray domains, JSONArray applications) {
        Set<String> policyIps = LocalFirewallVpnService.jsonSet(ips, true);
        Set<String> policyDomains = LocalFirewallVpnService.jsonSet(domains, false);
        Set<String> appNames = LocalFirewallVpnService.jsonSet(applications, false);
        for (String application : appNames) {
            String normalized = application.toLowerCase();
            if (!normalized.contains("youtube") && !normalized.contains("com.google.android.youtube")) continue;
            policyDomains.add("youtube.com");
        }
        SharedPreferences prefs = context.getSharedPreferences("soc_agent_firewall", 0);
        Set oldIps = prefs.getStringSet(POLICY_IPS, Collections.emptySet());
        Set oldDomains = prefs.getStringSet(BLOCKED_DOMAINS, Collections.emptySet());
        Set<String> appPackages = LocalFirewallVpnService.applicationPackages(appNames);
        Set oldApplications = prefs.getStringSet(BLOCKED_APPLICATIONS, Collections.emptySet());
        boolean changed = !policyIps.equals(oldIps) || !policyDomains.equals(oldDomains) || !appPackages.equals(oldApplications);
        prefs.edit().putStringSet(POLICY_IPS, policyIps).putStringSet(BLOCKED_DOMAINS, policyDomains).putStringSet(BLOCKED_APPLICATIONS, appPackages).apply();
        if (LocalFirewallVpnService.hasConsent(context) && (changed || !LocalFirewallVpnService.isRunning(context))) {
            LocalFirewallVpnService.reload(context);
        }
    }

    private static Set<String> jsonSet(JSONArray values, boolean requireIp) {
        HashSet<String> result = new HashSet<String>();
        if (values == null) {
            return result;
        }
        for (int i = 0; i < values.length(); ++i) {
            String value = values.optString(i, "").trim().toLowerCase();
            if (requireIp) {
                if (!LocalFirewallVpnService.isValidIpv4(value)) continue;
                result.add(value);
                continue;
            }
            if ((value = LocalFirewallVpnService.normalizeDomain(value)).isEmpty()) continue;
            result.add(value);
        }
        return result;
    }

    public void onCreate() {
        super.onCreate();
        this.startForeground(1003, this.buildNotification());
        this.handler.postDelayed(this.refreshRules, 600000L);
    }

    public int onStartCommand(Intent intent, int flags, int startId) {
        // Starting an already-running service must not tear down and rebuild the
        // tunnel unless rules actually changed or the tunnel was lost.
        if (this.tunnel == null || (intent != null && ACTION_RELOAD.equals(intent.getAction()))) {
            new Thread(this::establishTunnel, "ajnat-vpn-config").start();
        }
        return Service.START_STICKY;
    }

    private synchronized void establishTunnel() {
        this.closeTunnel();
        SharedPreferences prefs = this.getSharedPreferences("soc_agent_firewall", 0);
        HashSet<String> blocked = new HashSet<String>(prefs.getStringSet(BLOCKED_IPS, Collections.emptySet()));
        blocked.addAll(prefs.getStringSet(POLICY_IPS, Collections.emptySet()));
        HashSet<String> domains = new HashSet<String>(prefs.getStringSet(BLOCKED_DOMAINS, Collections.emptySet()));
        domains.addAll(prefs.getStringSet(COMMAND_DOMAINS, Collections.emptySet()));
        HashSet<String> blockedApplications = new HashSet<String>(prefs.getStringSet(BLOCKED_APPLICATIONS, Collections.emptySet()));
        blockedApplications.addAll(prefs.getStringSet(COMMAND_APPLICATIONS, Collections.emptySet()));
        boolean isolated = prefs.getBoolean(ISOLATED, false);
        HashSet<String> whitelist = new HashSet<String>(DEFAULT_WHITELIST);
        whitelist.addAll(prefs.getStringSet(WHITELIST_ENTRIES, Collections.emptySet()));
        HashSet<String> allowedBlocks = new HashSet<String>();
        for (String ip : blocked) if (!LocalFirewallVpnService.whitelistMatches(whitelist, ip, "ip")) allowedBlocks.add(ip);
        blocked = allowedBlocks;
        HashSet<String> allowedDomains = new HashSet<String>();
        for (String domain : domains) if (!LocalFirewallVpnService.whitelistMatches(whitelist, domain, "domain")) allowedDomains.add(domain);
        domains = allowedDomains;
        for (String domain : domains) {
            blocked.addAll(LocalFirewallVpnService.resolveDomainFamily(domain));
        }
        try {
            VpnService.Builder builder = new VpnService.Builder().setSession("AJNAT Firewall / IPS").setMtu(1500)
                    .addAddress("10.111.222.1", 32).addAddress("fd00:111:222::1", 128)
                    .setConfigureIntent(PendingIntent.getActivity((Context)this, (int)1004, (Intent)new Intent((Context)this, MainActivity.class), (int)0xC000000));
            boolean applicationMode = !blockedApplications.isEmpty();
            if (isolated) {
                // All device traffic enters this non-forwarding VPN and is
                // dropped. Excluding only AJNAT keeps remote unisolate alive.
                try {
                    builder.addDisallowedApplication(this.getPackageName());
                }
                catch (Exception exception) {}
            } else {
                for (String packageName : blockedApplications) {
                    try {
                        builder.addAllowedApplication(packageName);
                    }
                    catch (Exception exception) {}
                }
            }
            if (LocalFirewallVpnService.requiresFullTunnel(isolated, applicationMode)) {
                builder.addRoute("0.0.0.0", 0);
                builder.addRoute("::", 0);
            } else {
                for (String ip : blocked) {
                    if (!LocalFirewallVpnService.isValidIp(ip)) continue;
                    builder.addRoute(ip, ip.contains(":") ? 128 : 32);
                }
            }
            if (Build.VERSION.SDK_INT >= 29) {
                builder.setMetered(false);
            }
            this.tunnel = builder.establish();
            boolean running = this.tunnel != null;
            this.getSharedPreferences("soc_agent_firewall", 0).edit().putBoolean(RUNNING, running).apply();
            if (running) {
                this.startPacketMonitor(this.tunnel);
            }
        }
        catch (Exception ignored) {
            this.getSharedPreferences("soc_agent_firewall", 0).edit().putBoolean(RUNNING, false).apply();
        }
    }

    private void startPacketMonitor(ParcelFileDescriptor descriptor) {
        this.packetThread = new Thread(() -> {
            byte[] packet = new byte[Short.MAX_VALUE];
            try (FileInputStream input = new FileInputStream(descriptor.getFileDescriptor());){
                while (!Thread.currentThread().isInterrupted()) {
                    int length = input.read(packet);
                    if (length < 20) continue;
                    int version = (packet[0] & 0xF0) >> 4;
                    int headerLength;
                    int protocolNumber;
                    String destination;
                    if (version == 4) {
                        headerLength = (packet[0] & 0x0F) * 4;
                        if (headerLength < 20 || length < headerLength) continue;
                        protocolNumber = packet[9] & 0xFF;
                        destination = (packet[16] & 0xFF) + "." + (packet[17] & 0xFF) + "." + (packet[18] & 0xFF) + "." + (packet[19] & 0xFF);
                    } else if (version == 6 && length >= 40) {
                        headerLength = 40;
                        protocolNumber = packet[6] & 0xFF;
                        byte[] destinationBytes = new byte[16];
                        System.arraycopy(packet, 24, destinationBytes, 0, 16);
                        destination = InetAddress.getByAddress(destinationBytes).getHostAddress();
                    } else {
                        continue;
                    }
                    String protocol = protocolNumber == 6 ? "TCP" : protocolNumber == 17 ? "UDP" : "IP-" + protocolNumber;
                    int sourcePort = 0;
                    int destinationPort = 0;
                    if ((protocolNumber == 6 || protocolNumber == 17) && length >= headerLength + 4) {
                        sourcePort = ((packet[headerLength] & 0xFF) << 8) | (packet[headerLength + 1] & 0xFF);
                        destinationPort = ((packet[headerLength + 2] & 0xFF) << 8) | (packet[headerLength + 3] & 0xFF);
                    }
                    this.reportBlockedAttempt(destination, protocol, sourcePort, destinationPort);
                }
            }
            catch (Exception exception) {
                // empty catch block
            }
        }, "ajnat-vpn-ids");
        this.packetThread.start();
    }

    private void reportBlockedAttempt(String destination, String protocol, int sourcePort, int destinationPort) {
        long now = System.currentTimeMillis();
        Long previous = this.lastAlertAt.get(destination);
        if (previous != null && now - previous < 60000L) {
            return;
        }
        this.lastAlertAt.put(destination, now);
        Intent event = new Intent((Context)this, AgentService.class);
        event.setAction("com.soc.agent.IDS_EVENT");
        event.putExtra("remote_ip", destination);
        event.putExtra("protocol", protocol);
        event.putExtra("src_port", sourcePort);
        event.putExtra("dst_port", destinationPort);
        if (Build.VERSION.SDK_INT >= 26) {
            this.startForegroundService(event);
        } else {
            this.startService(event);
        }
    }

    private synchronized void closeTunnel() {
        if (this.packetThread != null) {
            this.packetThread.interrupt();
        }
        this.packetThread = null;
        try {
            if (this.tunnel != null) {
                this.tunnel.close();
            }
        }
        catch (Exception exception) {
            // empty catch block
        }
        this.tunnel = null;
    }

    public void onDestroy() {
        this.handler.removeCallbacksAndMessages(null);
        this.closeTunnel();
        this.getSharedPreferences("soc_agent_firewall", 0).edit().putBoolean(RUNNING, false).apply();
        super.onDestroy();
    }

    public void onRevoke() {
        this.stopSelf();
    }

    private Notification buildNotification() {
        NotificationManager manager = (NotificationManager)this.getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(new NotificationChannel("soc_agent_firewall", "AJNAT Firewall",
                    NotificationManager.IMPORTANCE_LOW));
        }
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder((Context)this, "soc_agent_firewall") : new Notification.Builder((Context)this);
        return builder.setContentTitle((CharSequence)"AJNAT Firewall / IPS").setContentText((CharSequence)"Blocking dashboard-managed malicious IP addresses").setSmallIcon(R.drawable.ic_launcher).setOngoing(true).build();
    }

    private static boolean isValidIpv4(String ip) {
        if (ip == null || !ip.matches("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")) {
            return false;
        }
        for (String part : ip.split("\\.")) {
            try {
                if (Integer.parseInt(part) <= 255) continue;
                return false;
            }
            catch (NumberFormatException error) {
                return false;
            }
        }
        return true;
    }

    static boolean isValidIp(String ip) {
        if (LocalFirewallVpnService.isValidIpv4(ip)) return true;
        if (ip == null || !ip.contains(":")) return false;
        try {
            return InetAddress.getByName(ip.split("%", 2)[0]) instanceof Inet6Address;
        }
        catch (Exception error) {
            return false;
        }
    }

    private static boolean sameIp(String left, String right) {
        if (!LocalFirewallVpnService.isValidIp(left) || !LocalFirewallVpnService.isValidIp(right)) return false;
        try {
            return Arrays.equals(
                    InetAddress.getByName(left.split("%", 2)[0]).getAddress(),
                    InetAddress.getByName(right.split("%", 2)[0]).getAddress());
        }
        catch (Exception error) {
            return false;
        }
    }

    private static boolean validIpCidr(String value) {
        String[] parts = value == null ? new String[0] : value.split("/", -1);
        if (parts.length != 2 || !LocalFirewallVpnService.isValidIp(parts[0])) return false;
        try {
            int prefix = Integer.parseInt(parts[1]);
            int maximum = parts[0].contains(":") ? 128 : 32;
            return prefix >= 0 && prefix <= maximum;
        }
        catch (NumberFormatException error) {
            return false;
        }
    }

    private static boolean ipv4InCidr(String ip, String cidr) {
        if (!LocalFirewallVpnService.isValidIp(ip) || !LocalFirewallVpnService.validIpCidr(cidr)) return false;
        String[] cidrParts = cidr.split("/", 2);
        int prefix = Integer.parseInt(cidrParts[1]);
        try {
            byte[] address = InetAddress.getByName(ip.split("%", 2)[0]).getAddress();
            byte[] network = InetAddress.getByName(cidrParts[0].split("%", 2)[0]).getAddress();
            if (address.length != network.length) return false;
            int fullBytes = prefix / 8;
            int remainingBits = prefix % 8;
            for (int index = 0; index < fullBytes; ++index) {
                if (address[index] != network[index]) return false;
            }
            if (remainingBits == 0) return true;
            int mask = (0xFF << (8 - remainingBits)) & 0xFF;
            return ((address[fullBytes] & 0xFF) & mask) == ((network[fullBytes] & 0xFF) & mask);
        }
        catch (Exception error) {
            return false;
        }
    }

    private static String normalizeDomain(String value) {
        if (value == null) {
            return "";
        }
        String domain = value.trim().toLowerCase().replaceFirst("^https?://", "").replaceFirst("^\\*\\.", "").replaceFirst("/.*$", "").replaceFirst(":\\d+$", "");
        return domain.matches("^[a-z0-9.-]+\\.[a-z]{2,}$") ? domain : "";
    }

    private static Set<String> resolveDomainFamily(String configuredDomain) {
        HashSet<String> hosts = new HashSet<String>();
        String domain = LocalFirewallVpnService.normalizeDomain(configuredDomain);
        if (domain.isEmpty()) {
            return Collections.emptySet();
        }
        hosts.add(domain);
        hosts.add("www." + domain);
        if (domain.equals("youtube.com") || domain.endsWith(".youtube.com")) {
            Collections.addAll(hosts, "youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com", "i.ytimg.com", "yt3.ggpht.com", "redirector.googlevideo.com");
        }
        HashSet<String> addresses = new HashSet<String>();
        for (String host : hosts) {
            try {
                for (InetAddress address : InetAddress.getAllByName(host)) {
                    if (!(address instanceof Inet4Address) && !(address instanceof Inet6Address)) continue;
                    addresses.add(address.getHostAddress());
                }
            }
            catch (Exception exception) {
            }
        }
        return addresses;
    }

    private static Set<String> applicationPackages(Set<String> applications) {
        HashSet<String> packages = new HashSet<String>();
        for (String application : applications) {
            String value = application.trim().toLowerCase();
            if (value.contains("youtube")) {
                packages.add("com.google.android.youtube");
                continue;
            }
            if (!value.matches("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)+$")) continue;
            packages.add(value);
        }
        return packages;
    }
}
