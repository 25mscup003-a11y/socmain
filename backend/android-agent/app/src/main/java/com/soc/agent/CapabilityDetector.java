package com.soc.agent;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import org.json.JSONObject;

/** Detects effective capabilities without assuming that requested privileges were granted. */
public final class CapabilityDetector {
    private final Context context;
    private final NativeDaemonClient daemon;

    public CapabilityDetector(Context context, NativeDaemonClient daemon) {
        this.context = context.getApplicationContext();
        this.daemon = daemon;
    }

    public CapabilityMode mode() {
        boolean privilegedApp = isPrivilegedSystemApp();
        if (privilegedApp && daemon.isAvailable()) return CapabilityMode.AOSP_INTEGRATED;
        if (privilegedApp) return CapabilityMode.PRIVILEGED_SYSTEM_APP;
        if (isManaged()) return CapabilityMode.MANAGED_DEVICE;
        return CapabilityMode.STANDARD_ANDROID;
    }

    public boolean isManaged() {
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (dpm == null) return false;
        String packageName = context.getPackageName();
        return dpm.isDeviceOwnerApp(packageName)
                || (Build.VERSION.SDK_INT >= 21 && dpm.isProfileOwnerApp(packageName));
    }

    public boolean isSystemApp() {
        try {
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(context.getPackageName(), 0);
            return (info.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    public boolean isPrivilegedSystemApp() {
        return isSystemApp() && context.getPackageManager().checkPermission(
                "android.permission.PACKAGE_USAGE_STATS", context.getPackageName())
                == PackageManager.PERMISSION_GRANTED;
    }

    public JSONObject report() {
        JSONObject result = new JSONObject();
        try {
            CapabilityMode detected = mode();
            result.put("mode", detected.name());
            result.put("managed_device", isManaged());
            result.put("system_app", isSystemApp());
            result.put("privileged_system_app", isPrivilegedSystemApp());
            DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            result.put("legacy_device_admin", dpm != null && dpm.isAdminActive(
                    new ComponentName(context, AgentDeviceAdminReceiver.class)));
            result.put("native_daemon", daemon.isAvailable());
            result.put("android_sdk", Build.VERSION.SDK_INT);
            result.put("kernel", System.getProperty("os.version", "unknown"));
            JSONObject nativeCapabilities = daemon.capabilities();
            if (nativeCapabilities != null) result.put("kernel_telemetry", nativeCapabilities);
        } catch (Exception ignored) {
        }
        return result;
    }
}
