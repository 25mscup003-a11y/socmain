package com.soc.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.os.Build;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(intent.getAction())
                || Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction())
                || "com.soc.agent.RESTART_AGENT".equals(intent.getAction())) {
            DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            boolean unlockedBoot = !Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(intent.getAction());
            boolean passwordConfigured = unlockedBoot && context
                    .getSharedPreferences("soc_agent_prefs", Context.MODE_PRIVATE)
                    .contains("password_hash");
            if (passwordConfigured && dpm != null && dpm.isDeviceOwnerApp(context.getPackageName())) {
                dpm.setUninstallBlocked(
                        new ComponentName(context, AgentDeviceAdminReceiver.class),
                        context.getPackageName(),
                        true
                );
            }
            Intent service = new Intent(context, AgentService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(service);
            } else {
                context.startService(service);
            }
        }
    }
}
