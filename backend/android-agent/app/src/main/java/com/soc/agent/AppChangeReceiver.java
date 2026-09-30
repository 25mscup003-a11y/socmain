package com.soc.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;

public class AppChangeReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        Uri data = intent.getData();
        String packageName = data != null ? data.getSchemeSpecificPart() : "unknown";

        Intent service = new Intent(context, AgentService.class);
        service.setAction(AgentService.ACTION_APP_EVENT);
        service.putExtra("event_action", action);
        service.putExtra("package_name", packageName);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(service);
        } else {
            context.startService(service);
        }
    }
}
