package com.soc.agent;

import android.content.Context;
import android.content.pm.PackageInfo;

/** Works in both Gradle APKs and platform Soong builds without BuildConfig. */
public final class AgentVersion {
    private AgentVersion() { }

    public static String current(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return info.versionName == null ? "unknown" : info.versionName;
        } catch (Exception ignored) {
            return "unknown";
        }
    }
}
