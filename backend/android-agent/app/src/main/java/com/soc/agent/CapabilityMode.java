package com.soc.agent;

/** Ordered runtime modes. A higher mode includes the safe fallbacks below it. */
public enum CapabilityMode {
    STANDARD_ANDROID,
    MANAGED_DEVICE,
    PRIVILEGED_SYSTEM_APP,
    AOSP_INTEGRATED
}
