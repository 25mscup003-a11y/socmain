# AJNAT controlled-AOSP integration

This tree builds the existing `com.soc.agent` application as a platform-signed
privileged product application and builds the SELinux-confined `ajnatd` daemon.
It does not disable Verified Boot, SELinux, package isolation, or signature
checks.

## Product integration

Place this directory at `vendor/ajnat/android-agent` (or change
`AJNAT_ANDROID_AGENT_PATH`) and add this line to the device product makefile:

```make
$(call inherit-product, vendor/ajnat/android-agent/aosp/ajnat_product.mk)
```

The resulting files are installed under `/product/priv-app` and `/product/bin`.
The APK must be signed by the ROM build's platform certificate; never distribute
that private key with the source tree or APK.

Build in the initialized AOSP environment:

```sh
m AJNATPrivilegedAgent ajnatd ajnatd_event_dispatcher_test ajnatd_health_monitor_test
atest ajnatd_event_dispatcher_test ajnatd_health_monitor_test
```

## Device validation

On a userdebug test image, verify:

```sh
adb shell pm path com.soc.agent
adb shell dumpsys package com.soc.agent
adb shell getenforce
adb shell getprop init.svc.ajnatd
adb shell logcat -d -s ajnatd
adb shell dumpsys activity services com.soc.agent/.AgentService
```

Keep SELinux enforcing. Collect real `avc: denied` records on each target AOSP
release and add only the exact read/connect permissions required by that
device's procfs, netlink, and sysfs labels. Do not use generated blanket policy.

`ajnatd` reports BTF, bpffs, tracefs, GKI, tracepoint, and SELinux capability
status. This implementation does not claim that eBPF is loaded; adding an eBPF
collector requires a target kernel/AOSP loader decision and target-specific
tests. Procfs and route-netlink collectors remain the safe fallback.
