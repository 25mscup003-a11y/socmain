"""
SOC4 Android Lightweight Agent — Architecture & Implementation Guide
====================================================================
Version: 1.0.0
Target: Android 8.0+ (API 26+)
Language: Kotlin / Java (Service)

OVERVIEW
--------
The Android agent is a background service that collects security events
from the device and sends them to the SOC4 backend over HTTPS.

Due to Android restrictions, the agent cannot:
  - Capture system-wide logs (requires root or ADB)
  - Monitor other apps' file access
  - Block network at kernel level

It CAN (without root):
  - Monitor network connectivity changes
  - Capture its own app installs/uninstalls
  - Monitor USB/OTG connections (with permission)
  - Collect device info (CPU, RAM, battery)
  - Monitor WiFi SSID changes
  - Detect screen lock/unlock events
  - Send heartbeats to backend
  - Receive remote commands (FCM push)

IMPLEMENTATION GUIDE
--------------------

1. PROJECT STRUCTURE
   android-agent/
   ├── app/
   │   ├── src/main/
   │   │   ├── AndroidManifest.xml
   │   │   └── java/com/soc4/agent/
   │   │       ├── MainActivity.kt          # Setup + permission request UI
   │   │       ├── AgentService.kt          # Foreground service (main loop)
   │   │       ├── HeartbeatWorker.kt       # WorkManager periodic heartbeat
   │   │       ├── collectors/
   │   │       │   ├── NetworkCollector.kt  # WiFi/data changes
   │   │       │   ├── AppCollector.kt      # Install/uninstall events
   │   │       │   ├── DeviceCollector.kt   # Device health (battery, storage)
   │   │       │   └── UsbCollector.kt      # USB OTG device events
   │   │       ├── receivers/
   │   │       │   ├── BootReceiver.kt      # Auto-start on boot
   │   │       │   └── FcmReceiver.kt       # Push command receiver
   │   │       └── api/
   │   │           ├── ApiClient.kt         # Retrofit HTTP client
   │   │           └── AlertSender.kt       # Queue + send to backend
   │   └── build.gradle
   └── README.md

2. KEY COMPONENTS

   AgentService (Foreground Service)
   ----------------------------------
   - Runs as a foreground service with persistent notification
   - Starts on boot via BootReceiver
   - Orchestrates all collectors
   - Checks subscription status every 5 minutes via heartbeat
   - Stops all monitoring if stop_monitoring=true from server

   HeartbeatWorker (WorkManager)
   --------------------------------
   - Runs every 15 minutes (minimum Android WorkManager interval)
   - Sends: { agent_key, agent_version, device_info, battery, network_type }
   - Receives: { stop_monitoring, update_available, commands }
   - If stop_monitoring=true: cancels WorkManager task, stops AgentService

   NetworkCollector
   -----------------
   - Listens to ConnectivityManager network callbacks
   - Reports: WIFI_CONNECTED, WIFI_DISCONNECTED, MOBILE_DATA, VPN_ON, VPN_OFF
   - Sends SSID changes (potential rogue AP detection)

   AppCollector
   -------------
   - Listens to ACTION_PACKAGE_ADDED / REMOVED / REPLACED
   - Reports: app installs, uninstalls, updates
   - Sends: package name, version, installer source

   UsbCollector
   -------------
   - Listens to UsbManager.ACTION_USB_DEVICE_ATTACHED
   - Reports: OTG device attached events, device class/product
   - Requires android.permission.USB_PERMISSION (user granted)

   FcmReceiver (Firebase Cloud Messaging)
   ----------------------------------------
   - Receives remote commands from SOC4 dashboard:
     * WIPE_DEVICE_COMMAND (enterprise MDM — requires Device Admin)
     * LOCK_SCREEN
     * REQUEST_DIAGNOSTICS
     * STOP_MONITORING

3. PERMISSIONS REQUIRED
   (in AndroidManifest.xml)

   <uses-permission android:name="android.permission.INTERNET" />
   <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
   <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
   <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
   <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
   <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
   <uses-permission android:name="android.permission.READ_PHONE_STATE" />
   <uses-permission android:name="android.permission.USB_PERMISSION" />
   <!-- Optional: Device Admin for remote wipe -->
   <uses-permission android:name="android.permission.BIND_DEVICE_ADMIN" />

4. ALERT FORMAT (same as desktop agent)
   {
     "agent_key":     "<from config>",
     "company_id":    "<from config>",
     "category":      "network|usb|system|app",
     "severity":      "low|medium|high|critical",
     "description":   "...",
     "timestamp":     "2024-01-01T00:00:00Z",
     "device_info": {
       "manufacturer": "Samsung",
       "model":        "Galaxy S24",
       "android":      "14",
       "serial":       "<hashed>",
       "imei":         "<hashed>"
     }
   }

5. BACKEND CONNECTION
   - Endpoint:  POST {server_url}/api/alerts
   - Auth:      x-integration-secret header
   - Transport: HTTPS (certificate pinning recommended)
   - Queue:     Local SQLite queue, retry on network failure
   - Batch:     POST {server_url}/api/alerts/batch (up to 50 events)

6. CONFIGURATION FILE
   assets/company_config.json (bundled by company admin at build time)
   OR downloaded from QR code scan at first launch:

   {
     "company_id":   "...",
     "agent_key":    "...",
     "server_url":   "https://soc4.yourdomain.com",
     "integration_secret": "...",
     "agent_version": "1.0.0",
     "heartbeat_interval_seconds": 900
   }

7. DISTRIBUTION
   - Compile as APK: ./gradlew assembleRelease
   - Sign with company keystore
   - Distribute via:
     * MDM (Mobile Device Management — e.g., Google Workspace, Intune)
     * Private Google Play store
     * APK sideload (enable Install Unknown Apps on target device)
   - The SOC4 dashboard generates a QR code for device enrollment

8. SUBSCRIPTION ENFORCEMENT
   - HeartbeatWorker polls /api/agent/heartbeat every 15 minutes
   - If stop_monitoring=true:
     1. HeartbeatWorker cancels itself
     2. Sends stopService(Intent) to AgentService
     3. AgentService shows notification: "Monitoring paused — subscription expired"
     4. All BroadcastReceivers unregistered
   - Resume: when company pays, next heartbeat enables monitoring again

9. DEPENDENCIES (build.gradle)
   implementation 'com.squareup.retrofit2:retrofit:2.+'
   implementation 'com.squareup.retrofit2:converter-gson:2.+'
   implementation 'com.squareup.okhttp3:logging-interceptor:4.+'
   implementation 'androidx.work:work-runtime-ktx:2.+'
   implementation 'com.google.firebase:firebase-messaging-ktx:23.+'
   implementation 'androidx.room:room-runtime:2.+'
   kapt 'androidx.room:room-compiler:2.+'

10. BUILDING THE APK (quick start)
    # Clone SOC4 repo (android-agent folder)
    git clone https://github.com/your-org/soc4.git
    cd soc4/android-agent

    # Place your company_config.json in app/src/main/assets/
    cp /path/to/company_config.json app/src/main/assets/

    # Build
    ./gradlew assembleRelease

    # Find output
    ls app/build/outputs/apk/release/
"""

# This file serves as the Android agent architecture outline.
# The full Kotlin implementation would be in a separate android-agent/ directory.
print("SOC4 Android Agent — Architecture Outline")
print("See ANDROID_AGENT.py for full specification")
