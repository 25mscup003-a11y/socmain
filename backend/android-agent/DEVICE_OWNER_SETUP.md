# Android managed uninstall protection

Android only permits an enterprise Device Owner to block removal from Settings.
The device must be newly provisioned (or factory reset), with no accounts added.

1. Install the generated AJNAT/SOC Agent APK.
2. Provision it before adding user accounts:

   `adb shell dpm set-device-owner com.soc.agent/.AgentDeviceAdminReceiver`

3. Open the app and set the required 8-character protection password.

The app then calls `DevicePolicyManager.setUninstallBlocked(...)`. Removal from
Android Settings is blocked by the OS. Use **UNINSTALL AGENT** inside the app,
enter the password, and confirm Android's uninstall dialog.

On an ordinary unmanaged phone, Android does not allow any APK to intercept the
system uninstaller. The in-app password gate still works, but enforced removal
protection requires Device Owner provisioning.
