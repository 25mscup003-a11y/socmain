package com.soc.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbDevice;

import org.json.JSONObject;

/** Converts Android USB attach/detach broadcasts into normalized queue events. */
public final class UsbEventReceiver extends BroadcastReceiver {
    public interface Listener {
        void onUsbEvent(String action, JSONObject payload);
    }

    private final Listener listener;

    public UsbEventReceiver(Listener listener) {
        this.listener = listener;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        UsbDevice device = intent.getParcelableExtra("device");
        JSONObject payload = new JSONObject();
        try {
            payload.put("event_type", "usb");
            payload.put("event_subtype", android.hardware.usb.UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)
                    ? "attach" : "detach");
            payload.put("event_time", System.currentTimeMillis());
            if (device != null) {
                payload.put("device", device.getDeviceName());
                payload.put("device_vendor", device.getManufacturerName());
                payload.put("usb_vendor_id", String.format("%04x", device.getVendorId()));
                payload.put("usb_product_id", String.format("%04x", device.getProductId()));
                payload.put("device_type", "usb");
            }
        } catch (Exception ignored) { }
        listener.onUsbEvent(action, payload);
    }
}
