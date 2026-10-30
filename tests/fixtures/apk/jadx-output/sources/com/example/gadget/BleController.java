package com.example.gadget;

import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import javax.crypto.spec.SecretKeySpec;

// synthetic sample used only by harald's static-scan tests. not real vendor code.
public class BleController {
    static final java.util.UUID SERVICE_UUID =
        java.util.UUID.fromString("0000ffe0-0000-1000-8000-00805f9b34fb");
    static final java.util.UUID CHARACTERISTIC_UUID =
        java.util.UUID.fromString("0000ffe1-0000-1000-8000-00805f9b34fb");

    SecretKeySpec buildKey(byte[] k) {
        return new SecretKeySpec(k, "AES");
    }

    void send(BluetoothGatt gatt, BluetoothGattCharacteristic ch) {
        byte[] frame = new byte[]{0x7e, 0x00, 0x01};
        ch.setValue(frame);
        gatt.writeCharacteristic(ch);
    }

    javax.crypto.Cipher cipher(SecretKeySpec key) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return c;
    }
}
