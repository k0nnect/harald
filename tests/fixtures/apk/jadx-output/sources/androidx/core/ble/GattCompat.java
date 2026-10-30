package androidx.core.ble;

// synthetic sample used only by harald's static-scan tests. not real library code.
// it sits in a third-party library tree, so the scan must find nothing in it.
public class GattCompat {
    static final java.util.UUID SERVICE_UUID =
        java.util.UUID.fromString("0000aaa0-0000-1000-8000-00805f9b34fb");
    static final int CHAR_UUID = 0xFFA1;
    static final String KEY = "EBESExQVFhcYGRobHB0eHw==";

    javax.crypto.spec.SecretKeySpec key(byte[] k) {
        return new javax.crypto.spec.SecretKeySpec(k, "AES");
    }

    void send(android.bluetooth.BluetoothGatt gatt,
            android.bluetooth.BluetoothGattCharacteristic ch) {
        ch.setValue(new byte[]{0x01});
        gatt.writeCharacteristic(ch);
    }
}
