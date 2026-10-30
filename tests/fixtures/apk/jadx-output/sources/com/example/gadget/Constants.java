package com.example.gadget;

// synthetic sample used only by harald's static-scan tests. not real vendor code.
// the two masks must not read as uuids; the short literal must.
final class Constants {
    static final int ALPHA_MASK = 0xFF000000;
    static final long ALL_BITS = 0xFFFFFFFFL;
    static final int NOTIFY_CHAR = 0xFFE2;

    // two base64 aes keys (16 and 32 bytes) the scan must flag, then two paths that
    // decode to 24 bytes and a 20-byte string it must not.
    static final String KEY_16 = "AAECAwQFBgcICQoLDA0ODw==";
    static final String KEY_32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    static final String COMPAT = "androidx/core/app/ActivityCompat";
    static final String DATA_DIR = "Android/data/com/abcdefghijklmno";
    static final String GREETING = "aGFyYWxkIGlzIG5vdCBhIGtleSE=";
}
