from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from harald.analyze import diff_payloads, guess_checks, looks_encrypted, try_keys


def aes_ecb_encrypt(key: bytes, plain: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plain) + encryptor.finalize()


KEY = bytes(range(16))
plains = [
    bytes([0x54, 0x10, c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    for c in (0x00, 0x40, 0x80, 0xFF)
]
payloads = [aes_ecb_encrypt(KEY, p) for p in plains]


def test_diff_finds_constant_header_and_varying_color():
    red = bytes.fromhex("7e070503ff0000ef")
    green = bytes.fromhex("7e07050300ff00ef")
    report = diff_payloads([red, green])
    assert report.constant == {0: 0x7E, 1: 0x07, 2: 0x05, 3: 0x03, 6: 0x00, 7: 0xEF}
    assert report.varying == [4, 5]
    assert report.lengths == {8: 2}
    longer = diff_payloads([red, green, green + b"\x01"])
    assert longer.lengths == {8: 2, 9: 1}
    assert longer.varying == [4, 5]


def test_sum8_detected():
    body = bytes.fromhex("7e070503ff0000")
    assert "sum8 at -1" in guess_checks(body + bytes([sum(body) & 0xFF]))
    assert "sum8 at -1" not in guess_checks(body + bytes([(sum(body) + 1) & 0xFF]))


def test_crc16_le_detected():
    # crc-16/ccitt-false check value for b"123456789" is 0x29b1
    checks = guess_checks(b"123456789" + bytes([0xB1, 0x29]))
    assert "crc16-ccitt at -2 (le)" in checks
    assert "crc16-ccitt at -2 (be)" not in checks


def test_plain_payloads_not_encrypted():
    colors = [
        bytes.fromhex(f"7e070503{rgb}10ef") for rgb in ("ff0000", "00ff00", "0000ff")
    ]
    assert looks_encrypted(colors) is False
    assert looks_encrypted(plains) is False
    assert looks_encrypted(payloads) is True


def test_try_keys_finds_correct_key():
    results = try_keys(payloads, [bytes(16), KEY, bytes(range(1, 17))])
    assert results[0].key_hex == KEY.hex()
    assert results[0].mode == "aes-ecb"
    assert results[0].score >= 0.9
    assert results[0].samples[0] == plains[0].hex()
