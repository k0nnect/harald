from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from harald.analyze import diff_payloads, guess_checks, looks_encrypted, try_keys


def aes_ecb_encrypt(key: bytes, plain: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plain) + encryptor.finalize()


def aes_cbc_zero_iv_encrypt(key: bytes, plain: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
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


def test_length_byte_detected():
    # counts the bytes after it (9 - 2) and the bytes after the header byte (8 - 1)
    assert "length at 1" in guess_checks(bytes.fromhex("7e070503ff000010ef"))
    assert "length at 1" in guess_checks(bytes.fromhex("7e070503ff0000ef"))


def test_crc16_le_detected():
    # crc-16/ccitt-false check value for b"123456789" is 0x29b1
    checks = guess_checks(b"123456789" + bytes([0xB1, 0x29]))
    assert "crc16-ccitt at -2 (le)" in checks
    assert "crc16-ccitt at -2 (be)" not in checks


def test_framed_sum8_found_in_real_xm5_frames():
    for frame in ("3e0c01000000022200313c", "3e0c000000000200000e3c"):
        assert "sum8 at -2 (framed)" in guess_checks(bytes.fromhex(frame))


def test_framed_xor8():
    body = bytes.fromhex("0c01000000022200")
    xor = 0
    for b in body:
        xor ^= b
    checks = guess_checks(b"\x3e" + body + bytes([xor]) + b"\x3c")
    assert "xor8 at -2 (framed)" in checks
    assert "sum8 at -2 (framed)" not in checks
    wrong = guess_checks(b"\x3e" + body + bytes([xor ^ 0xFF]) + b"\x3c")
    assert "xor8 at -2 (framed)" not in wrong


def test_plain_payloads_not_encrypted():
    colors = [
        bytes.fromhex(f"7e070503{rgb}10ef") for rgb in ("ff0000", "00ff00", "0000ff")
    ]
    assert looks_encrypted(colors) is False
    assert looks_encrypted(plains) is False
    assert looks_encrypted(payloads) is True


def test_shared_padding_block_does_not_hide_encryption():
    # a whole-block plaintext gets a whole padding block, and under ecb that block
    # encrypts the same in every payload
    padded = [aes_ecb_encrypt(KEY, p + bytes([16] * 16)) for p in plains]
    assert len({p[16:] for p in padded}) == 1
    assert looks_encrypted(padded) is True
    # a shared block is ignored, but the plain block left over still decides
    assert looks_encrypted([p + bytes(16) for p in plains]) is False


def test_identical_payloads_do_not_look_encrypted():
    assert looks_encrypted([payloads[0]] * 2) is False
    assert looks_encrypted([payloads[0]] * 3) is False
    # one payload has nothing to compare against, so only its bytes count
    assert looks_encrypted(payloads[:1]) is True


def test_try_keys_finds_correct_key():
    results = try_keys(payloads, [bytes(16), KEY, bytes(range(1, 17))])
    assert results[0].key_hex == KEY.hex()
    assert results[0].mode == "aes-ecb"
    assert results[0].score >= 0.9
    assert results[0].samples[0] == plains[0].hex()


def test_try_keys_prefers_cbc_when_later_blocks_only_decode_in_cbc():
    two_block = [p + bytes(range(16, 32)) for p in plains]
    cbc_payloads = [aes_cbc_zero_iv_encrypt(KEY, p) for p in two_block]
    results = try_keys(cbc_payloads, [bytes(16), KEY, bytes(range(1, 17))])
    assert results[0].key_hex == KEY.hex()
    assert results[0].mode == "aes-cbc-zero-iv"
    assert results[0].samples[0] == two_block[0].hex()
