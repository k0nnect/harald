"""Payload analysis: compare captured command payloads and test simple hypotheses.

Pure helpers over `bytes`. They show which bytes stay constant and which carry the
value, spot common checksums and length fields, judge whether payloads look
encrypted, and rank candidate app-wide aes keys by how well they decode them.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
AES_KEY_SIZES = (16, 24, 32)
MODES = ("aes-ecb", "aes-cbc-zero-iv")  # ecb first so it wins ties (see try_keys)
ENTROPY_THRESHOLD = 3.5


@dataclass
class DiffReport:
    lengths: dict[int, int]  # payload length -> how many payloads have it
    constant: dict[int, int]  # position -> the byte every payload has there
    varying: list[int]  # positions whose byte differs between payloads


@dataclass
class KeyResult:
    key_hex: str
    mode: str
    score: float
    samples: list[str]  # first 3 plaintexts as hex


def diff_payloads(payloads: list[bytes]) -> DiffReport:
    """Split byte positions into constant and varying, over the shortest payload."""
    lengths = dict(sorted(Counter(len(p) for p in payloads).items()))
    shortest = min(lengths, default=0)
    constant: dict[int, int] = {}
    varying: list[int] = []
    for i in range(shortest):
        values = {p[i] for p in payloads}
        if len(values) == 1:
            constant[i] = values.pop()
        else:
            varying.append(i)
    return DiffReport(lengths=lengths, constant=constant, varying=varying)


def guess_checks(payload: bytes) -> list[str]:
    """Name the common integrity and length fields this payload is consistent with.

    A length byte at position i matches when it equals the total length n, the
    bytes from it onward (n - i), or the bytes after it (n - i - 1). A framed
    checksum is the byte before a trailing end marker, over the bytes after a
    leading start marker.
    """
    n = len(payload)
    found: list[str] = []
    if n >= 2:
        body, last = payload[:-1], payload[-1]
        if sum(body) & 0xFF == last:
            found.append("sum8 at -1")
        if _xor8(body) == last:
            found.append("xor8 at -1")
    for i in (0, 1):
        if n > i and payload[i] in (n, n - i, n - i - 1):
            found.append(f"length at {i}")
    if n >= 3:
        crc = crc16_ccitt(payload[:-2])
        if payload[-2:] == crc.to_bytes(2, "little"):
            found.append("crc16-ccitt at -2 (le)")
        if payload[-2:] == crc.to_bytes(2, "big"):
            found.append("crc16-ccitt at -2 (be)")
    if n >= 4:
        framed, check = payload[1:-2], payload[-2]
        if sum(framed) & 0xFF == check:
            found.append("sum8 at -2 (framed)")
        if _xor8(framed) == check:
            found.append("xor8 at -2 (framed)")
    return found


def _xor8(data: bytes) -> int:
    xor = 0
    for b in data:
        xor ^= b
    return xor


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xffff, no reflection, no final xor."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def byte_entropy(data: bytes) -> float:
    """Shannon entropy of the byte values in `data`, in bits per byte."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def looks_encrypted(payloads: list[bytes]) -> bool:
    """Guess whether payloads are block-cipher output rather than plain commands.

    Every payload must be a non-empty multiple of 16 bytes. They are judged per
    16-byte block: a block that is byte-identical in every payload, such as the
    padding block a whole-block plaintext gets under ecb, tells nothing and is left
    out. Over the blocks that remain, True when no position is constant across the
    payloads (checked once there are at least 3) and the mean per-payload byte
    entropy is at least 3.5 bits. Fully identical payloads give False.
    """
    if not payloads or any(not p or len(p) % BLOCK for p in payloads):
        return False
    varying = [v for v in _without_shared_blocks(payloads) if v]
    if not varying:  # every block is shared: the payloads are identical
        return False
    if len(varying) >= 3 and diff_payloads(varying).constant:
        return False
    mean = sum(byte_entropy(v) for v in varying) / len(varying)
    return mean >= ENTROPY_THRESHOLD


def _without_shared_blocks(payloads: list[bytes]) -> list[bytes]:
    """Each payload minus the 16-byte blocks that every payload has byte-identical.

    A single payload has nothing to compare against, so it comes back whole.
    """
    if len(payloads) < 2:
        return list(payloads)
    longest = max(len(p) for p in payloads)
    # a payload too short for block i gives b"" there, so that block is not shared
    shared = {
        i
        for i in range(0, longest, BLOCK)
        if len({p[i : i + BLOCK] for p in payloads}) == 1
    }
    return [
        b"".join(p[i : i + BLOCK] for i in range(0, len(p), BLOCK) if i not in shared)
        for p in payloads
    ]


def try_keys(payloads: list[bytes], keys: list[bytes]) -> list[KeyResult]:
    """Decrypt payloads with each candidate key and mode, best-scoring first.

    Keys that are not 16, 24 or 32 bytes and payloads that are not a non-empty
    multiple of 16 bytes are skipped. With a zero iv, cbc's first plaintext
    block equals ecb's for any payload length, so `score` (first block only)
    always ties across the two modes. Ties are broken by the fraction of
    positions constant over the whole shortest plaintext, which tells the modes
    apart from the second block on. Single-block payloads still tie there too;
    ecb is tried first and the sort is stable, so ecb ranks first.
    """
    blocks = [p for p in payloads if p and len(p) % BLOCK == 0]
    if not blocks:
        return []
    ranked: list[tuple[float, float, KeyResult]] = []
    for key in keys:
        if len(key) not in AES_KEY_SIZES:
            continue
        for mode in MODES:
            plain = [_decrypt(key, mode, p) for p in blocks]
            result = KeyResult(
                key_hex=key.hex(),
                mode=mode,
                score=_score(plain),
                samples=[p.hex() for p in plain[:3]],
            )
            ranked.append((result.score, _full_score(plain), result))
    ranked.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [result for _, _, result in ranked]


def _decrypt(key: bytes, mode: str, data: bytes) -> bytes:
    cipher_mode = modes.ECB() if mode == "aes-ecb" else modes.CBC(bytes(BLOCK))
    decryptor = Cipher(algorithms.AES(key), cipher_mode).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _score(plain: list[bytes]) -> float:
    """Constant first-block positions, plus half the first-byte agreement, capped at 1."""
    constant = sum(len({p[i] for p in plain}) == 1 for i in range(BLOCK)) / BLOCK
    agree = Counter(p[0] for p in plain).most_common(1)[0][1] / len(plain)
    return min(1.0, constant + 0.5 * agree)


def _full_score(plain: list[bytes]) -> float:
    """Fraction of positions, over the shortest plaintext, constant across all."""
    shortest = min(len(p) for p in plain)
    return len(diff_payloads(plain).constant) / shortest
