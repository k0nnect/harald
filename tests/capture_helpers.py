"""Builders for synthetic hci capture files, so no test needs a real phone log.

Every built capture stamps record i at unix time `T0 + i * 0.25` seconds.
"""

from __future__ import annotations

import struct

T0 = 1_700_000_000.0

# btsnoop timestamps count microseconds from year 0; android's writer adds this delta.
BTSNOOP_EPOCH_DELTA_US = 0x00DCDDB30F2F8000

_H4_TYPE = {"cmd": 0x01, "acl_out": 0x02, "acl_in": 0x02, "evt": 0x04}
# btsnoop flags: bit0 set = received by the phone, bit1 set = command or event.
_BTSNOOP_FLAGS = {"cmd": 0b10, "evt": 0b11, "acl_out": 0b00, "acl_in": 0b01}


def _ts_us(i: int) -> int:
    return int(T0) * 1_000_000 + i * 250_000


def make_pklg(records: list[tuple[int, bytes]], byte_order: str = "big") -> bytes:
    """Build a packetlogger file. Each record is `(pkt_type, data)`."""
    order = {"big": ">", "little": "<"}[byte_order]
    out = bytearray()
    for i, (pkt_type, data) in enumerate(records):
        secs, usecs = divmod(_ts_us(i), 1_000_000)
        # len counts the 8 timestamp bytes, the type byte and the payload.
        out += struct.pack(order + "III", 8 + 1 + len(data), secs, usecs)
        out += bytes([pkt_type]) + data
    return bytes(out)


def make_btsnoop(records: list[tuple[str, bytes]], datalink: int = 1002) -> bytes:
    """Build a btsnoop file. Each record is `(kind, data)`; 1002 adds the h4 type byte."""
    out = bytearray(b"btsnoop\0" + struct.pack(">II", 1, datalink))
    for i, (kind, data) in enumerate(records):
        payload = bytes([_H4_TYPE[kind]]) + data if datalink == 1002 else data
        ts = _ts_us(i) + BTSNOOP_EPOCH_DELTA_US
        out += struct.pack(
            ">IIIIq", len(payload), len(payload), _BTSNOOP_FLAGS[kind], 0, ts
        )
        out += payload
    return bytes(out)
