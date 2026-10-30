"""Builders for synthetic hci capture files, so no test needs a real phone log.

Every built capture stamps record i at unix time `T0 + i * 0.25` seconds.
"""

from __future__ import annotations

import struct
from pathlib import Path

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


# att over hci acl, as the phone and the device exchange it.
PKLG_ACL_OUT, PKLG_ACL_IN = (
    0x02,
    0x03,
)  # packetlogger types: sent / received by the phone
CONN = 0x0040  # acl connection handle used by every built capture
ATT_CID = 0x0004
FFE1_HANDLE = 0x0012  # value handle that discovery maps to the ffe1 characteristic
WRITE_CMD = 0x52


def acl(handle: int, l2cap: bytes, pb: int = 0b00) -> bytes:
    """An hci acl packet carrying a whole l2cap frame or, with pb=0b01, a later fragment."""
    return struct.pack("<HH", handle | pb << 12, len(l2cap)) + l2cap


def l2cap(payload: bytes, cid: int = ATT_CID) -> bytes:
    """An l2cap basic frame: u16 payload length, u16 channel id, then the payload."""
    return struct.pack("<HH", len(payload), cid) + payload


def att(opcode: int, handle: int, value: bytes = b"") -> bytes:
    """An att pdu that names one handle: writes, notifications, indications, reads."""
    return bytes([opcode]) + struct.pack("<H", handle) + value


def read_by_type_req(type16: int) -> bytes:
    """An att read-by-type request over every handle for a 16-bit attribute type."""
    return bytes([0x08]) + struct.pack("<HHH", 0x0001, 0xFFFF, type16)


def char_decls(*chars: tuple[int, int]) -> bytes:
    """A read-by-type response of characteristic declarations, one per (value handle, uuid16).

    Each 7-byte entry is the declaration handle (value handle - 1), properties
    (read, write without response, write), the value handle and the uuid.
    """
    entries = b"".join(struct.pack("<HBHH", h - 1, 0x0E, h, u) for h, u in chars)
    return bytes([0x09, 7]) + entries


def write_capture(tmp_path: Path, *, discovery: bool, writes: list[bytes]) -> Path:
    """Write a .pklg where the phone sends each value to handle 0x0012 as a write_cmd.

    With `discovery`, the phone first discovers characteristics, which maps 0x0012 to
    the ffe1 characteristic.
    """
    records: list[tuple[int, bytes]] = []
    if discovery:
        records += [
            (PKLG_ACL_OUT, acl(CONN, l2cap(read_by_type_req(0x2803)))),
            (PKLG_ACL_IN, acl(CONN, l2cap(char_decls((FFE1_HANDLE, 0xFFE1))))),
        ]
    for value in writes:
        records.append(
            (PKLG_ACL_OUT, acl(CONN, l2cap(att(WRITE_CMD, FFE1_HANDLE, value))))
        )
    path = tmp_path / "capture.pklg"
    path.write_bytes(make_pklg(records))
    return path
