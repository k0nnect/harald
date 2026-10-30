"""Readers for apple packetlogger (.pklg) and btsnoop hci capture files.

Both formats become a flat list of `HciRecord`s. The format is picked by magic bytes:
btsnoop files start with `btsnoop\\0`; anything else is tried as packetlogger, which
has no magic.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from harald.errors import CaptureFormatError

HciKind = Literal["cmd", "evt", "acl_out", "acl_in"]

HINT = "expected a packetlogger .pklg or btsnoop file"

# packetlogger (wireshark wiretap/packetlogger.c): u32 len, u32 ts_secs, u32 ts_usecs,
# then len - 8 bytes whose first byte is the type. len counts the timestamp too.
_PKLG_KINDS: dict[int, HciKind] = {
    0x00: "cmd",
    0x01: "evt",
    0x02: "acl_out",
    0x03: "acl_in",
}
_PKLG_MIN_LEN = 9  # 8 timestamp bytes + the type byte

# btsnoop: magic, u32 version, u32 datalink, then records of u32 orig_len,
# u32 incl_len, u32 flags, u32 drops, i64 ts_us. all big-endian.
BTSNOOP_MAGIC = b"btsnoop\0"
_BTSNOOP_HEADER = struct.Struct(">8sII")
_BTSNOOP_RECORD = struct.Struct(">IIIIq")
_DATALINK_HCI = 1001  # no h4 byte; direction and type come from flags
_DATALINK_H4 = 1002  # first byte of each record is the h4 type
# btsnoop timestamps count microseconds from year 0; android's writer and wireshark
# both use this delta to the unix epoch.
BTSNOOP_EPOCH_DELTA_US = 0x00DCDDB30F2F8000
_FLAG_RECEIVED = 0x01
_FLAG_CMD_EVT = 0x02
_H4_CMD, _H4_ACL, _H4_EVT = 0x01, 0x02, 0x04


@dataclass
class HciRecord:
    """One hci packet. `data` excludes any h4 type byte; `acl_out` was sent by the phone."""

    ts: float
    kind: HciKind
    data: bytes


def read_capture(path: Path) -> list[HciRecord]:
    """Parse a packetlogger or btsnoop file into hci records, in file order."""
    raw = Path(path).read_bytes()
    if raw.startswith(BTSNOOP_MAGIC):
        return _read_btsnoop(raw)
    return _read_pklg(raw)


def _error(message: str) -> CaptureFormatError:
    return CaptureFormatError(message, hint=HINT)


def _walks(raw: bytes, order: str) -> bool:
    """True if `raw` is a non-empty chain of pklg records in this byte order to eof."""
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            return False
        (length,) = struct.unpack_from(order + "I", raw, offset)
        if length < _PKLG_MIN_LEN or length > len(raw) - offset - 4:
            return False
        offset += 4 + length
    return offset > 0


def _pklg_byte_order(raw: bytes) -> str:
    """The order whose record chain walks the whole file; big-endian if both do.

    Wireshark's tiebreak: a big-endian first len with zero low 16 bits and non-zero
    high 16 bits is really a small little-endian len, so little-endian wins then.
    """
    big, little = _walks(raw, ">"), _walks(raw, "<")
    if big and little:
        (length,) = struct.unpack_from(">I", raw)
        return "<" if length & 0xFFFF == 0 and length >> 16 else ">"
    if big:
        return ">"
    if little:
        return "<"
    raise _error("not a packetlogger or btsnoop capture")


def _read_pklg(raw: bytes) -> list[HciRecord]:
    header = struct.Struct(_pklg_byte_order(raw) + "III")
    records: list[HciRecord] = []
    offset = 0
    while offset < len(raw):  # _pklg_byte_order already checked every len
        length, secs, usecs = header.unpack_from(raw, offset)
        end = offset + 4 + length
        kind = _PKLG_KINDS.get(raw[offset + header.size])
        if kind is not None:
            data = raw[offset + header.size + 1 : end]
            records.append(HciRecord(secs + usecs / 1_000_000, kind, data))
        offset = end
    return records


def _read_btsnoop(raw: bytes) -> list[HciRecord]:
    if len(raw) < _BTSNOOP_HEADER.size:
        raise _error("btsnoop header is cut short")
    _, version, datalink = _BTSNOOP_HEADER.unpack_from(raw)
    if version != 1:
        raise _error(f"unsupported btsnoop version {version}")
    if datalink not in (_DATALINK_HCI, _DATALINK_H4):
        raise _error(f"unsupported btsnoop datalink {datalink}")
    records: list[HciRecord] = []
    offset = _BTSNOOP_HEADER.size
    while offset < len(raw):
        if len(raw) - offset < _BTSNOOP_RECORD.size:
            raise _error(f"btsnoop record at offset {offset} is cut short")
        _, incl_len, flags, _, ts_us = _BTSNOOP_RECORD.unpack_from(raw, offset)
        start = offset + _BTSNOOP_RECORD.size
        end = start + incl_len
        if end > len(raw):
            raise _error(f"btsnoop record at offset {offset} is cut short")
        payload = raw[start:end]
        received = bool(flags & _FLAG_RECEIVED)
        if datalink == _DATALINK_H4:
            if not payload:
                raise _error(f"btsnoop record at offset {offset} is empty")
            kind = _h4_kind(payload[0], received)
            data = payload[1:]
        else:
            kind = _flags_kind(flags, received)
            data = payload
        if kind is not None:
            ts = (ts_us - BTSNOOP_EPOCH_DELTA_US) / 1_000_000
            records.append(HciRecord(ts, kind, data))
        offset = end
    return records


def _h4_kind(h4_type: int, received: bool) -> HciKind | None:
    if h4_type == _H4_CMD:
        return "cmd"
    if h4_type == _H4_EVT:
        return "evt"
    if h4_type == _H4_ACL:
        return "acl_in" if received else "acl_out"
    return None  # sco, iso and vendor packets are not needed


def _flags_kind(flags: int, received: bool) -> HciKind:
    if flags & _FLAG_CMD_EVT:
        return "evt" if received else "cmd"
    return "acl_in" if received else "acl_out"
