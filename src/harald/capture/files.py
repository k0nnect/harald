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
CUT_SHORT_WARNING = (
    "the capture is cut short: the record at byte {offset} runs past the end of the "
    "file, so 1 record ({size} bytes) was skipped"
)

# the largest hci packet: an acl packet's 4-byte header plus the most data its 16-bit
# length field allows. commands, events and iso packets are all smaller. a record
# length above what this needs means the file is not a capture, or is damaged.
MAX_HCI_PACKET = 4 + 0xFFFF

# packetlogger (wireshark wiretap/packetlogger.c): u32 len, u32 ts_secs, u32 ts_usecs,
# then len - 8 bytes whose first byte is the type. len counts the timestamp too.
_PKLG_KINDS: dict[int, HciKind] = {
    0x00: "cmd",
    0x01: "evt",
    0x02: "acl_out",
    0x03: "acl_in",
}
_PKLG_MIN_LEN = 9  # 8 timestamp bytes + the type byte
_PKLG_MAX_LEN = _PKLG_MIN_LEN + MAX_HCI_PACKET

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
_BTSNOOP_MAX_LEN = 1 + MAX_HCI_PACKET  # an h4 type byte, then the packet
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
    """Parse a packetlogger or btsnoop file into hci records, in file order.

    A cut-short last record is dropped; `read_capture_with_warnings` also says so.
    """
    return read_capture_with_warnings(path)[0]


def read_capture_with_warnings(path: Path) -> tuple[list[HciRecord], list[str]]:
    """`read_capture`, plus lowercase warnings about the file.

    A capture copied while it was still recording can end partway through its last
    record. The records before it are kept, as long as at least one is whole, and a
    warning says where the cut record starts and how many bytes were skipped with it.
    Only a length some hci packet could have counts as such a cut: a longer one
    raises, as does damage anywhere else.
    """
    raw = Path(path).read_bytes()
    if raw.startswith(BTSNOOP_MAGIC):
        records, cut_at = _read_btsnoop(raw)
    else:
        records, cut_at = _read_pklg(raw)
    if cut_at is None:
        return records, []
    return records, [CUT_SHORT_WARNING.format(offset=cut_at, size=len(raw) - cut_at)]


def _error(message: str) -> CaptureFormatError:
    return CaptureFormatError(message, hint=HINT)


def _walk(raw: bytes, order: str) -> int:
    """How many bytes whole pklg records in this byte order cover from the start.

    The chain must reach eof, except that its last record may run past it. 0 means
    the chain breaks (a len below the minimum or above the largest hci record) or
    not one record is whole.
    """
    offset = 0
    while len(raw) - offset >= 4:
        (length,) = struct.unpack_from(order + "I", raw, offset)
        if not _PKLG_MIN_LEN <= length <= _PKLG_MAX_LEN:
            return 0
        if length > len(raw) - offset - 4:
            break  # the last record is cut short
        offset += 4 + length
    return offset


def _pklg_byte_order(raw: bytes) -> tuple[str, int]:
    """The order whose record chain covers more of the file, and where it ends.

    A chain that reaches eof covers the most. If both orders cover the same bytes,
    wireshark's tiebreak applies: a big-endian first len with zero low 16 bits and
    non-zero high 16 bits is really a small little-endian len, so little-endian wins.
    """
    big, little = _walk(raw, ">"), _walk(raw, "<")
    if not big and not little:
        raise _error("not a packetlogger or btsnoop capture")
    if big == little:
        (length,) = struct.unpack_from(">I", raw)
        return ("<" if length & 0xFFFF == 0 and length >> 16 else ">"), big
    return (">", big) if big > little else ("<", little)


def _read_pklg(raw: bytes) -> tuple[list[HciRecord], int | None]:
    """The records, and the offset of a cut-short last record (None if there is none)."""
    order, whole = _pklg_byte_order(raw)
    header = struct.Struct(order + "III")
    records: list[HciRecord] = []
    offset = 0
    while offset < whole:  # _pklg_byte_order already checked every len
        length, secs, usecs = header.unpack_from(raw, offset)
        end = offset + 4 + length
        kind = _PKLG_KINDS.get(raw[offset + header.size])
        if kind is not None:
            data = raw[offset + header.size + 1 : end]
            records.append(HciRecord(secs + usecs / 1_000_000, kind, data))
        offset = end
    return records, (whole if whole < len(raw) else None)


def _read_btsnoop(raw: bytes) -> tuple[list[HciRecord], int | None]:
    """The records, and the offset of a cut-short last record (None if there is none)."""
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
        if not _btsnoop_record_fits(raw, offset):  # the last record is cut short
            if offset == _BTSNOOP_HEADER.size:  # and not one whole record came first
                raise _error(f"btsnoop record at offset {offset} is cut short")
            return records, offset
        _, incl_len, flags, _, ts_us = _BTSNOOP_RECORD.unpack_from(raw, offset)
        start = offset + _BTSNOOP_RECORD.size
        end = start + incl_len
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
    return records, None


def _btsnoop_record_fits(raw: bytes, offset: int) -> bool:
    """True if the btsnoop record at `offset`, header and payload, ends by eof.

    Raises when its whole header holds a length no hci packet needs, or keeps more
    bytes than the packet had.
    """
    start = offset + _BTSNOOP_RECORD.size
    if start > len(raw):
        return False
    orig_len, incl_len = struct.unpack_from(">II", raw, offset)
    if incl_len > _BTSNOOP_MAX_LEN:
        raise _error(
            f"btsnoop record at offset {offset} claims {incl_len} bytes, "
            "more than any hci packet"
        )
    if incl_len > orig_len:
        raise _error(
            f"btsnoop record at offset {offset} keeps {incl_len} bytes "
            f"of a {orig_len}-byte packet"
        )
    return start + incl_len <= len(raw)


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
