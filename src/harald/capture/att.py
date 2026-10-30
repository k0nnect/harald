"""Decode att traffic out of hci acl records: writes, notifications, indications, reads.

acl fragments are reassembled into l2cap frames per connection and direction, and only
the att channel (cid 0x0004) is kept. Each connection gets its own handle-to-uuid map,
from the gatt discovery the phone ran against that device, when the capture caught
it: a capture can hold several connections, and their handles mean different things.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from harald.capture.files import HciRecord

Direction = Literal["phone->device", "device->phone"]

_DIRECTION: dict[str, Direction] = {
    "acl_out": "phone->device",
    "acl_in": "device->phone",
}
_OTHER_SIDE = {"acl_out": "acl_in", "acl_in": "acl_out"}

# acl: u16 handle (low 12 bits) + packet boundary flag (bits 12-13), u16 data length.
# l2cap: u16 payload length, u16 channel id. both little-endian.
_HEADER = struct.Struct("<HH")
_PB_CONTINUATION = 0b01
_ATT_CID = 0x0004

_FIND_INFO_RSP = 0x05
_READ_BY_TYPE_REQ, _READ_BY_TYPE_RSP = 0x08, 0x09
_READ_REQ, _READ_RSP = 0x0A, 0x0B
_HANDLE_OPS = {  # opcode, u16 handle, value
    0x12: "write_req",
    0x52: "write_cmd",
    0x1B: "notify",
    0x1D: "indicate",
    _READ_REQ: "read_req",
}
# the ops that address the device's gatt server, by the direction they travel. the
# rest address the phone's own server, whose handles the map does not describe.
_TO_DEVICE_SERVER: dict[Direction, frozenset[str]] = {
    "phone->device": frozenset({"write_req", "write_cmd", "read_req"}),
    "device->phone": frozenset({"notify", "indicate", "read_rsp"}),
}
# read-by-type entry: attribute handle, properties, value handle, 2- or 16-byte uuid.
_CHAR_DECL_SIZES = (7, 21)
_FIND_INFO_SIZES = {0x01: 4, 0x02: 18}  # format: handle + 2- or 16-byte uuid

SIG_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def sig_uuid(short: int) -> str:
    """Expand a 16-bit uuid onto the bluetooth sig base uuid."""
    return f"{short:08x}{SIG_BASE_SUFFIX}"


_CHAR_DECL_TYPE = sig_uuid(0x2803)


@dataclass
class AttEvent:
    """One att pdu worth showing. `index` is 1-based, as the timeline prints it."""

    index: int
    ts: float
    direction: Direction
    op: str
    conn: int
    handle: int | None
    uuid: str | None
    value: bytes

    def addresses_device(self) -> bool:
        """True for ops on the device's gatt server, which discovery describes."""
        return self.op in _TO_DEVICE_SERVER[self.direction]


def decode_att(
    records: list[HciRecord],
) -> tuple[list[AttEvent], dict[int, dict[int, str]]]:
    """Turn hci records into att events plus a handle-to-uuid map per connection.

    Each map is built from responses the device sent the phone on that connection, so
    it describes that device's gatt server. Only events that address that server
    (`AttEvent.addresses_device`) are labelled with a uuid.
    """
    events: list[AttEvent] = []
    handle_maps: dict[int, dict[int, str]] = {}  # conn -> handle -> uuid
    last_read: dict[tuple[int, str], int] = {}  # (conn, requesting side) -> handle
    # conn -> whether the phone's last read-by-type request asked for 0x2803
    wants_chars: dict[int, bool] = {}
    for ts, kind, conn, pdu in _att_pdus(records):
        op = pdu[0]
        if op == _READ_BY_TYPE_REQ and kind == "acl_out":
            wants_chars[conn] = _uuid(pdu[5:]) == _CHAR_DECL_TYPE
        elif op == _READ_BY_TYPE_RSP and kind == "acl_in":
            if wants_chars.get(conn, True):  # no request seen: go by shape alone
                _map_char_decls(pdu, handle_maps.setdefault(conn, {}))
        elif op == _FIND_INFO_RSP and kind == "acl_in":
            _map_find_info(pdu, handle_maps.setdefault(conn, {}))
        elif op in _HANDLE_OPS and len(pdu) >= 3:
            handle = int.from_bytes(pdu[1:3], "little")
            if op == _READ_REQ:
                last_read[(conn, kind)] = handle
            op_name, value = _HANDLE_OPS[op], pdu[3:]
            events.append(
                AttEvent(0, ts, _DIRECTION[kind], op_name, conn, handle, None, value)
            )
        elif op == _READ_RSP:
            handle = last_read.pop((conn, _OTHER_SIDE[kind]), None)
            value = pdu[1:]
            events.append(
                AttEvent(0, ts, _DIRECTION[kind], "read_rsp", conn, handle, None, value)
            )
    handle_maps = {conn: found for conn, found in handle_maps.items() if found}
    # numbered and labelled last, so discovery seen after an event still names it.
    for index, event in enumerate(events, 1):
        event.index = index
        if event.handle is not None and event.addresses_device():
            event.uuid = handle_maps.get(event.conn, {}).get(event.handle)
    return events, handle_maps


def _att_pdus(records: list[HciRecord]) -> Iterator[tuple[float, str, int, bytes]]:
    """Yield (ts, kind, conn, pdu) for each complete att pdu, stamped at its last fragment.

    The last fragment is when the pdu was complete, so events keep their time order.
    Fragments are joined per (conn, direction). A record shorter than its acl header
    claims (a snaplen cut) is skipped and drops that stream's partial frame, so later
    fragments can't be glued onto the wrong bytes.
    """
    partial: dict[tuple[int, str], bytearray] = {}
    for record in records:
        if record.kind not in _DIRECTION or len(record.data) < _HEADER.size:
            continue
        flags_handle, length = _HEADER.unpack_from(record.data)
        conn = flags_handle & 0x0FFF
        key = (conn, record.kind)
        body = record.data[_HEADER.size : _HEADER.size + length]
        if len(body) < length:
            partial.pop(key, None)
            continue
        if (flags_handle >> 12) & 0b11 == _PB_CONTINUATION:
            if key not in partial:
                continue  # the frame's start was not captured
            partial[key].extend(body)
        else:
            partial[key] = bytearray(body)
        frame = partial[key]
        if len(frame) < _HEADER.size:
            continue
        size, cid = _HEADER.unpack_from(frame)
        if len(frame) < _HEADER.size + size:
            continue
        del partial[key]
        pdu = bytes(frame[_HEADER.size : _HEADER.size + size])
        if cid == _ATT_CID and pdu:
            yield record.ts, record.kind, conn, pdu


def _uuid(raw: bytes) -> str | None:
    """A little-endian 2- or 16-byte att uuid as a lowercase uuid string."""
    if len(raw) == 2:
        return sig_uuid(int.from_bytes(raw, "little"))
    if len(raw) == 16:
        return str(UUID(bytes=raw[::-1]))
    return None


def _map_char_decls(pdu: bytes, handle_map: dict[int, str]) -> None:
    """Map value handles from a read-by-type response of characteristic declarations."""
    size = pdu[1] if len(pdu) > 1 else 0
    if size not in _CHAR_DECL_SIZES:
        return
    for at in range(2, len(pdu) - size + 1, size):
        entry = pdu[at : at + size]
        handle_map[int.from_bytes(entry[3:5], "little")] = _uuid(entry[5:])


def _map_find_info(pdu: bytes, handle_map: dict[int, str]) -> None:
    """Map every handle listed in a find-information response."""
    size = _FIND_INFO_SIZES.get(pdu[1]) if len(pdu) > 1 else None
    if size is None:
        return
    for at in range(2, len(pdu) - size + 1, size):
        handle_map[int.from_bytes(pdu[at : at + 2], "little")] = _uuid(
            pdu[at + 2 : at + size]
        )
