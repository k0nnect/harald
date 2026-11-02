"""Reassemble l2cap frames out of hci acl records.

acl fragments are joined per connection and direction, so a frame the controller split
across several acl packets comes out whole. att (ble) and rfcomm (classic) both read
their pdus from these frames.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from harald.capture.files import HciRecord

Direction = Literal["phone->device", "device->phone"]

DIRECTION: dict[str, Direction] = {
    "acl_out": "phone->device",
    "acl_in": "device->phone",
}
OTHER_SIDE = {"acl_out": "acl_in", "acl_in": "acl_out"}

# acl: u16 handle (low 12 bits) + packet boundary flag (bits 12-13), u16 data length.
# l2cap: u16 payload length, u16 channel id. both little-endian.
_HEADER = struct.Struct("<HH")
_PB_CONTINUATION = 0b01


@dataclass(frozen=True)
class L2capFrame:
    """One whole l2cap frame. `kind` "acl_out" was sent by the phone.

    `cid` is the channel id in the frame's header: the receiver's end of the channel.
    """

    ts: float
    kind: str
    conn: int
    cid: int
    payload: bytes


def l2cap_frames(records: list[HciRecord]) -> Iterator[L2capFrame]:
    """Yield each complete l2cap frame, stamped at its last fragment.

    The last fragment is when the frame was complete, so frames keep their time order.
    Fragments are joined per (conn, direction). A record shorter than its acl header
    claims (a snaplen cut) is skipped and drops that stream's partial frame, so later
    fragments can't be glued onto the wrong bytes. A continuation whose start was not
    captured is skipped.
    """
    partial: dict[tuple[int, str], bytearray] = {}
    for record in records:
        if record.kind not in DIRECTION or len(record.data) < _HEADER.size:
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
        payload = bytes(frame[_HEADER.size : _HEADER.size + size])
        yield L2capFrame(record.ts, record.kind, conn, cid, payload)
