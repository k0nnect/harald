"""Decode rfcomm traffic out of hci acl records: the serial streams of bluetooth classic.

rfcomm rides an l2cap channel opened for psm 0x0003. The channel's cids are learned from
the connection request and response on the signalling channel (cid 0x0001). cids are
local to each end, so a channel is known per (conn, sending side, cid): the phone's
frames carry the device's cid and the device's frames carry the phone's. Traffic on a
dynamic cid whose setup the capture missed is not decoded. When that traffic looks like
rfcomm, down to a valid fcs, `RfcommDecode.unmapped` names the cid instead. Other
setup-less channels (le credit-based channels, a headset's audio already streaming)
stay silent.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import NamedTuple

from harald.capture.files import HciRecord
from harald.capture.l2cap import (
    DIRECTION,
    OTHER_SIDE,
    Direction,
    L2capFrame,
    l2cap_frames,
)

_SIGNALLING_CID = 0x0001
_FIRST_DYNAMIC_CID = 0x0040
# signalling commands: u8 code, u8 identifier, u16 data length, then the data.
_COMMAND = struct.Struct("<BBH")
_CONN_REQ = 0x02  # psm, scid
_CONN_RSP = 0x03  # dcid, scid, result, status
_DISCONN_RSP = 0x07  # dcid, scid
_SUCCESS = 0x0000
_RFCOMM_PSM = 0x0003

# rfcomm controls, with the poll/final bit stripped.
_PF = 0x10
_SABM, _UA, _DM, _DISC, _UIH = 0x2F, 0x63, 0x0F, 0x43, 0xEF
_CONTROLS = frozenset({_SABM, _UA, _DM, _DISC, _UIH})
_OPS = {_SABM: "rfcomm_open", _DISC: "rfcomm_close", _UIH: "rfcomm"}
_IAP2_START = b"\xff\x5a"  # an apple iap2 link packet

# (conn, kind of the side that sends, cid its frames carry)
_ChannelKey = tuple[int, str, int]


@dataclass
class RfcommEvent:
    """One rfcomm event worth showing. `index` is 1-based, as the timeline prints it.

    `op` is "rfcomm" (data), "rfcomm_open" or "rfcomm_close"; only data has a value.
    """

    index: int
    ts: float
    direction: Direction
    op: str
    conn: int
    channel: int
    value: bytes


@dataclass
class RfcommDecode:
    """The rfcomm events, plus what the timeline should warn about.

    `unmapped` lists each (conn, cid) of a dynamic channel with no captured setup that
    carried at least one rfcomm-shaped frame (`_rfcomm_shaped`). `iap2` lists each
    (conn, channel) whose data includes a payload starting `ff 5a`. Both keep
    first-seen order and name each pair once.
    """

    events: list[RfcommEvent] = field(default_factory=list)
    unmapped: list[tuple[int, int]] = field(default_factory=list)
    iap2: list[tuple[int, int]] = field(default_factory=list)


def decode_rfcomm(records: list[HciRecord]) -> RfcommDecode:
    """Turn hci records into rfcomm events, following l2cap setup to find the channels."""
    result = RfcommDecode()
    pending: dict[_ChannelKey, int] = {}  # (conn, requester, its scid) -> psm
    channels: dict[_ChannelKey, int] = {}  # (conn, sender, cid it sends to) -> psm
    for frame in l2cap_frames(records):
        if not frame.payload:
            continue
        if frame.cid == _SIGNALLING_CID:
            _follow_setup(frame, pending, channels)
            continue
        if frame.cid < _FIRST_DYNAMIC_CID:
            continue
        psm = channels.get((frame.conn, frame.kind, frame.cid))
        if psm is None:
            if _rfcomm_shaped(frame.payload):
                _add_once(result.unmapped, (frame.conn, frame.cid))
        elif psm == _RFCOMM_PSM and (event := _rfcomm_event(frame)) is not None:
            result.events.append(event)
            if event.value.startswith(_IAP2_START):
                _add_once(result.iap2, (event.conn, event.channel))
    for index, event in enumerate(result.events, 1):
        event.index = index
    return result


def _follow_setup(
    frame: L2capFrame,
    pending: dict[_ChannelKey, int],
    channels: dict[_ChannelKey, int],
) -> None:
    """Track channel setup and teardown from one signalling frame's commands.

    Every channel is tracked, whatever its psm, so traffic on a channel that was set
    up is never reported as unmapped. A response's `dcid` is the responder's cid and its
    `scid` the requester's.
    """
    conn, kind, payload = frame.conn, frame.kind, frame.payload
    other = OTHER_SIDE[kind]
    at = 0
    while at + _COMMAND.size <= len(payload):
        code, _ident, size = _COMMAND.unpack_from(payload, at)
        data = payload[at + _COMMAND.size : at + _COMMAND.size + size]
        at += _COMMAND.size + size
        if code == _CONN_REQ and len(data) >= 4:
            psm, scid = struct.unpack_from("<HH", data)
            pending[(conn, kind, scid)] = psm
        elif code == _CONN_RSP and len(data) >= 6:
            dcid, scid, result = struct.unpack_from("<HHH", data)
            if result != _SUCCESS:
                continue  # pending or refused
            psm = pending.pop((conn, other, scid), None)
            if psm is not None:
                channels[(conn, other, dcid)] = psm  # the requester sends to dcid
                channels[(conn, kind, scid)] = psm  # the responder sends to scid
        elif code == _DISCONN_RSP and len(data) >= 4:
            dcid, scid = struct.unpack_from("<HH", data)
            channels.pop((conn, other, dcid), None)
            channels.pop((conn, kind, scid), None)


class _Frame(NamedTuple):
    dlci: int
    control: int  # p/f bit stripped
    info: bytes
    checked: bytes  # what the fcs covers
    end: int  # where the fcs byte belongs


def _parse(payload: bytes) -> _Frame | None:
    """Split one rfcomm frame, or None when it is shorter than its header and length.

    Address: dlci in the top six bits, server channel = dlci >> 1. Length: one byte,
    or two when the first byte's ea bit is clear. A uih with p/f set on a data dlci
    carries one credit byte before the info. The fcs byte follows the info.
    """
    if len(payload) < 3:
        return None
    dlci, control = payload[0] >> 2, payload[1]
    ctrl = control & ~_PF
    if payload[2] & 1:
        length, at = payload[2] >> 1, 3
    elif len(payload) >= 4:
        length, at = (payload[2] >> 1) | (payload[3] << 7), 4
    else:
        return None
    checked = payload[:2] if ctrl == _UIH else payload[:at]
    if ctrl == _UIH and control & _PF and dlci:
        at += 1  # credit byte
    if len(payload) < at + length:
        return None
    return _Frame(dlci, ctrl, payload[at : at + length], checked, at + length)


def _rfcomm_event(frame: L2capFrame) -> RfcommEvent | None:
    """The event one frame on a known rfcomm channel gives, or None.

    The fcs is not checked here: the channel's setup already says it is rfcomm.
    """
    parsed = _parse(frame.payload)
    op = _OPS.get(parsed.control) if parsed else None
    if parsed is None or op is None or parsed.dlci == 0:
        return None  # cut short, ua / dm, or multiplexer control
    value = parsed.info if parsed.control == _UIH else b""
    if parsed.control == _UIH and not value:
        return None  # credits only
    direction = DIRECTION[frame.kind]
    return RfcommEvent(0, frame.ts, direction, op, frame.conn, parsed.dlci >> 1, value)


def _rfcomm_shaped(payload: bytes) -> bool:
    """Whether a setup-less frame is rfcomm: ea bit set, a known control, a length that
    fills the frame exactly, and a valid fcs.
    """
    parsed = _parse(payload)
    return (
        parsed is not None
        and payload[0] & 1 == 1
        and parsed.control in _CONTROLS
        and len(payload) == parsed.end + 1
        and rfcomm_fcs(parsed.checked) == payload[-1]
    )


def rfcomm_fcs(checked: bytes) -> int:
    """The fcs rfcomm puts after a frame: a reflected crc-8 (x^8 + x^2 + x + 1).

    It covers the address and control bytes of a uih frame, and the address, control
    and length bytes of any other frame.
    """
    crc = 0xFF
    for byte in checked:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xE0 if crc & 1 else crc >> 1
    return 0xFF - crc


def _add_once(found: list[tuple[int, int]], pair: tuple[int, int]) -> None:
    if pair not in found:
        found.append(pair)
