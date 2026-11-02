"""Builders for synthetic hci capture files, so no test needs a real phone log.

Every built capture stamps record i at unix time `T0 + i * 0.25` seconds.
"""

from __future__ import annotations

import struct
from pathlib import Path

from harald.capture.rfcomm import rfcomm_fcs

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


# bluetooth classic: l2cap channel setup on the signalling channel, then rfcomm frames.
SIGNALLING_CID = 0x0001
RFCOMM_PSM = 0x0003
SABM, UA, DM, DISC, UIH = 0x2F, 0x63, 0x0F, 0x43, 0xEF  # rfcomm controls, p/f clear
PF = 0x10  # the rfcomm poll/final bit


def l2cap_conn_req(ident: int, psm: int, scid: int) -> bytes:
    """A connection request command; the payload goes on cid 0x0001."""
    return struct.pack("<BBHHH", 0x02, ident, 4, psm, scid)


def l2cap_conn_rsp(ident: int, dcid: int, scid: int, result: int = 0) -> bytes:
    """A connection response: `dcid` is the responder's new cid, `scid` the requester's."""
    return struct.pack("<BBHHHHH", 0x03, ident, 8, dcid, scid, result, 0)


def rfcomm_frame(
    channel: int,
    ctrl: int,
    info: bytes = b"",
    *,
    initiator: bool = True,
    credit: int | None = None,
) -> bytes:
    """An rfcomm frame on server `channel` (dlci = channel << 1).

    `initiator` sets the address byte's c/r bit. A `credit` sets the p/f bit and adds
    the credit byte a credit-based uih carries. The last byte is a real fcs, from
    harald's own `rfcomm_fcs`; test_fcs_matches_known_frames pins it to known frames.
    """
    address = (channel << 1) << 2 | int(initiator) << 1 | 1
    if credit is not None:
        ctrl |= PF
    size = len(info)
    length = bytes([size << 1 | 1]) if size < 0x80 else struct.pack("<H", size << 1)
    header = bytes([address, ctrl]) + length
    checked = header[:2] if ctrl & ~PF == UIH else header  # uih covers address+control
    body = (bytes([credit]) if credit is not None else b"") + info
    return header + body + bytes([rfcomm_fcs(checked)])


CLASSIC_CONN = 0x000B  # a bluetooth classic acl connection, beside the le one at CONN
# the phone opens the rfcomm l2cap channel with its cid 0x0040 and the device answers
# with 0x0041. each side's frames carry the other side's cid.
RFCOMM_PHONE_CID, RFCOMM_DEVICE_CID = 0x0040, 0x0041


def rfcomm_setup(conn: int = CLASSIC_CONN) -> list[tuple[int, bytes]]:
    """pklg records: the phone connects to the device's rfcomm psm and it accepts."""
    req = l2cap_conn_req(1, RFCOMM_PSM, RFCOMM_PHONE_CID)
    rsp = l2cap_conn_rsp(1, RFCOMM_DEVICE_CID, RFCOMM_PHONE_CID)
    return [
        (PKLG_ACL_OUT, acl(conn, l2cap(req, SIGNALLING_CID))),
        (PKLG_ACL_IN, acl(conn, l2cap(rsp, SIGNALLING_CID))),
    ]


def rfcomm_out(frame: bytes, conn: int = CLASSIC_CONN) -> tuple[int, bytes]:
    """A pklg record of an rfcomm frame the phone sends the device."""
    return (PKLG_ACL_OUT, acl(conn, l2cap(frame, RFCOMM_DEVICE_CID)))


def rfcomm_in(frame: bytes, conn: int = CLASSIC_CONN) -> tuple[int, bytes]:
    """A pklg record of an rfcomm frame the device sends the phone."""
    return (PKLG_ACL_IN, acl(conn, l2cap(frame, RFCOMM_PHONE_CID)))


def mixed_records() -> list[tuple[int, bytes]]:
    """pklg records of an le gadget on c=0x0040 and a classic one on c=0x000b.

    The timeline shows them as: #1 rfcomm_open ch=9, #2 write_cmd 01 to 0x0012 (ffe1),
    #3 rfcomm ch=9 3e 0c 00, #4 rfcomm_open ch=2, #5 rfcomm ch=2 01, #6 rfcomm ch=9
    3e 01 from the device, #7 notify 02 on 0x0015, #8 rfcomm_close ch=9.
    """
    return [
        (PKLG_ACL_OUT, acl(CONN, l2cap(read_by_type_req(0x2803)))),
        (PKLG_ACL_IN, acl(CONN, l2cap(char_decls((FFE1_HANDLE, 0xFFE1))))),
        *rfcomm_setup(),
        rfcomm_out(rfcomm_frame(9, SABM | PF)),
        rfcomm_in(rfcomm_frame(9, UA | PF, initiator=False)),
        (PKLG_ACL_OUT, acl(CONN, l2cap(att(WRITE_CMD, FFE1_HANDLE, b"\x01")))),
        rfcomm_out(rfcomm_frame(9, UIH, bytes.fromhex("3e0c00"))),
        rfcomm_out(rfcomm_frame(2, SABM | PF)),
        rfcomm_out(rfcomm_frame(2, UIH, b"\x01")),
        rfcomm_in(rfcomm_frame(9, UIH, bytes.fromhex("3e01"), initiator=False)),
        (PKLG_ACL_IN, acl(CONN, l2cap(att(0x1B, 0x0015, b"\x02")))),  # notify
        rfcomm_out(rfcomm_frame(9, DISC | PF)),
    ]


def mixed_capture(tmp_path: Path) -> Path:
    """Write `mixed_records` as a .pklg."""
    path = tmp_path / "mixed.pklg"
    path.write_bytes(make_pklg(mixed_records()))
    return path


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
