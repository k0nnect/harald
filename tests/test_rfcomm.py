import struct

import pytest
from capture_helpers import (
    CONN,
    DISC,
    FFE1_HANDLE,
    PF,
    PKLG_ACL_IN,
    PKLG_ACL_OUT,
    RFCOMM_PSM,
    SABM,
    SIGNALLING_CID,
    T0,
    UA,
    UIH,
    WRITE_CMD,
    acl,
    att,
    l2cap,
    l2cap_conn_req,
    l2cap_conn_rsp,
    make_btsnoop,
    make_pklg,
    rfcomm_frame,
)

from harald.capture.files import read_capture
from harald.capture.rfcomm import decode_rfcomm, rfcomm_fcs

# the phone opens rfcomm: its own cid is 0x0040, the device answers with 0x0041. each
# side's frames carry the other side's cid, so the phone sends on 0x0041.
PHONE_CID, DEVICE_CID = 0x0040, 0x0041
AVDTP_PSM = 0x0019
_PKLG_TYPE = {"acl_out": PKLG_ACL_OUT, "acl_in": PKLG_ACL_IN}


@pytest.fixture(params=["pklg", "btsnoop"])
def decode(request, tmp_path):
    """Write `(kind, data)` records as a pklg or btsnoop file, read it back, decode it."""

    def run(records):
        if request.param == "pklg":
            path = tmp_path / "capture.pklg"
            path.write_bytes(make_pklg([(_PKLG_TYPE[k], d) for k, d in records]))
        else:
            path = tmp_path / "btsnoop_hci.log"
            path.write_bytes(make_btsnoop(records))
        return decode_rfcomm(read_capture(path))

    return run


def _signal(kind, command, conn=CONN):
    return (kind, acl(conn, l2cap(command, cid=SIGNALLING_CID)))


def _setup(conn=CONN):
    """The phone connects to the device's rfcomm psm and the device accepts."""
    return [
        _signal("acl_out", l2cap_conn_req(1, RFCOMM_PSM, PHONE_CID), conn),
        _signal("acl_in", l2cap_conn_rsp(1, DEVICE_CID, PHONE_CID), conn),
    ]


def _to_device(frame, cid=DEVICE_CID, conn=CONN):
    return ("acl_out", acl(conn, l2cap(frame, cid=cid)))


def _to_phone(frame, cid=PHONE_CID, conn=CONN):
    return ("acl_in", acl(conn, l2cap(frame, cid=cid)))


def _seen(result):
    return [(e.op, e.direction, e.channel, e.value) for e in result.events]


def test_rfcomm_both_directions(decode):
    records = _setup() + [
        _to_device(rfcomm_frame(9, SABM | PF)),
        _to_phone(rfcomm_frame(9, UA | PF, initiator=False)),
        _to_device(rfcomm_frame(9, UIH, b"\x3e\x0c\x00")),
        _to_phone(rfcomm_frame(9, UIH, b"\x3e\x01", initiator=False)),
        _to_device(rfcomm_frame(9, DISC | PF)),
    ]
    result = decode(records)
    assert _seen(result) == [
        ("rfcomm_open", "phone->device", 9, b""),
        ("rfcomm", "phone->device", 9, b"\x3e\x0c\x00"),
        ("rfcomm", "device->phone", 9, b"\x3e\x01"),
        ("rfcomm_close", "phone->device", 9, b""),
    ]
    assert [e.index for e in result.events] == [1, 2, 3, 4]
    assert [e.ts for e in result.events] == [T0 + 0.5, T0 + 1.0, T0 + 1.25, T0 + 1.5]
    assert all(e.conn == CONN for e in result.events)
    assert result.unmapped == [] and result.iap2 == []


def test_cids_are_per_direction(decode):
    # the device opens avdtp to the phone, and the phone picks 0x0041 for it: the same
    # number the phone sends rfcomm on, but device->phone frames on 0x0041 are avdtp.
    records = _setup() + [
        _signal("acl_in", l2cap_conn_req(2, AVDTP_PSM, 0x0060)),
        _signal("acl_out", l2cap_conn_rsp(2, DEVICE_CID, 0x0060)),
        _to_phone(rfcomm_frame(9, UIH, b"avdtp", initiator=False), cid=DEVICE_CID),
        _to_device(rfcomm_frame(9, UIH, b"rfcomm")),
    ]
    result = decode(records)
    assert _seen(result) == [("rfcomm", "phone->device", 9, b"rfcomm")]
    assert result.unmapped == []  # the avdtp channel's setup was captured


def test_credit_byte_skipped(decode):
    records = _setup() + [
        _to_device(rfcomm_frame(9, UIH, b"abc", credit=7)),
        _to_phone(rfcomm_frame(9, UIH, initiator=False, credit=33)),  # credits only
    ]
    assert _seen(decode(records)) == [("rfcomm", "phone->device", 9, b"abc")]


def test_two_byte_length(decode):
    info = bytes(range(200))
    frame = rfcomm_frame(9, UIH, info)
    assert frame[2] & 1 == 0  # the length took two bytes
    result = decode(_setup() + [_to_device(frame)])
    assert _seen(result) == [("rfcomm", "phone->device", 9, info)]


def test_fragmented_acl_reassembled(decode):
    info = bytes(range(200))
    frame = l2cap(rfcomm_frame(9, UIH, info, credit=1), cid=DEVICE_CID)
    records = _setup() + [
        ("acl_out", acl(CONN, frame[:27])),
        _to_phone(rfcomm_frame(9, UIH, b"\x01", initiator=False)),
        ("acl_out", acl(CONN, frame[27:120], pb=0b01)),
        ("acl_out", acl(CONN, frame[120:], pb=0b01)),
    ]
    result = decode(records)
    assert _seen(result) == [
        ("rfcomm", "device->phone", 9, b"\x01"),
        ("rfcomm", "phone->device", 9, info),
    ]
    assert result.events[1].ts == T0 + 1.25  # stamped at its last fragment


def test_missing_setup_is_reported_not_raised(decode):
    records = [
        _to_device(rfcomm_frame(9, UIH, b"\x01"), cid=0x0041),
        _to_device(rfcomm_frame(9, UIH, b"\x02"), cid=0x0041),
    ]
    result = decode(records)
    assert result.events == []
    assert result.unmapped == [(CONN, 0x0041)]


def test_dlci0_ignored(decode):
    parameter_negotiation = bytes([0x83, 0x11, 0x12, 0xF0, 0, 0, 0x7F, 0, 0, 0])
    records = _setup() + [
        _to_device(rfcomm_frame(0, SABM | PF)),
        _to_phone(rfcomm_frame(0, UA | PF, initiator=False)),
        _to_device(rfcomm_frame(0, UIH, parameter_negotiation)),
        _to_device(rfcomm_frame(0, DISC | PF)),
        _to_device(rfcomm_frame(9, UIH, b"\x01")),
    ]
    assert _seen(decode(records)) == [("rfcomm", "phone->device", 9, b"\x01")]


def test_iap2_channel_flagged_once(decode):
    records = _setup() + [
        _to_device(rfcomm_frame(2, UIH, b"\xff\x55\x02\x00\xee\x10")),  # iap2 detect
        _to_phone(rfcomm_frame(2, UIH, b"\xff\x5a\x00\x1a", initiator=False)),
        _to_device(rfcomm_frame(2, UIH, b"\xff\x5a\x00\x1a")),
        _to_device(rfcomm_frame(9, UIH, b"\x3e\x0c")),
    ]
    result = decode(records)
    assert result.iap2 == [(CONN, 2)]
    assert len(result.events) == 4  # still shown as plain rfcomm events


def test_l2cap_disconnect_unmaps_the_channel(decode):
    # disconnection response from the device: dcid is its cid, scid the phone's.
    disconnect_rsp = struct.pack("<BBHHH", 0x07, 3, 4, DEVICE_CID, PHONE_CID)
    records = _setup() + [
        _to_device(rfcomm_frame(9, UIH, b"\x01")),
        _signal("acl_in", disconnect_rsp),
        _to_device(rfcomm_frame(9, UIH, b"\x02")),
    ]
    result = decode(records)
    assert _seen(result) == [("rfcomm", "phone->device", 9, b"\x01")]
    assert result.unmapped == [(CONN, DEVICE_CID)]


def test_short_frames_are_skipped(decode):
    whole = rfcomm_frame(9, UIH, b"\x01\x02\x03")
    long = rfcomm_frame(9, UIH, bytes(200))
    cut = [
        _to_device(whole[:2]),  # no length byte
        _to_device(long[:3]),  # no second length byte
        _to_device(whole[:5]),  # length says 3 info bytes, 2 are there
    ]
    result = decode(_setup() + cut + [_to_device(whole)])
    assert _seen(result) == [("rfcomm", "phone->device", 9, b"\x01\x02\x03")]


def test_fcs_matches_known_frames():
    # sabm and ua on dlci 0, as every rfcomm session opens; their fcs bytes are fixed.
    assert rfcomm_fcs(bytes([0x03, 0x3F, 0x01])) == 0x1C
    assert rfcomm_fcs(bytes([0x03, 0x73, 0x01])) == 0xD7
    assert rfcomm_frame(0, SABM | PF) == bytes.fromhex("033f011c")
    assert rfcomm_frame(0, UA | PF) == bytes.fromhex("037301d7")


def _hand_built(address, control, info=b""):
    """An rfcomm-like frame with a valid fcs, whatever its address and control say."""
    head = bytes([address, control, len(info) << 1 | 1])
    checked = head[:2] if control & ~PF == UIH else head
    return head + info + bytes([rfcomm_fcs(checked)])


def test_non_rfcomm_traffic_without_setup_is_not_reported(decode):
    # ble att, then setup-less dynamic channels that aren't rfcomm: an avdtp media
    # packet, and frames that each break one part of the rfcomm shape.
    good = rfcomm_frame(9, UIH, b"\x01")
    address = good[0]
    records = [
        ("acl_out", acl(CONN, l2cap(att(WRITE_CMD, FFE1_HANDLE, b"\x01")))),
        _to_device(bytes.fromhex("8060000100000000000000003e0c00"), cid=0x0042),
        _to_device(good[:-1] + bytes([good[-1] ^ 0xFF]), cid=0x0043),  # bad fcs
        _to_device(_hand_built(address & ~1, UIH, b"\x01"), cid=0x0044),  # ea clear
        _to_device(_hand_built(address, 0x01, b"\x01"), cid=0x0045),  # no such control
        _to_device(good[:-1] + b"\x00" + good[-1:], cid=0x0046),  # length too short
    ]
    result = decode(records)
    assert result.unmapped == []
    assert result.events == []
