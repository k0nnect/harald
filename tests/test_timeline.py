import os
import struct

from capture_helpers import (
    CONN,
    FFE1_HANDLE,
    PKLG_ACL_IN,
    PKLG_ACL_OUT,
    WRITE_CMD,
    acl,
    att,
    l2cap,
    make_pklg,
    read_by_type_req,
    write_capture,
)

from harald.capture.timeline import build_timeline, render

NOTIFY, READ_REQ, READ_RSP, FIND_INFO_RSP = 0x1B, 0x0A, 0x0B, 0x05


def _capture(tmp_path, records, name="records.pklg"):
    path = tmp_path / name
    path.write_bytes(make_pklg(records))
    return path


def _out(pdu: bytes, cid: int = 0x0004):
    return (PKLG_ACL_OUT, acl(CONN, l2cap(pdu, cid)))


def _in(pdu: bytes):
    return (PKLG_ACL_IN, acl(CONN, l2cap(pdu)))


def test_write_cmd_with_discovery_maps_uuid(tmp_path):
    tl = build_timeline(
        write_capture(tmp_path, discovery=True, writes=[bytes.fromhex("7e0705")])
    )
    ev = next(e for e in tl.events if e.op == "write_cmd")
    assert ev.direction == "phone->device"
    assert ev.uuid == "0000ffe1-0000-1000-8000-00805f9b34fb"
    assert "write_cmd  h=0x0012  ffe1  7e 07 05" in render(tl)
    assert tl.warnings == []


def test_missing_discovery_warns(tmp_path):
    tl = build_timeline(write_capture(tmp_path, discovery=False, writes=[b"\x01"]))
    assert tl.events[0].uuid is None and "toggle bluetooth off and on" in tl.warnings[0]


def test_fragmented_acl_is_reassembled(tmp_path):
    value = bytes(range(37))
    frame = l2cap(att(WRITE_CMD, FFE1_HANDLE, value))  # 4-byte header + 40-byte pdu
    assert len(frame) == 44
    records = [
        (PKLG_ACL_OUT, acl(CONN, frame[:27])),
        (PKLG_ACL_OUT, acl(CONN, frame[27:], pb=0b01)),  # the other 17 bytes
    ]
    tl = build_timeline(_capture(tmp_path, records))
    assert len(tl.events) == 1 and len(tl.events[0].value) == 37
    assert tl.events[0].value == value


def test_notify_direction(tmp_path):
    tl = build_timeline(_capture(tmp_path, [_in(att(NOTIFY, 0x0015, b"\x01\x02"))]))
    ev = tl.events[0]
    assert (ev.op, ev.direction, ev.handle, ev.value) == (
        "notify",
        "device->phone",
        0x0015,
        b"\x01\x02",
    )


def test_render_limits_and_footer(tmp_path):
    tl = build_timeline(write_capture(tmp_path, discovery=True, writes=[b"\x01"] * 500))
    out = render(tl)
    assert out.count("\n#") <= 200 and out.rstrip().endswith(
        "showing 1–200 of 500 events"
    )
    assert "showing 201–250 of 500 events" in render(tl, limit=50, offset=200)


def test_render_index_matches_footer(tmp_path):
    tl = build_timeline(write_capture(tmp_path, discovery=True, writes=[b"\x01"] * 3))
    lines = render(tl, limit=2, offset=1).splitlines()
    assert [line.split("  ")[0] for line in lines[:-1]] == ["#2", "#3"]
    assert lines[0].split("  ")[1] == "+0.250s"  # seconds since the first event
    assert lines[-1] == "showing 2–3 of 3 events"
    assert [e.index for e in tl.events] == [1, 2, 3]


def test_render_filters_by_handle(tmp_path):
    records = [_out(att(WRITE_CMD, FFE1_HANDLE, b"\x01")), _out(att(WRITE_CMD, 0x0020))]
    records += [_out(att(WRITE_CMD, FFE1_HANDLE, b"\x02"))]
    out = render(build_timeline(_capture(tmp_path, records)), handle=FFE1_HANDLE)
    lines = [line for line in out.splitlines() if not line.startswith("warning: ")]
    assert [line.split("  ")[0] for line in lines[:-1]] == ["#1", "#3"]
    assert "h=0x0020" not in out
    assert lines[-1] == "showing 1–2 of 2 events with h=0x0012"


def test_render_puts_warnings_first(tmp_path):
    tl = build_timeline(write_capture(tmp_path, discovery=False, writes=[b"\x01"]))
    first, second = render(tl).splitlines()[:2]
    assert first == "warning: " + tl.warnings[0]
    assert second.startswith("#1  ") and "h=0x0012  -  01" in second


def test_read_rsp_takes_handle_from_read_req(tmp_path):
    records = [_out(att(READ_REQ, FFE1_HANDLE)), _in(bytes([READ_RSP, 0x64]))]
    tl = build_timeline(_capture(tmp_path, records))
    req, rsp = tl.events
    assert (req.op, req.direction, req.handle) == ("read_req", "phone->device", 0x0012)
    assert (rsp.op, rsp.direction, rsp.handle, rsp.value) == (
        "read_rsp",
        "device->phone",
        0x0012,
        b"\x64",
    )


def test_find_info_maps_16_and_128_bit_uuids(tmp_path):
    custom = bytes.fromhex("6e400002b5a3f393e0a9e50e24dcca9e")  # nordic uart rx
    records = [
        _in(bytes([FIND_INFO_RSP, 0x01]) + struct.pack("<HH", 0x0013, 0x2902)),
        _in(bytes([FIND_INFO_RSP, 0x02]) + struct.pack("<H", 0x0020) + custom[::-1]),
        _out(att(WRITE_CMD, 0x0013, b"\x01\x00")),
        _out(att(WRITE_CMD, 0x0020, b"\xaa")),
    ]
    tl = build_timeline(_capture(tmp_path, records))
    assert tl.handle_map == {
        0x0013: "00002902-0000-1000-8000-00805f9b34fb",
        0x0020: "6e400002-b5a3-f393-e0a9-e50e24dcca9e",
    }
    out = render(tl)
    assert "h=0x0013  2902  01 00" in out
    assert "h=0x0020  6e400002-b5a3-f393-e0a9-e50e24dcca9e  aa" in out


def test_read_by_type_for_other_types_does_not_map(tmp_path):
    # a 5-byte device name read by type has the same shape as a characteristic
    # declaration; only a response to a 0x2803 request may fill the map.
    name_rsp = bytes([0x09, 7]) + struct.pack("<H", 0x0003) + b"strip"
    records = [_out(read_by_type_req(0x2A00)), _in(name_rsp)]
    records += [_out(att(WRITE_CMD, FFE1_HANDLE, b"\x01"))]
    tl = build_timeline(_capture(tmp_path, records))
    assert tl.handle_map == {}
    assert "toggle bluetooth off and on" in tl.warnings[0]


def test_non_att_and_cut_short_acl_records_are_skipped(tmp_path):
    good = att(WRITE_CMD, FFE1_HANDLE, b"\x07")
    # the acl header claims 2 more bytes than the cut record holds; the continuation
    # after it supplies exactly those bytes but must not complete the cut frame.
    cut = acl(CONN, l2cap(att(WRITE_CMD, FFE1_HANDLE, b"\x01\x02\x03")))[:-2]
    rest = acl(CONN, b"\x02\x03", pb=0b01)
    records = [
        _out(good, cid=0x0005),  # le signaling channel, not att
        (PKLG_ACL_OUT, cut),
        (PKLG_ACL_OUT, rest),
        _out(good),
    ]
    tl = build_timeline(_capture(tmp_path, records))
    assert [(e.op, e.value) for e in tl.events] == [("write_cmd", b"\x07")]


def test_build_timeline_is_cached_by_path_and_mtime(tmp_path):
    path = write_capture(tmp_path, discovery=True, writes=[b"\x01"])
    first = build_timeline(path)
    assert build_timeline(path) is first
    write_capture(tmp_path, discovery=True, writes=[b"\x01", b"\x02"])
    later = path.stat().st_mtime_ns + 1_000_000_000
    os.utime(path, ns=(later, later))
    rebuilt = build_timeline(path)
    assert rebuilt is not first and len(rebuilt.events) == 2
