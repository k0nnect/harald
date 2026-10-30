import pytest
from capture_helpers import T0, make_btsnoop, make_pklg

from harald.capture.files import read_capture
from harald.errors import CaptureFormatError

CMD = bytes.fromhex("030c00")  # hci reset
EVT = bytes.fromhex("0e0401030c00")  # command complete for reset
ACL_OUT = bytes.fromhex("40000700030004000a2a00")  # att read request
ACL_IN = bytes.fromhex("40200600020004000b64")  # att read response

PKLG_RECORDS = [(0x00, CMD), (0x02, ACL_OUT), (0x03, ACL_IN)]
BTSNOOP_RECORDS = [("cmd", CMD), ("evt", EVT), ("acl_out", ACL_OUT), ("acl_in", ACL_IN)]


def _read(tmp_path, raw: bytes, name: str = "capture.pklg"):
    path = tmp_path / name
    path.write_bytes(raw)
    return read_capture(path)


def _assert_pklg_records(records):
    assert [r.kind for r in records] == ["cmd", "acl_out", "acl_in"]
    assert [r.data for r in records] == [CMD, ACL_OUT, ACL_IN]
    assert [r.ts for r in records] == [T0, T0 + 0.25, T0 + 0.5]


def test_pklg_big_endian(tmp_path):
    _assert_pklg_records(_read(tmp_path, make_pklg(PKLG_RECORDS, byte_order="big")))


def test_pklg_little_endian(tmp_path):
    _assert_pklg_records(_read(tmp_path, make_pklg(PKLG_RECORDS, byte_order="little")))


def test_pklg_little_endian_large_first_record(tmp_path):
    # len 256 is 00 01 00 00 little-endian, which big-endian reads as 65536. that fits
    # a file over 64 kib, so only walking the whole record chain finds the real order.
    first = bytes(256 - 9)
    raw = make_pklg([(0x02, first)] + [(0x03, ACL_IN)] * 5000, byte_order="little")
    assert len(raw) > 65536
    records = _read(tmp_path, raw)
    assert len(records) == 5001
    assert (records[0].kind, records[0].data) == ("acl_out", first)
    assert all((r.kind, r.data) == ("acl_in", ACL_IN) for r in records[1:])


def test_pklg_both_orders_walk_uses_wireshark_tiebreak(tmp_path):
    # exactly 65540 bytes, so big-endian also walks, as one record of len 65536. that
    # len has zero low 16 bits and non-zero high 16 bits, so little-endian wins.
    filler = (0x03, bytes(7))  # 20 bytes per record
    raw = make_pklg([(0x02, bytes(256 - 9))] + [filler] * 3264, byte_order="little")
    assert len(raw) == 65540
    records = _read(tmp_path, raw)
    assert [r.kind for r in records] == ["acl_out"] + ["acl_in"] * 3264


def test_pklg_skips_syslog_records(tmp_path):
    raw = make_pklg([(0x00, CMD), (0xF7, b"bluetoothd: hello"), (0x01, EVT)])
    records = _read(tmp_path, raw)
    assert [r.kind for r in records] == ["cmd", "evt"]
    assert [r.data for r in records] == [CMD, EVT]


def test_btsnoop_h4(tmp_path):
    raw = make_btsnoop(BTSNOOP_RECORDS, datalink=1002)
    records = _read(tmp_path, raw, "btsnoop_hci.log")
    assert [(r.kind, r.data) for r in records] == BTSNOOP_RECORDS
    assert [r.ts for r in records] == [T0, T0 + 0.25, T0 + 0.5, T0 + 0.75]


def test_btsnoop_1001_flags(tmp_path):
    raw = make_btsnoop(BTSNOOP_RECORDS, datalink=1001)
    records = _read(tmp_path, raw, "btsnoop_hci.log")
    assert [(r.kind, r.data) for r in records] == BTSNOOP_RECORDS
    assert [r.ts for r in records] == [T0, T0 + 0.25, T0 + 0.5, T0 + 0.75]


def test_garbage_file_raises_capture_error(tmp_path):
    with pytest.raises(CaptureFormatError) as e:
        _read(tmp_path, b"this is not a bluetooth capture at all", "notes.txt")
    assert e.value.hint == "expected a packetlogger .pklg or btsnoop file"
