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
