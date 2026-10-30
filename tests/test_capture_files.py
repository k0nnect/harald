import gzip
import struct

import pytest
from capture_helpers import T0, make_btsnoop, make_pklg

from harald.capture.files import read_capture, read_capture_with_warnings
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


def _read_warned(tmp_path, raw: bytes, name: str = "capture.pklg"):
    path = tmp_path / name
    path.write_bytes(raw)
    return read_capture_with_warnings(path)


def _assert_cut_short_warning(warnings: list[str], offset: int, size: int) -> None:
    expected = (
        f"the capture is cut short: the record at byte {offset} runs past the end "
        f"of the file, so 1 record ({size} bytes) was skipped"
    )
    assert warnings == [expected]


# the last pklg record (acl_in) starts at byte 40 and is 23 bytes long: 1 cuts its
# payload, 19 leaves only its length field, 20 cuts into the length field itself.
@pytest.mark.parametrize("byte_order", ["big", "little"])
@pytest.mark.parametrize("cut", [1, 19, 20])
def test_pklg_cut_short_last_record_keeps_the_ones_before(tmp_path, byte_order, cut):
    raw = make_pklg(PKLG_RECORDS, byte_order=byte_order)[:-cut]
    records, warnings = _read_warned(tmp_path, raw)
    assert [(r.kind, r.data) for r in records] == [("cmd", CMD), ("acl_out", ACL_OUT)]
    _assert_cut_short_warning(warnings, 40, 23 - cut)
    assert read_capture(tmp_path / "capture.pklg") == records  # same signature


def test_pklg_whole_file_has_no_warnings(tmp_path):
    records, warnings = _read_warned(tmp_path, make_pklg(PKLG_RECORDS))
    _assert_pklg_records(records)
    assert warnings == []


def test_pklg_damage_in_the_middle_still_raises(tmp_path):
    raw = bytearray(make_pklg(PKLG_RECORDS))
    raw[16:20] = struct.pack(">I", 3)  # the second record's len, below the minimum
    with pytest.raises(CaptureFormatError):
        _read(tmp_path, bytes(raw))
    with pytest.raises(CaptureFormatError):  # no whole record before the cut
        _read(tmp_path, make_pklg(PKLG_RECORDS[:1])[:-1])


# the last btsnoop record (acl_in) starts at byte 111: a 24-byte header, then 11
# bytes. 1 cuts its payload, 11 leaves only its header, 20 cuts into the header.
@pytest.mark.parametrize("cut", [1, 11, 20])
def test_btsnoop_cut_short_last_record_keeps_the_ones_before(tmp_path, cut):
    raw = make_btsnoop(BTSNOOP_RECORDS)[:-cut]
    records, warnings = _read_warned(tmp_path, raw, "btsnoop_hci.log")
    assert [(r.kind, r.data) for r in records] == BTSNOOP_RECORDS[:3]
    _assert_cut_short_warning(warnings, 111, 35 - cut)
    assert read_capture(tmp_path / "btsnoop_hci.log") == records  # same signature


def test_btsnoop_damage_in_the_middle_still_raises(tmp_path):
    raw = bytearray(make_btsnoop(BTSNOOP_RECORDS))
    # empty the second record (at byte 44): incl_len 0, and drop its 7 payload bytes
    raw[48:52] = struct.pack(">I", 0)
    del raw[68:75]
    with pytest.raises(CaptureFormatError, match="offset 44 is empty"):
        _read(tmp_path, bytes(raw), "btsnoop_hci.log")
    with pytest.raises(CaptureFormatError, match="cut short"):  # no whole record
        _read(tmp_path, make_btsnoop(BTSNOOP_RECORDS[:1])[:-1], "btsnoop_hci.log")


@pytest.mark.parametrize(
    "raw",
    [
        gzip.compress(b"not a capture\n" * 100, mtime=0),
        # its first four bytes read as a 66051-byte record that fits in the file
        bytes(range(256)) * 280,
    ],
    ids=["gzip", "binary"],
)
def test_non_capture_binary_raises(tmp_path, raw):
    with pytest.raises(CaptureFormatError) as e:
        _read(tmp_path, raw, "not-a-capture.bin")
    assert e.value.hint == "expected a packetlogger .pklg or btsnoop file"


# the largest pklg record: 8 timestamp bytes, a type byte, and an acl packet of a
# 4-byte header plus 65535 bytes of data.
@pytest.mark.parametrize("byte_order", ["big", "little"])
def test_pklg_oversize_length_mid_file_raises(tmp_path, byte_order):
    order = {"big": ">", "little": "<"}[byte_order]
    raw = bytearray(make_pklg(PKLG_RECORDS, byte_order=byte_order))
    raw[16:20] = struct.pack(order + "I", 65549)  # the second record's len
    with pytest.raises(CaptureFormatError) as e:
        _read(tmp_path, bytes(raw))
    assert e.value.hint == "expected a packetlogger .pklg or btsnoop file"
    # the largest plausible len that runs past the end is still a cut tail
    raw[16:20] = struct.pack(order + "I", 65548)
    records, warnings = _read_warned(tmp_path, bytes(raw))
    assert [(r.kind, r.data) for r in records] == [("cmd", CMD)]
    _assert_cut_short_warning(warnings, 16, len(raw) - 16)


def test_btsnoop_oversize_length_mid_file_raises(tmp_path):
    raw = bytearray(make_btsnoop(BTSNOOP_RECORDS))
    raw[44:52] = struct.pack(">II", 65541, 65541)  # the second record's lengths
    with pytest.raises(CaptureFormatError, match="offset 44") as e:
        _read(tmp_path, bytes(raw), "btsnoop_hci.log")
    assert e.value.hint == "expected a packetlogger .pklg or btsnoop file"
    # one byte less is a plausible h4 acl packet, so it reads as a cut tail
    raw[44:52] = struct.pack(">II", 65540, 65540)
    records, warnings = _read_warned(tmp_path, bytes(raw), "btsnoop_hci.log")
    assert [(r.kind, r.data) for r in records] == BTSNOOP_RECORDS[:1]
    _assert_cut_short_warning(warnings, 44, len(raw) - 44)


def test_btsnoop_record_longer_than_its_packet_raises(tmp_path):
    raw = bytearray(make_btsnoop(BTSNOOP_RECORDS))
    raw[44:48] = struct.pack(">I", 1)  # orig_len 1, while incl_len is 7
    with pytest.raises(CaptureFormatError, match="offset 44") as e:
        _read(tmp_path, bytes(raw), "btsnoop_hci.log")
    assert e.value.hint == "expected a packetlogger .pklg or btsnoop file"
