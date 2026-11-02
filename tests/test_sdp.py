"""harald.sdp: the data-element codec, the pdus, records, and the query loop.

Nothing here opens a bluetooth socket. The gadget's side is bytes from
`sdp_fixtures` (or written out by hand), and `query` talks to a fake socket through its
`connect` seam.
"""

import errno
import struct

import pytest
from classic_fakes import XM5_ADDRESS, XM5_RECORDS
from sdp_fixtures import (
    alt,
    attribute_list,
    encode_records,
    response,
    seq,
    split_responses,
    text,
    uint,
    uuid16,
)

from harald import btsock, sdp
from harald.arm import normalize_uuid
from harald.classic import BackendError, ServiceRecord

SPP = "00001101-0000-1000-8000-00805f9b34fb"


def h(text: str) -> bytes:
    return bytes.fromhex(text)


def failed(call, *args) -> BackendError:
    with pytest.raises(BackendError) as info:
        call(*args)
    assert info.value.code == "failed"
    return info.value


# data elements


def test_nil():
    assert sdp.decode(h("00")) == (None, 1)


@pytest.mark.parametrize(
    ("data", "value"),
    [
        ("08 ff", 0xFF),
        ("09 0102", 0x0102),
        ("0a 01020304", 0x01020304),
        ("0b 0102030405060708", 0x0102030405060708),
        ("0c 0102030405060708090a0b0c0d0e0f10", 0x0102030405060708090A0B0C0D0E0F10),
    ],
)
def test_uint_every_size(data, value):
    assert sdp.decode(h(data)) == (value, len(h(data)))


@pytest.mark.parametrize(
    ("data", "value"),
    [
        ("10 ff", -1),
        ("11 fffe", -2),
        ("12 7fffffff", 0x7FFFFFFF),
        ("13 8000000000000000", -(2**63)),
        ("14 ffffffffffffffffffffffffffffffff", -1),
    ],
)
def test_int_every_size(data, value):
    assert sdp.decode(h(data)) == (value, len(h(data)))


@pytest.mark.parametrize(
    ("data", "value"),
    [
        ("19 1101", SPP),
        ("1a 00001101", SPP),
        ("1a 12345678", "12345678-0000-1000-8000-00805f9b34fb"),
        ("1c 956c7b26d49a4ba8b03fb17d393cb6e2", "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"),
    ],
)
def test_uuid_every_size_is_normalized(data, value):
    decoded, end = sdp.decode(h(data))
    assert isinstance(decoded, sdp.Uuid)
    assert decoded == value == normalize_uuid(value)
    assert end == len(h(data))


@pytest.mark.parametrize(
    "header",
    ["25 03", "26 0003", "27 00000003", "45 03", "46 0003", "47 00000003"],
)
def test_text_and_url_every_length_size(header):
    header = h(header)
    decoded, end = sdp.decode(header + b"abc")
    assert decoded == "abc"
    assert type(decoded) is str  # not a Uuid
    assert end == len(header) + 3


def test_text_is_utf8_and_never_fails_to_decode():
    assert sdp.decode(h("25 02") + "é".encode())[0] == "é"
    assert sdp.decode(h("25 01 ff"))[0] == "�"


def test_bool():
    assert sdp.decode(h("28 01")) == (True, 2)
    assert sdp.decode(h("28 00")) == (False, 2)


@pytest.mark.parametrize("header", ["35 07", "36 0007", "37 00000007"])
def test_sequence_every_length_size(header):
    data = h(header) + h("08 01") + h("19 0100") + h("28 01")
    assert sdp.decode(data) == ([1, normalize_uuid("0100"), True], len(data))


@pytest.mark.parametrize("header", ["3d 04", "3e 0004", "3f 00000004"])
def test_alternative_every_length_size(header):
    data = h(header) + h("35 02 08 05")
    assert sdp.decode(data) == ([[5]], len(data))


def test_empty_sequence():
    assert sdp.decode(h("35 00")) == ([], 2)


def test_decode_from_an_offset():
    assert sdp.decode(h("ffff 09 0102 00"), 2) == (0x0102, 5)


@pytest.mark.parametrize(
    "data",
    [
        "01",  # nil with a size
        "0d 01 ff",  # uint with a length field
        "18 ff",  # 8-bit uuid
        "1b 0102030405060708",  # 64-bit uuid
        "20 61",  # text without a length field
        "29 0001",  # 16-bit bool
        "30 00",  # sequence without a length field
        "48 00",  # reserved type 9
        "f8",  # reserved type 31
    ],
)
def test_bad_header_fails(data):
    assert "bad sdp reply" in failed(sdp.decode, h(data)).detail


@pytest.mark.parametrize(
    "data",
    [
        "",
        "09 01",
        "0c 0102",
        "1c 956c7b26",
        "25 05 6162",
        "26 00",
        "27 000000",
        "35 04 08 01",
        "3f ffffffff",
    ],
)
def test_truncated_element_fails(data):
    assert "bad sdp reply" in failed(sdp.decode, h(data)).detail


def test_element_overrunning_its_sequence_fails():
    # the sequence holds 2 bytes; the uint32 inside it wants 5
    failed(sdp.decode, h("35 02 0a 00000000"))


def test_deep_nesting_fails_cleanly():
    data = h("00")
    for _ in range(200):
        data = seq(data)
    failed(sdp.decode, data)


# records


def test_xm5_round_trip():
    assert sdp.parse_records(encode_records(XM5_RECORDS)) == XM5_RECORDS


def test_records_carry_plain_str_uuids():
    record = sdp.parse_records(encode_records(XM5_RECORDS[:1]))[0]
    assert all(type(u) is str for u in record.uuids)


def test_record_without_rfcomm_has_no_channel():
    records = [ServiceRecord("Pnp", [normalize_uuid("1200")], None)]
    assert sdp.parse_records(encode_records(records)) == records


def test_record_without_a_name():
    records = [ServiceRecord(None, [SPP], 3)]
    assert sdp.parse_records(encode_records(records)) == records


def test_name_drops_trailing_nuls():
    lists = seq(attribute_list([(0x0000, uint(1, 4)), (0x0100, text("Serial\x00"))]))
    assert sdp.parse_records(lists) == [ServiceRecord("Serial", [], None)]


def test_duplicate_handles_appear_once():
    records = [
        ServiceRecord("one", [SPP], 1),
        ServiceRecord("one again", [SPP], 1),
        ServiceRecord("two", [SPP], 2),
    ]
    parsed = sdp.parse_records(encode_records(records, handles=[7, 7, 8]))
    assert parsed == [records[0], records[2]]


def test_channel_inside_an_alternative_protocol_list():
    stacks = alt(seq(seq(uuid16(0x0100)), seq(uuid16(0x0003), uint(5, 1))))
    lists = seq(attribute_list([(0x0000, uint(1, 4)), (0x0004, stacks)]))
    assert sdp.parse_records(lists)[0].channel == 5


@pytest.mark.parametrize(
    "channel",
    [
        "09 012c",  # uint16 300
        "10 ff",  # int8 -1
        "08 00",  # 0
        "08 1f",  # 31, one past the last rfcomm channel
        "0c 00000010000000000000000000000000",  # uint128 2**100
    ],
)
def test_channel_outside_1_to_30_is_none(channel):
    stack = seq(seq(uuid16(0x0100)), seq(uuid16(0x0003) + h(channel)))
    lists = seq(attribute_list([(0x0000, uint(1, 4)), (0x0004, stack)]))
    assert sdp.parse_records(lists)[0].channel is None


def test_no_records():
    assert sdp.parse_records(seq()) == []


def test_every_proper_prefix_fails():
    lists = encode_records(XM5_RECORDS)
    for length in range(len(lists)):
        failed(sdp.parse_records, lists[:length])


def test_extra_bytes_after_the_lists_fail():
    failed(sdp.parse_records, encode_records(XM5_RECORDS) + h("00"))


@pytest.mark.parametrize(
    "lists",
    [
        uint(1, 2),  # not a sequence
        seq(uint(1, 2)),  # a record that is not a sequence
        seq(seq(uint(0, 2))),  # an attribute id without a value
        seq(seq(text("id"), uint(1, 4))),  # an attribute id that is not a number
        seq(seq(seq(), uint(1, 4))),  # nor this
    ],
)
def test_malformed_records_fail(lists):
    failed(sdp.parse_records, lists)


@pytest.mark.parametrize("value", [0x00, 0x07, 0x35, 0xFF])
def test_any_corrupt_byte_gives_records_or_failed(value):
    lists = encode_records(XM5_RECORDS)
    for at in range(len(lists)):
        corrupt = lists[:at] + bytes([value]) + lists[at + 1 :]
        try:
            assert isinstance(sdp.parse_records(corrupt), list)
        except BackendError as exc:
            assert exc.code == "failed"


# pdus


def test_build_first_request():
    assert sdp.build_request(1, b"") == h(
        "06 0001 000f"  # ServiceSearchAttributeRequest, transaction 1, 15 bytes
        "35 03 19 0100"  # pattern: sequence { uuid16 l2cap }
        "ffff"  # maximum attribute byte count
        "35 05 0a 0000ffff"  # attributes: sequence { uint32 range 0x0000-0xffff }
        "00"  # no continuation state
    )


def test_build_request_with_continuation():
    assert sdp.build_request(0x0203, h("aabbccdd")) == h(
        "06 0203 0013 35 03 19 0100 ffff 35 05 0a 0000ffff 04 aabbccdd"
    )


def test_parse_response():
    pdu = response(3, h("35 00"), h("0102"))
    assert sdp.parse_response(pdu, 3) == (h("35 00"), h("0102"))
    assert sdp.parse_response(response(4, b"", b""), 4) == (b"", b"")


def test_error_response_names_the_sdp_error():
    error = failed(sdp.parse_response, h("01 0001 0002 0003"), 1)
    assert "0x0003" in error.detail
    assert "invalid request syntax" in error.detail


def test_wrong_transaction_fails():
    assert "transaction" in failed(sdp.parse_response, response(2, b"", b""), 1).detail


def test_unexpected_pdu_fails():
    failed(sdp.parse_response, h("03 0001 0000"), 1)


def test_every_proper_prefix_of_a_response_fails():
    pdu = response(1, encode_records(XM5_RECORDS[:2]), h("01020304"))
    for length in range(len(pdu)):
        failed(sdp.parse_response, pdu[:length], 1)


@pytest.mark.parametrize(
    "pdu",
    [
        response(1, h("35 00"), b"") + h("00"),  # a byte past the parameters
        h("07 0001 0005 0004 3500 00"),  # byte count longer than the list
        h("07 0001 0005 0001 3500 00"),  # byte count shorter than the list
        response(1, b"", bytes(17)),  # continuation state over 16 bytes
        h("01 0001 0001 00"),  # an error without a whole code
    ],
)
def test_malformed_responses_fail(pdu):
    failed(sdp.parse_response, pdu, 1)


# query


class FakeSocket:
    """An l2cap seqpacket socket: each `recv` returns the next queued pdu, or raises
    it if it is an exception."""

    def __init__(self, replies: list[bytes | BaseException]) -> None:
        self.replies = list(replies)
        self.sent: list[bytes] = []
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def send(self, data: bytes) -> int:
        self.sent.append(data)
        return len(data)

    def recv(self, size: int) -> bytes:
        assert size == 65535
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def close(self) -> None:
        self.closed = True


def run(sock: FakeSocket, **kwargs) -> tuple[list[ServiceRecord], list[tuple]]:
    connects = []

    def connect(address, psm, *, timeout):
        connects.append((address, psm, timeout))
        return sock

    return sdp.query(XM5_ADDRESS, connect=connect, **kwargs), connects


def test_query_follows_continuations():
    lists = encode_records(XM5_RECORDS)
    chunk = -(-len(lists) // 3)
    replies = split_responses(lists, chunk, 1)
    assert len(replies) == 3
    sock = FakeSocket(replies)
    records, connects = run(sock, timeout=4.0)
    assert records == XM5_RECORDS
    assert connects == [(XM5_ADDRESS, btsock.SDP_PSM, 4.0)]
    assert sock.timeouts == [4.0]
    assert [struct.unpack_from(">H", pdu, 1)[0] for pdu in sock.sent] == [1, 2, 3]
    assert sock.sent == [
        sdp.build_request(1, b""),
        sdp.build_request(2, struct.pack(">I", chunk)),
        sdp.build_request(3, struct.pack(">I", 2 * chunk)),
    ]
    assert sock.closed


def test_query_default_timeout():
    sock = FakeSocket(split_responses(encode_records([]), 100, 1))
    assert run(sock) == ([], [(XM5_ADDRESS, btsock.SDP_PSM, 10.0)])


def test_query_error_response_fails_and_closes():
    sock = FakeSocket([h("01 0001 0002 0006")])
    with pytest.raises(BackendError) as info:
        run(sock)
    assert info.value.code == "failed"
    assert "0x0006" in info.value.detail
    assert sock.closed


def test_query_wrong_transaction_fails_and_closes():
    lists = encode_records(XM5_RECORDS)
    sock = FakeSocket(split_responses(lists, 100, 1)[:1] + [response(9, b"", b"")])
    with pytest.raises(BackendError) as info:
        run(sock)
    assert info.value.code == "failed"
    assert sock.closed


def test_query_timeout():
    sock = FakeSocket([TimeoutError("timed out")])
    with pytest.raises(BackendError) as info:
        run(sock, timeout=2.0)
    assert info.value.code == "timeout"
    assert sock.closed


def test_query_maps_os_errors():
    sock = FakeSocket([ConnectionResetError(errno.ECONNRESET, "reset")])
    with pytest.raises(BackendError) as info:
        run(sock)
    assert (info.value.code, info.value.detail) == ("failed", "the channel is closed")
    assert sock.closed


def test_query_gadget_hangs_up():
    sock = FakeSocket([b""])
    with pytest.raises(BackendError) as info:
        run(sock)
    assert info.value.code == "failed"
    assert sock.closed


def test_query_gives_up_on_endless_continuations():
    replies = [response(n, b"", h("01")) for n in range(1, sdp.MAX_PDUS + 2)]
    sock = FakeSocket(replies)
    with pytest.raises(BackendError) as info:
        run(sock)
    assert info.value.code == "failed"
    assert len(sock.sent) == sdp.MAX_PDUS
    assert sock.closed


def test_query_connect_errors_pass_through():
    def connect(address, psm, *, timeout):
        raise BackendError("not_connected", "host is down")

    with pytest.raises(BackendError) as info:
        sdp.query(XM5_ADDRESS, connect=connect)
    assert info.value.code == "not_connected"
