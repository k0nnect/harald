"""Service discovery (sdp) over l2cap, for bluetooth classic on linux.

On the mac, IOBluetooth hands harald a gadget's service records from its sdp cache.
On linux harald asks the gadget itself: one ServiceSearchAttributeRequest on l2cap psm
1 for every attribute of every record that lists l2cap (uuid 0x0100, which every
connectable record does, whatever its browse group), following continuation states
until the reply is whole.

The codec is pure functions over bytes. Malformed or truncated input raises
`BackendError("failed", "bad sdp reply: ...")`, never `IndexError` or `struct.error`.
"""

from __future__ import annotations

import socket
import struct
import uuid
from collections.abc import Callable

from harald import btsock
from harald.arm import normalize_uuid
from harald.classic import BackendError, ServiceRecord

MAX_PDUS = 256  # continuation rounds before a reply that never ends is given up on

_ERROR_RESPONSE = 0x01
_SEARCH_ATTRIBUTE_REQUEST = 0x06
_SEARCH_ATTRIBUTE_RESPONSE = 0x07
_PATTERN = bytes.fromhex("35 03 19 0100")  # sequence { uuid16 l2cap }
_ALL_ATTRIBUTES = bytes.fromhex("35 05 0a 0000ffff")  # sequence { uint32 range }
_MAX_BYTES = 0xFFFF
_MAX_STATE = 16  # bytes of continuation state the spec allows
_MAX_DEPTH = 32  # real records nest a handful of sequences deep

_SIZES = (1, 2, 4, 8, 16)
# element type -> the size indexes it may use; the rest take a 1/2/4-byte length
_FIXED = {0: (0,), 1: range(5), 2: range(5), 3: (1, 2, 4), 5: (0,)}
_VARIABLE = (4, 6, 7, 8)  # text, sequence, alternative, url

_HANDLE, _CLASSES, _PROTOCOLS, _NAME = 0x0000, 0x0001, 0x0004, 0x0100
_RFCOMM = normalize_uuid("0003")

_ERRORS = {
    0x0001: "unsupported sdp version",
    0x0002: "invalid service record handle",
    0x0003: "invalid request syntax",
    0x0004: "invalid pdu size",
    0x0005: "invalid continuation state",
    0x0006: "insufficient resources",
}


class Uuid(str):
    """A decoded sdp uuid as harald's normalized 128-bit text. A subclass, so a uuid
    and a text string with the same characters stay apart."""


def _bad(detail: str) -> BackendError:
    return BackendError("failed", f"bad sdp reply: {detail}")


def decode(data: bytes, offset: int = 0) -> tuple[object, int]:
    """The data element at `offset` in `data`, and the offset just past it.

    nil is None, a uint or int an int, a uuid a `Uuid`, text or a url a str, a bool a
    bool, a sequence or alternative a list.
    """
    return _decode(data, offset, len(data), 0)


def _decode(data: bytes, offset: int, end: int, depth: int) -> tuple[object, int]:
    if depth > _MAX_DEPTH:
        raise _bad("elements nested too deep")
    if offset >= end:
        raise _bad(f"an element runs past byte {end}")
    header = data[offset]
    kind, index = header >> 3, header & 7
    start = offset + 1
    if kind in _VARIABLE and index >= 5:
        width = 1 << (index - 5)
        if start + width > end:
            raise _bad(f"an element runs past byte {end}")
        size = int.from_bytes(data[start : start + width], "big")
        start += width
    elif index in _FIXED.get(kind, ()):
        size = 0 if kind == 0 else _SIZES[index]
    else:
        raise _bad(f"element {header:#04x} at byte {offset}")
    stop = start + size
    if stop > end:
        raise _bad(f"an element runs past byte {end}")
    if kind in (6, 7):
        items = []
        while start < stop:
            item, start = _decode(data, start, stop, depth + 1)
            items.append(item)
        return items, stop
    raw = data[start:stop]
    if kind == 0:
        return None, stop
    if kind in (1, 2):
        return int.from_bytes(raw, "big", signed=kind == 2), stop
    if kind == 3:
        text = str(uuid.UUID(bytes=raw)) if size == 16 else normalize_uuid(raw.hex())
        return Uuid(text), stop
    if kind == 5:
        return raw[0] != 0, stop
    return raw.decode("utf-8", "replace"), stop


def build_request(transaction: int, continuation: bytes) -> bytes:
    """A ServiceSearchAttributeRequest for every attribute of every record that lists
    l2cap, resuming at `continuation` (empty for the first pdu)."""
    params = (
        _PATTERN
        + struct.pack(">H", _MAX_BYTES)
        + _ALL_ATTRIBUTES
        + bytes([len(continuation)])
        + continuation
    )
    header = struct.pack(">BHH", _SEARCH_ATTRIBUTE_REQUEST, transaction, len(params))
    return header + params


def parse_response(pdu: bytes, transaction: int) -> tuple[bytes, bytes]:
    """The attribute-list bytes and continuation state in the reply to `transaction`.

    An sdp error response, or any other pdu, raises `BackendError("failed")`.
    """
    if len(pdu) < 5:
        raise _bad(f"a {len(pdu)}-byte pdu")
    pdu_id, tid, length = struct.unpack_from(">BHH", pdu)
    if length != len(pdu) - 5:
        raise _bad(f"a pdu of {len(pdu) - 5} bytes says {length}")
    if tid != transaction:
        raise _bad(f"transaction {tid}, expected {transaction}")
    if pdu_id == _ERROR_RESPONSE:
        if length < 2:
            raise _bad("an error without its code")
        (code,) = struct.unpack_from(">H", pdu, 5)
        detail, name = f"sdp error {code:#06x}", _ERRORS.get(code)
        raise BackendError("failed", f"{detail}: {name}" if name else detail)
    if pdu_id != _SEARCH_ATTRIBUTE_RESPONSE:
        raise _bad(f"pdu {pdu_id:#04x}")
    if length < 3:
        raise _bad("a response without its byte count")
    (count,) = struct.unpack_from(">H", pdu, 5)
    state_at = 7 + count
    if state_at >= len(pdu):
        raise _bad(f"{count} bytes of attribute lists in a {length}-byte response")
    state = pdu[state_at + 1 :]
    if len(state) != pdu[state_at] or len(state) > _MAX_STATE:
        raise _bad("a bad continuation state")
    return pdu[7:state_at], state


def parse_records(attribute_lists: bytes) -> list[ServiceRecord]:
    """The records in a whole AttributeLists: a sequence of per-record sequences of
    (attribute id, value) pairs. A handle seen before is skipped."""
    lists, end = decode(attribute_lists)
    if end != len(attribute_lists):
        raise _bad("bytes after the attribute lists")
    if not isinstance(lists, list):
        raise _bad("the attribute lists are not a sequence")
    records = []
    handles: set[int] = set()
    for element in lists:
        attributes = _attributes(element)
        handle = attributes.get(_HANDLE)
        if type(handle) is int:
            if handle in handles:
                continue
            handles.add(handle)
        records.append(
            ServiceRecord(
                name=_name(attributes.get(_NAME)),
                uuids=_uuids(attributes.get(_CLASSES)),
                channel=_channel(attributes.get(_PROTOCOLS)),
            )
        )
    return records


def _attributes(element: object) -> dict[int, object]:
    if not isinstance(element, list) or len(element) % 2:
        raise _bad("a record is not attribute id, value pairs")
    ids = element[::2]
    if not all(type(attr) is int for attr in ids):
        raise _bad("an attribute id is not a number")
    return dict(zip(ids, element[1::2]))


def _name(value: object) -> str | None:
    if not isinstance(value, str) or isinstance(value, Uuid):
        return None
    return value.rstrip("\x00") or None  # gadgets often send the c string's nul


def _uuids(element: object) -> list[str]:
    """The uuids in a service-class list, walking into sequences."""
    if isinstance(element, Uuid):
        return [str(element)]
    if isinstance(element, list):
        return [u for child in element for u in _uuids(child)]
    return []


def _channel(element: object) -> int | None:
    """The rfcomm channel in a protocol descriptor list (or an alternative of them);
    None for a channel outside 1-30, which rfcomm can't reach."""
    if not isinstance(element, list):
        return None
    if element and isinstance(element[0], Uuid) and element[0] == _RFCOMM:
        channel = element[1] if len(element) > 1 else None
        return channel if type(channel) is int and 1 <= channel <= 30 else None
    for child in element:
        channel = _channel(child)
        if channel is not None:
            return channel
    return None


def query(
    address: str,
    *,
    timeout: float = 10.0,
    connect: Callable[..., socket.socket] = btsock.connect_l2cap,
) -> list[ServiceRecord]:
    """Every service record on `address`, read over l2cap psm 1.

    `timeout` bounds the connect and each reply.
    """
    sock = connect(address, btsock.SDP_PSM, timeout=timeout)
    attribute_lists = bytearray()
    try:
        sock.settimeout(timeout)
        continuation = b""
        for transaction in range(1, MAX_PDUS + 1):
            sock.send(build_request(transaction, continuation))
            pdu = sock.recv(65535)
            if not pdu:
                raise BackendError("failed", "the gadget closed the sdp channel")
            piece, continuation = parse_response(pdu, transaction)
            attribute_lists += piece
            if not continuation:
                break
        else:
            raise _bad(f"no end after {MAX_PDUS} pdus")
    except TimeoutError:
        raise BackendError("timeout", f"no sdp answer in {timeout:g} s") from None
    except OSError as exc:
        raise BackendError(*btsock.error_code(exc.errno or 0)) from None
    finally:
        sock.close()
    return parse_records(bytes(attribute_lists))
