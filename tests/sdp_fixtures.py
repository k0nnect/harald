"""Sdp bytes for tests: a small data-element encoder, and fake continuation replies.

`encode_records` writes what a gadget's sdp server sends for a list of
`ServiceRecord`s, one sdp record each, so `harald.sdp` is tested against bytes it did
not make itself. Every record also lists the public browse group (attribute 0x0005),
a uuid that must not leak into `ServiceRecord.uuids`.
"""

from __future__ import annotations

import struct
import uuid

from harald.classic import ServiceRecord

NIL, UINT, INT, UUID, TEXT, BOOL, SEQUENCE, ALTERNATIVE, URL = range(9)
L2CAP = 0x0100
RFCOMM = 0x0003
PUBLIC_BROWSE_ROOT = 0x1002
FIRST_HANDLE = 0x00010000
_BASE_TAIL = "-0000-1000-8000-00805f9b34fb"


def element(kind: int, payload: bytes) -> bytes:
    """A text, sequence, alternative or url element, with the shortest length field."""
    size = len(payload)
    if size < 0x100:
        return bytes([kind << 3 | 5, size]) + payload
    if size < 0x10000:
        return bytes([kind << 3 | 6]) + struct.pack(">H", size) + payload
    return bytes([kind << 3 | 7]) + struct.pack(">I", size) + payload


def uint(value: int, size: int) -> bytes:
    index = (1, 2, 4, 8, 16).index(size)
    return bytes([UINT << 3 | index]) + value.to_bytes(size, "big")


def uuid16(value: int) -> bytes:
    return bytes([UUID << 3 | 1]) + value.to_bytes(2, "big")


def uuid_element(text: str) -> bytes:
    """A 16-bit uuid for a short class on the bluetooth base uuid, else 128-bit."""
    if text.startswith("0000") and text.endswith(_BASE_TAIL):
        return uuid16(int(text[4:8], 16))
    return bytes([UUID << 3 | 4]) + uuid.UUID(text).bytes


def text(value: str) -> bytes:
    return element(TEXT, value.encode())


def seq(*items: bytes) -> bytes:
    return element(SEQUENCE, b"".join(items))


def alt(*items: bytes) -> bytes:
    return element(ALTERNATIVE, b"".join(items))


def attribute_list(attributes: list[tuple[int, bytes]]) -> bytes:
    """One record: a sequence of (uint16 attribute id, value) pairs."""
    return seq(*(uint(attr, 2) + value for attr, value in attributes))


def encode_record(record: ServiceRecord, handle: int) -> bytes:
    stack = [seq(uuid16(L2CAP))]
    if record.channel is not None:
        stack.append(seq(uuid16(RFCOMM), uint(record.channel, 1)))
    attributes = [
        (0x0000, uint(handle, 4)),
        (0x0001, seq(*map(uuid_element, record.uuids))),
        (0x0004, seq(*stack)),
        (0x0005, seq(uuid16(PUBLIC_BROWSE_ROOT))),
    ]
    if record.name is not None:
        attributes.append((0x0100, text(record.name)))
    return attribute_list(attributes)


def encode_records(
    records: list[ServiceRecord], handles: list[int] | None = None
) -> bytes:
    """The AttributeLists a gadget sends for `records`: one sequence of records."""
    if handles is None:
        handles = [FIRST_HANDLE + i for i in range(len(records))]
    return seq(*map(encode_record, records, handles))


def response(transaction: int, piece: bytes, state: bytes) -> bytes:
    """A ServiceSearchAttributeResponse pdu (0x07)."""
    params = struct.pack(">H", len(piece)) + piece + bytes([len(state)]) + state
    return struct.pack(">BHH", 0x07, transaction, len(params)) + params


def split_responses(
    attribute_lists: bytes, chunk: int, transaction_start: int
) -> list[bytes]:
    """Responses carrying `attribute_lists` `chunk` bytes at a time, transaction ids
    counting up from `transaction_start`. Every one but the last has a continuation
    state: the 4-byte offset of the next piece."""
    starts = range(0, len(attribute_lists), chunk) or range(1)
    pdus = []
    for n, start in enumerate(starts):
        end = start + chunk
        state = struct.pack(">I", end) if end < len(attribute_lists) else b""
        pdus.append(response(transaction_start + n, attribute_lists[start:end], state))
    return pdus
