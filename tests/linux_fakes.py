"""Fakes for a classic driver's linux link, so its linux path runs with no radio.

`FakeBluez` installs fake `dbus_fast` modules whose bluez answers GetManagedObjects;
`SdpServer` is the l2cap socket to a gadget's sdp server, answering from
`sdp_fixtures.encode_records`; `Peer` is the gadget's end of a socketpair that
stands in for the rfcomm channel. `Rig` puts them behind a loaded driver's
`linux_new_socket`, `linux_libc_connect` and `linux_kernel_has_bluetooth` seams.
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import enum
import socket
import struct
import symtable
import sys
import threading
import time
import types
import uuid

from sdp_fixtures import encode_records, response

ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"


def names_needed(block: str, source: str) -> set[str]:
    """The global names the code in `block` uses that `source`, the driver around it,
    never binds at its top level (and python does not have built in)."""
    used = set()
    tables = [symtable.symtable(block, "block", "exec")]
    while tables:
        table = tables.pop()
        top = table.get_type() == "module"
        used |= {
            symbol.get_name()
            for symbol in table.get_symbols()
            if symbol.is_referenced() and (top or symbol.is_global())
        }
        tables += table.get_children()
    driver = symtable.symtable(source, "driver", "exec")
    bound = {
        symbol.get_name()
        for symbol in driver.get_symbols()
        if symbol.is_assigned() or symbol.is_imported()
    }
    return used - bound - set(dir(builtins))


class Variant:
    """Like dbus_fast's Variant: the value is in `.value`."""

    def __init__(self, value):
        self.value = value


def device(
    address,
    *,
    alias=None,
    name=None,
    uuids=(),
    paired=True,
    connected=False,
    kind="public",
):
    """One bluez device object, its address printed the way bluez prints it."""
    props = {
        "Address": Variant(address.upper()),
        "AddressType": Variant(kind),
        "Paired": Variant(paired),
        "Connected": Variant(connected),
        "UUIDs": Variant([u.upper() for u in uuids]),
    }
    if alias is not None:
        props["Alias"] = Variant(alias)
    if name is not None:
        props["Name"] = Variant(name)
    path = "/org/bluez/hci0/dev_" + address.upper().replace(":", "_")
    return path, {DEVICE: props}


def bluez(*devices, powered=(True,)):
    """A GetManagedObjects result: one adapter per `powered` entry, then `devices`."""
    objects = {"/org/bluez": {"org.bluez.AgentManager1": {}}}
    for i, on in enumerate(powered):
        objects[f"/org/bluez/hci{i}"] = {ADAPTER: {"Powered": Variant(on)}}
    objects.update(devices)
    return objects


class FakeBluez:
    """bluez on a fake system bus. GetManagedObjects answers `objects`, or the d-bus
    error named `error`, after `delay` seconds; `connect_error` is raised by the
    bus's connect."""

    def __init__(self, objects=None, *, error=None, connect_error=None, delay=0.0):
        self.objects = bluez() if objects is None else objects
        self.error = error
        self.connect_error = connect_error
        self.delay = delay
        self.calls = []
        self.disconnects = 0

    def install(self, monkeypatch):
        fake = self

        class BusType(enum.Enum):
            SESSION = 0
            SYSTEM = 1

        class MessageType(enum.Enum):
            METHOD_RETURN = 2
            ERROR = 3

        class Message:
            def __init__(self, **fields):
                self.fields = fields

        class MessageBus:
            def __init__(self, bus_type=BusType.SESSION):
                assert bus_type is BusType.SYSTEM

            async def connect(self):
                if fake.connect_error is not None:
                    raise fake.connect_error
                return self

            async def call(self, message):
                fake.calls.append(message.fields)
                await asyncio.sleep(fake.delay)
                if fake.error is not None:
                    return types.SimpleNamespace(
                        message_type=MessageType.ERROR,
                        error_name=fake.error,
                        body=["nope"],
                    )
                return types.SimpleNamespace(
                    message_type=MessageType.METHOD_RETURN,
                    error_name=None,
                    body=[fake.objects],
                )

            def disconnect(self):
                fake.disconnects += 1

            async def wait_for_disconnect(self):
                return None

        top = types.ModuleType("dbus_fast")
        top.BusType, top.Message, top.MessageType = BusType, Message, MessageType
        aio = types.ModuleType("dbus_fast.aio")
        aio.MessageBus = MessageBus
        top.aio = aio
        monkeypatch.setitem(sys.modules, "dbus_fast", top)
        monkeypatch.setitem(sys.modules, "dbus_fast.aio", aio)
        return self


class SdpServer:
    """The l2cap socket to a gadget's sdp server. Each ServiceSearchAttributeRequest
    gets the records that list the uuid searched for, `chunk` bytes of them per pdu
    with a continuation state for the rest. `recv_error` is raised by recv."""

    def __init__(self, records, chunk=4096, recv_error=None):
        self.records = records
        self.chunk = chunk
        self.recv_error = recv_error
        self.requests = []
        self.replies = []
        self.closed = False

    def setblocking(self, flag):
        pass

    def settimeout(self, seconds):
        pass

    def fileno(self):
        return -1

    def send(self, pdu):
        self.requests.append(pdu)
        # the search pattern is one 128-bit uuid; only attribute 4 is asked for
        assert pdu[:1] == b"\x06" and pdu[5:8] == b"\x35\x11\x1c", pdu.hex()
        assert pdu[24:31] == bytes.fromhex("ffff 3503 090004"), pdu.hex()
        state = pdu[32:]
        assert pdu[3:5] == struct.pack(">H", len(pdu) - 5) and pdu[31] == len(state)
        wanted = str(uuid.UUID(bytes=pdu[8:24]))
        lists = encode_records([r for r in self.records if wanted in r.uuids])
        start = int.from_bytes(state, "big")
        end = start + self.chunk
        state = struct.pack(">I", end) if end < len(lists) else b""
        transaction = int.from_bytes(pdu[1:3], "big")
        self.replies.append(response(transaction, lists[start:end], state))
        return len(pdu)

    def recv(self, size):
        if self.recv_error is not None:
            raise self.recv_error
        return self.replies.pop(0)

    def close(self):
        self.closed = True


class Peer:
    """The gadget's end of the rfcomm channel. `answer` is given each piece read
    and returns what to send back, which goes out `piece` bytes at a time, as rfcomm
    hands a long message over in several frames."""

    def __init__(self, sock, answer, piece=5):
        self.sock = sock
        self.answer = answer
        self.piece = piece
        self.received = bytearray()
        self.hung_up = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(10)
        with contextlib.suppress(OSError), self.sock:
            while data := self.sock.recv(4096):
                self.received += data
                reply = self.answer(data)
                for start in range(0, len(reply), self.piece):
                    self.sock.sendall(reply[start : start + self.piece])
                    time.sleep(0.01)
        self.hung_up.set()


class Rig:
    """A driver's linux link wired to fakes: bluez `objects` on a fake d-bus, an sdp
    server with `records`, and a socketpair for rfcomm whose far end is a `Peer`
    once `serve` is called. `connects` keeps each sockaddr the driver packed. The
    kernel has bluetooth unless `kernel_bluetooth` is set False; `probes` counts the
    times the driver asked."""

    def __init__(self, driver, monkeypatch, objects, records, *, chunk=4096):
        monkeypatch.setattr(sys, "platform", "linux")
        self.bluez = FakeBluez(objects).install(monkeypatch)
        self.sdp = SdpServer(records, chunk=chunk)
        self.ours, self.theirs = socket.socketpair()
        self.connects = []
        self.peer = None
        self.kernel_bluetooth = True
        self.probes = 0
        monkeypatch.setattr(driver, "linux_new_socket", self.new_socket)
        monkeypatch.setattr(driver, "linux_libc_connect", self.libc_connect)
        monkeypatch.setattr(driver, "linux_kernel_has_bluetooth", self.has_bluetooth)

    def has_bluetooth(self):
        self.probes += 1
        return self.kernel_bluetooth

    def new_socket(self, kind, proto):
        if proto == 0:  # l2cap, for sdp
            assert kind == socket.SOCK_SEQPACKET
            return self.sdp
        assert (kind, proto) == (socket.SOCK_STREAM, 3)
        return self.ours

    def libc_connect(self, fd, addr):
        self.connects.append(addr)
        return 0

    def serve(self, answer, piece=5):
        self.peer = Peer(self.theirs, answer, piece)
        return self.peer

    def close(self):
        self.ours.close()
        self.theirs.close()
