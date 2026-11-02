"""harald.classic_linux: the linux backend, tested with no radio and no d-bus.

bluez's objects, the sdp query and the rfcomm connect are injected into
`LinuxBackend`; a channel runs over `socket.socketpair()`, whose far end plays the
gadget. The default bluez call runs against fake `dbus_fast` modules, so these tests
pass on a mac (where dbus-fast is not installed) and on linux alike.
"""

import asyncio
import enum
import errno
import socket
import sys
import threading
import time
import types
from types import SimpleNamespace

import pytest
from classic_fakes import XM5_ADDRESS, XM5_RECORDS

from harald import btsock, classic, classic_linux, hints
from harald.arm import arm
from harald.classic import (
    BackendError,
    ClassicDevice,
    paired_devices,
    send,
    services,
)
from harald.classic_linux import LinuxBackend, LinuxChannel, bluez_paired
from harald.errors import BluetoothUnavailable, DeviceNotFound, HaraldError

OTHER = "aa:bb:cc:44:55:66"
M1 = bytes.fromhex("3e0c00000000020000103c")
M2 = bytes.fromhex("3e0c01000000020600163c")
M3 = bytes.fromhex("3e0d00000000020601163c")
SERVICE_UNKNOWN = "org.freedesktop.DBus.Error.ServiceUnknown"
NAME_HAS_NO_OWNER = "org.freedesktop.DBus.Error.NameHasNoOwner"
ACCESS_DENIED = "org.freedesktop.DBus.Error.AccessDenied"
# what dbus-daemon answers when it cannot activate a disabled or masked bluetoothd
NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"
UNIT_MASKED = "org.freedesktop.systemd1.UnitMasked"
SPAWN_FAILED = "org.freedesktop.DBus.Error.Spawn.ChildExited"


class Variant:
    """Like dbus_fast's Variant: the value is in `.value`."""

    def __init__(self, value):
        self.value = value


class FakeDBusError(Exception):
    """Like dbus_fast.errors.DBusError: the error's name is in `.type`."""

    def __init__(self, type_, text=""):
        super().__init__(text)
        self.type = type_
        self.text = text


def device(
    address,
    *,
    paired=True,
    connected=False,
    alias=None,
    name=None,
    address_type="public",
):
    """One bluez device object, its address printed the way bluez prints it."""
    props = {
        "Address": Variant(address.upper()),
        "AddressType": Variant(address_type),
        "Paired": Variant(paired),
        "Connected": Variant(connected),
    }
    if alias is not None:
        props["Alias"] = Variant(alias)
    if name is not None:
        props["Name"] = Variant(name)
    path = "/org/bluez/hci0/dev_" + address.upper().replace(":", "_")
    return path, {"org.bluez.Device1": props, "org.freedesktop.DBus.Properties": {}}


def bluez(*devices, powered=(True,)):
    """A GetManagedObjects result: one adapter per `powered` entry, then `devices`."""
    objects = {"/org/bluez": {"org.bluez.AgentManager1": {}}}
    for i, on in enumerate(powered):
        objects[f"/org/bluez/hci{i}"] = {
            "org.bluez.Adapter1": {
                "Address": Variant(f"AA:BB:CC:00:00:0{i}"),
                "Powered": Variant(on),
            },
        }
    objects.update(devices)
    return objects


class Parts:
    """What a LinuxBackend is given: bluez's objects (or the error getting them
    raises), an sdp query (or the error it raises), an rfcomm connect, and a kernel
    with bluetooth or without, each recording its calls."""

    def __init__(self, objects=None, sock=None, kernel_bluetooth=True, sdp_error=None):
        if objects is None:
            objects = bluez(device(XM5_ADDRESS, alias="WH-1000XM5"))
        self.objects = objects
        self.sock = sock
        self.kernel_bluetooth = kernel_bluetooth
        self.sdp_error = sdp_error
        self.dbus_calls = 0
        self.queries = []
        self.connects = []
        self.probes = 0

    def managed_objects(self):
        self.dbus_calls += 1
        if isinstance(self.objects, BaseException):
            raise self.objects
        return self.objects

    def sdp_query(self, address):
        self.queries.append(address)
        if self.sdp_error is not None:
            raise self.sdp_error
        return list(XM5_RECORDS)

    def connect(self, address, channel, *, timeout):
        self.connects.append((address, channel, timeout))
        return self.sock

    def kernel_has_bluetooth(self):
        self.probes += 1
        return self.kernel_bluetooth

    def backend(self):
        return LinuxBackend(
            managed_objects=self.managed_objects,
            sdp_query=self.sdp_query,
            connect=self.connect,
            kernel_has_bluetooth=self.kernel_has_bluetooth,
        )


class Gadget:
    """The far end of a channel: answers each read with ee + what it read, and
    hangs up after `hang_up_after` reads if that is given."""

    def __init__(self, sock, hang_up_after=None):
        self.sock = sock
        self.hang_up_after = hang_up_after
        self.reads = []
        self.eof = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(10)
        with self.sock:
            while True:
                try:
                    data = self.sock.recv(4096)
                except OSError:
                    return
                if not data:
                    self.eof.set()
                    return
                self.reads.append(data)
                self.sock.sendall(b"\xee" + data)
                if len(self.reads) == self.hang_up_after:
                    return  # leaving `with` hangs up


@pytest.fixture(autouse=True)
def no_cached_backend(monkeypatch):
    monkeypatch.setattr(classic, "_backend", None)


@pytest.fixture
def pair():
    """A connected socketpair: (harald's end, the gadget's end)."""
    ours, theirs = socket.socketpair()
    yield ours, theirs
    ours.close()
    theirs.close()


class Probe:
    """A bluetooth socket made only to be closed: notes its arguments and close."""

    def __init__(self, probed, args):
        self.probed, self.args = probed, args

    def close(self):
        self.probed.append((self.args, "closed"))


@pytest.fixture
def dbus(monkeypatch):
    """Fake dbus_fast modules, so the default bluez call runs with no d-bus, on a
    kernel with bluetooth: each bluetooth socket made goes to `probed` once closed.

    Set `reply` (made with `ok` or `error`), `connect_error` or `call_delay`; the
    buses made are in `buses`.
    """
    state = SimpleNamespace(
        buses=[], reply=None, connect_error=None, call_delay=0.0, probed=[]
    )
    monkeypatch.setattr(btsock, "_new_socket", lambda *args: Probe(state.probed, args))

    class BusType(enum.Enum):
        SESSION = 0
        SYSTEM = 1

    class MessageType(enum.Enum):
        METHOD_CALL = 1
        METHOD_RETURN = 2
        ERROR = 3

    class Message:
        def __init__(self, **fields):
            self.fields = fields

    class MessageBus:
        def __init__(self, bus_type=BusType.SESSION):
            asyncio.get_running_loop()  # dbus-fast makes its bus in a running loop
            self.bus_type = bus_type
            self.calls = []
            self.disconnected = False
            state.buses.append(self)

        async def connect(self):
            if state.connect_error is not None:
                raise state.connect_error
            return self

        async def call(self, message):
            self.calls.append(message.fields)
            await asyncio.sleep(state.call_delay)
            return state.reply

        def disconnect(self):
            self.disconnected = True

        async def wait_for_disconnect(self):
            return None

    top = types.ModuleType("dbus_fast")
    top.BusType = BusType
    top.Message = Message
    top.MessageType = MessageType
    top.DBusError = FakeDBusError
    aio = types.ModuleType("dbus_fast.aio")
    aio.MessageBus = MessageBus
    top.aio = aio
    monkeypatch.setitem(sys.modules, "dbus_fast", top)
    monkeypatch.setitem(sys.modules, "dbus_fast.aio", aio)
    state.system = BusType.SYSTEM
    state.ok = lambda objects: SimpleNamespace(
        message_type=MessageType.METHOD_RETURN, body=[objects], error_name=None
    )
    state.error = lambda name, text: SimpleNamespace(
        message_type=MessageType.ERROR, body=[text], error_name=name
    )
    return state


def readers():
    """Channel reader threads still running."""
    return [t for t in threading.enumerate() if t.name == "harald-rfcomm-reader"]


def joined(drained):
    return b"".join(data for _, data in drained)


def after(chunks, message):
    """Everything that arrived after message number `message`, in one piece."""
    return b"".join(chunk.data for chunk in chunks if chunk.after == message)


async def eventually(condition, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition never came true"
        await asyncio.sleep(0.005)


# --- bluez's paired devices --------------------------------------------------


def test_bluez_paired_keeps_paired_devices_sorted_by_address():
    objects = bluez(
        device(OTHER, alias="Speaker", name="SPK-1", connected=True),
        device(XM5_ADDRESS, name="WH-1000XM5"),
        device("aa:bb:cc:77:88:99", paired=False, alias="Stranger"),
        device("aa:bb:cc:00:00:09"),  # neither alias nor name
    )
    assert bluez_paired(objects) == [
        ClassicDevice("aa:bb:cc:00:00:09", None, False),
        ClassicDevice(XM5_ADDRESS, "WH-1000XM5", False),
        ClassicDevice(OTHER, "Speaker", True),
    ]


def test_bluez_paired_skips_le_random_addresses():
    # an le random address is never a br/edr device; a public one may be
    objects = bluez(
        device(XM5_ADDRESS, name="WH-1000XM5"),
        device(OTHER, name="Tracker", address_type="random"),
        device("aa:bb:cc:77:88:99", name="Band", address_type="public"),
    )
    assert [d.address for d in bluez_paired(objects)] == [
        XM5_ADDRESS,
        "aa:bb:cc:77:88:99",
    ]


@pytest.mark.parametrize("alias", ["AA-BB-CC-11-22-33", "aa-bb-cc-11-22-33"])
def test_bluez_paired_drops_the_address_alias_of_a_nameless_device(alias):
    # with no Name, bluez makes the Alias the address with dashes; that is no name
    objects = bluez(device(XM5_ADDRESS, alias=alias))
    assert bluez_paired(objects) == [ClassicDevice(XM5_ADDRESS, None, False)]


def test_bluez_paired_keeps_an_alias_someone_set():
    objects = bluez(
        device(XM5_ADDRESS, alias="desk headphones"),
        device(OTHER, alias="AA-BB-CC-11-22-33"),  # some other device's address
    )
    assert [d.name for d in bluez_paired(objects)] == [
        "desk headphones",
        "AA-BB-CC-11-22-33",
    ]


def test_bluez_paired_reads_plain_values_too():
    objects = {
        "/org/bluez/hci0": {"org.bluez.Adapter1": {"Powered": True}},
        "/org/bluez/hci0/dev_AA_BB_CC_11_22_33": {
            "org.bluez.Device1": {
                "Address": "AA:BB:CC:11:22:33",
                "Paired": True,
                "Connected": True,
                "Name": "WH-1000XM5",
            }
        },
    }
    assert bluez_paired(objects) == [ClassicDevice(XM5_ADDRESS, "WH-1000XM5", True)]


@pytest.mark.parametrize("powered", [(), (False,), (False, False)])
def test_no_powered_adapter_is_bluetooth_off(powered):
    with pytest.raises(BackendError) as e:
        bluez_paired(bluez(device(XM5_ADDRESS), powered=powered))
    assert e.value.code == "bluetooth_off"


def test_one_powered_adapter_is_enough():
    objects = bluez(device(XM5_ADDRESS), powered=(False, True))
    assert [d.address for d in bluez_paired(objects)] == [XM5_ADDRESS]


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (FakeDBusError(SERVICE_UNKNOWN), "bluetooth_off"),  # bluetoothd not running
        (FakeDBusError(NAME_HAS_NO_OWNER), "bluetooth_off"),
        (
            FakeDBusError(NO_SUCH_UNIT, "Unit dbus-org.bluez.service not found."),
            "bluetooth_off",
        ),
        (
            FakeDBusError(UNIT_MASKED, "Unit bluetooth.service is masked."),
            "bluetooth_off",
        ),
        (FakeDBusError(SPAWN_FAILED, "Launch helper exited"), "bluetooth_off"),
        (FakeDBusError(ACCESS_DENIED), "permission"),
        (FileNotFoundError(2, "No such file or directory"), "bluetooth_off"),
        (ConnectionRefusedError(111, "Connection refused"), "bluetooth_off"),
        (PermissionError(13, "Permission denied"), "permission"),
        (FakeDBusError("org.bluez.Error.Failed", "boom"), "failed"),
        (ConnectionResetError(104, "Connection reset by peer"), "failed"),
        (OSError(5, "Input/output error"), "failed"),
    ],
)
def test_dbus_failures_map_to_codes(error, code):
    with pytest.raises(BackendError) as e:
        Parts(objects=error).backend().paired()
    assert e.value.code == code


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (
            ConnectionResetError(104, "Connection reset by peer"),
            "connection reset by peer",
        ),
        (OSError(5, "Input/output error"), "input/output error"),
        (OSError("no errno"), "no errno"),
    ],
)
def test_only_a_missing_or_refusing_bus_is_no_system_bus(error, detail):
    # any other OSError is no proof bluez is out of reach: it fails with its words
    parts = Parts(objects=error, kernel_bluetooth=False)
    with pytest.raises(BackendError) as e:
        parts.backend().paired()
    assert (e.value.code, e.value.detail) == ("failed", detail)
    assert parts.probes == 0


# bluez out of reach: no system bus, no bluetoothd on it, or no adapter
OUT_OF_REACH = [
    FileNotFoundError(2, "No such file or directory"),
    ConnectionRefusedError(111, "Connection refused"),
    FakeDBusError(SERVICE_UNKNOWN),
    FakeDBusError(NAME_HAS_NO_OWNER),
    FakeDBusError(NO_SUCH_UNIT),
    FakeDBusError(UNIT_MASKED),
    FakeDBusError(SPAWN_FAILED),
    bluez(device(XM5_ADDRESS), powered=()),
]


@pytest.mark.parametrize("objects", OUT_OF_REACH)
def test_bluez_out_of_reach_on_a_kernel_without_bluetooth_is_unsupported(objects):
    parts = Parts(objects=objects, kernel_bluetooth=False)
    with pytest.raises(BackendError) as e:
        parts.backend().paired()
    assert e.value.code == "unsupported"
    assert "kernel" in e.value.detail and "bluetooth" in e.value.detail
    assert parts.probes == 1


@pytest.mark.parametrize("objects", OUT_OF_REACH)
def test_bluez_out_of_reach_on_a_kernel_with_bluetooth_is_bluetooth_off(objects):
    parts = Parts(objects=objects, kernel_bluetooth=True)
    with pytest.raises(BackendError) as e:
        parts.backend().paired()
    assert e.value.code == "bluetooth_off"
    assert parts.probes == 1


@pytest.mark.parametrize(
    "objects",
    [
        bluez(device(XM5_ADDRESS), powered=(False,)),  # an adapter: bluetooth is off
        FakeDBusError(ACCESS_DENIED),
        PermissionError(13, "Permission denied"),
        TimeoutError(),
        FakeDBusError("org.bluez.Error.Failed", "boom"),
    ],
)
def test_bluez_in_reach_never_asks_the_kernel(objects):
    parts = Parts(objects=objects, kernel_bluetooth=False)
    with pytest.raises(BackendError) as e:
        parts.backend().paired()
    assert e.value.code != "unsupported"
    assert parts.probes == 0


@pytest.mark.usefixtures("on_linux")
@pytest.mark.parametrize("objects", OUT_OF_REACH)
async def test_a_linux_without_bluetooth_reaches_the_user_as_such(objects):
    # wsl, or a container: no bluetoothd could help, so its hint would mislead
    backend = Parts(objects=objects, kernel_bluetooth=False).backend()
    for call in (
        lambda: paired_devices(backend=backend),
        lambda: services(XM5_ADDRESS, backend=backend),
    ):
        with pytest.raises(HaraldError) as e:
            await call()
        assert (e.value.message, e.value.hint) == hints.unsupported_classic()
        assert e.value.message == "this linux has no bluetooth support"
        assert "systemctl" not in e.value.hint


@pytest.mark.usefixtures("on_linux")
@pytest.mark.parametrize(
    ("objects", "hint"),
    [
        (FakeDBusError(SERVICE_UNKNOWN), "bluetooth_off"),
        (FakeDBusError(NO_SUCH_UNIT), "bluetooth_off"),  # bluetoothd disabled
        (FakeDBusError(UNIT_MASKED), "bluetooth_off"),  # bluetoothd masked
        (FakeDBusError(SPAWN_FAILED), "bluetooth_off"),
        (FileNotFoundError(2, "No such file or directory"), "bluetooth_off"),
        (bluez(device(XM5_ADDRESS), powered=()), "bluetooth_off"),
        (bluez(device(XM5_ADDRESS), powered=(False,)), "bluetooth_off"),
        (FakeDBusError(ACCESS_DENIED), "permission"),
    ],
)
async def test_bluez_trouble_reaches_the_user_as_a_linux_hint(objects, hint):
    backend = Parts(objects=objects).backend()
    for call in (
        lambda: paired_devices(backend=backend),
        lambda: services(XM5_ADDRESS, backend=backend),
    ):
        with pytest.raises(BluetoothUnavailable) as e:
            await call()
        assert e.value.hint == getattr(hints, hint)()


# --- the default bluez call, over fake dbus_fast modules ---------------------


async def test_the_default_asks_bluez_on_the_system_bus_from_a_worker_thread(dbus):
    dbus.reply = dbus.ok(bluez(device(XM5_ADDRESS, alias="WH-1000XM5")))
    # classic runs the backend in an executor thread, where the call makes its loop
    devices = await paired_devices(backend=LinuxBackend())
    assert devices == [ClassicDevice(XM5_ADDRESS, "WH-1000XM5", False)]
    [bus] = dbus.buses
    assert bus.bus_type is dbus.system
    assert bus.calls == [
        {
            "destination": "org.bluez",
            "path": "/",
            "interface": "org.freedesktop.DBus.ObjectManager",
            "member": "GetManagedObjects",
        }
    ]
    assert bus.disconnected


@pytest.mark.parametrize(
    ("name", "code"),
    [
        (SERVICE_UNKNOWN, "bluetooth_off"),
        (NAME_HAS_NO_OWNER, "bluetooth_off"),
        (NO_SUCH_UNIT, "bluetooth_off"),
        (ACCESS_DENIED, "permission"),
    ],
)
def test_the_default_maps_an_error_reply(dbus, name, code):
    dbus.reply = dbus.error(name, "nope")
    with pytest.raises(BackendError) as e:
        LinuxBackend().paired()
    assert e.value.code == code
    assert dbus.buses[0].disconnected


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(2, "No such file or directory"),
        ConnectionRefusedError(111, "Connection refused"),
    ],
)
def test_the_default_with_no_system_bus_is_bluetooth_off(dbus, error):
    dbus.connect_error = error
    with pytest.raises(BackendError) as e:
        LinuxBackend().paired()
    assert e.value.code == "bluetooth_off"
    assert dbus.buses[0].disconnected
    # the kernel was asked with one rfcomm socket, made and closed at once
    assert dbus.probed == [((socket.SOCK_STREAM, btsock.BTPROTO_RFCOMM), "closed")]


@pytest.mark.parametrize("err", [errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT])
def test_the_default_with_no_system_bus_and_no_kernel_bluetooth(dbus, monkeypatch, err):
    dbus.connect_error = FileNotFoundError(2, "No such file or directory")

    def no_bluetooth(*args):
        raise OSError(err, "nope")

    monkeypatch.setattr(btsock, "_new_socket", no_bluetooth)
    with pytest.raises(BackendError) as e:
        LinuxBackend().paired()
    assert e.value.code == "unsupported"


def test_the_default_gives_up_on_a_bluez_that_never_answers(dbus, monkeypatch):
    monkeypatch.setattr(classic_linux, "DBUS_TIMEOUT", 0.1)
    dbus.reply = dbus.ok(bluez())
    dbus.call_delay = 5.0
    start = time.monotonic()
    with pytest.raises(BackendError) as e:
        LinuxBackend().paired()
    assert time.monotonic() - start < 2
    assert e.value.code == "failed"
    assert dbus.buses[0].disconnected


def test_without_dbus_fast_paired_fails_cleanly(monkeypatch):
    monkeypatch.setitem(sys.modules, "dbus_fast", None)
    backend = LinuxBackend()  # constructing it needs no dbus-fast
    with pytest.raises(BackendError) as e:
        backend.paired()
    assert e.value.code == "failed"
    assert "dbus-fast" in e.value.detail


# --- records and open ---------------------------------------------------------


def test_records_refuse_an_unpaired_address_without_asking_it():
    parts = Parts()
    with pytest.raises(BackendError) as e:
        parts.backend().records(OTHER, False)
    assert e.value.code == "not_paired"
    assert parts.queries == []


def test_records_are_cached_until_refreshed():
    parts = Parts()
    backend = parts.backend()
    assert backend.records(XM5_ADDRESS, False) == XM5_RECORDS
    assert backend.records(XM5_ADDRESS, False) == XM5_RECORDS
    assert parts.queries == [XM5_ADDRESS]
    assert backend.records(XM5_ADDRESS, True) == XM5_RECORDS
    assert parts.queries == [XM5_ADDRESS] * 2

    parts.objects = bluez()  # unpaired since: the cache is no way around that
    with pytest.raises(BackendError) as e:
        backend.records(XM5_ADDRESS, False)
    assert e.value.code == "not_paired"


@pytest.mark.usefixtures("on_linux")
async def test_unpaired_reaches_the_user_as_a_linux_pairing_hint():
    with pytest.raises(DeviceNotFound) as e:
        await services(OTHER, backend=Parts().backend())
    assert e.value.hint == hints.pair(OTHER)


@pytest.mark.usefixtures("on_linux")
async def test_a_busy_sdp_connect_names_the_gadget_not_a_channel():
    # the sdp query's l2cap connect is busy: there is no channel number to name
    backend = Parts(sdp_error=BackendError("busy", "device or resource busy")).backend()
    with pytest.raises(HaraldError) as e:
        await services(XM5_ADDRESS, backend=backend)
    assert e.value.message == f"{XM5_ADDRESS} is busy"
    assert "None" not in e.value.message
    on_a_channel = classic._mapped(BackendError("busy"), XM5_ADDRESS, 9)
    assert on_a_channel.message == f"channel 9 on {XM5_ADDRESS} is busy"
    assert e.value.hint == on_a_channel.hint


def test_open_refuses_an_unpaired_address_without_connecting():
    parts = Parts()
    with pytest.raises(BackendError) as e:
        parts.backend().open(OTHER, 9)
    assert e.value.code == "not_paired"
    assert parts.connects == []


def test_open_connects_rfcomm_with_a_15_second_timeout(pair):
    parts = Parts(sock=pair[0])
    channel = parts.backend().open(XM5_ADDRESS, 9)
    try:
        assert isinstance(channel, LinuxChannel)
        assert parts.connects == [(XM5_ADDRESS, 9, 15.0)]
        assert parts.dbus_calls == 1  # the pairing check
    finally:
        channel.close()


# --- LinuxChannel ---------------------------------------------------------------


def test_drain_returns_what_arrived_before_it_with_arrival_times(pair):
    ours, theirs = pair
    channel = LinuxChannel(ours)
    try:
        before = time.monotonic()
        theirs.sendall(b"hello")
        time.sleep(0.2)
        drained = channel.drain(0)
        assert joined(drained) == b"hello"
        assert all(before <= at <= time.monotonic() for at, _ in drained)
        assert channel.drain(0) == []  # a drain hands over what it returned
    finally:
        channel.close()


def test_a_long_reply_arrives_whole_and_in_order(pair):
    # rfcomm hands a long reply over in frames, so one send is not one chunk
    ours, theirs = pair
    channel = LinuxChannel(ours)
    data = bytes(range(256)) * 256
    try:
        theirs.sendall(data)
        drained = channel.drain(0.3)
    finally:
        channel.close()
    assert joined(drained) == data
    assert len(drained) > 1
    times = [at for at, _ in drained]
    assert times == sorted(times)


def test_drain_waits_its_seconds(pair):
    channel = LinuxChannel(pair[0])
    try:
        start = time.monotonic()
        assert channel.drain(0.3) == []
        assert time.monotonic() - start >= 0.3
    finally:
        channel.close()


def test_close_from_another_thread_ends_a_drain_at_once(pair):
    channel = LinuxChannel(pair[0])
    closing = threading.Timer(0.1, channel.close)
    closing.start()
    start = time.monotonic()
    channel.drain(5)
    assert time.monotonic() - start < 0.1 + 0.5
    closing.join()


def test_close_from_another_thread_ends_a_blocked_write(pair):
    channel = LinuxChannel(pair[0])  # the gadget never reads, so the write blocks
    errors = []

    def write():
        try:
            channel.write(b"x" * 10_000_000)
        except BackendError as exc:
            errors.append(exc)

    writer = threading.Thread(target=write)
    writer.start()
    time.sleep(0.2)
    assert writer.is_alive()
    start = time.monotonic()
    channel.close()
    writer.join(2)
    assert time.monotonic() - start < 0.5
    assert [e.code for e in errors] == ["failed"]


def test_a_write_the_gadget_never_takes_times_out(pair, monkeypatch):
    monkeypatch.setattr(classic_linux, "WRITE_TIMEOUT", 0.2)
    channel = LinuxChannel(pair[0])
    try:
        with pytest.raises(BackendError) as e:
            channel.write(b"x" * 10_000_000)
        assert e.value.code == "timeout"
    finally:
        channel.close()


def test_after_the_gadget_hangs_up_drain_keeps_what_came_and_write_fails(pair):
    ours, theirs = pair
    channel = LinuxChannel(ours)
    try:
        theirs.sendall(b"bye")
        theirs.close()
        assert joined(channel.drain(0.2)) == b"bye"
        with pytest.raises(BackendError) as e:
            channel.write(M1)
        assert (e.value.code, e.value.detail) == ("failed", "the channel is closed")
    finally:
        channel.close()


def test_close_twice_is_fine_and_leaves_nothing_running(pair):
    ours, _ = pair
    channel = LinuxChannel(ours)
    assert readers()
    channel.close()
    channel.close()
    assert ours.fileno() == -1
    assert readers() == []
    assert channel.drain(1) == []  # at once: the channel is closed
    with pytest.raises(BackendError) as e:
        channel.write(M1)
    assert (e.value.code, e.value.detail) == ("failed", "the channel is closed")


# --- classic.send over a LinuxBackend -------------------------------------------


async def test_send_returns_the_echoes_and_spends_a_write_per_message(pair):
    ours, theirs = pair
    gadget = Gadget(theirs)
    parts = Parts(sock=ours)
    arm(XM5_ADDRESS, writes=5)
    result = await send(XM5_ADDRESS, "9", [M1, M2], listen=0.3, backend=parts.backend())
    assert result.sent == 2
    assert result.writes_left == 3
    assert result.stopped == ""
    assert after(result.chunks, 1) == b"\xee" + M1
    assert after(result.chunks, 2) == b"\xee" + M2
    assert b"".join(gadget.reads) == M1 + M2
    assert parts.queries == [XM5_ADDRESS]
    assert parts.connects == [(XM5_ADDRESS, 9, 15.0)]
    assert gadget.eof.wait(1)  # send closed the channel
    assert ours.fileno() == -1


async def test_cancelling_send_mid_drain_closes_the_socket_within_a_second(pair):
    # review focus 1: an mcp client cancels classic_send while the channel drains
    ours, theirs = pair
    gadget = Gadget(theirs)
    backend = Parts(sock=ours).backend()
    started = []  # the seconds of each drain, as it starts
    drains = []  # (seconds, when it returned)
    opening = backend.open

    def open_watched(address, channel):
        opened = opening(address, channel)
        draining = opened.drain

        def drain(seconds):
            started.append(seconds)
            try:
                return draining(seconds)
            finally:
                drains.append((seconds, time.monotonic()))

        opened.drain = drain
        return opened

    backend.open = open_watched
    arm(XM5_ADDRESS, writes=5)
    task = asyncio.create_task(
        send(XM5_ADDRESS, "9", [M1], listen=30.0, backend=backend)
    )
    # M1 is out and send is in its 30 s drain: cancel then, not after a guessed wait
    await eventually(lambda: gadget.reads and 30.0 in started)
    cancelled = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert gadget.eof.wait(1)
    assert time.monotonic() - cancelled < 1
    assert ours.fileno() == -1
    assert readers() == []
    # the 30 s drain's thread was let go too, not left waiting out its time
    await eventually(lambda: len(drains) == 2, timeout=1)
    assert drains[1][0] == 30.0
    assert drains[1][1] - cancelled < 1


async def test_a_gadget_hanging_up_midway_keeps_what_was_sent(pair):
    # review focus 2: the gadget hangs up after message 1 of 3
    ours, theirs = pair
    gadget = Gadget(theirs, hang_up_after=1)
    arm(XM5_ADDRESS, writes=5)
    result = await send(
        XM5_ADDRESS, "9", [M1, M2, M3], listen=0.3, backend=Parts(sock=ours).backend()
    )
    assert result.sent == 1
    assert result.stopped == "bluetooth error: the channel is closed"
    assert after(result.chunks, 1) == b"\xee" + M1
    assert result.writes_left == 3  # message 2's write was spent on the attempt
    assert gadget.reads == [M1]
    assert ours.fileno() == -1


# --- dispatch -----------------------------------------------------------------


def test_default_backend_on_linux_is_one_linux_backend(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    backend = classic.default_backend()
    assert isinstance(backend, LinuxBackend)
    assert classic.default_backend() is backend

    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(BackendError) as e:
        classic.default_backend()
    assert e.value.code == "unsupported"
