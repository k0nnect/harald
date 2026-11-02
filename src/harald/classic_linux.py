"""Linux's bluetooth classic backend: bluez for pairings, kernel sockets for the rest.

Pairing belongs to bluez, so `paired` asks bluetoothd over the system d-bus with
dbus-fast. dbus-fast is a linux-only dependency, so it is imported only when that call
runs. `classic` calls the backend from executor threads, where no event loop runs, so
each call makes its own short one there with `asyncio.run`. When bluez is out of reach
(no system bus, no bluetoothd on it, or no adapter), the kernel is asked whether it has
bluetooth at all: a container or wsl may not, and no bluetoothd could fix that.

Everything else goes around bluez: service records come from harald's own sdp client
(`harald.sdp`) and a channel is an rfcomm socket from `harald.btsock`, which work on
pythons built without `socket.AF_BLUETOOTH`. `records` and `open` first check that
bluez has the address paired, so an unpaired gadget gets the pairing hint, not an sdp
query or a connect that fails less clearly.

A `LinuxChannel` keeps everything the gadget sends from the moment it opens: a reader
thread stamps each recv with `time.monotonic()`, and `drain` hands over what it kept.
rfcomm delivers a long reply in frames of about 1000 bytes, so one message may come
back as several chunks. `close` wakes a waiting `drain`, and shuts the socket down
before closing it, which wakes a blocked `write` and the reader in whatever thread.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

from harald import bluez, btsock, sdp
from harald.classic import BackendError, ClassicDevice, ServiceRecord

CONNECT_TIMEOUT = 15.0  # seconds, for an rfcomm connect
WRITE_TIMEOUT = 10.0  # for one write's sendall
DBUS_TIMEOUT = 10.0  # for bluez's answer, connect included
CLOSE_WAIT = 1.0  # for the reader thread to stop after a close
RECV_SIZE = 4096

_ADAPTER = "org.bluez.Adapter1"
_DEVICE = "org.bluez.Device1"
_CLOSED = "the channel is closed"

Objects = dict[str, dict[str, dict[str, Any]]]  # path -> interface -> property


def bluez_paired(objects: Objects) -> list[ClassicDevice]:
    """The paired devices in a bluez `GetManagedObjects` result, sorted by address.

    A device on an le random address is skipped: it cannot be bluetooth classic. A
    nameless device's Alias, which bluez makes its address with dashes, is no name.
    Property values may be dbus-fast `Variant`s or plain values. With no adapter, or
    none powered, there is no bluetooth to use: BackendError("bluetooth_off").
    """
    adapters = [ifaces[_ADAPTER] for ifaces in objects.values() if _ADAPTER in ifaces]
    if not adapters:
        raise BackendError("bluetooth_off", "no bluetooth adapter")
    if not any(_value(adapter, "Powered") for adapter in adapters):
        raise BackendError("bluetooth_off", "the bluetooth adapter is off")
    devices = []
    for interfaces in objects.values():
        props = interfaces.get(_DEVICE, {})
        address = str(_value(props, "Address") or "").lower()
        if not (address and _value(props, "Paired")):
            continue
        if _value(props, "AddressType") == "random":  # le only: never br/edr
            continue
        alias, name = _value(props, "Alias"), _value(props, "Name")
        if name is None and str(alias).lower() == address.replace(":", "-"):
            alias = None  # bluez's stand-in for a device with no name
        name = alias or name
        devices.append(
            ClassicDevice(
                address=address,
                name=str(name) if name else None,
                connected=bool(_value(props, "Connected")),
            )
        )
    return sorted(devices, key=lambda device: device.address)


def _value(props: dict[str, Any], key: str) -> Any:
    value = props.get(key)
    return getattr(value, "value", value)  # a dbus-fast Variant holds it in .value


def bluez_objects() -> Objects:
    """bluez's `GetManagedObjects`, asked over the system bus in a private event loop.

    Raises what dbus-fast does: a DBusError for an error reply, a FileNotFoundError or
    ConnectionRefusedError when there is no system bus. `LinuxBackend.paired` turns
    them into BackendErrors.
    """
    try:
        from dbus_fast import BusType, DBusError, Message, MessageType
        from dbus_fast.aio import MessageBus
    except ImportError:
        raise BackendError(
            "failed", "dbus-fast is missing: uv tool install --reinstall harald"
        ) from None

    async def ask() -> Objects:
        bus = MessageBus(bus_type=BusType.SYSTEM)
        connected = False
        try:
            await bus.connect()
            connected = True
            reply = await bus.call(
                Message(
                    destination="org.bluez",
                    path="/",
                    interface="org.freedesktop.DBus.ObjectManager",
                    member="GetManagedObjects",
                )
            )
        finally:
            bus.disconnect()
            if connected:  # the bus closes its socket once it sees the disconnect
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(bus.wait_for_disconnect(), CLOSE_WAIT)
        if reply.message_type == MessageType.ERROR:
            text = str(reply.body[0]) if reply.body else ""
            raise DBusError(
                reply.error_name or "org.freedesktop.DBus.Error.Failed", text
            )
        return reply.body[0]

    return asyncio.run(asyncio.wait_for(ask(), DBUS_TIMEOUT))


def _dbus_error(exc: Exception) -> BackendError:
    """The BackendError for a failed bluez call. dbus-fast's DBusError carries the
    d-bus error's name in `type`; no system bus at all is a FileNotFoundError (no
    socket) or ConnectionRefusedError (no one on it). `bluetooth_off` here always
    means bluez is out of reach."""
    name = getattr(exc, "type", "")
    if not isinstance(name, str):
        name = ""
    if bluez.not_running(name):
        return BackendError("bluetooth_off", "bluetoothd is not running")
    if name == bluez.ACCESS_DENIED:
        return BackendError("permission", "d-bus denied access to bluez")
    if isinstance(exc, PermissionError):
        return BackendError("permission", "no access to the system bus")
    if isinstance(exc, TimeoutError):  # before OSError, its base
        return BackendError("failed", f"bluez did not answer in {DBUS_TIMEOUT:g} s")
    if isinstance(exc, (FileNotFoundError, ConnectionRefusedError)):
        return BackendError("bluetooth_off", "no system bus")
    if isinstance(exc, OSError):
        return BackendError("failed", (exc.strerror or str(exc)).lower())
    detail = str(exc) or type(exc).__name__
    return BackendError("failed", f"bluez: {name}: {detail}" if name else detail)


class LinuxBackend:
    """`classic.Backend` over bluez and kernel sockets. Constructing it starts
    nothing and imports nothing linux-only; the parts are injectable for tests."""

    def __init__(
        self,
        *,
        managed_objects: Callable[[], Objects] | None = None,
        sdp_query: Callable[[str], list[ServiceRecord]] = sdp.query,
        connect: Callable[..., socket.socket] = btsock.connect_rfcomm,
        kernel_has_bluetooth: Callable[[], bool] = btsock.kernel_has_bluetooth,
    ) -> None:
        self._managed_objects = managed_objects or bluez_objects
        self._sdp_query = sdp_query
        self._connect = connect
        self._kernel_has_bluetooth = kernel_has_bluetooth
        self._records: dict[str, list[ServiceRecord]] = {}

    def paired(self) -> list[ClassicDevice]:
        try:
            objects = self._managed_objects()
        except BackendError:
            raise
        except Exception as exc:  # noqa: BLE001 - a hint, never a traceback
            error = _dbus_error(exc)
            if error.code == "bluetooth_off":  # no system bus, or no bluetoothd on it
                error = self._out_of_reach(error)
            raise error from None
        if not any(_ADAPTER in interfaces for interfaces in objects.values()):
            no_adapter = BackendError("bluetooth_off", "no bluetooth adapter")
            raise self._out_of_reach(no_adapter)
        return bluez_paired(objects)

    def _out_of_reach(self, error: BackendError) -> BackendError:
        """`error`, for a bluez out of reach, unless the kernel has no bluetooth at
        all (a container, wsl): then it is `unsupported`, which no bluetoothd fixes."""
        if self._kernel_has_bluetooth():
            return error
        return BackendError("unsupported", btsock.NO_KERNEL_BLUETOOTH)

    def records(self, address: str, refresh: bool) -> list[ServiceRecord]:
        """The gadget's records over sdp, cached per process until `refresh`."""
        self._check_paired(address)
        records = None if refresh else self._records.get(address)
        if records is None:
            records = self._records[address] = self._sdp_query(address)
        return list(records)

    def open(self, address: str, channel: int) -> LinuxChannel:
        self._check_paired(address)
        sock = self._connect(address, channel, timeout=CONNECT_TIMEOUT)
        try:
            return LinuxChannel(sock)
        except BaseException:
            sock.close()
            raise

    def _check_paired(self, address: str) -> None:
        if all(device.address != address for device in self.paired()):
            raise BackendError("not_paired", address)


class LinuxChannel:
    """`classic.Channel` over a connected rfcomm socket."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        # one timeout for the socket's life, so the reader's recv and a write's
        # sendall never change it under each other; an idle reader just reads again
        sock.settimeout(WRITE_TIMEOUT)
        self._changed = threading.Condition()
        self._received: list[tuple[float, bytes]] = []
        self._closing = False
        self._ended = False  # the gadget hung up, or the socket failed
        self._reader = threading.Thread(
            target=self._read, name="harald-rfcomm-reader", daemon=True
        )
        self._reader.start()

    def write(self, data: bytes) -> None:
        if self._closing or self._ended:
            raise BackendError("failed", _CLOSED)
        try:
            self._sock.sendall(data)
        except TimeoutError:
            raise BackendError(
                "timeout", f"a write took over {WRITE_TIMEOUT:g} s"
            ) from None
        except OSError as exc:
            if self._closing:
                raise BackendError("failed", _CLOSED) from None
            raise BackendError(*btsock.error_code(exc.errno or 0)) from None

    def drain(self, seconds: float) -> list[tuple[float, bytes]]:
        """Wait `seconds` (less if closed meanwhile), then return what arrived."""
        deadline = time.monotonic() + seconds
        with self._changed:
            while not self._closing:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self._changed.wait(left)
            received, self._received = self._received, []
        return received

    def close(self) -> None:
        """Close the channel, waking any blocked write or drain. Never raises."""
        with self._changed:
            already, self._closing = self._closing, True
            self._changed.notify_all()
        if already:
            return
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)  # wakes a blocked recv or sendall
        self._reader.join(CLOSE_WAIT)
        with contextlib.suppress(OSError):
            self._sock.close()

    def _read(self) -> None:
        while not self._closing:
            try:
                data = self._sock.recv(RECV_SIZE)
            except TimeoutError:
                continue
            except OSError:
                break
            if not data:
                break  # the gadget hung up
            arrived = (time.monotonic(), data)
            with self._changed:
                self._received.append(arrived)
        self._ended = True
