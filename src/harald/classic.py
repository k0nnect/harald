"""Bluetooth classic (rfcomm): channel rules, and arm-gated sessions over a backend.

The rules are pure functions over the gadget's service records, as a backend reads
them over sdp. A channel is protected if any record on it lists a standard profile
(hands-free, headset, obex, iap2 and the like); harald never opens one. A channel is
firmware-update class if any record on it lists a `DFU_UUIDS` member, so writes to it
need `harald arm --allow-dfu`, as for ble.

The async api (`paired_devices`, `services`, `send`, `listen`) runs a synchronous
`Backend` through `asyncio.to_thread`. Every `send` message spends one arm write. A
`BackendError` never leaves this module: it becomes a `HaraldError` with a hint,
worded for the platform by `harald.hints`.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import re
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Protocol

from harald import hints

# normalize_uuid is re-exported: classic.normalize_uuid is the same function the
# write gate uses, so classification here and the firmware-update check agree.
from harald.arm import (
    DFU_UUIDS,
    MAC_ADDRESS,
    check_write,
    consume_write,
    device_key,
    live_grant,
    normalize_uuid,
)
from harald.errors import (
    BluetoothUnavailable,
    DeviceNotFound,
    HaraldError,
    ProtectedChannel,
    WriteDenied,
)

_NUMBER = re.compile(r"[0-9]+|0x[0-9a-f]+")
_CHANNELS = range(1, 31)  # rfcomm server channels
MAX_LISTEN = 30.0  # seconds: the most one send's `listen` or one listen may wait

_PROTECTED_SHORT = (
    "1103",  # dial-up networking
    "1105",  # obex object push
    "1106",  # obex file transfer
    "1108",  # headset
    "1112",  # headset audio gateway
    "111e",  # hands-free
    "111f",  # hands-free audio gateway
    "112d",  # sim access
    "112f",  # phonebook access server (pse)
    "1130",  # phonebook access
    "1131",  # headset hs
    "1132",  # message access server
    "1133",  # message notification server
    "1134",  # message access profile
)
PROTECTED_CLASSES: frozenset[str] = frozenset(
    {normalize_uuid(short) for short in _PROTECTED_SHORT}
    | {"00000000-deca-fade-deca-deafdecacaff"}  # apple iap2
)


@dataclass
class ClassicDevice:
    address: str
    name: str | None
    connected: bool


@dataclass
class ServiceRecord:
    name: str | None
    uuids: list[str]
    channel: int | None  # rfcomm server channel; None if rfcomm can't reach it
    protected: bool = False
    firmware_update: bool = False


@dataclass
class Target:
    channel: int
    service_uuid: str  # what the write gate judges: a DFU_UUIDS member if there is one
    firmware_update: bool


def normalize_address(text: str) -> str:
    """Lowercase colon form of a classic (mac) address; hyphens are accepted."""
    address = text.strip()
    if not MAC_ADDRESS.fullmatch(address):
        raise HaraldError(
            f"not a bluetooth classic address: {text!r}",
            hint="use the address harald classic devices shows, e.g. aa:bb:cc:11:22:33",
        )
    return device_key(address)


def mark(records: list[ServiceRecord]) -> list[ServiceRecord]:
    """Return copies of `records` with `protected` and `firmware_update` set.

    The flags belong to the channel: if any record on a channel lists a protected (or
    firmware-update) uuid, every record on that channel gets the flag. A record with
    no channel is judged on its own uuids.
    """
    on_channel: dict[int, set[str]] = {}
    for record in records:
        if record.channel is not None:
            on_channel.setdefault(record.channel, set()).update(_classes(record))
    marked = []
    for record in records:
        if record.channel is None:
            classes = set(_classes(record))
        else:
            classes = on_channel[record.channel]
        marked.append(
            replace(
                record,
                uuids=list(record.uuids),
                protected=bool(classes & PROTECTED_CLASSES),
                firmware_update=bool(classes & DFU_UUIDS),
            )
        )
    return marked


def resolve(records: list[ServiceRecord], service: str, address: str) -> Target:
    """Find the channel `service` names on `address`; refuse ones harald must not open.

    `service` is a channel number (decimal, or 0x hex) from 1 to 30, or else a
    service-class uuid in any form, so "1101" is the spp uuid, not channel 1101.
    """
    refresh = f"run: harald classic services {address} --refresh"
    marked = mark(records)
    named = None
    channel = _channel_number(service)
    if channel is None:
        named = normalize_uuid(service)
        channels = sorted(
            {
                r.channel
                for r in marked
                if r.channel is not None and named in _classes(r)
            }
        )
        if not channels:
            raise HaraldError(f"service {named} not found on {address}", hint=refresh)
        if len(channels) > 1:
            raise HaraldError(
                f"service {named} is on more than one channel of {address}",
                hint="name the channel number instead",
            )
        channel = channels[0]

    on_channel = [r for r in marked if r.channel == channel]
    if not on_channel:
        raise HaraldError(
            f"channel {channel} is not in {address}'s service records", hint=refresh
        )
    if on_channel[0].protected:
        raise ProtectedChannel(
            f"channel {channel} on {address} is a standard profile",
            hint="harald only talks to vendor and serial-port channels; "
            "pick another from: harald classic services " + address,
        )
    classes = [uuid for r in on_channel for uuid in _classes(r)]
    if not classes:
        # nothing to judge the channel by, so fail closed
        raise HaraldError(
            f"channel {channel} on {address} lists no service class", hint=refresh
        )
    firmware = [uuid for uuid in classes if uuid in DFU_UUIDS]
    return Target(
        channel=channel,
        service_uuid=firmware[0] if firmware else named or classes[0],
        firmware_update=on_channel[0].firmware_update,
    )


def _classes(record: ServiceRecord) -> list[str]:
    return [normalize_uuid(uuid) for uuid in record.uuids]


def _channel_number(service: str) -> int | None:
    """The rfcomm channel `service` names, or None if it is not a number from 1-30."""
    text = service.strip().lower()
    if not _NUMBER.fullmatch(text):
        return None
    number = int(text, 16) if text.startswith("0x") else int(text)
    return number if number in _CHANNELS else None


class BackendError(Exception):
    """A backend failure, by code. `classic` maps each code to a HaraldError with a hint.

    Codes: unsupported, bluetooth_off, permission, not_paired, pairing, not_connected,
    stuck, busy, timeout, failed.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class Channel(Protocol):
    """An open rfcomm channel. Calls block; `classic` runs them off the event loop.

    `close` may be called from another thread while `write` or `drain` is blocked
    (when the caller is cancelled), and must make them return promptly.
    """

    def write(self, data: bytes) -> None: ...

    def drain(self, seconds: float) -> list[tuple[float, bytes]]:
        """Wait `seconds`, then return `(time.monotonic() at arrival, data)` for
        everything received since the open or the last drain."""
        ...

    def close(self) -> None: ...


class Backend(Protocol):
    def paired(self) -> list[ClassicDevice]: ...

    def records(self, address: str, refresh: bool) -> list[ServiceRecord]: ...

    def open(self, address: str, channel: int) -> Channel:
        """Open `channel` on `address`, bringing the link up first if needed."""
        ...


@dataclass
class Chunk:
    after: int  # the 1-based message number this followed; 0 = before any
    seconds: float  # since the channel opened
    data: bytes


@dataclass
class SendResult:
    sent: int
    writes_left: int
    chunks: list[Chunk]
    stopped: str = ""  # why sending stopped early, if it did


_backend: Backend | None = None


def default_backend() -> Backend:
    """This platform's backend, made once per process: IOBluetooth on a mac, bluez
    and kernel sockets on linux; anywhere else, BackendError("unsupported")."""
    global _backend
    if sys.platform not in ("darwin", "linux"):
        raise BackendError("unsupported")
    if _backend is None:
        # pyobjc is only imported on a mac, dbus-fast only on linux
        if sys.platform == "darwin":
            from harald.classic_mac import MacBackend

            _backend = MacBackend()
        else:
            from harald.classic_linux import LinuxBackend

            _backend = LinuxBackend()
    return _backend


async def paired_devices(*, backend: Backend | None = None) -> list[ClassicDevice]:
    with _backend_errors(""):
        return await asyncio.to_thread(_chosen(backend).paired)


async def services(
    address: str, *, refresh: bool = False, backend: Backend | None = None
) -> list[ServiceRecord]:
    """The device's service records, marked protected and firmware-update."""
    address = normalize_address(address)
    with _backend_errors(address):
        records = await asyncio.to_thread(_chosen(backend).records, address, refresh)
    return mark(records)


async def send(
    address: str,
    service: str,
    messages: list[bytes],
    listen: float = 2.0,
    *,
    backend: Backend | None = None,
) -> SendResult:
    """Write each message to the channel `service` names, listening `listen` seconds
    (0 to MAX_LISTEN) after each. Every message spends one arm write; if the budget
    runs out partway, the result keeps what was sent and received, with `stopped`
    saying why. Bad input (no message, an empty one, a bad `listen`) is refused
    before anything is opened or spent."""
    address = normalize_address(address)
    if not messages:
        raise HaraldError("nothing to send", hint="pass at least one hex message")
    if not all(messages):
        raise HaraldError(
            "empty message", hint="each message needs at least one byte of hex"
        )
    _check_seconds(listen, "listen")
    grant = check_write(address, live_grant(address))  # before touching the backend
    backend = _chosen(backend)
    target = await _target(backend, address, service)
    # consume_write's own firmware-update check, run before anything is opened
    check_write(address, grant, target.service_uuid)

    channel = await _open(backend, address, target)
    start = time.monotonic()
    chunks: list[Chunk] = []
    sent = writes_left = 0
    stopped = ""
    try:
        with _backend_errors(address, target.channel):
            chunks += _chunks(await asyncio.to_thread(channel.drain, 0.0), 0, start)
        for i, message in enumerate(messages, start=1):
            try:
                grant = consume_write(
                    address, target.service_uuid, f"rfcomm:{target.channel}"
                )
            except WriteDenied as exc:
                if i == 1:
                    raise
                stopped, writes_left = _reason(exc), 0
                break
            writes_left = grant.writes_left
            try:
                await asyncio.to_thread(channel.write, message)
                sent += 1
                drained = await asyncio.to_thread(channel.drain, listen)
            except BackendError as exc:
                error = _mapped(exc, address, target.channel)
                if sent == 0:
                    raise error from exc
                # keep what was sent and received; writes_left is the real budget
                stopped = _reason(error)
                break
            chunks += _chunks(drained, i, start)
    finally:
        await _close(channel)
    return SendResult(
        sent=sent, writes_left=writes_left, chunks=chunks, stopped=stopped
    )


async def listen(
    address: str, service: str, seconds: float, *, backend: Backend | None = None
) -> list[Chunk]:
    """Open the channel `service` names, send nothing, and collect `seconds` of data
    (0 to MAX_LISTEN).

    Not arm-gated, but protected channels are still refused."""
    address = normalize_address(address)
    _check_seconds(seconds, "seconds")
    backend = _chosen(backend)
    target = await _target(backend, address, service)
    channel = await _open(backend, address, target)
    start = time.monotonic()
    try:
        with _backend_errors(address, target.channel):
            drained = await asyncio.to_thread(channel.drain, seconds)
    finally:
        await _close(channel)
    return _chunks(drained, 0, start)


def _check_seconds(seconds: float, name: str) -> None:
    """Refuse a listening time that is negative, not finite or over MAX_LISTEN."""
    if not (math.isfinite(seconds) and 0 <= seconds <= MAX_LISTEN):
        raise HaraldError(
            f"{name} must be from 0 to {MAX_LISTEN:g} s, got {seconds:g}",
            hint=f"harald listens for at most {MAX_LISTEN:g} s at a time",
        )


def _chosen(backend: Backend | None) -> Backend:
    with _backend_errors(""):
        return backend if backend is not None else default_backend()


async def _target(backend: Backend, address: str, service: str) -> Target:
    """Resolve `service` against the device's cached records (refusing protected
    channels and ones not in the records) before anything is opened."""
    with _backend_errors(address):
        records = await asyncio.to_thread(backend.records, address, False)
    return resolve(records, service, address)


async def _open(backend: Backend, address: str, target: Target) -> Channel:
    """Open the target channel in a thread; if the caller is cancelled meanwhile, the
    open still finishes there, and whatever it opened is closed."""
    # a plain executor future, not a task, so nothing (loop shutdown included) can
    # cancel it and drop a channel that did open
    opening = asyncio.get_running_loop().run_in_executor(
        None, backend.open, address, target.channel
    )
    try:
        with _backend_errors(address, target.channel):
            return await asyncio.shield(opening)
    except asyncio.CancelledError:
        opening.add_done_callback(_close_when_opened)
        raise


def _close_when_opened(opening: asyncio.Future[Channel]) -> None:
    if opening.cancelled() or opening.exception() is not None:
        return
    # off the event loop: a real close can block for a moment
    threading.Thread(
        target=_close_quietly,
        args=(opening.result(),),
        name="harald-classic-close",
        daemon=True,
    ).start()


def _chunks(
    drained: list[tuple[float, bytes]], after: int, start: float
) -> list[Chunk]:
    # data can land between the open completing and `start`; call that 0 s, not < 0
    return [Chunk(after, max(0.0, at - start), data) for at, data in drained]


async def _close(channel: Channel) -> None:
    """Close the channel, even when the caller is being cancelled.

    The close is handed to a thread before the first await and shielded, so a
    cancellation (anyio's re-delivers at every await) can stop the wait but never
    the close. A failed close never replaces the result or the real error.
    """
    closing = asyncio.get_running_loop().run_in_executor(None, _close_quietly, channel)
    await asyncio.shield(closing)


def _close_quietly(channel: Channel) -> None:
    with contextlib.suppress(BackendError, OSError):
        channel.close()


def _reason(error: HaraldError) -> str:
    """`SendResult.stopped`: the error's message and its hint."""
    return f"{error.message}; {error.hint}" if error.hint else error.message


@contextlib.contextmanager
def _backend_errors(address: str, channel: int | None = None) -> Iterator[None]:
    """Turn a BackendError into the HaraldError (with a hint) the user should see."""
    try:
        yield
    except BackendError as exc:
        raise _mapped(exc, address, channel) from exc


def _mapped(exc: BackendError, address: str, channel: int | None) -> HaraldError:
    code = exc.code
    if code == "unsupported":
        message, hint = hints.unsupported_classic()
        return HaraldError(message, hint=hint)
    if code == "bluetooth_off":
        return BluetoothUnavailable(
            hints.bluetooth_off_message(), hint=hints.bluetooth_off()
        )
    if code == "permission":
        return BluetoothUnavailable(
            "permission denied for bluetooth", hint=hints.permission()
        )
    if code == "not_paired":
        return DeviceNotFound(
            f"{address} is not paired with {hints.here()}", hint=hints.pair(address)
        )
    if code == "pairing":
        return DeviceNotFound(
            f"{address} rejected {hints.here()}'s pairing key",
            hint=hints.repair(address),
        )
    if code == "not_connected":
        return DeviceNotFound(f"{address} is not connected", hint=hints.connect())
    if code == "stuck":
        return HaraldError(
            f"{hints.machine()} would not open a channel to {address}",
            hint=hints.stuck(),
        )
    if code == "busy":  # with no channel, the sdp query's connect was busy
        busy = address if channel is None else f"channel {channel} on {address}"
        return HaraldError(
            f"{busy} is busy",
            hint="close the vendor app on your phone, "
            "or turn the phone's bluetooth off",
        )
    if code == "timeout":
        return HaraldError(f"{address} stopped answering", hint=hints.timeout())
    # "failed", and any code this module does not know
    return HaraldError(f"bluetooth error: {exc.detail or code}")
