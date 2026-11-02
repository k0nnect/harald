# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pyobjc-framework-IOBluetooth>=11; sys_platform == 'darwin'",
#     "dbus-fast>=2; sys_platform == 'linux'",
# ]
# ///
"""drive a sony wh-1000xm5's noise cancelling, ambient sound and battery readout.

    harald drive wh-1000xm5 status
    harald drive wh-1000xm5 anc on|off
    harald drive wh-1000xm5 ambient on|off
    harald drive wh-1000xm5 battery
    harald drive wh-1000xm5 --address aa:bb:cc:11:22:33 status

it runs on a mac or linux. the headphones must be paired with this computer and, on
a mac, connected to it. the driver opens sony's control channel over rfcomm, says one
thing, and closes it again; audio keeps playing. it only ever sends the handshake,
the noise control read (66 17) and set (68 17), the battery read (22 00) and acks.
protocol.md, next to this file, explains the bytes.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ctypes
import errno
import os
import select
import socket
import struct
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

SERVICE_UUID = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"
NAME_HINT = "WH-1000XM5"

START, END, ESC = 0x3E, 0x3C, 0x3D
DATA, ACK = 0x0C, 0x01

HANDSHAKE = bytes.fromhex("0000")  # reply 01 00, a 4-byte version, 2 flag bytes
READ_NC = bytes.fromhex("6617")  # reply 67 17 ST SW MD VF LV
BATTERY = bytes.fromhex("2200")  # reply 23 00 LV CS

HANDSHAKE_RETRY = 1.25  # seconds before the handshake is sent again
REPLY_TIMEOUT = 3.0
OPEN_TIMEOUT = 5.0
WRITE_TIMEOUT = 3.0
CLOSE_TIMEOUT = 1.0

CHARGING = {0: "not charging", 1: "charging", 2: "unknown", 3: "charged"}

BLUETOOTH_HINT = (
    "turn bluetooth on and allow your terminal app in "
    "system settings > privacy & security > bluetooth"
)
CONNECT_HINT = "turn it on and connect it to this mac in system settings > bluetooth"
STUCK_HINT = (
    "the mac's bluetooth is stuck: turn bluetooth off and on in the menu bar, "
    "then try again"
)
BUSY_HINT = "close the vendor app on your phone, or turn the phone's bluetooth off"
TIMEOUT_HINT = (
    "move closer and try again; if it keeps happening, "
    "turn the mac's bluetooth off and on"
)
USAGE_HINT = "use: anc on|off, ambient on|off, battery or status"


def timeout_hint() -> str:
    """TIMEOUT_HINT, in linux's words when the driver runs there."""
    return LINUX_TIMEOUT_HINT if sys.platform == "linux" else TIMEOUT_HINT


class DriverError(Exception):
    """A failure to print as `error: <message>` and `  hint: <hint>`, exit 2."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


# --- framing --------------------------------------------------------------------


def frame(data_type: int, seq: int, payload: bytes) -> bytes:
    """One frame: 3e, then the escaped type, seq, length, payload and checksum, then
    3c."""
    body = bytes([data_type, seq]) + len(payload).to_bytes(4, "big") + payload
    body += bytes([sum(body) & 0xFF])
    out = bytearray([START])
    for byte in body:
        if byte in (START, END, ESC):
            out += bytes([ESC, byte & 0xEF])
        else:
            out.append(byte)
    out.append(END)
    return bytes(out)


def _unframe(raw: bytes) -> tuple[int, int, bytes] | None:
    """(data type, seq, payload) from the bytes between 3e and 3c, or None if they
    are not a whole frame with the right checksum."""
    body = bytearray()
    escaped = False
    for byte in raw:
        if escaped:
            body.append(byte | 0x10)
            escaped = False
        elif byte == ESC:
            escaped = True
        else:
            body.append(byte)
    if escaped or len(body) < 7:
        return None
    length = int.from_bytes(body[2:6], "big")
    if len(body) != 7 + length or sum(body[:-1]) & 0xFF != body[-1]:
        return None
    return body[0], body[1], bytes(body[6:-1])


class Deframer:
    """Turns rfcomm chunks into frames. A frame cut between chunks (even right after
    its 3d escape byte) waits in the buffer for the rest; bytes that are not part of
    a whole checksum-valid frame are dropped."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, int, bytes]]:
        self._buffer += data
        frames = []
        while (end := self._buffer.find(END)) >= 0:
            # 3e never appears inside a frame, so the last one before the end
            # starts it; anything earlier is a frame that lost its end
            start = self._buffer.rfind(START, 0, end)
            raw = bytes(self._buffer[start + 1 : end]) if start >= 0 else None
            del self._buffer[: end + 1]
            if raw is not None and (parsed := _unframe(raw)) is not None:
                frames.append(parsed)
        start = self._buffer.find(START)
        del self._buffer[: start if start >= 0 else len(self._buffer)]
        return frames


# --- the protocol ---------------------------------------------------------------


@dataclass
class NcState:
    """Noise control: `switch` on or off; when on, `ambient` (else noise
    cancelling), with `voice` focus and ambient `level` 0-20."""

    switch: bool
    ambient: bool
    voice: bool
    level: int


class Mdr:
    """One conversation with the headphones over `link`, which has write(bytes) and
    read(seconds) -> bytes: what arrived within that time, b"" if nothing did."""

    def __init__(self, link) -> None:
        self.link = link
        self.seq = 0
        self._deframer = Deframer()

    def _exchange(
        self, payload: bytes, expect: bytes, seconds: float
    ) -> tuple[bool, bytes | None]:
        """Send `payload`, then wait up to `seconds` for its ack and for a command
        data frame starting with `expect`. Returns (acked, that frame's payload or
        None).

        Only an ack carrying 1 minus the seq sent is this frame's ack; any other is
        stale (say, the ack for a resent handshake) and ignored, so the next frame
        never goes out with an old seq that the headphones would take for a resend.
        Every data frame is acked as soon as it arrives (the headphones resend an
        unacked one every 0.75 s); frames that are not the one expected are acked
        and ignored.
        """
        sent = self.seq
        self.link.write(frame(DATA, sent, payload))
        acked, reply = False, None
        deadline = time.monotonic() + seconds
        while not (acked and reply is not None):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = self.link.read(remaining)
            if not chunk:
                break
            for data_type, seq, body in self._deframer.feed(chunk):
                if data_type == ACK:
                    if not acked and seq == 1 - sent:
                        acked, self.seq = True, seq  # the seq to use next
                    continue
                self.link.write(frame(ACK, seq ^ 1, b""))  # 1 minus a seq of 0 or 1
                if data_type == DATA and reply is None and body.startswith(expect):
                    reply = body
        if reply is not None and not acked:
            self.seq = 1 - sent  # answered, so it was taken; its ack got lost
        return acked, reply

    def _ask(self, payload: bytes, expect: bytes, size: int) -> bytes:
        _, reply = self._exchange(payload, expect, REPLY_TIMEOUT)
        if reply is None:
            raise DriverError("the headphones did not answer", hint=timeout_hint())
        if len(reply) < size:
            raise DriverError(f"the headphones sent a short reply: {reply.hex()}")
        return reply

    def handshake(self) -> None:
        for seconds in (HANDSHAKE_RETRY, REPLY_TIMEOUT):
            _, reply = self._exchange(HANDSHAKE, b"\x01", seconds)
            if reply is not None:
                return
        restart = "turn the mac's bluetooth off and on"
        if sys.platform == "linux":
            restart = "restart bluetooth with sudo systemctl restart bluetooth"
        raise DriverError(
            "the headphones did not answer the handshake",
            hint=f"close the sony app on your phone, then {restart}",
        )

    def read_nc(self) -> NcState:
        reply = self._ask(READ_NC, b"\x67\x17", 7)  # 67 17 ST SW MD VF LV
        sw, md, vf, lv = reply[3:7]
        return NcState(switch=sw == 1, ambient=md == 1, voice=vf == 1, level=lv)

    def set_nc(self, state: NcState) -> None:
        """Set noise control; the headphones ack, then announce the change (69 17)."""
        payload = bytes(
            [0x68, 0x17, 0x01, state.switch, state.ambient, state.voice, state.level]
        )
        acked, notice = self._exchange(payload, b"\x69\x17", REPLY_TIMEOUT)
        if not acked and notice is None:
            raise DriverError("the headphones did not take the setting", timeout_hint())

    def battery(self) -> tuple[int, str]:
        reply = self._ask(BATTERY, b"\x23\x00", 4)
        return reply[2], CHARGING.get(reply[3], "unknown")


# --- commands -------------------------------------------------------------------

COMMANDS = {"anc": True, "ambient": True, "battery": False, "status": False}


def parse(args: list[str]) -> tuple[str, bool | None]:
    """The command and, for anc and ambient, on (True) or off (False)."""
    if not args:
        raise DriverError("no command", hint=USAGE_HINT)
    command, rest = args[0], args[1:]
    if command not in COMMANDS:
        raise DriverError(f"unknown command: {command}", hint=USAGE_HINT)
    if not COMMANDS[command]:
        if rest:
            raise DriverError(f"{command} takes no on or off", hint=USAGE_HINT)
        return command, None
    if rest not in (["on"], ["off"]):
        raise DriverError(
            f"{command} needs on or off",
            hint=f"e.g. harald drive wh-1000xm5 {command} on",
        )
    return command, rest[0] == "on"


def describe(state: NcState) -> str:
    if not state.switch:
        return "noise control off"
    if not state.ambient:
        return "noise cancelling on"
    return f"ambient on, level {state.level}" + (", voice focus" if state.voice else "")


def run(args: list[str], link) -> str:
    """Carry out one command over `link`; return the line to print."""
    command, on = parse(args)
    mdr = Mdr(link)
    mdr.handshake()
    if command == "battery":
        level, charging = mdr.battery()
        return f"battery {level}%, {charging}"
    state = mdr.read_nc()
    if command == "status":
        return describe(state)
    if on and command == "anc":
        mdr.set_nc(NcState(switch=True, ambient=False, voice=False, level=state.level))
        return "noise cancelling on"
    if on:  # ambient on: keep the voice focus and level just read
        mdr.set_nc(NcState(True, True, state.voice, state.level))
        return "ambient on"
    mdr.set_nc(NcState(switch=False, ambient=False, voice=False, level=state.level))
    return "noise control off"


# --- the mac's rfcomm -----------------------------------------------------------

# IOBluetooth does not retain delegates, and a late callback into a freed one would
# crash, so delegates and channels live until the process ends.
_KEEP_ALIVE: list[Any] = []
_DELEGATE_CLASS: list[Any] = []

# IOReturn values (IOKit/IOReturn.h)
_IO_ERROR, _IO_BUSY, _IO_TIMEOUT = 0xE00002BC, 0xE00002D5, 0xE00002D6


def _address(text: str) -> str:
    return text.strip().lower().replace("-", ":")


def _open_error(status: int, connected: bool, name: str) -> DriverError:
    """The error for an rfcomm open that ended with IOReturn `status` (pyobjc hands
    it over signed, so it is masked to 32 bits)."""
    status &= 0xFFFFFFFF
    if status == _IO_BUSY:
        return DriverError("the control channel is busy", hint=BUSY_HINT)
    if connected and status in (_IO_ERROR, _IO_TIMEOUT):
        return DriverError("the mac would not open the control channel", STUCK_HINT)
    if not connected:
        return DriverError(f"{name} is not connected", hint=CONNECT_HINT)
    return DriverError(f"bluetooth error: open status {status:#x}")


@contextlib.contextmanager
def open_link(address: str | None) -> Iterator[Any]:
    """Open the headphones' control channel and yield a link to it; close it after.

    On linux the linux link below opens it. On a mac, IOBluetooth calls back only on
    the main thread's run loop, so this runs on the main thread and pumps that run
    loop itself while it waits.
    """
    if sys.platform == "linux":
        link = linux_open_link(address or "", NAME_HINT, SERVICE_UUID)
        try:
            yield _LinuxMdrLink(link)
        finally:
            link.close()
        return
    try:
        import IOBluetooth
        import objc
        from Foundation import NSDate, NSDefaultRunLoopMode, NSObject, NSRunLoop
    except ImportError:
        raise DriverError(
            "this driver needs macos", hint="run it on a mac with bluetooth"
        ) from None

    def pump_until(done: Callable[[], bool], seconds: float) -> bool:
        loop = NSRunLoop.currentRunLoop()
        deadline = time.monotonic() + seconds
        while not done():
            if time.monotonic() >= deadline:
                return False
            with objc.autorelease_pool():
                ran = loop.runMode_beforeDate_(
                    NSDefaultRunLoopMode, NSDate.dateWithTimeIntervalSinceNow_(0.01)
                )
            if not ran:  # nothing on the run loop yet, so it returned at once
                time.sleep(0.01)
        return True

    if not _DELEGATE_CLASS:

        class WH1000XM5Delegate(NSObject):
            """Stores what IOBluetooth reports; a python error must never unwind
            into IOBluetooth, so each callback only records."""

            def init(self):
                this = objc.super(WH1000XM5Delegate, self).init()
                if this is None:
                    return None
                this.open_status = None
                this.writes_done = 0
                this.write_status = 0
                this.closed = False
                this.received = bytearray()
                return this

            def rfcommChannelOpenComplete_status_(self, channel, status):
                self.open_status = status

            def rfcommChannelData_data_length_(self, channel, data, length):
                try:
                    self.received += bytes(data[:length])
                except (TypeError, ValueError):
                    pass

            def rfcommChannelWriteComplete_refcon_status_(
                self, channel, refcon, status
            ):
                self.write_status = status
                self.writes_done += 1

            def rfcommChannelClosed_(self, channel):
                self.closed = True

        _DELEGATE_CLASS.append(WH1000XM5Delegate)

    paired = IOBluetooth.IOBluetoothDevice.pairedDevices()
    if paired is None:
        raise DriverError(
            "bluetooth is off or not allowed for this app", BLUETOOTH_HINT
        )
    pair_hint = "pair it in system settings > bluetooth"
    for device in paired:
        if address is None:
            if str(device.name() or "").startswith(NAME_HINT):
                break
        elif _address(str(device.addressString() or "")) == _address(address):
            break
    else:
        if address is None:
            raise DriverError(f"no paired {NAME_HINT} found", hint=pair_hint)
        raise DriverError(f"no paired device at {_address(address)}", hint=pair_hint)
    name = str(device.name() or _address(str(device.addressString() or "")))
    if not device.isConnected():
        raise DriverError(f"{name} is not connected", hint=CONNECT_HINT)

    uuid = IOBluetooth.IOBluetoothSDPUUID.uuidWithBytes_length_(
        bytes.fromhex(SERVICE_UUID.replace("-", "")), 16
    )
    # the channel number comes from the mac's cached sdp record (9 on this unit)
    record = device.getServiceRecordForUUID_(uuid)
    status, channel_id = -1, None
    if record is not None:
        status, channel_id = record.getRFCOMMChannelID_(None)
    if status != 0:
        raise DriverError(
            f"{name} lists no sony control channel",
            hint="turn the headphones off and on, connect them to this mac, "
            "then try again",
        )

    delegate = _DELEGATE_CLASS[0].alloc().init()
    _KEEP_ALIVE.append(delegate)
    status, channel = device.openRFCOMMChannelAsync_withChannelID_delegate_(
        None, channel_id, delegate
    )
    if channel is not None:
        _KEEP_ALIVE.append(channel)

    def close() -> None:
        # a channel left open makes the mac refuse every later open until its
        # bluetooth is turned off and on, so this runs on every way out
        if channel is None or delegate.closed:
            return
        with contextlib.suppress(Exception):
            channel.closeChannel()
            pump_until(lambda: delegate.closed, CLOSE_TIMEOUT)

    try:
        if status != 0:
            raise _open_error(status, bool(device.isConnected()), name)
        if not pump_until(lambda: delegate.open_status is not None, OPEN_TIMEOUT):
            # the link is up and the open never finishes: the stuck-mac signature
            if device.isConnected():
                raise DriverError(
                    "the mac would not open the control channel", STUCK_HINT
                )
            raise DriverError(f"{name} is not connected", hint=CONNECT_HINT)
        if delegate.open_status != 0:
            raise _open_error(delegate.open_status, bool(device.isConnected()), name)
        yield _MacLink(channel, delegate, pump_until)
    finally:
        close()


class _MacLink:
    """write and read over an open IOBluetoothRFCOMMChannel, for Mdr."""

    def __init__(self, channel: Any, delegate: Any, pump_until: Callable) -> None:
        self._channel = channel
        self._delegate = delegate
        self._pump_until = pump_until

    def _closed(self) -> DriverError:
        return DriverError("the headphones closed the control channel", TIMEOUT_HINT)

    def write(self, data: bytes) -> None:
        delegate = self._delegate
        if delegate.closed:
            raise self._closed()
        before = delegate.writes_done
        status = self._channel.writeAsync_length_refcon_(data, len(data), None)
        if status != 0:
            raise DriverError(f"bluetooth error: write status {status & 0xFFFFFFFF:#x}")
        if not self._pump_until(
            lambda: delegate.writes_done > before or delegate.closed, WRITE_TIMEOUT
        ):
            raise DriverError("the headphones stopped answering", hint=TIMEOUT_HINT)
        if delegate.writes_done <= before:
            raise self._closed()
        if delegate.write_status != 0:
            status = delegate.write_status & 0xFFFFFFFF
            raise DriverError(f"bluetooth error: write status {status:#x}")

    def read(self, seconds: float) -> bytes:
        delegate = self._delegate
        self._pump_until(lambda: bool(delegate.received) or delegate.closed, seconds)
        data = bytes(delegate.received)
        delegate.received.clear()
        if not data and delegate.closed:
            raise self._closed()
        return data


# --- linux link: copied from harald's templates/linux_link.py.tmpl as it is ---
# on linux, bluez says over d-bus which devices are paired, the gadget's sdp server
# says which rfcomm channel its service is on, and a kernel socket opens it. uv's
# pythons lack socket.AF_BLUETOOTH, so sockets are made from the numbers and
# connected through libc. harald puts this block in every classic driver as it is;
# it uses the driver's DriverError and the stdlib modules the driver imports.

LINUX_SECONDS = 15.0  # for bluez to answer, a connect, and each sdp reply
LINUX_WRITE_SECONDS = 10.0
LINUX_RETRY_PAUSE = 0.2  # before a busy or reset connect is made again
LINUX_OFF = "bluetooth is off or bluetoothd is not running"
LINUX_OFF_HINT = (
    "turn bluetooth on with bluetoothctl power on (first rfkill unblock "
    "bluetooth if it is blocked); bluetoothd must be running: "
    "systemctl status bluetooth, and if it is disabled, "
    "sudo systemctl enable --now bluetooth"
)
LINUX_DENIED = "permission denied for bluetooth"
LINUX_PERMISSION_HINT = (
    "add yourself to the bluetooth group, then log out and back in; if harald "
    "runs in a sandbox such as snap or flatpak, run it outside"
)
LINUX_NO_KERNEL = "this linux has no bluetooth support"
LINUX_NO_KERNEL_HINT = "containers and wsl usually don't; run harald where the radio is"
LINUX_CONNECT_HINT = "turn it on, bring it close and disconnect it from your phone"
LINUX_BUSY_HINT = (
    "close the vendor app on your phone, or turn the phone's bluetooth off"
)
LINUX_TIMEOUT_HINT = (
    "move closer and try again; if it keeps happening, "
    "restart bluetooth with sudo systemctl restart bluetooth"
)
LINUX_NOT_RUNNING = (  # d-bus errors for a bluetoothd that is not running
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
    "org.freedesktop.systemd1.",  # d-bus could not start it: disabled, masked
    "org.freedesktop.DBus.Error.Spawn.",
)
LINUX_BAD_SDP = "bluetooth error: bad sdp reply"
LINUX_RFCOMM = bytes.fromhex("00000003 0000 1000 8000 00805f9b34fb")  # uuid 0x0003
# sdp data element (type, size index) -> bytes, for the fixed-size types
LINUX_SDP_SIZES = {(0, 0): 0, (3, 1): 2, (3, 2): 4, (3, 4): 16, (5, 0): 1} | {
    (kind, index): 1 << index for kind in (1, 2) for index in range(5)
}


def linux_pair_hint(address: str = "", again: bool = False) -> str:
    """How to pair `address` (with none, a gadget) with bluetoothctl, or `again`."""
    shown = address or "<address>"
    steps = (
        "bluetoothctl pairable on, bluetoothctl scan on until the gadget shows up, "
        f"then bluetoothctl pair {shown} and bluetoothctl trust {shown}"
    )
    if again:
        return f"pair it again: bluetoothctl remove {address}, then {steps}"
    return f"pair it: {steps}" if address else f"pair one: {steps}"


def linux_bluez_objects() -> dict:
    """bluez's GetManagedObjects over the system d-bus, in an event loop of its own."""
    try:
        from dbus_fast import BusType, Message, MessageType
        from dbus_fast.aio import MessageBus
    except ImportError:
        raise DriverError(
            "dbus-fast is missing",
            "run the driver with uv, which installs it: uv run driver.py --help",
        ) from None

    async def ask():
        bus = MessageBus(bus_type=BusType.SYSTEM)
        connected = False
        try:
            await bus.connect()
            connected = True
            return await bus.call(
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
                    await asyncio.wait_for(bus.wait_for_disconnect(), 1.0)

    reply = asyncio.run(asyncio.wait_for(ask(), LINUX_SECONDS))
    if reply.message_type != MessageType.ERROR:
        return reply.body[0]
    name = reply.error_name or ""
    if name.startswith(LINUX_NOT_RUNNING):
        raise linux_no_bluez()
    if name == "org.freedesktop.DBus.Error.AccessDenied":
        raise DriverError(LINUX_DENIED, LINUX_PERMISSION_HINT)
    raise DriverError(f"bluetooth error: bluez answered {name}")


def linux_kernel_has_bluetooth() -> bool:
    """False if the kernel has no bluetooth sockets at all (a container, wsl). The
    rfcomm socket made to see is closed at once; nothing goes over the radio."""
    try:
        linux_new_socket(socket.SOCK_STREAM, 3).close()
    except OSError as exc:
        return exc.errno not in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT)
    return True


def linux_no_bluez() -> DriverError:
    """bluez is out of reach (no system bus, no bluetoothd, no adapter): bluetooth
    is off, unless the kernel has no bluetooth at all, which no bluetoothd fixes."""
    if linux_kernel_has_bluetooth():
        return DriverError(LINUX_OFF, LINUX_OFF_HINT)
    return DriverError(LINUX_NO_KERNEL, LINUX_NO_KERNEL_HINT)


def linux_paired() -> list[tuple[str, str | None, list[str], bool]]:
    """(address, name, uuids, connected) of each device bluez has paired, by address,
    but for le-only ones. A nameless device's name is None, not its dashed address."""
    try:
        objects = linux_bluez_objects()
    except DriverError:
        raise
    except PermissionError:
        raise DriverError(LINUX_DENIED, LINUX_PERMISSION_HINT) from None
    except TimeoutError:
        message = f"bluetooth error: bluez did not answer in {LINUX_SECONDS:g} s"
        raise DriverError(message) from None
    except (FileNotFoundError, ConnectionRefusedError):  # no system bus
        raise linux_no_bluez() from None
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise DriverError(f"bluetooth error: {detail.lower()}") from None
    except Exception as exc:  # noqa: BLE001 - a message, never a traceback
        detail = str(exc) or type(exc).__name__
        raise DriverError(f"bluetooth error: {detail.lower()}") from None
    adapter = "org.bluez.Adapter1"
    found = [
        linux_value(i[adapter], "Powered") for i in objects.values() if adapter in i
    ]
    if not found:  # no adapter
        raise linux_no_bluez()
    if not any(found):
        raise DriverError(LINUX_OFF, LINUX_OFF_HINT)
    paired = []
    for interfaces in objects.values():
        props = interfaces.get("org.bluez.Device1", {})
        address = str(linux_value(props, "Address") or "").lower()
        if not address or not linux_value(props, "Paired"):
            continue
        if linux_value(props, "AddressType") == "random":  # le only
            continue
        alias, name = linux_value(props, "Alias"), linux_value(props, "Name")
        if name is None and str(alias).lower() == address.replace(":", "-"):
            alias = None
        name = alias or name
        uuids = [str(uuid).lower() for uuid in linux_value(props, "UUIDs") or ()]
        connected = bool(linux_value(props, "Connected"))
        paired.append((address, str(name) if name else None, uuids, connected))
    return sorted(paired, key=lambda device: device[0])


def linux_value(props: dict, key: str):
    value = props.get(key)
    return getattr(value, "value", value)  # dbus-fast hands most over in a Variant


def linux_pick(paired, address: str, name_hint: str, service_uuid: str) -> str:
    """The address to open, chosen as on a mac: `address` if bluez has it paired,
    else a device named `name_hint`*, a connected one first, else the one device
    that lists `service_uuid`, refusing more than one rather than guess."""
    if address:
        wanted = address.strip().lower().replace("-", ":")
        if all(device[0] != wanted for device in paired):
            message = f"{wanted} is not paired with this computer"
            raise DriverError(message, linux_pair_hint(wanted))
        return wanted
    if name_hint:
        first = sorted(paired, key=lambda device: not device[3])  # connected first
        matches = [a for a, name, *_ in first if (name or "").startswith(name_hint)]
        wanted = f"paired device named {name_hint}*"
    else:
        matches = [a for a, _, uuids, _ in paired if service_uuid.lower() in uuids]
        wanted = f"paired device with service {service_uuid}"
    if not matches:
        raise DriverError(f"no {wanted} found", linux_pair_hint())
    if len(matches) > 1 and not name_hint:
        found = ", ".join(matches)
        raise DriverError(
            f"more than one paired device lists service {service_uuid}: {found}",
            "pass --address with the one to use",
        )
    return matches[0]


def linux_bdaddr(address: str) -> bytes:
    """The 6-byte bdaddr_t for a printed address: the kernel keeps it reversed."""
    return bytes.fromhex(address.replace(":", "").replace("-", ""))[::-1]


def linux_sockaddr_rc(address: str, channel: int) -> bytes:
    """struct sockaddr_rc: family, bdaddr, channel, a pad byte (10 bytes)."""
    return struct.pack("<H6sBx", 31, linux_bdaddr(address), channel)


def linux_sockaddr_l2(address: str, psm: int) -> bytes:
    """struct sockaddr_l2: family, psm, bdaddr, cid 0, br/edr, a pad byte (14)."""
    return struct.pack("<HH6sHBx", 31, psm, linux_bdaddr(address), 0, 0)


def linux_new_socket(kind: int, proto: int) -> socket.socket:
    return socket.socket(31, kind, proto)  # AF_BLUETOOTH


def linux_libc_connect(fd: int, addr: bytes) -> int:
    """libc's connect(2): 0 once it is connected, else the errno it set."""
    connect = ctypes.CDLL(None, use_errno=True).connect
    connect.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
    return 0 if connect(fd, addr, len(addr)) == 0 else ctypes.get_errno()


def linux_error(err: int, address: str, what: str, connecting: bool) -> DriverError:
    """The DriverError for errno `err` from a bluetooth socket to `address`. From a
    connect, EACCES and EBADE mean the gadget has lost this computer's key."""
    if connecting and err in (errno.EACCES, getattr(errno, "EBADE", 52)):
        message = f"{address} rejected this computer's pairing key"
        return DriverError(message, linux_pair_hint(address, again=True))
    if err in (errno.EACCES, errno.EPERM):
        return DriverError(LINUX_DENIED, LINUX_PERMISSION_HINT)
    if err in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
        return DriverError(LINUX_NO_KERNEL, LINUX_NO_KERNEL_HINT)
    off = (errno.ENODEV, errno.EADDRNOTAVAIL, errno.ENETDOWN)
    if err in off or err == getattr(errno, "ERFKILL", 132):
        return DriverError(LINUX_OFF, LINUX_OFF_HINT)
    if err in (errno.EHOSTDOWN, errno.EHOSTUNREACH):
        return DriverError(f"{address} is not connected", LINUX_CONNECT_HINT)
    if err in (errno.EBUSY, errno.EADDRINUSE, errno.EALREADY):
        return DriverError(f"{what} on {address} is busy", LINUX_BUSY_HINT)
    if err == errno.ETIMEDOUT:
        return DriverError(f"{address} stopped answering", LINUX_TIMEOUT_HINT)
    if err == errno.ECONNREFUSED:
        return DriverError("bluetooth error: the gadget refused the connection")
    if err in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
        return DriverError("bluetooth error: the channel is closed")
    return DriverError(f"bluetooth error: {os.strerror(err).lower()}")


def linux_open(kind, proto, addr: bytes, timeout: float, address: str, what: str):
    """A blocking bluetooth socket connected to `addr`, in `timeout` at most. A
    connect refused as busy or reset is made once more, on a new socket: a channel
    just closed stays busy until the gadget confirms the close, and closing the last
    one ends the rfcomm session under it, resetting a connect made meanwhile."""
    deadline = time.monotonic() + timeout
    retried = False
    while True:
        try:
            sock = linux_new_socket(kind, proto)
        except OSError as exc:
            raise linux_error(exc.errno or 0, address, what, False) from None
        try:
            sock.setblocking(False)
            err = linux_libc_connect(sock.fileno(), addr)
            if err == errno.EINPROGRESS:
                err = errno.ETIMEDOUT
                left = max(deadline - time.monotonic(), 0) if retried else timeout
                if select.select([], [sock], [], left)[1]:
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err in (errno.EBUSY, errno.ECONNRESET) and not retried:
                retried = True
                sock.close()
                time.sleep(LINUX_RETRY_PAUSE)
                continue
            if err:
                raise linux_error(err, address, what, True)
            sock.setblocking(True)
            return sock
        except BaseException:
            sock.close()
            raise


def linux_connect(address: str, channel: int, timeout: float) -> socket.socket:
    """An rfcomm stream socket connected to `channel` on `address`."""
    addr, what = linux_sockaddr_rc(address, channel), f"channel {channel}"
    return linux_open(socket.SOCK_STREAM, 3, addr, timeout, address, what)


def linux_sdp_channel(address: str, service_uuid: str, timeout: float) -> int:
    """The rfcomm channel `address` lists for `service_uuid`, asked over sdp (l2cap
    psm 1) with ServiceSearchAttributeRequests for that uuid's records' attribute 4,
    the protocol list, following continuation states until the reply is whole."""
    search = b"\x35\x11\x1c" + bytes.fromhex(service_uuid.replace("-", ""))
    search += b"\xff\xff\x35\x03\x09\x00\x04"  # any size; attribute 4 only
    addr = linux_sockaddr_l2(address, 1)
    sock = linux_open(socket.SOCK_SEQPACKET, 0, addr, timeout, address, "sdp")
    lists, state = bytearray(), b""
    try:
        sock.settimeout(timeout)
        for transaction in range(1, 257):
            params = search + bytes([len(state)]) + state
            sock.send(struct.pack(">BHH", 6, transaction, len(params)) + params)
            piece, state = linux_sdp_reply(sock.recv(65535), transaction)
            lists += piece
            if not state:
                break
        else:
            raise DriverError(f"{LINUX_BAD_SDP}: it never ends")
    except TimeoutError:
        raise DriverError(f"{address} stopped answering", LINUX_TIMEOUT_HINT) from None
    except OSError as exc:
        raise linux_error(exc.errno or 0, address, "sdp", False) from None
    finally:
        sock.close()
    channel = linux_sdp_lists_channel(bytes(lists))
    if channel is None:
        message = f"{address} lists no rfcomm channel for {service_uuid}"
        raise DriverError(message, "turn the gadget off and on, then try again")
    return channel


def linux_sdp_reply(pdu: bytes, transaction: int) -> tuple[bytes, bytes]:
    """The attribute lists and continuation state in the reply to `transaction`."""
    if pdu[:1] == b"\x01":
        raise DriverError("bluetooth error: the gadget's sdp server refused")
    end = 7 + int.from_bytes(pdu[5:7], "big")
    if (
        len(pdu) < 8
        or pdu[0] != 7
        or struct.unpack_from(">HH", pdu, 1) != (transaction, len(pdu) - 5)
        or end >= len(pdu)
        or pdu[end] != len(pdu) - end - 1
        or pdu[end] > 16
    ):
        raise DriverError(LINUX_BAD_SDP)
    return pdu[7:end], pdu[end + 1 :]


def linux_sdp_lists_channel(lists: bytes) -> int | None:
    """The first rfcomm channel in the protocol lists of a whole reply's records."""
    records, end = linux_sdp_element(lists, 0, len(lists))
    if end != len(lists) or not isinstance(records, list):
        raise DriverError(LINUX_BAD_SDP)
    if any(not isinstance(record, list) or len(record) % 2 for record in records):
        raise DriverError(LINUX_BAD_SDP)
    pairs = [zip(record[::2], record[1::2]) for record in records]
    return linux_rfcomm_channel([value for p in pairs for a, value in p if a == 4])


def linux_sdp_element(data: bytes, at: int, end: int, depth: int = 0):
    """The sdp data element at `at` and the offset after it: a list for a sequence
    or alternative, an int, a uuid as 16 bytes (a short one on the base uuid), else
    None. Anything malformed or cut short is a DriverError."""
    if at >= end or depth > 32:
        raise DriverError(LINUX_BAD_SDP)
    kind, index = data[at] >> 3, data[at] & 7
    at += 1
    size = LINUX_SDP_SIZES.get((kind, index))
    if kind in (4, 6, 7, 8) and index >= 5:  # text, sequence, alternative, url
        width = 1 << (index - 5)
        size, at = int.from_bytes(data[at : at + width], "big"), at + width
    if size is None or at + size > end:
        raise DriverError(LINUX_BAD_SDP)
    stop = at + size
    if kind in (6, 7):
        items = []
        while at < stop:
            item, at = linux_sdp_element(data, at, stop, depth + 1)
            items.append(item)
        return items, stop
    raw = data[at:stop]
    if kind == 3:
        return (raw.rjust(4, b"\0") + LINUX_RFCOMM[4:] if size < 16 else raw), stop
    if kind in (1, 2):
        return int.from_bytes(raw, "big", signed=kind == 2), stop
    return None, stop


def linux_rfcomm_channel(element) -> int | None:
    """The number after the rfcomm uuid in a protocol list, if it is 1-30: the
    channels rfcomm can reach, so a hostile reply never reaches struct.pack."""
    if not isinstance(element, list):
        return None
    if element[:1] == [LINUX_RFCOMM]:
        channel = element[1] if len(element) > 1 else None
        return channel if type(channel) is int and 1 <= channel <= 30 else None
    for child in element:
        channel = linux_rfcomm_channel(child)
        if channel is not None:
            return channel
    return None


class LinuxLink:
    """write, read and close over a connected rfcomm socket, as MacLink has them."""

    def __init__(self, sock: socket.socket, address: str) -> None:
        self.sock = sock
        self.address = address
        self.ended = False  # the gadget hung up, or the link is closed
        sock.settimeout(LINUX_WRITE_SECONDS)

    def write(self, data: bytes) -> None:
        if self.ended:
            raise DriverError("bluetooth error: the channel is closed")
        try:
            self.sock.sendall(data)
        except TimeoutError:
            message = f"{self.address} stopped answering"
            raise DriverError(message, LINUX_TIMEOUT_HINT) from None
        except OSError as exc:
            error = linux_error(exc.errno or 0, self.address, "the channel", False)
            raise error from None

    def read(self, seconds: float, first: bool = False) -> bytes:
        """Wait `seconds`, less if the gadget hangs up or, with `first`, once
        anything came, then return all that arrived since the open or the last
        read. rfcomm hands a long message over in frames of about 1000 bytes."""
        data = bytearray()
        deadline = time.monotonic() + seconds
        while not self.ended and not (first and data):
            left = deadline - time.monotonic()
            if not select.select([self.sock], [], [], max(left, 0))[0]:
                break
            try:
                piece = self.sock.recv(4096)
            except OSError:
                piece = b""
            self.ended = not piece
            data += piece
            if left <= 0:
                break
        return bytes(data)

    def close(self) -> None:
        """Close the socket at once. Never raises; a second close does nothing."""
        self.ended = True
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self.sock.close()


def linux_open_link(address_hint: str, name_hint: str, service_uuid: str):
    """A LinuxLink to the rfcomm channel for `service_uuid` on the paired device
    `linux_pick` finds, at the channel the device's sdp server lists."""
    address = linux_pick(linux_paired(), address_hint, name_hint, service_uuid)
    channel = linux_sdp_channel(address, service_uuid, LINUX_SECONDS)
    return LinuxLink(linux_connect(address, channel, LINUX_SECONDS), address)


# --- end of the linux link -----------------------------------------------------


class _LinuxMdrLink:
    """The linux link as Mdr uses it: a read ends once anything has come, and a
    channel the headphones closed is an error, as on a mac."""

    def __init__(self, link: Any) -> None:
        self._link = link

    def _closed(self) -> DriverError:
        return DriverError("the headphones closed the control channel", timeout_hint())

    def write(self, data: bytes) -> None:
        if self._link.ended:
            raise self._closed()
        self._link.write(data)

    def read(self, seconds: float) -> bytes:
        data = self._link.read(seconds, first=True)
        if not data and self._link.ended:
            raise self._closed()
        return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="driver.py",
        description="drive a sony wh-1000xm5: noise cancelling, ambient sound, battery",
    )
    parser.add_argument(
        "command", nargs="*", help="anc on|off, ambient on|off, battery or status"
    )
    parser.add_argument(
        "--address", help="the headphones' address, instead of finding them by name"
    )
    args = parser.parse_intermixed_args(argv)
    try:
        parse(args.command)  # before anything opens
        with open_link(args.address) as link:
            line = run(args.command, link)
    except DriverError as e:
        print(f"error: {e.message}", file=sys.stderr)
        if e.hint:
            print(f"  hint: {e.hint}", file=sys.stderr)
        return 2
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
