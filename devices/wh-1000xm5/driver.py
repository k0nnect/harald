# /// script
# requires-python = ">=3.11"
# dependencies = ["pyobjc-framework-IOBluetooth>=11; sys_platform == 'darwin'"]
# ///
"""drive a sony wh-1000xm5's noise cancelling, ambient sound and battery readout.

    harald drive wh-1000xm5 status
    harald drive wh-1000xm5 anc on|off
    harald drive wh-1000xm5 ambient on|off
    harald drive wh-1000xm5 battery
    harald drive wh-1000xm5 --address aa:bb:cc:11:22:33 status

the headphones must be paired with this mac and connected to it. the driver opens
sony's control channel over rfcomm, says one thing, and closes it again; audio keeps
playing. it only ever sends the handshake, the noise control read (66 17) and set
(68 17), the battery read (22 00) and acks. protocol.md, next to this file, explains
the bytes.
"""

from __future__ import annotations

import argparse
import contextlib
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
            raise DriverError("the headphones did not answer", hint=TIMEOUT_HINT)
        if len(reply) < size:
            raise DriverError(f"the headphones sent a short reply: {reply.hex()}")
        return reply

    def handshake(self) -> None:
        for seconds in (HANDSHAKE_RETRY, REPLY_TIMEOUT):
            _, reply = self._exchange(HANDSHAKE, b"\x01", seconds)
            if reply is not None:
                return
        raise DriverError(
            "the headphones did not answer the handshake",
            hint="close the sony app on your phone, "
            "then turn the mac's bluetooth off and on",
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
            raise DriverError("the headphones did not take the setting", TIMEOUT_HINT)

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

    IOBluetooth calls back only on the main thread's run loop, so this runs on the
    main thread and pumps that run loop itself while it waits.
    """
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
