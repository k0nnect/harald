"""The mcp server: harald's core modules exposed as tools for a coding agent.

Every tool returns plain json values and never raises at the agent. A `HaraldError`
comes back as `{"error": message, "hint": hint}`; a missing file, bad hex, malformed
toml or a non-zip apk comes back as `{"error": <lowercased text>, "hint": ""}`.

Writes go through `ble.Session.write`, which spends the human's `harald arm` budget.
There is deliberately no tool that arms, disarms or enables writes, so the agent can
never approve its own writes. Tool docstrings are the descriptions the agent reads,
so they are lowercase like all other harald output.
"""

from __future__ import annotations

import functools
import inspect
import zipfile
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from bleak.exc import BleakError
from mcp.server import MCPServer

from harald import __version__, analyze, apk, ble, library, workspace
from harald.capture.timeline import build_timeline, render
from harald.errors import HaraldError

Record = dict[str, Any]
Failure = dict[str, str]  # {"error": ..., "hint": ...}

EXPECTED_TOOLS: frozenset[str] = frozenset(
    {
        "scan",
        "connect",
        "read_char",
        "write_char",
        "subscribe",
        "open_capture",
        "diff",
        "guess_checks",
        "try_keys",
        "analyze_apk",
        "list_devices",
        "load_device",
        "read_notes",
        "save_note",
    }
)

INSTRUCTIONS = (
    "harald helps you work out the bluetooth le protocol of a gadget the user owns: "
    "scan and connect, decode phone captures, compare payloads, test candidate keys, "
    "scan the vendor's android app, and keep notes per device. writes are refused "
    "until the human runs `harald arm <address>` in their own terminal; no tool can "
    'arm. a tool that fails returns {"error": ..., "hint": ...}: act on the hint.'
)

# HaraldError carries its own hint; the rest are what the core modules let through
# for missing paths, malformed input (bad hex, toml, zip) and radio failures that
# ble.py does not map (a missing or unreadable characteristic, a dropped link).
_CAUGHT = (HaraldError, OSError, ValueError, zipfile.BadZipFile, BleakError)


def _failure(exc: Exception) -> Failure:
    if isinstance(exc, HaraldError):
        return {"error": exc.message, "hint": exc.hint}
    return {"error": (str(exc) or type(exc).__name__).lower(), "hint": ""}


def _guarded(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a tool so expected errors come back as a failure dict instead of raising.

    `functools.wraps` keeps the name, docstring and signature mcp builds the tool from.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def guarded_async(*args: Any, **kwargs: Any) -> Any:
            try:
                return await fn(*args, **kwargs)
            except _CAUGHT as exc:
                return _failure(exc)

        return guarded_async

    @functools.wraps(fn)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _CAUGHT as exc:
            return _failure(exc)

    return guarded


def _from_hex(values: list[str]) -> list[bytes]:
    return [bytes.fromhex(value) for value in values]


def build_server(
    *, scanner_cls=ble.BleakScanner, client_cls=ble.BleakClient
) -> MCPServer:
    """An `MCPServer` with every harald tool registered. BLE backends are injectable."""
    mcp = MCPServer("harald", instructions=INSTRUCTIONS, version=__version__)

    def tool(fn: Callable[..., Any]) -> Callable[..., Any]:
        description = inspect.cleandoc(fn.__doc__ or "")
        return mcp.tool(description=description)(_guarded(fn))

    @asynccontextmanager
    async def session(address: str) -> AsyncIterator[ble.Session]:
        """One connection per tool call, closed afterwards so the gadget stays free."""
        conn = ble.Session(address, client_cls=client_cls)
        await conn.connect()
        try:
            yield conn
        finally:
            await conn.close()

    @tool
    async def scan(timeout: float = 5.0) -> list[Record] | Failure:
        """scan for bluetooth le devices for `timeout` seconds, strongest signal first.

        manufacturer_data maps each company id (as 0x-hex) to its payload hex.
        """
        devices = await ble.scan(timeout, scanner_cls=scanner_cls)
        return [
            asdict(d)
            | {
                "manufacturer_data": {
                    f"0x{cid:04x}": data for cid, data in d.manufacturer_data.items()
                }
            }
            for d in devices
        ]

    @tool
    async def connect(address: str) -> Record | Failure:
        """connect to a device and list its gatt services and their characteristics.

        use the characteristic uuids listed here with read_char, write_char and subscribe.
        """
        async with session(address) as conn:
            services = await conn.services()
        return {"address": address, "services": [asdict(s) for s in services]}

    @tool
    async def read_char(address: str, char_uuid: str) -> str | Failure:
        """read a characteristic once; returns its value as hex."""
        async with session(address) as conn:
            return (await conn.read(char_uuid)).hex()

    @tool
    async def write_char(
        address: str, char_uuid: str, data_hex: str, response: bool | None = None
    ) -> Record | Failure:
        """write hex bytes to a characteristic; returns the writes left.

        refused unless the human armed this device by running `harald arm <address>`
        in their own terminal. each write spends one from that budget, and
        firmware-update services stay blocked. by default it writes without response
        when the characteristic allows that, and with response otherwise.
        response=true waits for the device to acknowledge the write; false does not.
        """
        data = bytes.fromhex(data_hex)
        async with session(address) as conn:
            writes_left = await conn.write(char_uuid, data, response=response)
        return {"writes_left": writes_left}

    @tool
    async def subscribe(
        address: str, char_uuid: str, seconds: float
    ) -> list[Record] | Failure:
        """collect notifications from a characteristic for `seconds`.

        returns one entry per notification: seconds since the start and the value as hex.
        """
        async with session(address) as conn:
            events = await conn.subscribe(char_uuid, seconds)
        return [{"seconds": round(t, 3), "value_hex": v.hex()} for t, v in events]

    @tool
    def open_capture(
        path: str, limit: int = 200, offset: int = 0, handle: int | None = None
    ) -> str | Failure:
        """show the att timeline of a phone capture (packetlogger .pklg or btsnoop log).

        one line per att event with time, direction, op, handle, uuid and value hex;
        any warnings come first and a `showing a–b of n events` footer comes last.
        page with limit and offset. handle (an integer, e.g. 18 for h=0x0012) keeps
        only events on that handle, and offset then counts those filtered events.
        relative paths resolve against the server's working directory.
        """
        timeline = build_timeline(Path(path))
        return render(timeline, limit=limit, offset=offset, handle=handle)

    @tool
    def diff(payloads_hex: list[str]) -> Record | Failure:
        """compare hex payloads byte by byte.

        returns how many payloads have each length, the byte at every position that is
        the same in all of them (over the shortest), the positions that vary, and
        whether the set looks like block-cipher output.
        """
        payloads = _from_hex(payloads_hex)
        report = analyze.diff_payloads(payloads)
        return {
            "lengths": {str(n): count for n, count in report.lengths.items()},
            "constant": {str(i): f"{b:02x}" for i, b in report.constant.items()},
            "varying": report.varying,
            "looks_encrypted": analyze.looks_encrypted(payloads),
        }

    @tool
    def guess_checks(payload_hex: str) -> list[str] | Failure:
        """name the checksums and length fields one hex payload is consistent with.

        checks sum8 and xor8 in the last byte, crc16-ccitt in the last two, and a
        length byte at position 0 or 1.
        """
        return analyze.guess_checks(bytes.fromhex(payload_hex))

    @tool
    def try_keys(
        payloads_hex: list[str], keys_hex: list[str]
    ) -> list[Record] | Failure:
        """decrypt hex payloads with each candidate aes key, in ecb and in cbc with a
        zero iv, best-scoring first. samples holds the first plaintexts as hex.

        the score only tells keys apart across several distinct payloads: with one
        payload, or identical copies, every key scores 1.0. keys that are not 16, 24
        or 32 bytes and payloads that are not a multiple of 16 bytes are skipped.
        """
        results = analyze.try_keys(_from_hex(payloads_hex), _from_hex(keys_hex))
        return [asdict(r) for r in results]

    @tool
    def analyze_apk(path: str) -> Record | Failure:
        """statically analyze a vendor android app (.apk, .xapk or .apks) already on disk.

        detects the framework. for a native app it runs jadx and lists gatt uuids and
        file:line candidates (uuids, aes keys, base64 blobs, command builders) to open
        under jadx_dir. flutter and react-native apps keep their ble code compiled, so
        the warnings point to capture analysis instead. harald never downloads apps.
        """
        report = apk.analyze_apk(Path(path))
        return asdict(report) | {
            "path": str(report.path),
            "jadx_dir": None if report.jadx_dir is None else str(report.jadx_dir),
        }

    @tool
    def list_devices() -> list[Record] | Failure:
        """list the gadgets in harald's device library, with status and summary."""
        return [asdict(meta) for meta in library.list_devices()]

    @tool
    def load_device(slug: str) -> Record | Failure:
        """the device library entry for one slug, including any app-wide key and cipher."""
        return asdict(library.load_device(slug))

    @tool
    def read_notes(slug: str) -> str | Failure:
        """the working notes for a device, or an empty string when there are none.

        notes live in harald-work/<slug>/notes.md, relative to the server's working
        directory.
        """
        return workspace.read_notes(slug)

    @tool
    def save_note(slug: str, text: str) -> Record | Failure:
        """append a timestamped note to harald-work/<slug>/notes.md.

        the path is relative to the server's working directory. slugs use lowercase
        letters, digits and hyphens, e.g. demo-lamp.
        """
        workspace.append_note(slug, text)
        return {"saved": True}

    return mcp


def run() -> None:
    """Serve harald's tools over stdio until the client disconnects."""
    build_server().run(transport="stdio")
