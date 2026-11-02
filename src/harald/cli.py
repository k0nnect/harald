"""The human cli: `harald <command>`, run by the gadget's owner in their own terminal.

This is the only place writes can be armed (`harald arm`); the mcp server has no
tool for it. `harald arm` needs a terminal on stdin and stdout and a person typing
`arm` at its prompt, so piping `arm` into it arms nothing. That stops casual or
accidental arming by an agent; it is not a sandbox against one that can run any
command or write any file on the machine. Expected failures print
`error: <message>` and `  hint: <hint>` to stderr and exit with code 2, never a
traceback.

The ble backends (`scanner_cls`, `client_cls`), the classic backend
(`classic_backend`; None means the platform's) and the driver runner (`runner`) are
module-level hooks so tests can swap in fakes; they are looked up on every call.
IOBluetooth calls back only on the main thread, so on a mac each `harald classic`
command runs its asyncio work under `classic_mac.run_main`.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import math
import subprocess
import sys
import time
import zipfile
from collections.abc import Awaitable, Callable, Coroutine
from pathlib import Path
from typing import Any, TypeVar

from bleak.exc import BleakError

from harald import __version__, arm, ble, classic, hints, library, workspace
from harald.apk import analyze_apk
from harald.capture.timeline import build_timeline, render
from harald.errors import HaraldError, LibraryError
from harald.playbook import install_playbook

scanner_cls = ble.BleakScanner
client_cls = ble.BleakClient
runner = subprocess.run
classic_backend: classic.Backend | None = None

T = TypeVar("T")

# HaraldError carries its own hint; the rest are what the core modules let through
# for missing paths, malformed input (bad hex, toml, zip) and unmapped radio failures.
_CAUGHT = (HaraldError, OSError, ValueError, zipfile.BadZipFile, BleakError)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # --help, --version or a usage error, already printed
        return int(exc.code or 0)
    try:
        return args.func(args)
    except _CAUGHT as exc:
        message, hint = _describe(exc)
        print(f"error: {message}", file=sys.stderr)
        if hint:
            print(f"  hint: {hint}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


def _describe(exc: Exception) -> tuple[str, str]:
    """The message and hint to print. File names in os errors stay as given."""
    if isinstance(exc, HaraldError):
        return exc.message, exc.hint
    if isinstance(exc, OSError) and exc.strerror:
        message = exc.strerror.lower()
        if exc.filename is not None:
            message = f"{message}: {exc.filename}"
        return message, ""
    return (str(exc) or type(exc).__name__).lower(), ""


def _on_device(address: str, action: Callable[[ble.Session], Awaitable[Any]]) -> Any:
    """Connect, run `action` on the session, then disconnect so the gadget stays free."""

    async def run() -> Any:
        conn = ble.Session(address, client_cls=client_cls)
        await conn.connect()
        try:
            return await action(conn)
        finally:
            # a failing disconnect must not replace the result or the original error
            with contextlib.suppress(*ble.CLEANUP_ERRORS):
                await conn.close()

    return asyncio.run(run())


def _scan(args: argparse.Namespace) -> int:
    devices = asyncio.run(ble.scan(args.timeout, scanner_cls=scanner_cls))
    if not devices:
        print("no devices found")
        return 0
    width = max(len("address"), *(len(d.address) for d in devices))
    print(f"{'address':<{width}}  {'rssi':>4}  name")
    for d in devices:
        print(f"{d.address:<{width}}  {d.rssi:>4}  {d.name or '-'}")
    return 0


def _is_terminal(stream: Any) -> bool:
    """True if `stream` is a terminal; a missing stream (None) is not one."""
    return stream is not None and stream.isatty()


def _arm(args: argparse.Namespace) -> int:
    """Arm only for a person at a terminal who types `arm`. There is no bypass flag."""
    if not (_is_terminal(sys.stdin) and _is_terminal(sys.stdout)):
        raise HaraldError(
            "harald arm only runs in an interactive terminal",
            hint="run it yourself, in your own terminal; "
            "an agent should ask the human to run it",
        )
    print(
        f"this lets harald write to {arm.device_key(args.device)}: "
        f"up to {args.writes} writes in the next {args.minutes} min"
    )
    if args.allow_dfu:
        print("firmware-update services will be allowed too")
    try:
        answer = input("type arm to confirm: ")
    except EOFError:  # ctrl-d
        print()
        answer = ""
    if answer.strip() != "arm":
        print("not armed")
        return 1
    grant = arm.arm(args.device, args.writes, args.minutes, args.allow_dfu)
    print(
        f"armed {grant.device}: write budget {grant.writes_left}, "
        f"expires in {args.minutes} min"
    )
    if grant.allow_dfu:
        print("firmware-update services are allowed for this grant")
    print(f"revoke with: harald disarm {grant.device}")
    return 0


def _disarm(args: argparse.Namespace) -> int:
    arm.disarm(args.device)
    print(f"disarmed {args.device}")
    return 0


def _status(args: argparse.Namespace) -> int:
    grants = arm.status()
    if not grants:
        print("nothing is armed")
        return 0
    now = time.time()
    width = max(len("device"), *(len(g.device) for g in grants))
    print(f"{'device':<{width}}  {'writes left':<11}  {'expires in':<10}  dfu")
    for g in grants:
        minutes = math.ceil(max(g.expires_at - now, 0) / 60)
        dfu = "allowed" if g.allow_dfu else "blocked"
        expires = f"{minutes} min"
        print(f"{g.device:<{width}}  {g.writes_left:<11}  {expires:<10}  {dfu}")
    return 0


def _connect(args: argparse.Namespace) -> int:
    services = _on_device(args.address, lambda conn: conn.services())
    for service in services:
        print(f"service {service.uuid}")
        for char in service.chars:
            props = ", ".join(char.properties)
            print(f"  {char.uuid}  h=0x{char.handle:04x}  {props}")
    return 0


def _read(args: argparse.Namespace) -> int:
    value = _on_device(args.address, lambda conn: conn.read(args.char))
    print(value.hex())
    return 0


def _write(args: argparse.Namespace) -> int:
    data = bytes.fromhex(args.hex)  # bad hex fails before connecting
    left = _on_device(
        args.address, lambda conn: conn.write(args.char, data, response=args.response)
    )
    print(f"wrote {data.hex()} to {args.char}; writes left: {left}")
    return 0


def _run_classic(work: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run a classic command's asyncio work: under `classic_mac.run_main` on a mac,
    since IOBluetooth calls back only on the main thread, and directly elsewhere."""
    if sys.platform == "darwin":
        try:
            from harald import classic_mac  # pyobjc is only imported on a mac
        except ImportError:
            pass
        else:
            return classic_mac.run_main(lambda: asyncio.run(work()))
    return asyncio.run(work())


def _classic_devices(args: argparse.Namespace) -> int:
    devices = _run_classic(lambda: classic.paired_devices(backend=classic_backend))
    if not devices:
        print(f"no paired classic devices; {hints.pair_one()}")
        return 0
    width = max(len("address"), *(len(d.address) for d in devices))
    print(f"{'address':<{width}}  connected  name")
    for d in devices:
        connected = "yes" if d.connected else "no"
        print(f"{d.address:<{width}}  {connected:<9}  {d.name or '-'}")
    return 0


def _classic_services(args: argparse.Namespace) -> int:
    address = classic.normalize_address(args.address)
    records = _run_classic(
        lambda: classic.services(address, refresh=args.refresh, backend=classic_backend)
    )
    if not records:
        retry = f"; run: harald classic services {address} --refresh"
        print(f"no service records for {address}{'' if args.refresh else retry}")
        return 0
    for r in records:
        channel = "ch=-" if r.channel is None else f"ch={r.channel}"
        flags = ("  protected" if r.protected else "") + (
            "  firmware update" if r.firmware_update else ""
        )
        uuids = ",".join(r.uuids) or "-"
        print(f"{channel:<5}  {uuids}  {r.name or '-'}{flags}")
    return 0


def _classic_send(args: argparse.Namespace) -> int:
    # argparse has already turned every message into bytes, so bad hex never gets here
    result = _run_classic(
        lambda: classic.send(
            args.address, args.service, args.hex, args.listen, backend=classic_backend
        )
    )
    for chunk in result.chunks:
        print(f"after #{chunk.after}  {_chunk_line(chunk)}")
    noun = "message" if result.sent == 1 else "messages"
    print(f"sent {result.sent} {noun}; writes left: {result.writes_left}")
    if result.stopped:
        # a partial send: 1, so a script can tell it from a whole one (0) and
        # from an error that sent nothing (2)
        print(f"stopped: {result.stopped}", file=sys.stderr)
        return 1
    return 0


def _classic_listen(args: argparse.Namespace) -> int:
    chunks = _run_classic(
        lambda: classic.listen(
            args.address, args.service, args.seconds, backend=classic_backend
        )
    )
    if not chunks:
        print(f"nothing received in {args.seconds:g}s")
    for chunk in chunks:
        print(_chunk_line(chunk))
    return 0


def _chunk_line(chunk: classic.Chunk) -> str:
    return f"+{chunk.seconds:.3f}s  {chunk.data.hex(' ')}"


def _capture_open(args: argparse.Namespace) -> int:
    timeline = build_timeline(Path(args.path))
    # render puts the timeline's warnings first; they are not printed again here.
    print(
        render(
            timeline,
            limit=args.limit,
            offset=args.offset,
            handle=args.handle,
            conn=args.conn,
            channel=args.channel,
        )
    )
    return 0


def _apk(args: argparse.Namespace) -> int:
    report = analyze_apk(Path(args.path))
    for warning in report.warnings:
        print(f"warning: {warning}")
    print(f"framework: {report.framework}")
    if report.package:
        print(f"package: {report.package}")
    if report.jadx_dir is not None:
        print(f"jadx output: {report.jadx_dir}")
    if report.totals:  # what the scan found, before the lists below were capped
        print("totals: " + ", ".join(f"{k} {n}" for k, n in report.totals.items()))
    if report.gatt_uuids:
        print("gatt uuids:")
        for uuid in report.gatt_uuids:
            print(f"  {uuid}")
    if report.candidates:
        print("candidates (file:line under the jadx output):")
        for c in report.candidates:
            print(f"  {c.kind}  {c.location}  {c.snippet}")
    return 0


def _devices(args: argparse.Namespace) -> int:
    metas = library.list_devices()
    if not metas:
        print("the device library is empty")
        return 0
    width = max(len("slug"), *(len(m.slug) for m in metas))
    print(f"{'slug':<{width}}  {'status':<11}  {'transport':<9}  name")
    for m in metas:
        summary = f"  {m.summary}" if m.summary else ""
        print(f"{m.slug:<{width}}  {m.status:<11}  {m.transport:<9}  {m.name}{summary}")
    return 0


def _device(args: argparse.Namespace) -> int:
    meta = library.load_device(args.slug)
    protocol = library.protocol_path(meta.slug)
    driver = library.driver_path(meta.slug)
    rows = [
        ("name", meta.name),
        ("vendor", meta.vendor),
        ("status", meta.status),
        ("transport", meta.transport),
        ("key scope", meta.key_scope),
        ("key", meta.key_hex),
        ("cipher", meta.cipher),
        ("services", ", ".join(meta.service_uuids)),
        ("name hint", meta.name_hint),
        ("summary", meta.summary),
        ("protocol", protocol if protocol.is_file() else None),
        ("driver", driver if driver.is_file() else None),
    ]
    for label, value in rows:
        if value:
            print(f"{label}: {value}")
    return 0


def _drive(args: argparse.Namespace) -> int:
    meta = library.load_device(args.slug)  # an unknown slug points at harald devices
    driver = library.driver_path(meta.slug)
    if not driver.is_file():
        raise LibraryError(
            f"{meta.slug} has no driver yet",
            hint=f"its status is {meta.status}; run: harald devices",
        )
    return runner(["uv", "run", str(driver), *args.args], check=False).returncode


def _notes(args: argparse.Namespace) -> int:
    text = workspace.read_notes(args.slug)
    if text:
        print(text, end="")
    else:
        print(f"no notes yet in {_notes_path(args.slug)}")
    return 0


def _note(args: argparse.Namespace) -> int:
    workspace.append_note(args.slug, " ".join(args.text))
    print(f"saved to {_notes_path(args.slug)}")
    return 0


def _notes_path(slug: str) -> Path:
    return workspace.DEFAULT_ROOT / slug / "notes.md"


def _playbook_install(args: argparse.Namespace) -> int:
    path = install_playbook(args.agent, Path(args.dest))
    print(f"installed {path}")
    return 0


def _mcp(args: argparse.Namespace) -> int:
    # the mcp sdk is slow to import, and only this command needs it.
    from harald import server

    server.run()
    return 0


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be a positive integer, got {text!r}")
    return value


def _number(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"must be a number such as 0x0012 or 18, got {text!r}"
        ) from None


def _hex_message(text: str) -> bytes:
    try:
        data = bytes.fromhex(text)
    except ValueError:
        data = b""
    if not data:
        raise argparse.ArgumentTypeError(
            f"must be hex bytes such as 3e010000000000013c, got {text!r}"
        )
    return data


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = math.nan
    if not (math.isfinite(value) and value >= 0):
        raise argparse.ArgumentTypeError(
            f"must be a number of seconds, 0 or more, got {text!r}"
        )
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harald",
        description="work out the bluetooth le and classic protocol of gadgets you own",
    )
    parser.add_argument("--version", action="version", version=f"harald {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    def command(
        name: str,
        func: Callable[[argparse.Namespace], int],
        summary: str,
        group: Any = sub,
    ):
        cmd = group.add_parser(name, help=summary, description=summary)
        cmd.set_defaults(func=func)
        return cmd

    scan = command("scan", _scan, "list bluetooth le devices nearby, strongest first")
    scan.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="seconds",
        help="how long to listen (default 5)",
    )

    arm_cmd = command("arm", _arm, "allow writes to one device for a limited time")
    arm_cmd.add_argument(
        "device",
        help="the device address, as harald scan or harald classic devices shows it",
    )
    arm_cmd.add_argument(
        "--writes",
        type=_positive_int,
        default=50,
        metavar="n",
        help="writes allowed (default 50)",
    )
    arm_cmd.add_argument(
        "--minutes",
        type=_positive_int,
        default=30,
        metavar="m",
        help="minutes the grant lasts (default 30)",
    )
    arm_cmd.add_argument(
        "--allow-dfu",
        action="store_true",
        help="also allow writes to firmware-update services",
    )

    disarm = command("disarm", _disarm, "revoke a device's write grant")
    disarm.add_argument("device")

    command("status", _status, "show which devices are armed")

    connect = command(
        "connect", _connect, "list a device's services and characteristics"
    )
    connect.add_argument("address")

    read = command("read", _read, "read a characteristic once and print it as hex")
    read.add_argument("address")
    read.add_argument("char", help="characteristic uuid")

    write = command("write", _write, "write hex bytes to a characteristic (needs arm)")
    write.add_argument("address")
    write.add_argument("char", help="characteristic uuid")
    write.add_argument("hex", help="the bytes to write, e.g. 7e0405")
    write.add_argument(
        "--response",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="wait for the device to acknowledge the write, or not. by default it "
        "writes without response when the characteristic allows that",
    )

    classic_cmd = sub.add_parser(
        "classic", help="talk to paired bluetooth classic (rfcomm) devices"
    )
    classic_sub = classic_cmd.add_subparsers(
        dest="classic_command", required=True, metavar="<command>"
    )
    service_help = (
        "an rfcomm service uuid or channel number from harald classic services"
    )
    command(
        "devices",
        _classic_devices,
        f"list the bluetooth classic devices paired with {hints.here()}",
        classic_sub,
    )
    services = command(
        "services",
        _classic_services,
        "list a paired classic device's rfcomm service records",
        classic_sub,
    )
    services.add_argument("address")
    services.add_argument(
        "--refresh",
        action="store_true",
        help=f"ask the device again instead of trusting {hints.machine()}'s cache",
    )
    send = command(
        "send",
        _classic_send,
        "send hex messages to an rfcomm channel and show what comes back (needs arm)",
        classic_sub,
    )
    send.add_argument("address")
    send.add_argument("service", help=service_help)
    send.add_argument(
        "hex",
        nargs="+",
        type=_hex_message,
        help="the messages, sent in order, e.g. 3e010000000000013c",
    )
    send.add_argument(
        "--listen",
        type=_seconds,
        default=2.0,
        metavar="s",
        help="seconds to listen after each message (default 2, at most 30)",
    )
    listen = command(
        "listen",
        _classic_listen,
        "show what an rfcomm channel says, sending nothing",
        classic_sub,
    )
    listen.add_argument("address")
    listen.add_argument("service", help=service_help)
    listen.add_argument(
        "--seconds",
        type=_seconds,
        default=5.0,
        metavar="s",
        help="how long to listen (default 5, at most 30)",
    )

    capture = sub.add_parser("capture", help="read phone captures")
    capture_sub = capture.add_subparsers(
        dest="capture_command", required=True, metavar="<command>"
    )
    opened = capture_sub.add_parser(
        "open",
        help="show the att and rfcomm timeline of a .pklg or btsnoop capture",
        description="show the att and rfcomm timeline of a .pklg or btsnoop capture",
    )
    opened.set_defaults(func=_capture_open)
    opened.add_argument("path")
    opened.add_argument(
        "--limit",
        type=int,
        default=200,
        metavar="n",
        help="events to show (default 200)",
    )
    opened.add_argument(
        "--offset", type=int, default=0, metavar="n", help="events to skip (default 0)"
    )
    opened.add_argument(
        "--handle",
        type=_number,
        metavar="h",
        help="only events on this att handle, e.g. 0x0012",
    )
    opened.add_argument(
        "--conn",
        type=_number,
        metavar="c",
        help="only events on this acl connection, e.g. 0x0040",
    )
    opened.add_argument(
        "--channel",
        type=_number,
        metavar="n",
        help="only rfcomm events on this channel, e.g. 9",
    )

    apk = command("apk", _apk, "statically analyze a vendor android app on disk")
    apk.add_argument("path", help="an .apk, .xapk or .apks file")

    command("devices", _devices, "list the device library")

    device = command("device", _device, "show one device library entry")
    device.add_argument("slug")

    drive = command("drive", _drive, "run a library device's driver with uv")
    drive.add_argument("slug")
    drive.add_argument(
        "args", nargs=argparse.REMAINDER, help="passed through to the driver"
    )

    notes = command("notes", _notes, "show the working notes for a device")
    notes.add_argument("slug")

    note = command("note", _note, "append a timestamped note for a device")
    note.add_argument("slug")
    note.add_argument("text", nargs="+")

    playbook = sub.add_parser("playbook", help="install the agent playbook")
    playbook_sub = playbook.add_subparsers(
        dest="playbook_command", required=True, metavar="<command>"
    )
    installed = playbook_sub.add_parser(
        "install",
        help="copy the playbook for claude code or codex into a folder",
        description="copy the playbook into a folder: SKILL.md for claude-code, "
        "AGENTS.md for codex. claude code reads skills from .claude/skills/<name>/",
    )
    installed.set_defaults(func=_playbook_install)
    installed.add_argument("agent", help="claude-code or codex")
    installed.add_argument(
        "--dest",
        default=".",
        metavar="folder",
        help="the folder to write into, created if missing (default .)",
    )

    command("mcp", _mcp, "run the mcp server over stdio for a coding agent")
    return parser
