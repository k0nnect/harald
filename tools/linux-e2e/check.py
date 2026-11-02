"""harald's end-to-end checks against the rig's fake gadget, inside the vm.

vm.sh runs this with the python of a venv that uv made from its own cpython 3.13,
which has no `socket.AF_BLUETOOTH`, with harald installed from the shipped tree. It
runs harald as a user would: the `harald` command, `harald mcp` over stdio, and a
driver rendered from a `DriverSpec` under `uv run`.

Pairing the classic gadget is rig setup, done with bluetoothctl as a person would.
Arming happens in this process, with `harald.arm.arm()` and a throwaway HARALD_HOME
that the harald subprocesses share; nothing here runs `harald arm` or answers its
prompt. Each check prints PASS or FAIL with a short detail; the exit status is 1 if
any failed.

usage: python check.py [--tree <the shipped tree>]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Callable
from pathlib import Path

import harald
from harald import arm, classic
from harald.classic_linux import LinuxBackend
from harald.templates import DriverCommand, DriverSpec, render_driver

ADDRESS = "00:aa:01:01:00:43"  # the gadget, classic: btvirt's first tcp client
LE_ADDRESS = "C0:DE:CA:FE:00:01"  # the gadget, le random static
NAME = "harald-gadget"
VENDOR = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"
SPP = "00001101-0000-1000-8000-00805f9b34fb"
HANDS_FREE = "0000111e-0000-1000-8000-00805f9b34fb"
VENDOR_CH, SPP_CH, HANDS_FREE_CH = 9, 3, 7
GATT_SERVICE = "68617261-6c64-4000-8000-000000000000"
GATT_READ = "68617261-6c64-4000-8000-000000000001"
GATT_WRITE = "68617261-6c64-4000-8000-000000000002"
GATT_NOTIFY = "68617261-6c64-4000-8000-000000000003"
GREETING = b"hello".hex()
CLOSE_LIMIT = 1.0  # seconds a close or a cancel may take (review focus 1)

HARALD = str(Path(sys.executable).with_name("harald"))
WORK = Path(tempfile.mkdtemp(prefix="harald-rig-"))
ARMED = WORK / "armed"  # the HARALD_HOME every armed check shares
EMPTY = WORK / "empty"  # a HARALD_HOME with nothing armed
STARTED = time.time()

results: list[tuple[str, bool, str]] = []


def report(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}", flush=True)
    return ok


def env(home: Path) -> dict[str, str]:
    return dict(os.environ, HARALD_HOME=str(home))


def run(argv: list[str], *, home: Path = ARMED, timeout: float = 120) -> Result:
    started = time.monotonic()
    proc = subprocess.run(
        argv,
        check=False,
        env=env(home),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return Result(proc, time.monotonic() - started)


def hrun(*args: str, home: Path = ARMED, timeout: float = 120) -> Result:
    return run([HARALD, *args], home=home, timeout=timeout)


class Result:
    def __init__(self, proc: subprocess.CompletedProcess, seconds: float) -> None:
        self.code = proc.returncode
        self.out = proc.stdout
        self.err = proc.stderr
        self.seconds = seconds

    @property
    def clean(self) -> bool:
        """No python traceback leaked out."""
        return "Traceback" not in self.out + self.err

    def tail(self) -> str:
        lines = (self.out + self.err).strip().splitlines()
        return f"exit {self.code}: " + " | ".join(lines[-3:])


def writes_left(device: str) -> int:
    grant = arm.live_grant(device)
    return grant.writes_left if grant else 0


def gadget_log() -> str:
    """What the gadget logged since this check started (rig tooling, so sudo)."""
    argv = ["sudo", "-n", "journalctl", "-u", "harald-gadget", "-o", "cat"]
    argv += ["--since", f"@{int(STARTED)}"]
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def received(out: str) -> dict[int, str]:
    """`harald classic send` output: the hex that arrived after each message."""
    got: dict[int, str] = {}
    for line in out.splitlines():
        if line.startswith("after #"):
            _after, label, _seconds, *data = line.split()
            number = int(label[1:])
            got[number] = got.get(number, "") + "".join(data)
    return got


# --- setup ----------------------------------------------------------------------


def check_python(tree: Path | None) -> None:
    exe = Path(sys.executable).resolve()
    uv_python = "/uv/python/" in str(exe)
    report(
        "uv python 3.13 without AF_BLUETOOTH",
        sys.version_info[:2] == (3, 13)
        and uv_python
        and hasattr(socket, "AF_BLUETOOTH") is False,
        f"{sys.version.split()[0]} {exe}, "
        f"hasattr(socket, 'AF_BLUETOOTH') = {hasattr(socket, 'AF_BLUETOOTH')}",
    )
    if tree is None:
        return
    installed = Path(harald.__file__).parent
    source = tree / "src" / "harald"
    differ = [
        str(path.relative_to(source))
        for path in sorted(source.rglob("*"))
        if path.is_file()
        and "__pycache__" not in path.parts
        and digest(path) != digest(installed / path.relative_to(source))
    ]
    report(
        "harald installed from the shipped tree",
        not differ,
        f"harald {harald.__version__}" + (f", differs: {differ[:3]}" if differ else ""),
    )


def digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "missing"


def pair_gadget() -> None:
    """Rig setup, as a person would do it: forget the gadget, then scan, pair (just
    works) and trust it with bluetoothctl."""
    upper = ADDRESS.upper()
    for address in (upper, LE_ADDRESS):
        run(["bluetoothctl", "remove", address])
    run(["bluetoothctl", "pairable", "on"])
    scan = run(["bluetoothctl", "--timeout", "5", "scan", "bredr"])
    pair = run(
        ["bluetoothctl", "--agent", "NoInputNoOutput", "--timeout", "8"]
        + ["pair", upper]
    )
    run(["bluetoothctl", "trust", upper])
    info = run(["bluetoothctl", "info", upper]).out
    ok = "Paired: yes" in info and "Bonded: yes" in info and "Trusted: yes" in info
    report(
        "rig: pair the classic gadget",
        ok,
        f"found by inquiry: {upper in scan.out}, "
        + ("paired, bonded, trusted" if ok else pair.tail()),
    )


# --- classic, through the cli ------------------------------------------------------


def check_classic_cli() -> None:
    devices = hrun("classic", "devices")
    line = next((x for x in devices.out.splitlines() if x.startswith(ADDRESS)), "")
    report(
        "classic devices lists the gadget as paired",
        devices.code == 0 and NAME in line,
        " ".join(line.split()) or devices.tail(),
    )

    services = hrun("classic", "services", ADDRESS, "--refresh")
    rows = [line.split() for line in services.out.splitlines()]
    want = {
        VENDOR: (f"ch={VENDOR_CH}", False),
        SPP: (f"ch={SPP_CH}", False),
        HANDS_FREE: (f"ch={HANDS_FREE_CH}", True),
    }
    found = {
        uuid: any(
            row[0] == channel
            and uuid in row[1].split(",")
            and (row[-1] == "protected") == protected
            for row in rows
            if len(row) >= 3
        )
        for uuid, (channel, protected) in want.items()
    }
    report(
        "classic services: vendor ch 9, spp ch 3, hands-free ch 7 protected",
        services.code == 0 and all(found.values()),
        "; ".join(" ".join(row) for row in rows) or services.tail(),
    )

    arm.arm(ADDRESS, writes=100, minutes=15)
    before = writes_left(ADDRESS)
    send = hrun("classic", "send", ADDRESS, VENDOR, "a50102", "a50203", "--listen", "1")
    got = received(send.out)
    after = writes_left(ADDRESS)
    report(
        "classic send echoes, one arm write per message",
        send.code == 0
        and got == {1: "eea50102", 2: "eea50203"}
        and f"sent 2 messages; writes left: {after}" in send.out
        and before - after == 2,
        f"replies {got}, writes left {before} -> {after}, {send.seconds:.2f} s"
        if send.code == 0
        else send.tail(),
    )

    by_number = hrun("classic", "send", ADDRESS, str(VENDOR_CH), "a5", "--listen", "1")
    report(
        "classic send by channel number",
        by_number.code == 0 and received(by_number.out) == {1: "eea5"},
        f"replies {received(by_number.out)}"
        if by_number.code == 0
        else by_number.tail(),
    )

    before = writes_left(ADDRESS)
    listen = hrun("classic", "listen", ADDRESS, "1101", "--seconds", "1.5")
    report(
        "classic listen hears the spp greeting, spends nothing",
        listen.code == 0
        and GREETING in listen.out.replace(" ", "")
        and writes_left(ADDRESS) == before,
        " ".join(listen.out.split()) if listen.code == 0 else listen.tail(),
    )

    before = writes_left(ADDRESS)
    refusals = [
        hrun("classic", "send", ADDRESS, "111e", "01", "--listen", "0"),
        hrun("classic", "send", ADDRESS, str(HANDS_FREE_CH), "01", "--listen", "0"),
        hrun("classic", "listen", ADDRESS, "111e", "--seconds", "0"),
    ]
    opened = f"rfcomm ch {HANDS_FREE_CH} open" in gadget_log()
    report(
        "hands-free refused as protected (send by uuid and number, listen)",
        all(r.code == 2 and "standard profile" in r.err and r.clean for r in refusals)
        and writes_left(ADDRESS) == before
        and not opened,
        f"{refusals[0].err.splitlines()[0] if refusals[0].err else refusals[0].tail()}"
        f"; gadget saw ch {HANDS_FREE_CH} open: {opened}",
    )

    unarmed = hrun("classic", "send", ADDRESS, VENDOR, "c0ffee", home=EMPTY)
    reached = "rx c0ffee" in gadget_log()
    report(
        "unarmed classic send refused",
        unarmed.code == 2
        and f"writes to {ADDRESS} are locked" in unarmed.err
        and unarmed.clean
        and not reached,
        f"{unarmed.err.strip().splitlines()[0] if unarmed.err else unarmed.tail()}"
        f"; reached the gadget: {reached}",
    )

    before = writes_left(ADDRESS)
    hangup = hrun(
        "classic", "send", ADDRESS, VENDOR, "a50a", "dead", "a50b", "--listen", "1"
    )
    report(
        "classic send keeps what it had when the gadget hangs up",
        hangup.code == 1
        and received(hangup.out).get(1) == "eea50a"
        and "sent 2 messages" in hangup.out
        and "stopped: " in hangup.err
        and hangup.clean,
        f"{hangup.out.strip().splitlines()[-1] if hangup.out else ''}; "
        f"{hangup.err.strip()}; writes spent {before - writes_left(ADDRESS)}",
    )


# --- the mcp server ----------------------------------------------------------------


class Mcp:
    """A bare mcp client: json-rpc lines over `harald mcp`'s stdin and stdout."""

    def __init__(self, home: Path) -> None:
        self.proc = subprocess.Popen(
            [HARALD, "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env(home),
            text=True,
            bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self.log: list[str] = []  # the server's stderr, drained so it never blocks
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(
            target=self.log.extend, args=(self.proc.stderr,), daemon=True
        ).start()
        self.ids = 0
        self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "harald-rig", "version": "1"},
            },
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.lines.put(line)

    def _send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict, timeout: float = 90) -> dict:
        self.ids += 1
        self._send(
            {"jsonrpc": "2.0", "id": self.ids, "method": method, "params": params}
        )
        deadline = time.monotonic() + timeout
        while True:
            line = self.lines.get(timeout=max(0.1, deadline - time.monotonic()))
            message = json.loads(line)
            if message.get("id") == self.ids:
                if "error" in message:
                    raise RuntimeError(f"mcp {method}: {message['error']}")
                return message["result"]

    def call(self, tool: str, **arguments) -> object:
        """The tool's json value: a list or record, or {"error", "hint"}."""
        result = self.request("tools/call", {"name": tool, "arguments": arguments})
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured.get("result", structured)
        texts = [c["text"] for c in result.get("content", []) if c["type"] == "text"]
        values = [json.loads(text) for text in texts]
        return values[0] if len(values) == 1 else values

    def close(self) -> None:
        self.proc.stdin.close()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def check_mcp() -> None:
    mcp = Mcp(ARMED)
    try:
        records = mcp.call("classic_services", address=ADDRESS)
        if not isinstance(records, list):
            records = []
        by_channel = {r.get("channel"): r for r in records if isinstance(r, dict)}
        ok = (
            VENDOR in by_channel.get(VENDOR_CH, {}).get("uuids", [])
            and SPP in by_channel.get(SPP_CH, {}).get("uuids", [])
            and HANDS_FREE in by_channel.get(HANDS_FREE_CH, {}).get("uuids", [])
            and by_channel[HANDS_FREE_CH].get("protected") is True
            and by_channel[VENDOR_CH].get("protected") is False
        )
        report(
            "mcp classic_services",
            ok,
            ", ".join(
                f"ch {r.get('channel')} {r.get('name')}"
                + (" protected" if r.get("protected") else "")
                for r in records
            )
            or str(records),
        )

        before = writes_left(ADDRESS)
        sent = mcp.call(
            "classic_send",
            address=ADDRESS,
            service=VENDOR,
            messages_hex=["a5c1"],
            listen=1.0,
        )
        echo = (
            [c.get("value_hex") for c in sent.get("received", [])]
            if isinstance(sent, dict)
            else []
        )
        after = writes_left(ADDRESS)
        report(
            "mcp classic_send echoes, one arm write",
            isinstance(sent, dict)
            and sent.get("sent") == 1
            and "".join(echo) == "eea5c1"
            and sent.get("writes_left") == after == before - 1
            and sent.get("stopped") == "",
            f"received {echo}, writes left {before} -> {after}" if echo else str(sent),
        )

        refused = mcp.call(
            "classic_send",
            address=ADDRESS,
            service="111e",
            messages_hex=["01"],
            listen=0,
        )
        report(
            "mcp classic_send refuses hands-free",
            isinstance(refused, dict)
            and "standard profile" in refused.get("error", ""),
            str(refused),
        )
    finally:
        mcp.close()

    mcp = Mcp(EMPTY)
    try:
        refused = mcp.call(
            "classic_send",
            address=ADDRESS,
            service=VENDOR,
            messages_hex=["01"],
            listen=0,
        )
        report(
            "mcp classic_send refuses when unarmed",
            isinstance(refused, dict)
            and f"writes to {ADDRESS} are locked" in refused.get("error", ""),
            str(refused),
        )
    finally:
        mcp.close()


# --- drivers -----------------------------------------------------------------------


def check_driver() -> None:
    spec = DriverSpec(
        slug="harald-gadget",
        name="harald gadget",
        vendor="harald rig",
        address_hint="",
        name_hint=NAME,
        service_uuid=VENDOR,
        write_char_uuid="",
        cipher=None,
        key_hex=None,
        commands=[DriverCommand("say", ["value"], "bytes.fromhex(value)")],
        transport="classic",
        init_payloads=["a501"],
        reply_seconds=1.0,
    )
    source = render_driver(spec)
    path = WORK / "driver" / "driver.py"
    path.parent.mkdir()
    path.write_text(source)
    probe = run(
        ["uv", "run", "--quiet", "--no-project", "python", "-c"]
        + [
            "import socket, sys; print(sys.version.split()[0], hasattr(socket, 'AF_BLUETOOTH'))"
        ]
    )
    driver = run(["uv", "run", "--quiet", str(path), "say", "a5b2"], timeout=300)
    report(
        "rendered classic driver runs on linux (by name, sdp, rfcomm)",
        "dbus-fast>=2; sys_platform == 'linux'" in source
        and driver.code == 0
        and f"sent say to {ADDRESS}" in driver.out
        and "reply: eea501eea5b2" in driver.out,
        " | ".join(driver.out.strip().splitlines()) or driver.tail(),
    )
    version, *has = probe.out.split() or [""]
    report(
        "uv run picks uv's python 3.13 for drivers",
        version.startswith("3.13.") and has == ["False"],
        f"python, AF_BLUETOOTH: {probe.out.strip() or probe.tail()}",
    )


def check_wh1000xm5() -> None:
    battery = hrun("drive", "wh-1000xm5", "--address", ADDRESS, "battery", timeout=300)
    status = hrun("drive", "wh-1000xm5", "--address", ADDRESS, "status", timeout=300)
    report(
        "stretch: harald drive wh-1000xm5 battery and status",
        battery.code == 0
        and battery.out.strip() == "battery 62%, not charging"
        and status.code == 0
        and status.out.strip() == "noise cancelling on",
        f"{battery.out.strip() or battery.tail()}; {status.out.strip() or status.tail()}",
    )


# --- bluetooth le ------------------------------------------------------------------


def check_ble() -> None:
    scan = hrun("scan", "--timeout", "8")
    line = next((x for x in scan.out.splitlines() if LE_ADDRESS in x.upper()), "")
    report(
        "ble scan finds the gadget",
        scan.code == 0 and NAME in line,
        " ".join(line.split()) or scan.tail(),
    )

    connect = hrun("connect", LE_ADDRESS)
    report(
        "ble connect lists the gadget's service",
        connect.code == 0
        and f"service {GATT_SERVICE}" in connect.out
        and all(c in connect.out for c in (GATT_READ, GATT_WRITE, GATT_NOTIFY)),
        f"{len(connect.out.splitlines())} lines, {connect.seconds:.1f} s"
        if connect.code == 0
        else connect.tail(),
    )

    read = hrun("read", LE_ADDRESS, GATT_READ)
    report(
        "ble read",
        read.code == 0 and read.out.strip() == b"harald-read".hex(),
        read.out.strip() or read.tail(),
    )

    unarmed = hrun("write", LE_ADDRESS, GATT_WRITE, "102030", home=EMPTY)
    report(
        "ble write refused when unarmed",
        unarmed.code == 2 and "are locked" in unarmed.err and unarmed.clean,
        unarmed.err.strip().splitlines()[0] if unarmed.err else unarmed.tail(),
    )

    arm.arm(LE_ADDRESS, writes=5, minutes=15)
    before = writes_left(LE_ADDRESS)
    write = hrun("write", LE_ADDRESS, GATT_WRITE, "102030", "--response")
    after = writes_left(LE_ADDRESS)
    report(
        "ble write after arming, one arm write",
        write.code == 0
        and before - after == 1
        and f"writes left: {after}" in write.out,
        write.out.strip() or write.tail(),
    )

    mcp = Mcp(ARMED)
    try:
        events = mcp.call(
            "subscribe", address=LE_ADDRESS, char_uuid=GATT_NOTIFY, seconds=2
        )
    finally:
        mcp.close()
    values = [e.get("value_hex") for e in events] if isinstance(events, list) else []
    report(
        "ble subscribe gets a notification (mcp subscribe)",
        GREETING in values,
        str(values) if values else str(events),
    )


# --- closing a linux channel -------------------------------------------------------


def readers() -> int:
    return sum(t.name == "harald-rfcomm-reader" for t in threading.enumerate())


def check_close_latency() -> None:
    timings = []
    for _ in range(3):
        cli = hrun("classic", "send", ADDRESS, VENDOR, "a5d0", "--listen", "0")
        timings.append(cli.seconds)
    report(
        "classic send --listen 0, whole command",
        cli.code == 0,
        ", ".join(f"{t:.2f} s" for t in timings) if cli.code == 0 else cli.tail(),
    )

    fds = len(os.listdir("/proc/self/fd"))
    backend = LinuxBackend()
    numbers: dict[str, float] = {}

    started = time.monotonic()
    channel = backend.open(ADDRESS, VENDOR_CH)
    numbers["open"] = time.monotonic() - started
    started = time.monotonic()
    channel.close()
    numbers["close idle"] = time.monotonic() - started

    channel = backend.open(ADDRESS, VENDOR_CH)
    woke: list[float] = []
    drainer = threading.Thread(
        target=lambda: (channel.drain(10), woke.append(time.monotonic()))
    )
    drainer.start()
    time.sleep(0.3)
    started = time.monotonic()
    channel.close()
    numbers["close"] = time.monotonic() - started
    drainer.join(5)
    numbers["drain woken"] = (woke[0] if woke else time.monotonic() + 99) - started

    channel = backend.open(ADDRESS, VENDOR_CH)
    channel.write(b"\xa5\xd1")  # its echo is on its way back
    started = time.monotonic()
    channel.close()
    numbers["close mid-reply"] = time.monotonic() - started

    async def cancelled_send() -> float:
        task = asyncio.create_task(
            classic.send(ADDRESS, VENDOR, [b"\xa5\xd2"], 10.0, backend=backend)
        )
        await asyncio.sleep(1.0)
        started = time.monotonic()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return time.monotonic() - started

    numbers["cancelled send"] = asyncio.run(cancelled_send())
    time.sleep(CLOSE_LIMIT + 0.5)
    left, leaked = readers(), len(os.listdir("/proc/self/fd")) - fds
    report(
        f"linux channel close and cancel under {CLOSE_LIMIT:g} s, nothing leaks",
        all(v < CLOSE_LIMIT for k, v in numbers.items() if k != "open")
        and left == 0
        and leaked <= 0,
        ", ".join(f"{k} {v * 1000:.0f} ms" for k, v in numbers.items())
        + f"; reader threads left {left}, fds leaked {leaked}",
    )

    async def back_to_back(count: int) -> list[str]:
        """Sends one after another on one backend, as an mcp server makes them: each
        opens the channel the last one has only just closed."""
        outcomes = []
        for i in range(count):
            try:
                result = await classic.send(
                    ADDRESS, VENDOR, [bytes([0xA5, 0xE0 + i])], 0.0, backend=backend
                )
                outcomes.append("ok" if result.sent == 1 else result.stopped)
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                outcomes.append(str(exc))
        return outcomes

    started = time.monotonic()
    outcomes = asyncio.run(back_to_back(12))
    failures = [outcome for outcome in outcomes if outcome != "ok"]
    report(
        "12 classic sends back to back on one backend",
        not failures,
        f"{outcomes.count('ok')} ok in {time.monotonic() - started:.1f} s"
        + (f"; {failures[:2]}" if failures else ""),
    )


# --- bluetooth off -----------------------------------------------------------------


def check_adapter_off() -> None:
    run(["bluetoothctl", "power", "off"])
    try:
        time.sleep(0.5)
        devices = hrun("classic", "devices")
        scan = hrun("scan", "--timeout", "2")
    finally:
        run(["bluetoothctl", "power", "on"])
    report(
        "adapter off: a hint, never a traceback",
        all(r.code == 2 and "hint:" in r.err and r.clean for r in (devices, scan)),
        " | ".join(r.err.strip().splitlines()[0] for r in (devices, scan) if r.err)
        or devices.tail(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tree", type=Path, help="the tree harald was installed from")
    args = parser.parse_args()
    os.environ["HARALD_HOME"] = str(ARMED)  # where this process arms
    ARMED.mkdir()
    EMPTY.mkdir()
    steps: list[tuple[str, Callable[[], None]]] = [
        ("python", lambda: check_python(args.tree)),
        ("pairing", pair_gadget),
        ("classic cli", check_classic_cli),
        ("mcp", check_mcp),
        ("driver", check_driver),
        ("wh-1000xm5", check_wh1000xm5),
        ("ble", check_ble),
        ("close latency", check_close_latency),
        ("adapter off", check_adapter_off),
    ]
    for name, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - a failed check, not a crashed run
            traceback.print_exc()
            report(f"{name} (crashed)", False, f"{type(exc).__name__}: {exc}")
    failed = [r for r in results if not r[1]]
    width = max(len(name) for name, _, _ in results)
    print(f"\n{'check':<{width}}  result  detail")
    for name, ok, detail in results:
        print(f"{name:<{width}}  {'PASS' if ok else 'FAIL':<6}  {detail}")
    print(
        f"\n{len(results) - len(failed)} passed, {len(failed)} failed, "
        f"{time.time() - STARTED:.0f} s"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
