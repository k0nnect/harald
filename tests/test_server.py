"""The mcp server, driven through `MCPServer.call_tool` the way a client calls it."""

import asyncio
import sys
import zipfile

import pytest
from bleak.exc import BleakError
from capture_helpers import mixed_capture, write_capture
from classic_fakes import XM5_ADDRESS, FakeBackend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService

import harald
from harald import server as server_module
from harald.apk import ApkReport, Candidate
from harald.arm import arm, live_grant
from harald.classic import ClassicDevice
from harald.server import EXPECTED_TOOLS, INSTRUCTIONS, build_server

ADDR = "AA-11"
HPC = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"  # an xm5 vendor channel, 9
M1 = bytes.fromhex("3e0c00000000020000103c")
ACK = bytes.fromhex("3e010100000000023c")
HELLO = bytes.fromhex("3e0c000000000801000300201600004f3c")


async def call(server, name, **arguments):
    """Run one tool through the server; return its structured result."""
    result = await server.call_tool(name, arguments)
    return result.structured_content["result"]


async def test_tools_registered():
    server = build_server()
    names = {tool.name for tool in await server.list_tools()}
    assert names == EXPECTED_TOOLS
    assert EXPECTED_TOOLS == {
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
        "classic_devices",
        "classic_services",
        "classic_send",
        "classic_listen",
    }
    assert {"arm", "disarm", "write_enable"}.isdisjoint(names)


async def test_write_refused_when_not_armed():
    server = build_server(client_cls=FakeClient)
    result = await call(
        server, "write_char", address=ADDR, char_uuid=CHR, data_hex="0102"
    )
    assert set(result) == {"error", "hint"}
    assert "harald arm" in result["hint"]
    assert FakeClient.writes == []


async def test_write_reaches_client_when_armed():
    arm("aa-11", writes=5)
    server = build_server(client_cls=FakeClient)
    result = await call(
        server, "write_char", address=ADDR, char_uuid=CHR, data_hex="0102"
    )
    assert result == {"writes_left": 4}
    # the default fake characteristic allows write-without-response, so that is used
    assert FakeClient.writes == [(CHR, b"\x01\x02", False)]


@pytest.mark.parametrize(
    "error", [BleakError("Not connected"), OSError("link lost"), TimeoutError()]
)
async def test_failing_disconnect_keeps_the_result_and_the_error(error):
    FakeClient.reset(disconnect_error=error)
    server = build_server(client_cls=FakeClient)
    denied = await call(
        server, "write_char", address=ADDR, char_uuid=CHR, data_hex="0102"
    )
    assert denied["error"] == "writes to AA-11 are locked"
    assert "harald arm" in denied["hint"]
    arm("aa-11", writes=5)
    result = await call(
        server, "write_char", address=ADDR, char_uuid=CHR, data_hex="0102"
    )
    assert result == {"writes_left": 4}
    assert FakeClient.writes == [(CHR, b"\x01\x02", False)]


async def test_write_type_defaults_to_the_characteristic():
    arm("aa-11", writes=5)
    FakeClient.reset(services=[FakeService(SVC, [FakeChar(CHR, 0x12, ["write"])])])
    server = build_server(client_cls=FakeClient)
    await call(server, "write_char", address=ADDR, char_uuid=CHR, data_hex="01")
    await call(
        server, "write_char", address=ADDR, char_uuid=CHR, data_hex="02", response=False
    )
    assert FakeClient.writes == [(CHR, b"\x01", True), (CHR, b"\x02", False)]


async def test_scan_tool_sorted():
    server = build_server(scanner_cls=FakeScanner)
    devices = await call(server, "scan", timeout=0.1)
    assert [d["address"] for d in devices] == ["BB-22", "AA-11", "CC-33"]
    assert [d["rssi"] for d in devices] == [-40, -70, -90]
    assert devices[1]["manufacturer_data"] == {"0x004c": "0215"}


async def test_open_capture_filters_by_connection(tmp_path):
    path = write_capture(tmp_path, discovery=True, writes=[b"\x01", b"\x02"])
    server = build_server()
    out = await call(server, "open_capture", path=str(path), conn=0x0040)
    assert "c=0x0040  phone->device  write_cmd  h=0x0012  ffe1  01" in out
    assert out.endswith("showing 1–2 of 2 events with c=0x0040")
    other = await call(server, "open_capture", path=str(path), conn=0x0041)
    assert other == "showing 0 of 0 events with c=0x0041"


async def test_open_capture_filters_by_rfcomm_channel(tmp_path):
    server = build_server()
    out = await call(
        server, "open_capture", path=str(mixed_capture(tmp_path)), channel=9
    )
    lines = out.splitlines()
    assert [line.split("  ")[0] for line in lines[:-1]] == ["#1", "#3", "#6", "#8"]
    assert lines[1] == "#3  +0.750s  c=0x000b  phone->device  rfcomm  ch=9  -  3e 0c 00"
    assert lines[-1] == "showing 1–4 of 4 events with ch=9"
    [tool] = [t for t in await server.list_tools() if t.name == "open_capture"]
    assert "channel" in tool.input_schema["properties"]
    doc = " ".join(tool.description.split())
    for words in ("rfcomm", "channel", "btsnoop", "iap2"):
        assert words in doc


async def test_missing_capture_returns_error(tmp_path):
    server = build_server()
    result = await call(server, "open_capture", path=str(tmp_path / "missing.pklg"))
    assert "no such file" in result["error"]
    assert result["hint"] == ""


async def test_read_tools_return_hex():
    FakeClient.reset(reads={CHR: b"\x0a\x0b"}, notifications={CHR: [b"\x01", b"\x02"]})
    server = build_server(client_cls=FakeClient)
    info = await call(server, "connect", address=ADDR)
    assert info["services"] == [
        {
            "uuid": SVC,
            "chars": [
                {
                    "uuid": CHR,
                    "handle": 0x12,
                    "properties": ["write-without-response", "notify"],
                }
            ],
        }
    ]
    assert await call(server, "read_char", address=ADDR, char_uuid="ffe1") == "0a0b"
    events = await call(server, "subscribe", address=ADDR, char_uuid=CHR, seconds=0)
    assert [e["value_hex"] for e in events] == ["01", "02"]


async def test_ble_error_returns_error():
    server = build_server(client_cls=FakeClient)
    result = await call(server, "read_char", address=ADDR, char_uuid="ffe2")
    assert "0000ffe2-0000-1000-8000-00805f9b34fb was not found" in result["error"]
    assert result["hint"] == ""


def _ecb(key: bytes, plain: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plain) + encryptor.finalize()


async def test_analysis_tools_take_and_give_hex():
    server = build_server()
    report = await call(server, "diff", payloads_hex=["7e01ff", "7e0200"])
    assert report == {
        "lengths": {"3": 2},
        "constant": {"0": "7e"},
        "varying": [1, 2],
        "looks_encrypted": False,
    }
    assert "sum8 at -1" in await call(server, "guess_checks", payload_hex="010203")

    key = bytes(range(16))
    payloads = [_ecb(key, bytes([0x54, c]) + bytes(14)).hex() for c in (0x00, 0x80)]
    ranked = await call(
        server, "try_keys", payloads_hex=payloads, keys_hex=[bytes(16).hex(), key.hex()]
    )
    assert ranked[0]["key_hex"] == key.hex()
    assert ranked[0]["samples"][0].startswith("5400")

    bad = await call(server, "guess_checks", payload_hex="zz")
    assert bad["error"] and bad["hint"] == ""


async def test_notes_and_library_tools(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    server = build_server()
    assert await call(server, "read_notes", slug="demo-lamp") == ""
    saved = await call(
        server, "save_note", slug="demo-lamp", text="ffe1 takes 7e frames"
    )
    assert saved == {"saved": True}
    assert "ffe1 takes 7e frames" in await call(server, "read_notes", slug="demo-lamp")
    assert (tmp_path / "harald-work" / "demo-lamp" / "notes.md").is_file()

    escape = await call(server, "save_note", slug="../escape", text="x")
    assert "invalid device slug" in escape["error"]
    unknown = await call(server, "load_device", slug="nope")
    assert "harald devices" in unknown["hint"]


async def test_analyze_apk_returns_plain_values(tmp_path):
    apk = tmp_path / "flutter.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libapp.so", b"\x00")
    server = build_server()
    report = await call(server, "analyze_apk", path=str(apk))
    assert report["path"] == str(apk)
    assert report["framework"] == "flutter"
    assert report["jadx_dir"] is None
    assert report["totals"] == {}

    not_zip = tmp_path / "broken.apk"
    not_zip.write_bytes(b"not a zip")
    assert await call(server, "analyze_apk", path=str(not_zip)) == {
        "error": "file is not a zip file",
        "hint": "",
    }


async def test_analyze_apk_returns_the_totals(tmp_path, monkeypatch):
    report = ApkReport(
        path=tmp_path / "app.apk",
        package="com.example.gadget",
        framework="native",
        gatt_uuids=["0000ffe1-0000-1000-8000-00805f9b34fb"],
        candidates=[Candidate("char-uuid", "sources/a/Ble.java:3", "UUID u = x;")],
        jadx_dir=tmp_path / "jadx",
        warnings=[],
        totals={"gatt_uuids": 61, "char-uuid": 61, "aes-key": 0},
    )
    monkeypatch.setattr("harald.apk.analyze_apk", lambda path: report)
    result = await call(build_server(), "analyze_apk", path=str(report.path))
    assert result["totals"] == {"gatt_uuids": 61, "char-uuid": 61, "aes-key": 0}
    assert result["candidates"] == [
        {
            "kind": "char-uuid",
            "location": "sources/a/Ble.java:3",
            "snippet": "UUID u = x;",
        }
    ]
    assert result["jadx_dir"] == str(tmp_path / "jadx")


async def test_instructions_mention_classic_and_no_arm_tool():
    assert "bluetooth le or classic (rfcomm) protocol" in INSTRUCTIONS
    assert "write_char and classic_send are refused" in INSTRUCTIONS
    assert "harald arm <address>" in INSTRUCTIONS
    assert "no tool can arm" in INSTRUCTIONS
    assert 'returns {"error": ..., "hint": ...}: act on the hint' in INSTRUCTIONS
    tools = {tool.name: tool for tool in await build_server().list_tools()}
    send_doc = " ".join(tools["classic_send"].description.split())
    for phrase in (
        "harald arm <address>",
        "each message spends one armed write, a query included",
        "classic has no read",
        "one connection, in order",
        "handshakes and acks",
        "classic_services",
        "firmware-update channels stay blocked",
        "0 = before the first",
        "stopped",
    ):
        assert phrase in send_doc
    assert send_doc == send_doc.lower()


async def test_classic_tool_descriptions_fit_a_mac_and_linux():
    # docstrings are fixed when the server is built, so they name no platform
    tools = {tool.name: tool for tool in await build_server().list_tools()}
    classic_tools = (
        "classic_devices",
        "classic_services",
        "classic_send",
        "classic_listen",
    )
    for name in classic_tools:
        doc = " ".join(tools[name].description.split())
        assert "mac" not in doc
        assert "system settings" not in doc
    devices_doc = " ".join(tools["classic_devices"].description.split())
    assert "paired with this computer" in devices_doc
    services_doc = " ".join(tools["classic_services"].description.split())
    assert "records from this computer's cache" in services_doc


async def test_classic_devices_shape():
    backend = FakeBackend(devices=[ClassicDevice(XM5_ADDRESS, "WH-1000XM5", True)])
    server = build_server(classic_backend=backend)
    assert await call(server, "classic_devices") == [
        {"address": XM5_ADDRESS, "name": "WH-1000XM5", "connected": True}
    ]


async def test_classic_services_shape():
    backend = FakeBackend()
    server = build_server(classic_backend=backend)
    records = await call(server, "classic_services", address=XM5_ADDRESS)
    assert records[0] == {
        "name": "Hands-Free unit",
        "uuids": ["0000111e-0000-1000-8000-00805f9b34fb"],
        "channel": 1,
        "protected": True,
        "firmware_update": False,
    }
    hpc = next(r for r in records if r["channel"] == 9)
    assert hpc["protected"] is False
    await call(server, "classic_services", address=XM5_ADDRESS, refresh=True)
    assert backend.asked == [(XM5_ADDRESS, False), (XM5_ADDRESS, True)]


async def test_classic_send_unarmed_is_a_failure_dict():
    backend = FakeBackend()
    server = build_server(classic_backend=backend)
    result = await call(
        server,
        "classic_send",
        address=XM5_ADDRESS,
        service="9",
        messages_hex=[M1.hex()],
    )
    assert result == {
        "error": "writes to aa:bb:cc:11:22:33 are locked",
        "hint": "ask the human to run: harald arm aa:bb:cc:11:22:33 --writes 50 --minutes 30",
    }
    assert backend.opened == []


async def test_classic_send_shape():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(replies={M1: [ACK]})
    server = build_server(classic_backend=backend)
    result = await call(
        server,
        "classic_send",
        address=XM5_ADDRESS,
        service=HPC,
        messages_hex=[M1.hex()],
        listen=0.5,
    )
    assert set(result) == {"sent", "writes_left", "received", "stopped"}
    assert result["sent"] == 1
    assert result["writes_left"] == 4
    assert result["stopped"] == ""
    [chunk] = result["received"]
    assert set(chunk) == {"after", "seconds", "value_hex"}
    assert chunk["after"] == 1
    assert chunk["value_hex"] == ACK.hex()
    assert chunk["seconds"] == round(chunk["seconds"], 3)
    assert backend.writes == [M1]
    assert backend.channel.drains == [0.0, 0.5]
    assert live_grant(XM5_ADDRESS).writes_left == 4


async def test_classic_send_bad_hex_is_a_failure_dict():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    server = build_server(classic_backend=backend)
    result = await call(
        server, "classic_send", address=XM5_ADDRESS, service="9", messages_hex=["zz"]
    )
    assert result["error"] and result["hint"] == ""
    assert backend.opened == []
    assert live_grant(XM5_ADDRESS).writes_left == 5


async def test_classic_send_empty_message_is_a_failure_dict():
    # "" is valid hex for no bytes at all: refused before a write is spent
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    server = build_server(classic_backend=backend)
    result = await call(
        server,
        "classic_send",
        address=XM5_ADDRESS,
        service="9",
        messages_hex=[M1.hex(), ""],
    )
    assert result == {
        "error": "empty message",
        "hint": "each message needs at least one byte of hex",
    }
    assert backend.opened == []
    assert backend.writes == []
    assert live_grant(XM5_ADDRESS).writes_left == 5


async def test_classic_listening_over_30_seconds_is_a_failure_dict():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    server = build_server(classic_backend=backend)
    sent = await call(
        server,
        "classic_send",
        address=XM5_ADDRESS,
        service="9",
        messages_hex=[M1.hex()],
        listen=31,
    )
    heard = await call(
        server, "classic_listen", address=XM5_ADDRESS, service="9", seconds=31
    )
    assert sent["error"] == "listen must be from 0 to 30 s, got 31"
    assert heard["error"] == "seconds must be from 0 to 30 s, got 31"
    assert backend.opened == []
    assert live_grant(XM5_ADDRESS).writes_left == 5


async def test_classic_listen_shape():
    backend = FakeBackend(on_open=[HELLO])
    server = build_server(classic_backend=backend)
    chunks = await call(
        server, "classic_listen", address=XM5_ADDRESS, service="9", seconds=0.5
    )
    assert [set(c) for c in chunks] == [{"seconds", "value_hex"}]
    assert chunks[0]["value_hex"] == HELLO.hex()
    assert backend.channel.drains == [0.5]


async def test_classic_listen_protected_is_a_failure_dict():
    backend = FakeBackend()
    server = build_server(classic_backend=backend)
    result = await call(
        server, "classic_listen", address=XM5_ADDRESS, service="1", seconds=1.0
    )
    assert result["error"] == "channel 1 on aa:bb:cc:11:22:33 is a standard profile"
    assert "harald classic services aa:bb:cc:11:22:33" in result["hint"]
    assert backend.opened == []


class StandInServer:
    def __init__(self, ran):
        self.ran = ran

    def run(self, transport):
        self.ran.append(("serve", transport))


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("darwin", [("run_main", "enter"), ("serve", "stdio"), ("run_main", "exit")]),
        ("linux", [("serve", "stdio")]),
    ],
)
def test_run_serves_under_run_main_only_on_darwin(monkeypatch, platform, expected):
    ran = []

    def run_main(fn):
        ran.append(("run_main", "enter"))
        result = fn()
        ran.append(("run_main", "exit"))
        return result

    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr("harald.classic_mac.run_main", run_main)
    monkeypatch.setattr(server_module, "build_server", lambda: StandInServer(ran))
    server_module.run()
    assert ran == expected


def test_run_serves_directly_when_the_mac_backend_cannot_load(monkeypatch):
    ran = []
    monkeypatch.setattr(sys, "platform", "darwin")
    # if the import below were not blocked, run_main would show up in `ran`
    monkeypatch.setattr(
        "harald.classic_mac.run_main", lambda fn: ran.append(("run_main", fn))
    )
    # `from harald import classic_mac` takes the package attribute when it is
    # there, so block both the attribute and the module entry
    monkeypatch.delattr(harald, "classic_mac", raising=False)
    monkeypatch.setitem(sys.modules, "harald.classic_mac", None)
    monkeypatch.setattr(server_module, "build_server", lambda: StandInServer(ran))
    server_module.run()
    assert ran == [("serve", "stdio")]


def test_ble_tools_answer_under_the_real_run_main():
    # `harald mcp` serves under run_main on a mac, so every tool runs off the main
    # thread; the fakes stand in for the radio, and run_main only pumps the run loop
    pytest.importorskip("IOBluetooth")
    from harald.classic_mac import run_main

    async def session():
        server = build_server(scanner_cls=FakeScanner, client_cls=FakeClient)
        devices = await call(server, "scan", timeout=0.1)
        value = await call(server, "read_char", address=ADDR, char_uuid=CHR)
        return devices, value

    FakeClient.reset(reads={CHR: b"\x0a\x0b"})
    devices, value = run_main(lambda: asyncio.run(session()))
    assert [d["address"] for d in devices] == ["BB-22", "AA-11", "CC-33"]
    assert value == "0a0b"
