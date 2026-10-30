"""The mcp server, driven through `MCPServer.call_tool` the way a client calls it."""

import zipfile

import pytest
from bleak.exc import BleakError
from capture_helpers import write_capture
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService

from harald.arm import arm
from harald.server import EXPECTED_TOOLS, build_server

ADDR = "AA-11"


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

    not_zip = tmp_path / "broken.apk"
    not_zip.write_bytes(b"not a zip")
    assert await call(server, "analyze_apk", path=str(not_zip)) == {
        "error": "file is not a zip file",
        "hint": "",
    }
