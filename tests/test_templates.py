"""Output templates: a protocol write-up and a standalone driver, rendered from a spec.

The rendered driver is loaded as a module and driven with the bleak fakes, so no
test needs a radio.
"""

import importlib.util
import re
import sys
import tomllib
from dataclasses import replace

import pytest
from bleak.exc import BleakError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService

from harald.errors import HaraldError
from harald.templates import DriverCommand, DriverSpec, render_driver, render_protocol

KEY_HEX = "000102030405060708090a0b0c0d0e0f"
# the reference regex from pep 723, for the `# /// script` block that uv reads
SCRIPT_BLOCK = re.compile(
    r"(?m)^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$"
)
BASIC_CSS = (
    "black", "silver", "gray", "white", "maroon", "red", "purple", "fuchsia",
    "green", "lime", "olive", "yellow", "navy", "blue", "teal", "aqua",
)  # fmt: skip


@pytest.fixture
def spec() -> DriverSpec:
    return DriverSpec(
        slug="demo-lamp",
        name="demo lamp",
        vendor="acme",
        address_hint="AA-11",
        service_uuid=SVC,
        write_char_uuid=CHR,
        cipher="aes-ecb",
        key_hex=KEY_HEX,
        commands=[
            DriverCommand(
                "color",
                ["color"],
                r'(b"\x7e\x00\x05\x03" + rgb_bytes(color)).ljust(16, b"\x00")',
            ),
            DriverCommand("on", [], r'b"\x7e\x00\x04\x01".ljust(16, b"\x00")'),
            DriverCommand("off", [], r'b"\x7e\x00\x04\x00".ljust(16, b"\x00")'),
            DriverCommand(
                "brightness",
                ["level"],
                r'(b"\x7e\x00\x01" + bytes([int(level)])).ljust(16, b"\x00")',
            ),
        ],
    )


def load_driver(spec: DriverSpec, tmp_path):
    """Render `spec`, load it as a module, and point it at the bleak fakes."""
    path = tmp_path / "driver.py"
    path.write_text(render_driver(spec), encoding="utf-8")
    module_spec = importlib.util.spec_from_file_location("rendered_driver", path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    module.BleakClient = FakeClient
    module.BleakScanner = FakeScanner
    return module


def aes_decrypt(data: bytes, mode) -> bytes:
    decryptor = Cipher(algorithms.AES(bytes.fromhex(KEY_HEX)), mode).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def test_render_driver_is_valid_python(spec):
    compile(render_driver(spec), "driver.py", "exec")
    awkward = replace(
        spec, name='bob\'s "lamp"\n', vendor="", cipher=None, key_hex=None
    )
    compile(render_driver(awkward), "driver.py", "exec")


def test_render_driver_has_cli_and_commands(spec):
    source = render_driver(spec)
    assert "argparse" in source
    assert "def main(" in source
    for command in spec.commands:
        assert command.name in source


def test_render_driver_is_standalone(spec):
    source = render_driver(spec)
    assert "import harald" not in source
    assert "from harald" not in source


def test_render_protocol_contains_fields(spec):
    text = render_protocol(spec)
    assert spec.service_uuid in text
    assert spec.cipher in text
    for command in spec.commands:
        assert command.name in text
    headings = [line for line in text.splitlines() if line.startswith("#")]
    assert headings
    for heading in headings:
        assert heading == heading.lower()
        assert heading.isascii()  # so no emoji


def test_driver_declares_its_dependencies_for_uv(spec):
    source = render_driver(spec)
    assert source.startswith("# /// script\n")
    block = SCRIPT_BLOCK.search(source)
    assert block is not None
    assert block["type"] == "script"
    content = "".join(
        line[2:] if line.startswith("# ") else line[1:]
        for line in block["content"].splitlines(keepends=True)
    )
    meta = tomllib.loads(content)
    assert meta["requires-python"] == ">=3.11"
    assert meta["dependencies"] == ["bleak>=3.0", "cryptography>=44"]


def test_driver_knows_colour_names_and_hex(spec, tmp_path):
    driver = load_driver(spec, tmp_path)
    assert set(BASIC_CSS) <= set(driver.COLORS)
    assert driver.rgb_bytes("pink") == bytes.fromhex("ffc0cb")
    assert driver.rgb_bytes("Red") == bytes.fromhex("ff0000")
    assert driver.rgb_bytes("ff8800") == bytes.fromhex("ff8800")
    with pytest.raises(driver.DriverError, match="unknown colour: chartreuse-ish"):
        driver.rgb_bytes("chartreuse-ish")


@pytest.mark.parametrize(
    ("cipher", "mode"),
    [("aes-ecb", modes.ECB()), ("aes-cbc-zero-iv", modes.CBC(bytes(16)))],
)
def test_driver_encrypts_whole_blocks_only(spec, tmp_path, cipher, mode):
    driver = load_driver(replace(spec, cipher=cipher), tmp_path)
    plaintext = bytes(range(32))
    assert aes_decrypt(driver.encrypt(plaintext), mode) == plaintext
    with pytest.raises(driver.DriverError, match="15 bytes"):
        driver.encrypt(bytes(15))


def test_driver_color_pink_writes_without_response_when_allowed(spec, tmp_path, capsys):
    driver = load_driver(spec, tmp_path)
    assert driver.main(["color", "pink"]) == 0
    [(char, data, response)] = FakeClient.writes
    assert char.uuid == CHR
    # the default fake characteristic has write-without-response
    assert response is False
    expected = b"\x7e\x00\x05\x03" + bytes.fromhex("ffc0cb")
    assert aes_decrypt(data, modes.ECB()) == expected.ljust(16, b"\x00")
    assert capsys.readouterr().out == "sent color to AA-11\n"


def test_driver_writes_with_response_otherwise(spec, tmp_path):
    FakeClient.reset(services=[FakeService(SVC, [FakeChar(CHR, 0x12, ["write"])])])
    driver = load_driver(replace(spec, cipher=None, key_hex=None), tmp_path)
    assert driver.main(["brightness", "50"]) == 0
    [(_char, data, response)] = FakeClient.writes
    assert response is True
    assert data == (b"\x7e\x00\x01\x32").ljust(16, b"\x00")  # no cipher: plaintext


def test_driver_address_flag_defaults_to_the_hint(spec, tmp_path):
    parser = load_driver(spec, tmp_path).build_parser()
    assert parser.parse_args(["on"]).address == "AA-11"
    assert parser.parse_args(["--address", "X", "on"]).address == "X"
    assert parser.parse_args(["color", "red", "--address", "X"]).address == "X"


def test_driver_help_and_usage_errors_are_lowercase(
    spec, tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "argv", ["driver.py"])  # argparse's prog
    fade = DriverCommand("fade", ["Speed"], r'bytes([int(Speed)]).ljust(16, b"\x00")')
    mixed = replace(spec, name="Demo Lamp", commands=[*spec.commands, fade])
    driver = load_driver(mixed, tmp_path)
    names = [command.name for command in mixed.commands]
    texts = []
    for argv in (["--help"], *([name, "--help"] for name in names), ["fade"]):
        with pytest.raises(SystemExit):
            driver.main(argv)
        captured = capsys.readouterr()
        texts.append(captured.out + captured.err)
    assert "control demo lamp over bluetooth le" in texts[0]
    assert "--address address" in texts[0]
    assert "arguments are required: speed" in texts[-1]
    for text in texts:
        text = text.replace(mixed.address_hint, "")  # the hint is shown as given
        assert [c for c in text if c.isascii() and c.isupper()] == []


def test_driver_scans_for_the_service_without_an_address(spec, tmp_path, capsys):
    driver = load_driver(replace(spec, address_hint=""), tmp_path)
    assert driver.main(["off"]) == 0
    assert len(FakeClient.writes) == 1
    assert capsys.readouterr().out.endswith("sent off to AA-11\n")  # AA-11 has SVC


def test_driver_reports_when_no_device_advertises_the_service(spec, tmp_path, capsys):
    FakeScanner.reset(adverts=[])
    driver = load_driver(replace(spec, address_hint=""), tmp_path)
    assert driver.main(["off"]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"error: no device advertising {SVC} found\n")
    assert err == err.lower()
    assert FakeClient.writes == []


def test_driver_failing_disconnect_keeps_the_result_and_the_error(
    spec, tmp_path, capsys
):
    FakeClient.reset(disconnect_error=BleakError("Not connected"))
    driver = load_driver(spec, tmp_path)
    assert driver.main(["on"]) == 0
    assert capsys.readouterr().out == "sent on to AA-11\n"
    assert len(FakeClient.writes) == 1
    FakeClient.reset(services=[], disconnect_error=BleakError("Not connected"))
    assert driver.main(["on"]) == 2
    assert capsys.readouterr().err.startswith(
        f"error: characteristic {CHR} not found on AA-11\n"
    )


def test_driver_reports_a_bad_value(spec, tmp_path, capsys):
    driver = load_driver(spec, tmp_path)
    assert driver.main(["brightness", "abc"]) == 2
    assert capsys.readouterr().err.startswith("error: bad value for brightness: ")
    assert FakeClient.writes == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"cipher": "aes-gcm"}, "unknown cipher: aes-gcm"),
        ({"key_hex": None}, "aes-ecb needs key_hex"),
        ({"slug": "Demo Lamp"}, "invalid device slug"),
        ({"commands": [DriverCommand("on", [], "b'\\x01' +")]}, "payload_py for on"),
        ({"commands": [DriverCommand("on", ["for"], "b''")]}, "param for on: 'for'"),
    ],
)
def test_render_refuses_a_bad_spec(spec, change, message):
    bad = replace(spec, **change)
    for render in (render_driver, render_protocol):
        with pytest.raises(HaraldError, match=message):
            render(bad)
