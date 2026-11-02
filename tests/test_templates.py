"""Output templates: a protocol write-up and a standalone driver, rendered from a spec.

The rendered driver is loaded as a module and driven with the bleak fakes, a faked
IOBluetooth, or (for a classic driver's linux link) a fake bluez, sdp server and
rfcomm peer, so no test needs a radio.
"""

import ast
import contextlib
import errno
import importlib.util
import os
import re
import socket
import sys
import time
import tomllib
import types
import uuid
from dataclasses import replace
from importlib.resources import files

import pytest
from bleak.exc import (
    BleakBluetoothNotAvailableError,
    BleakBluetoothNotAvailableReason,
    BleakError,
)
from classic_fakes import XM5_RECORDS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService, advert
from linux_fakes import FakeBluez, Rig, bluez, device, names_needed
from sdp_fixtures import encode_records, response

import harald.classic
import harald.classic_linux
from harald import bluez as bluez_names
from harald import btsock, hints
from harald.classic import BackendError, ServiceRecord
from harald.errors import HaraldError
from harald.templates import (
    DriverCommand,
    DriverSpec,
    linux_link,
    render_driver,
    render_protocol,
)

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
    assert driver.rgb_bytes("pink") == bytes.fromhex("ff1493")
    assert driver.rgb_bytes("Red") == bytes.fromhex("ff0000")
    assert driver.rgb_bytes("ff8800") == bytes.fromhex("ff8800")
    with pytest.raises(driver.DriverError, match="unknown colour: chartreuse-ish"):
        driver.rgb_bytes("chartreuse-ish")


def test_driver_colours_are_saturated_for_leds(spec, tmp_path):
    # an led strip mixes light, so a pale css colour such as pink (ffc0cb) shows as
    # near white. every named colour is a grey (r == g == b) or nearly fully saturated.
    driver = load_driver(spec, tmp_path)
    for name, value in driver.COLORS.items():
        r, g, b = bytes.fromhex(value)
        if r == g == b:
            continue
        top, low = max(r, g, b), min(r, g, b)
        assert (top - low) / top >= 0.9, name
    assert driver.COLORS["green"] == "00ff00"  # css green is a dark green


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
    expected = b"\x7e\x00\x05\x03" + bytes.fromhex("ff1493")
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


def test_driver_finds_a_gadget_that_hides_its_service_by_name(spec, tmp_path, capsys):
    # many gadgets advertise only a name. macos then drops them from a scan filtered
    # by service, so a name_hint has to scan unfiltered and match the name.
    FakeScanner.reset(
        adverts=[advert("DD-44", "lamp-7f3a", -60), advert("EE-55", None, -40)]
    )
    shared = replace(spec, address_hint="", name_hint="lamp-")
    driver = load_driver(shared, tmp_path)
    assert driver.main(["off"]) == 0
    assert capsys.readouterr().out.endswith("sent off to DD-44\n")
    assert len(FakeClient.writes) == 1
    FakeScanner.reset(adverts=[advert("EE-55", "other", -40)])
    assert driver.main(["off"]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"error: no device advertising {SVC} or named lamp-* found\n")
    # without a name_hint the same gadget stays out of reach
    FakeScanner.reset(adverts=[advert("DD-44", "lamp-7f3a", -60)])
    assert load_driver(replace(shared, name_hint=""), tmp_path).main(["off"]) == 2


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


# what a ble driver has always said on a mac when bluetooth is off or not allowed
MAC_BLUETOOTH_OFF = (
    "bluetooth is off or not allowed for this app",
    (
        "turn bluetooth on and allow your terminal app in "
        "system settings > privacy & security > bluetooth"
    ),
)


def test_driver_words_bluetooth_off_for_the_os_it_runs_on(spec, tmp_path, monkeypatch):
    driver = load_driver(spec, tmp_path)  # loaded once: the os is read at run time
    monkeypatch.setattr(sys, "platform", "darwin")
    assert driver.bluetooth_off() == MAC_BLUETOOTH_OFF
    monkeypatch.setattr(sys, "platform", "linux")
    message, hint = driver.bluetooth_off()
    assert hint.startswith("turn bluetooth on with bluetoothctl power on")
    assert "mac" not in message + hint
    assert "system settings" not in hint
    # the driver cannot import harald, so it keeps its own copy of harald's words
    assert (message, hint) == (hints.bluetooth_off_message(), hints.bluetooth_off())
    monkeypatch.setattr(sys, "platform", "darwin")
    assert (hints.bluetooth_off_message(), hints.bluetooth_off()) == MAC_BLUETOOTH_OFF


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_driver_with_bluetooth_off_prints_the_hint_for_its_os(
    spec, tmp_path, monkeypatch, capsys, platform
):
    monkeypatch.setattr(sys, "platform", platform)
    off = BleakBluetoothNotAvailableError(
        "Bluetooth is turned off", BleakBluetoothNotAvailableReason.POWERED_OFF
    )
    FakeClient.reset(connect_error=off)
    assert load_driver(spec, tmp_path).main(["on"]) == 2
    message, hint = (
        MAC_BLUETOOTH_OFF
        if platform == "darwin"
        else (hints.bluetooth_off_message(), hints.bluetooth_off())
    )
    assert capsys.readouterr().err == f"error: {message}\n  hint: {hint}\n"
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


# --- bluetooth classic ----------------------------------------------------------

SPP = "00001101-0000-1000-8000-00805f9b34fb"  # the serial port profile
CLASSIC_ADDRESS = "aa:bb:cc:11:22:33"
PYOBJC = "pyobjc-framework-IOBluetooth>=11; sys_platform == 'darwin'"
DBUS_FAST = "dbus-fast>=2; sys_platform == 'linux'"
STUCK_HINT = (
    "the mac's bluetooth is stuck: turn bluetooth off and on in the menu bar, "
    "then try again"
)
SHARED_CODE = ("COLORS", "DriverError", "rgb_bytes", "build_payload", "encrypt", "fail")
CONNECT_HINT = "turn it on and connect it to this mac in system settings > bluetooth"
TIMEOUT_HINT = (
    "move closer and try again; if it keeps happening, "
    "turn the mac's bluetooth off and on"
)
# IOReturn values, some signed as pyobjc hands them over
IO_ERROR = 0xE00002BC
IO_BUSY = -0x1FFFFD2B  # 0xe00002d5
IO_BAD_ARGUMENT = 0xE00002C2


@pytest.fixture
def classic(spec) -> DriverSpec:
    return replace(
        spec,
        slug="demo-speaker",
        name="demo speaker",
        address_hint="AA-BB-CC-11-22-33",
        service_uuid="1101",
        write_char_uuid="",
        transport="classic",
        init_payloads=["AA 01", "aa02"],
        reply_seconds=1.5,
    )


class FakeLink:
    """Stands in for the classic driver's `open_link`: records the open, the writes,
    the reads and the close, and answers each read with `reply`."""

    address = CLASSIC_ADDRESS

    def __init__(self, reply=b"", write_error=None, close_error=None):
        self.reply = reply
        self.write_error = write_error
        self.close_error = close_error
        self.opened = []
        self.writes = []
        self.reads = []
        self.closed = False

    def open(self, address_hint, name_hint, service_uuid):
        self.opened.append((address_hint, name_hint, service_uuid))
        return self

    def write(self, data):
        if self.write_error is not None:
            raise self.write_error
        self.writes.append(data)

    def read(self, seconds):
        self.reads.append(seconds)
        return self.reply

    def close(self):
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class FakeRunLoop:
    """The main thread's run loop: IOBluetooth's callbacks wait here until the
    driver pumps it, as they do on a mac."""

    def __init__(self):
        self.pending = []

    def later(self, callback):
        self.pending.append(callback)

    def runMode_beforeDate_(self, mode, date):
        ran, self.pending = self.pending, []
        for callback in ran:
            callback()
        return bool(ran)


class FakeRFCOMM:
    """An IOBluetoothRFCOMMChannel. Each write completes with `write_complete` (None:
    never), unless `write_start` refuses it first; each close is counted, and
    confirmed on the run loop."""

    def __init__(
        self, loop, delegate, mtu=4, write_start=0, write_complete=0, close_error=None
    ):
        self.loop, self.delegate, self.mtu = loop, delegate, mtu
        self.write_start, self.write_complete = write_start, write_complete
        self.close_error = close_error
        self.writes, self.closes = [], 0

    def getMTU(self):
        if isinstance(self.mtu, Exception):
            raise self.mtu
        return self.mtu

    def writeAsync_length_refcon_(self, data, length, refcon):
        self.writes.append(bytes(data[:length]))
        if self.write_start:
            return self.write_start
        if self.write_complete is not None:
            self.loop.later(
                lambda: self.delegate.rfcommChannelWriteComplete_refcon_status_(
                    self, refcon, self.write_complete
                )
            )
        return 0

    def closeChannel(self):
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error
        self.hang_up()
        return 0

    def send(self, data):
        """The gadget sends `data`."""
        self.loop.later(
            lambda: self.delegate.rfcommChannelData_data_length_(self, data, len(data))
        )

    def hang_up(self):
        """The channel closes, from either end."""
        self.loop.later(lambda: self.delegate.rfcommChannelClosed_(self))


class FakeRecord:
    """An IOBluetoothSDPServiceRecord with an rfcomm channel, or none."""

    def __init__(self, channel):
        self.channel = channel

    def getRFCOMMChannelID_(self, _):
        return (0, self.channel) if self.channel is not None else (IO_ERROR, 0)


class FakeDevice:
    """A paired IOBluetoothDevice. Its cached service records list `services` on
    rfcomm `channel`. Opening that hands back a FakeRFCOMM: `open_start` is the
    async open's status, and `open_complete` the status its callback brings (None:
    it never comes). `connected_after_open` replaces `connected` once an open has
    started, and `greeting` is data the gadget sends as soon as it is open."""

    def __init__(
        self,
        address,
        name,
        connected=True,
        services=(),
        *,
        loop=None,
        channel=9,
        open_start=0,
        open_complete=0,
        connected_after_open=None,
        greeting=b"",
        **rfcomm,
    ):
        self._address, self._name, self._connected = address, name, connected
        self.services, self.loop, self.channel = services, loop, channel
        self.open_start, self.open_complete = open_start, open_complete
        self.connected_after_open, self.greeting = connected_after_open, greeting
        self.rfcomm_options, self.rfcomm, self.opened = rfcomm, None, []

    def addressString(self):
        return self._address

    def name(self):
        return self._name

    def isConnected(self):
        return self._connected

    def getServiceRecordForUUID_(self, sdp_uuid):
        return FakeRecord(self.channel) if sdp_uuid in self.services else None

    def openRFCOMMChannelAsync_withChannelID_delegate_(self, _, channel, delegate):
        self.opened.append(channel)
        if self.connected_after_open is not None:
            self._connected = self.connected_after_open
        rfcomm = self.rfcomm = FakeRFCOMM(self.loop, delegate, **self.rfcomm_options)
        if self.open_start == 0 and self.open_complete is not None:
            self.loop.later(
                lambda: delegate.rfcommChannelOpenComplete_status_(
                    rfcomm, self.open_complete
                )
            )
            if self.greeting:
                rfcomm.send(self.greeting)
        return self.open_start, rfcomm


class FakeNSObject:
    """Enough of NSObject for the driver's own delegate class: alloc, then init."""

    @classmethod
    def alloc(cls):
        return cls.__new__(cls)

    def init(self):
        return self


class NoSuchClass(Exception):
    pass


def no_such_class(name):
    raise NoSuchClass(name)


class FakeMac:
    """What the classic driver's mac_modules hands back: pyobjc and IOBluetooth,
    faked around one run loop and the paired devices (None: bluetooth is off)."""

    def __init__(self):
        self.loop = FakeRunLoop()
        self.paired = []
        self.IOBluetooth = types.SimpleNamespace(
            IOBluetoothDevice=types.SimpleNamespace(pairedDevices=lambda: self.paired),
            IOBluetoothSDPUUID=types.SimpleNamespace(
                uuidWithBytes_length_=lambda raw, n: str(uuid.UUID(bytes=raw[:n]))
            ),
        )
        self.objc = types.SimpleNamespace(
            lookUpClass=no_such_class,
            nosuchclass_error=NoSuchClass,
            super=super,
            autorelease_pool=contextlib.nullcontext,
        )
        self.NSDate = types.SimpleNamespace(dateWithTimeIntervalSinceNow_=float)
        self.NSDefaultRunLoopMode = "default"
        self.NSObject = FakeNSObject
        self.NSRunLoop = types.SimpleNamespace(currentRunLoop=lambda: self.loop)

    def device(self, address="AA-BB-CC-11-22-33", name="Speaker 7f", **kwargs):
        kwargs.setdefault("services", (SPP,))
        device = FakeDevice(address, name, loop=self.loop, **kwargs)
        self.paired.append(device)
        return device


def linked_driver(spec, tmp_path, monkeypatch, link):
    driver = load_driver(spec, tmp_path)
    monkeypatch.setattr(driver, "open_link", link.open)
    return driver


def metadata(source: str) -> dict:
    block = SCRIPT_BLOCK.search(source)
    assert block is not None
    content = "".join(
        line[2:] if line.startswith("# ") else line[1:]
        for line in block["content"].splitlines(keepends=True)
    )
    return tomllib.loads(content)


def top_level_source(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in tree.body:
        targets = [getattr(node, "name", None)]
        targets += [t.id for t in getattr(node, "targets", []) if hasattr(t, "id")]
        if name in targets:
            return ast.get_source_segment(source, node)
    raise AssertionError(f"{name} not found")


def test_classic_driver_is_valid_python(classic):
    compile(render_driver(classic), "driver.py", "exec")
    awkward = replace(
        classic,
        name='bob\'s "speaker"\n',
        vendor="",
        address_hint="",
        name_hint="Bob's",
        cipher=None,
        key_hex=None,
        init_payloads=[],
        reply_seconds=0,
    )
    compile(render_driver(awkward), "driver.py", "exec")


def test_classic_driver_declares_pyobjc_dbus_fast_and_not_bleak(classic):
    source = render_driver(classic)
    assert source.startswith("# /// script\n")
    meta = metadata(source)
    assert meta["requires-python"] == ">=3.11"
    assert meta["dependencies"] == ["cryptography>=44", PYOBJC, DBUS_FAST]
    assert "bleak" not in source
    assert "import harald" not in source
    assert "from harald" not in source


def test_classic_driver_loads_without_pyobjc(classic, tmp_path, monkeypatch):
    # as on ubuntu ci: nothing from pyobjc may be imported until open_link runs
    for name in ("IOBluetooth", "objc", "Foundation"):
        monkeypatch.setitem(sys.modules, name, None)
    driver = load_driver(classic, tmp_path)
    assert driver.SERVICE_UUID == SPP
    assert driver.ADDRESS_HINT == CLASSIC_ADDRESS  # lowercase colon form
    assert driver.INIT_PAYLOADS == ("aa01", "aa02")
    assert driver.REPLY_SECONDS == 1.5


def test_classic_driver_off_a_mac(classic, tmp_path, monkeypatch):
    driver = load_driver(classic, tmp_path)
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(driver.DriverError, match="^this driver needs a mac$"):
        driver.mac_modules()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setitem(sys.modules, "IOBluetooth", None)
    with pytest.raises(driver.DriverError, match="pyobjc-framework-iobluetooth"):
        driver.mac_modules()


def test_classic_driver_sends_init_payloads_then_the_command(
    classic, tmp_path, monkeypatch, capsys
):
    link = FakeLink(reply=bytes.fromhex("0102ff"))
    driver = linked_driver(classic, tmp_path, monkeypatch, link)
    assert driver.main(["on"]) == 0
    assert link.opened == [(CLASSIC_ADDRESS, "", SPP)]
    init, command = link.writes[:2], link.writes[2:]
    assert init == [b"\xaa\x01", b"\xaa\x02"]  # as they are, never encrypted
    [data] = command
    assert aes_decrypt(data, modes.ECB()) == b"\x7e\x00\x04\x01".ljust(16, b"\x00")
    assert link.reads == [1.5]
    assert link.closed
    assert capsys.readouterr().out == f"sent on to {CLASSIC_ADDRESS}\nreply: 0102ff\n"


def test_classic_driver_without_reply_seconds_reads_nothing(
    classic, tmp_path, monkeypatch, capsys
):
    plain = replace(classic, cipher=None, key_hex=None, reply_seconds=0)
    link = FakeLink(reply=b"\x01")
    driver = linked_driver(plain, tmp_path, monkeypatch, link)
    assert driver.main(["brightness", "50", "--address", "AA:BB:CC:DD:EE:FF"]) == 0
    assert link.opened == [("AA:BB:CC:DD:EE:FF", "", SPP)]
    assert link.writes == [
        b"\xaa\x01",
        b"\xaa\x02",
        b"\x7e\x00\x01\x32".ljust(16, b"\0"),
    ]
    assert link.reads == []
    assert link.closed
    assert capsys.readouterr().out == f"sent brightness to {CLASSIC_ADDRESS}\n"


def test_classic_driver_says_when_no_reply_came(classic, tmp_path, monkeypatch, capsys):
    driver = linked_driver(classic, tmp_path, monkeypatch, FakeLink(reply=b""))
    assert driver.main(["off"]) == 0
    assert capsys.readouterr().out.endswith("\nreply: none in 1.5 s\n")


def test_classic_driver_closes_on_every_path(classic, tmp_path, monkeypatch, capsys):
    driver = load_driver(classic, tmp_path)
    failing = FakeLink(write_error=driver.DriverError("x stopped answering", "move"))
    monkeypatch.setattr(driver, "open_link", failing.open)
    assert driver.main(["on"]) == 2
    assert failing.closed
    assert capsys.readouterr().err == "error: x stopped answering\n  hint: move\n"
    # a failing close keeps the result, and keeps the original error
    stuck = FakeLink(close_error=OSError("busy"))
    monkeypatch.setattr(driver, "open_link", stuck.open)
    assert driver.main(["on"]) == 0
    assert stuck.closed
    assert capsys.readouterr().out.startswith(f"sent on to {CLASSIC_ADDRESS}\n")
    both = FakeLink(
        write_error=driver.DriverError("x stopped answering", "move"),
        close_error=OSError("busy"),
    )
    monkeypatch.setattr(driver, "open_link", both.open)
    assert driver.main(["on"]) == 2
    assert capsys.readouterr().err.startswith("error: x stopped answering\n")


def test_classic_driver_bad_value_opens_nothing(classic, tmp_path, monkeypatch, capsys):
    link = FakeLink()
    driver = linked_driver(classic, tmp_path, monkeypatch, link)
    assert driver.main(["brightness", "abc"]) == 2
    assert capsys.readouterr().err.startswith("error: bad value for brightness: ")
    assert link.opened == []


def test_classic_driver_help_and_usage_errors_are_lowercase(
    classic, tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "argv", ["driver.py"])  # argparse's prog
    mixed = replace(classic, name="Demo Speaker")
    driver = load_driver(mixed, tmp_path)
    names = [command.name for command in mixed.commands]
    texts = []
    for argv in (["--help"], *([name, "--help"] for name in names), ["color"]):
        with pytest.raises(SystemExit):
            driver.main(argv)
        captured = capsys.readouterr()
        texts.append(captured.out + captured.err)
    assert "control demo speaker over bluetooth classic" in texts[0]
    assert "--address address" in texts[0]
    assert f"default address: {CLASSIC_ADDRESS}" in texts[0]
    assert "arguments are required: color" in texts[-1]
    for text in texts:
        assert [c for c in text if c.isascii() and c.isupper()] == []


@pytest.fixture(params=["mac", "linux"])
def os_name(request, monkeypatch):
    """Each device-choice case runs on the mac path and on the linux one."""
    monkeypatch.setattr(
        sys, "platform", "darwin" if request.param == "mac" else "linux"
    )
    return request.param


def pick(driver, paired, address="", name_hint="", os_name="mac"):
    """The FakeDevice the driver picks: on a mac from IOBluetooth's devices, on
    linux from bluez's (address, name, uuids, connected) of the same devices."""
    if os_name == "mac":
        return driver.pick_device(
            paired, address, name_hint, lambda device: SPP in device.services, SPP
        )
    by_address = {d.addressString().lower().replace("-", ":"): d for d in paired}
    listed = [
        (a, d.name(), list(d.services), d.isConnected()) for a, d in by_address.items()
    ]
    return by_address[driver.linux_pick(listed, address, name_hint, SPP)]


def harald_says(code, address="", channel=None):
    """What harald itself says for a backend error `code`, as (message, hint)."""
    error = harald.classic._mapped(BackendError(code), address, channel)
    return error.message, error.hint


def test_classic_lookup_by_address_takes_only_that_address(classic, tmp_path, os_name):
    driver = load_driver(classic, tmp_path)
    speaker = FakeDevice("AA-BB-CC-11-22-33", "Speaker 7f", connected=False)
    bose = FakeDevice("aa-bb-cc-dd-ee-ff", "Bose QC35", services=(SPP,))
    paired = [bose, speaker]
    assert pick(driver, paired, "aa:bb:cc:11:22:33", "Bose", os_name) is speaker
    assert pick(driver, paired, "AA-BB-CC-DD-EE-FF", "Speaker", os_name) is bose
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, paired, "00:00:00:00:00:01", "Speaker", os_name)
    words = (raised.value.message, raised.value.hint)
    if os_name == "mac":
        assert words == (
            "00:00:00:00:00:01 is not paired with this mac",
            "pair it in system settings > bluetooth",
        )
    else:
        assert words == harald_says("not_paired", "00:00:00:00:00:01")


def test_classic_lookup_by_name_ignores_devices_that_only_list_the_service(
    classic, tmp_path, os_name
):
    # the speaker is paired but off, and a connected headset also lists the serial
    # port service: the driver must not write the speaker's commands to the headset
    driver = load_driver(classic, tmp_path)
    speaker = FakeDevice("AA-BB-CC-11-22-33", "Speaker 7f", connected=False)
    bose = FakeDevice("aa-bb-cc-dd-ee-ff", "Bose QC35", services=(SPP,))
    assert (
        pick(driver, [bose, speaker], name_hint="Speaker", os_name=os_name) is speaker
    )
    # among name matches, a connected one comes first, whatever the paired order
    spare = FakeDevice("11-22-33-44-55-66", "Speaker 80")
    assert pick(driver, [speaker, bose, spare], "", "Speaker", os_name) is spare
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, [bose, speaker], name_hint="Lamp", os_name=os_name)
    assert raised.value.message == "no paired device named Lamp* found"
    if os_name == "mac":
        assert raised.value.hint == "pair it in system settings > bluetooth"
    else:
        assert raised.value.hint == hints.pair_one()


def test_classic_lookup_by_service_needs_exactly_one_device(classic, tmp_path, os_name):
    driver = load_driver(classic, tmp_path)
    speaker = FakeDevice("AA-BB-CC-11-22-33", "Speaker 7f", services=(SPP,))
    bose = FakeDevice("aa-bb-cc-dd-ee-ff", "Bose QC35", services=(SPP,))
    phone = FakeDevice("11-22-33-44-55-66", "phone")
    assert pick(driver, [phone, speaker], os_name=os_name) is speaker
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, [speaker, phone, bose], os_name=os_name)
    assert raised.value.message == (
        f"more than one paired device lists service {SPP}: "
        "aa:bb:cc:11:22:33, aa:bb:cc:dd:ee:ff"
    )
    assert raised.value.hint == "pass --address with the one to use"
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, [phone], os_name=os_name)
    assert raised.value.message == f"no paired device with service {SPP} found"


@pytest.mark.parametrize(
    ("status", "connected", "message", "hint"),
    [
        (
            -0x1FFFFD2B,  # 0xe00002d5 as pyobjc hands it over
            True,
            f"channel 9 on {CLASSIC_ADDRESS} is busy",
            "close the vendor app on your phone, or turn the phone's bluetooth off",
        ),
        (
            0xE00002BC,
            True,
            f"the mac would not open a channel to {CLASSIC_ADDRESS}",
            STUCK_HINT,
        ),
        (
            0xE00002D6,
            False,
            f"{CLASSIC_ADDRESS} is not connected",
            "turn it on and connect it to this mac in system settings > bluetooth",
        ),
        (0xE00002C0, True, "bluetooth error: open status 0xe00002c0", ""),
    ],
)
def test_classic_driver_open_errors(
    classic, tmp_path, status, connected, message, hint
):
    driver = load_driver(classic, tmp_path)
    error = driver.open_error(status, connected, CLASSIC_ADDRESS, 9)
    assert (error.message, error.hint) == (message, hint)


def test_both_drivers_take_the_shared_code_from_one_place(spec, classic):
    folder = files("harald") / "templates"
    for name in ("driver.py.tmpl", "driver_classic.py.tmpl"):
        text = (folder / name).read_text(encoding="utf-8")
        assert "$payload_code" in text and "$cli_code" in text, name
        for shared in ("COLORS = {", "def encrypt(", "def build_parser(", "def fail("):
            assert shared not in text, (name, shared)
    ble, rfcomm = render_driver(spec), render_driver(classic)
    for name in (*SHARED_CODE, "COMMANDS", "add_address", "build_parser"):
        same = top_level_source(rfcomm, name) == top_level_source(ble, name)
        # the command line differs only in the words for the transport
        assert same is (name not in ("add_address", "build_parser")), name
    # main is the transport after the payload is built, so only its start is shared
    head = [top_level_source(s, "main").splitlines()[:6] for s in (ble, rfcomm)]
    assert head[0] == head[1]
    assert (
        head[0][-1] == "        payload = encrypt(build_payload(args.command, values))"
    )


def test_classic_spec_with_a_characteristic_is_refused(classic):
    for render in (render_driver, render_protocol):
        with pytest.raises(HaraldError) as raised:
            render(replace(classic, write_char_uuid=CHR))
        assert raised.value.message == "classic drivers have no characteristic"
        assert raised.value.hint == "leave write_char_uuid empty"


def test_render_protocol_for_classic_names_the_rfcomm_service(classic):
    text = render_protocol(classic)
    assert "over bluetooth classic" in text
    assert "rfcomm" in text
    assert f"- service: `{SPP}`" in text
    assert "characteristic" not in text
    assert "`aa01`" in text and "`aa02`" in text
    assert "1.5 s" in text
    assert classic.cipher in text
    for command in classic.commands:
        assert f"### {command.name}" in text
    headings = [line for line in text.splitlines() if line.startswith("#")]
    for heading in headings:
        assert heading == heading.lower()
        assert heading.isascii()
    bare = render_protocol(replace(classic, init_payloads=[], reply_seconds=0))
    assert "aa01" not in bare


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"transport": "usb"}, "unknown transport: usb"),
        ({"init_payloads": ["zz"]}, "invalid init payload: 'zz'"),
        ({"init_payloads": [""]}, "invalid init payload: ''"),
        ({"reply_seconds": -1}, "reply_seconds must be 0 to 30"),
        ({"reply_seconds": 31}, "reply_seconds must be 0 to 30"),
        ({"reply_seconds": float("nan")}, "reply_seconds must be 0 to 30"),
        ({"address_hint": "speaker"}, "not a bluetooth classic address"),
        ({"service_uuid": "nope"}, "invalid uuid: 'nope'"),
    ],
)
def test_render_refuses_a_bad_classic_spec(classic, change, message):
    bad = replace(classic, **change)
    for render in (render_driver, render_protocol):
        with pytest.raises(HaraldError, match=re.escape(message)):
            render(bad)


@pytest.mark.parametrize("change", [{"init_payloads": ["00"]}, {"reply_seconds": 1.0}])
def test_ble_spec_refuses_classic_only_fields(spec, change):
    # the ble driver has no use for them, so a spec that sets them is a mistake
    for render in (render_driver, render_protocol):
        with pytest.raises(HaraldError, match="only for classic drivers"):
            render(replace(spec, **change))


# --- the classic driver's open_link, over a faked IOBluetooth ---------------------


@pytest.fixture
def mac(classic, tmp_path, monkeypatch):
    """The classic driver, whose mac_modules hands back a FakeMac, with short waits.
    pyobjc is blocked as well, so a missed patch fails rather than reach bluetooth.
    It runs as on a mac wherever the tests run, since linux takes the linux link."""
    monkeypatch.setattr(sys, "platform", "darwin")
    for name in ("IOBluetooth", "objc", "Foundation"):
        monkeypatch.setitem(sys.modules, name, None)
    driver = load_driver(classic, tmp_path)
    fake = FakeMac()
    monkeypatch.setattr(driver, "mac_modules", lambda: fake)
    for name in ("OPEN_SECONDS", "WRITE_SECONDS", "CLOSE_SECONDS"):
        monkeypatch.setattr(driver, name, 0.05)
    monkeypatch.setattr(driver, "REPLY_SECONDS", 0.05)
    return types.SimpleNamespace(driver=driver, fake=fake)


def open_error(mac, address=CLASSIC_ADDRESS, name_hint=""):
    with pytest.raises(mac.driver.DriverError) as raised:
        mac.driver.open_link(address, name_hint, SPP)
    return raised.value


def test_open_link_writes_in_mtu_pieces_reads_and_closes_once(mac):
    device = mac.fake.device(mtu=4)
    link = mac.driver.open_link(CLASSIC_ADDRESS, "", SPP)
    assert (link.address, link.mtu, device.opened) == (CLASSIC_ADDRESS, 4, [9])
    rfcomm = device.rfcomm
    link.write(bytes(range(10)))
    assert rfcomm.writes == [bytes(range(4)), bytes(range(4, 8)), bytes(range(8, 10))]
    rfcomm.send(b"\x01\x02")
    rfcomm.send(b"\x03")
    assert link.read(0.05) == b"\x01\x02\x03"
    assert link.read(0) == b""
    link.close()
    link.close()
    assert rfcomm.closes == 1


def test_open_link_by_name_never_opens_another_device(mac):
    # the reviewer's case: the named speaker is off, a connected headset lists spp
    bose = mac.fake.device("aa-bb-cc-dd-ee-ff", "Bose QC35")
    speaker = mac.fake.device(connected=False)
    error = open_error(mac, address="", name_hint="Speaker")
    assert (error.message, error.hint) == (
        f"{CLASSIC_ADDRESS} is not connected",
        CONNECT_HINT,
    )
    assert bose.opened == speaker.opened == []


def test_open_link_opens_nothing_it_cannot_use(mac):
    mac.fake.paired = None
    error = open_error(mac)
    assert error.message == "bluetooth is off or not allowed for this app"
    assert "privacy & security > bluetooth" in error.hint
    mac.fake.paired = []
    off = mac.fake.device(connected=False)
    assert open_error(mac).message == f"{CLASSIC_ADDRESS} is not connected"
    mac.fake.paired = []
    unlisted = mac.fake.device(channel=None)
    error = open_error(mac)
    assert error.message == f"{CLASSIC_ADDRESS} lists no rfcomm channel for {SPP}"
    assert off.opened == unlisted.opened == []


@pytest.mark.parametrize(
    ("status", "connected_after_open", "message", "hint"),
    [
        (IO_BUSY, None, f"channel 9 on {CLASSIC_ADDRESS} is busy", "close the vendor"),
        (IO_ERROR, None, f"the mac would not open a channel to {CLASSIC_ADDRESS}", ""),
        (IO_ERROR, False, f"{CLASSIC_ADDRESS} is not connected", "turn it on"),
    ],
)
def test_open_link_closes_after_a_refused_open(
    mac, status, connected_after_open, message, hint
):
    device = mac.fake.device(
        open_start=status, connected_after_open=connected_after_open
    )
    error = open_error(mac)
    assert error.message == message
    assert error.hint.startswith(hint)
    assert device.rfcomm.closes == 1


@pytest.mark.parametrize(
    ("status", "connected_after_open", "message"),
    [
        (IO_BUSY, None, f"channel 9 on {CLASSIC_ADDRESS} is busy"),
        (IO_BAD_ARGUMENT, None, "bluetooth error: open status 0xe00002c2"),
        (IO_BAD_ARGUMENT, False, f"{CLASSIC_ADDRESS} is not connected"),
    ],
)
def test_open_link_closes_after_a_failed_open_complete(
    mac, status, connected_after_open, message
):
    device = mac.fake.device(
        open_complete=status, connected_after_open=connected_after_open
    )
    assert open_error(mac).message == message
    assert device.rfcomm.closes == 1


@pytest.mark.parametrize(
    ("connected_after_open", "message", "hint"),
    [
        (None, f"the mac would not open a channel to {CLASSIC_ADDRESS}", STUCK_HINT),
        (False, f"{CLASSIC_ADDRESS} is not connected", CONNECT_HINT),
    ],
)
def test_open_link_closes_an_open_that_never_completes(
    mac, connected_after_open, message, hint
):
    device = mac.fake.device(
        open_complete=None, connected_after_open=connected_after_open
    )
    error = open_error(mac)
    assert (error.message, error.hint) == (message, hint)
    assert device.rfcomm.closes == 1


def test_open_link_closes_when_the_mtu_cannot_be_read(mac):
    device = mac.fake.device(mtu=RuntimeError("the channel went away"))
    assert open_error(mac).message == "bluetooth error: no mtu for channel 9"
    assert device.rfcomm.closes == 1


def test_link_write_that_never_completes_times_out(mac):
    mac.fake.device(write_complete=None)
    link = mac.driver.open_link(CLASSIC_ADDRESS, "", SPP)
    with pytest.raises(mac.driver.DriverError) as raised:
        link.write(b"\x01")
    assert (raised.value.message, raised.value.hint) == (
        f"{CLASSIC_ADDRESS} stopped answering",
        TIMEOUT_HINT,
    )


@pytest.mark.parametrize(
    ("write_start", "write_complete"), [(IO_ERROR, 0), (0, -0x1FFFFD44)]
)
def test_link_write_reports_a_failed_write(mac, write_start, write_complete):
    mac.fake.device(write_start=write_start, write_complete=write_complete)
    link = mac.driver.open_link(CLASSIC_ADDRESS, "", SPP)
    with pytest.raises(
        mac.driver.DriverError, match="^bluetooth error: write status 0xe00002bc$"
    ):
        link.write(b"\x01")


def test_link_after_the_gadget_closes_the_channel(mac):
    device = mac.fake.device(write_complete=None)
    link = mac.driver.open_link(CLASSIC_ADDRESS, "", SPP)
    rfcomm = device.rfcomm
    rfcomm.hang_up()  # while a write waits for its write-complete
    with pytest.raises(
        mac.driver.DriverError, match="^bluetooth error: the channel closed$"
    ):
        link.write(b"\x01")
    with pytest.raises(mac.driver.DriverError, match="the channel is closed$"):
        link.write(b"\x02")
    link.close()
    assert rfcomm.closes == 0  # the gadget closed it already
    # a read returns what came before the close, without waiting out its time
    device = mac.fake.device(address="aa-bb-cc-dd-ee-ff")
    link = mac.driver.open_link("aa:bb:cc:dd:ee:ff", "", SPP)
    device.rfcomm.send(b"\x09")
    device.rfcomm.hang_up()
    started = time.monotonic()
    assert link.read(5) == b"\x09"
    assert time.monotonic() - started < 1


def test_link_close_never_raises_and_closes_once(mac):
    device = mac.fake.device(close_error=RuntimeError("closeChannel failed"))
    link = mac.driver.open_link(CLASSIC_ADDRESS, "", SPP)
    link.close()
    link.close()
    assert device.rfcomm.closes == 1


def test_main_over_a_faked_mac_closes_the_channel_on_every_path(mac, capsys):
    device = mac.fake.device(mtu=8, greeting=b"\x0a\x0b")
    assert mac.driver.main(["on"]) == 0
    writes = device.rfcomm.writes
    assert writes[:2] == [b"\xaa\x01", b"\xaa\x02"]
    command = b"".join(writes[2:])
    assert [len(piece) for piece in writes[2:]] == [8, 8]  # the mtu split
    assert aes_decrypt(command, modes.ECB()) == b"\x7e\x00\x04\x01".ljust(16, b"\0")
    assert capsys.readouterr().out == f"sent on to {CLASSIC_ADDRESS}\nreply: 0a0b\n"
    assert device.rfcomm.closes == 1
    mac.fake.paired = []
    stalled = mac.fake.device(write_complete=None)
    assert mac.driver.main(["on"]) == 2
    assert capsys.readouterr().err == (
        f"error: {CLASSIC_ADDRESS} stopped answering\n  hint: {TIMEOUT_HINT}\n"
    )
    assert stalled.rfcomm.closes == 1


# --- the classic driver's linux link ----------------------------------------------

HEADSET = "00001108-0000-1000-8000-00805f9b34fb"
VENDOR_UUID = "8901dfa8-5c7e-4d8f-9f0c-c2b70683f5f0"
SPEAKER_RECORDS = [
    ServiceRecord("Headset", [HEADSET], 2),
    ServiceRecord("Serial", [SPP], 5),
    ServiceRecord("vendor", [VENDOR_UUID], 21),
]
GET_MANAGED_OBJECTS = {
    "destination": "org.bluez",
    "path": "/",
    "interface": "org.freedesktop.DBus.ObjectManager",
    "member": "GetManagedObjects",
}
ERFKILL = getattr(errno, "ERFKILL", 132)  # linux's value; the mac has none
EBADE = getattr(errno, "EBADE", 52)  # linux's value; the mac has none


@pytest.fixture
def linux(classic, tmp_path, monkeypatch):
    """The classic driver on linux: bluez has the speaker paired, its sdp server
    holds SPEAKER_RECORDS, a socketpair is its rfcomm channel, and waits are short."""
    driver = load_driver(classic, tmp_path)
    objects = bluez(device(CLASSIC_ADDRESS, alias="Speaker 7f", uuids=[SPP]))
    rig = Rig(driver, monkeypatch, objects, SPEAKER_RECORDS)
    monkeypatch.setattr(driver, "REPLY_SECONDS", 0.5)
    monkeypatch.setattr(driver, "LINUX_SECONDS", 0.5)
    monkeypatch.setattr(driver, "LINUX_WRITE_SECONDS", 0.5)
    yield types.SimpleNamespace(driver=driver, rig=rig)
    rig.close()


def test_every_classic_driver_carries_the_linux_link_as_it_is(spec, classic):
    block = linux_link()
    assert block == block.strip("\n") and block.startswith("# ")
    text = (files("harald") / "templates" / "linux_link.py.tmpl").read_text("utf-8")
    assert text == block + "\n"
    for each in (classic, replace(classic, address_hint="", name_hint="Speaker")):
        assert block in render_driver(each)
    assert "def linux_" not in render_driver(spec)  # bleak covers linux for ble


def test_the_linux_link_needs_only_what_its_driver_has(classic):
    assert names_needed(linux_link(), render_driver(classic)) == set()


def test_classic_driver_says_it_runs_on_a_mac_or_linux(classic):
    source = render_driver(classic)
    docstring = ast.get_docstring(ast.parse(source))
    assert "mac or linux" in docstring
    assert "dbus-fast" in docstring
    assert "mac only" not in docstring
    assert "paired with this mac" not in docstring


@pytest.mark.parametrize("address", [CLASSIC_ADDRESS, "AA-BB-CC-DD-EE-FF"])
@pytest.mark.parametrize("number", [1, 5, 30])
def test_linux_sockaddrs_match_haralds(classic, tmp_path, address, number):
    driver = load_driver(classic, tmp_path)
    rc = driver.linux_sockaddr_rc(address, number)
    l2 = driver.linux_sockaddr_l2(address, number)
    assert (len(rc), len(l2)) == (10, 14)
    assert rc == btsock.sockaddr_rc(address, number)
    assert l2 == btsock.sockaddr_l2(address, number)


def test_linux_libc_connect_returns_the_errno(classic, tmp_path):
    # a real connect(2) through ctypes, on a socket that can never take this address
    driver = load_driver(classic, tmp_path)
    addr = driver.linux_sockaddr_rc(CLASSIC_ADDRESS, 1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        err = driver.linux_libc_connect(sock.fileno(), addr)
    assert err in errno.errorcode


def test_linux_link_words_are_haralds(classic, tmp_path, on_linux):
    # the driver cannot import harald, so it keeps its own copy of harald's words
    driver = load_driver(classic, tmp_path)
    assert driver.LINUX_OFF == hints.bluetooth_off_message()
    assert driver.LINUX_OFF_HINT == hints.bluetooth_off()
    assert driver.LINUX_PERMISSION_HINT == hints.permission()
    assert driver.LINUX_CONNECT_HINT == hints.connect()
    assert driver.LINUX_TIMEOUT_HINT == hints.timeout()
    assert (driver.LINUX_NO_KERNEL, driver.LINUX_NO_KERNEL_HINT) == (
        hints.unsupported_classic()
    )
    assert (driver.LINUX_NO_KERNEL, driver.LINUX_NO_KERNEL_HINT) == (
        hints.no_bluetooth_support()
    )
    assert driver.linux_pair_hint(CLASSIC_ADDRESS) == hints.pair(CLASSIC_ADDRESS)
    assert driver.linux_pair_hint() == hints.pair_one()
    again = driver.linux_pair_hint(CLASSIC_ADDRESS, again=True)
    assert again == hints.repair(CLASSIC_ADDRESS)
    for hint in (driver.LINUX_OFF_HINT, driver.LINUX_TIMEOUT_HINT):
        assert "mac" not in hint


@pytest.mark.parametrize("connecting", [True, False])
@pytest.mark.parametrize(
    "err",
    [
        errno.EAFNOSUPPORT,
        errno.EPROTONOSUPPORT,
        errno.ENODEV,
        errno.EADDRNOTAVAIL,
        errno.ENETDOWN,
        ERFKILL,
        errno.EHOSTDOWN,
        errno.EHOSTUNREACH,
        errno.EBUSY,
        errno.EADDRINUSE,
        errno.EALREADY,
        errno.ETIMEDOUT,
        errno.EACCES,
        errno.EPERM,
        EBADE,
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.EPIPE,
        errno.ENOTCONN,
        errno.EIO,
    ],
)
def test_linux_link_errors_say_what_harald_says(
    classic, tmp_path, on_linux, err, connecting
):
    # btsock's errno table and classic's words, on a connect or anywhere else
    driver = load_driver(classic, tmp_path)
    code, detail = btsock.error_code(err, connecting=connecting)
    expected = harald.classic._mapped(BackendError(code, detail), CLASSIC_ADDRESS, 9)
    error = driver.linux_error(err, CLASSIC_ADDRESS, "channel 9", connecting)
    assert (error.message, error.hint) == (expected.message, expected.hint)


def test_linux_paired_lists_what_bluez_has_paired(classic, tmp_path, monkeypatch):
    driver = load_driver(classic, tmp_path)
    fake = FakeBluez(
        bluez(
            device(
                "aa:bb:cc:dd:ee:ff",
                alias="Bose QC35",
                name="Bose QC35",
                uuids=[SPP],
                connected=True,
            ),
            # nameless: bluez's alias for it is its address with dashes
            device(CLASSIC_ADDRESS, alias="AA-BB-CC-11-22-33", uuids=[SPP, HEADSET]),
            device("11:22:33:44:55:66", alias="desk", name="Speaker 80"),  # renamed
            device("aa:bb:cc:44:55:66", alias="tag", kind="random"),  # le only
            device("aa:bb:cc:77:88:99", alias="seen", paired=False),
        )
    ).install(monkeypatch)
    assert driver.linux_paired() == [
        ("11:22:33:44:55:66", "desk", [], False),
        (CLASSIC_ADDRESS, None, [SPP, HEADSET], False),
        ("aa:bb:cc:dd:ee:ff", "Bose QC35", [SPP], True),
    ]
    assert fake.calls == [GET_MANAGED_OBJECTS]
    assert fake.disconnects == 1


def test_linux_name_match_takes_a_connected_device_first(
    classic, tmp_path, monkeypatch
):
    # two paired devices match the name and only the second is connected, as on a
    # mac it is the one taken; with neither connected, the first is
    driver = load_driver(classic, tmp_path)
    for connected, chosen in ((True, CLASSIC_ADDRESS), (False, "11:22:33:44:55:66")):
        FakeBluez(
            bluez(
                device("11:22:33:44:55:66", alias="Speaker 80"),
                device(CLASSIC_ADDRESS, alias="Speaker 7f", connected=connected),
                device("aa:bb:cc:dd:ee:ff", alias="Bose QC35", connected=True),
            )
        ).install(monkeypatch)
        paired = driver.linux_paired()
        assert [address for address, *_ in paired][:2] == [
            "11:22:33:44:55:66",
            CLASSIC_ADDRESS,
        ]
        assert driver.linux_pick(paired, "", "Speaker", SPP) == chosen


OFF, DENIED = "off", "denied"


class ProbeSocket:
    """A bluetooth socket made only to see that the kernel has bluetooth."""

    def __init__(self, kind, proto):
        self.kind, self.proto, self.closed = kind, proto, False

    def close(self):
        self.closed = True


def kernel(driver, monkeypatch, err=None) -> list[ProbeSocket]:
    """The driver's kernel: with bluetooth when `err` is None, keeping each socket the
    driver makes in the list returned; without it, making one fails with `err`."""
    made = []

    def new_socket(kind, proto):
        if err is not None:
            raise OSError(err, os.strerror(err))
        made.append(ProbeSocket(kind, proto))
        return made[-1]

    monkeypatch.setattr(driver, "linux_new_socket", new_socket)
    return made


# bluez out of reach: no bluetoothd on the bus, no system bus, or no adapter
BLUEZ_OUT_OF_REACH = [
    *[FakeBluez(error=name) for name in bluez_names.NOT_RUNNING],
    *[FakeBluez(error=f"{start}NoSuchUnit") for start in bluez_names.NOT_STARTED],
    FakeBluez(connect_error=FileNotFoundError(2, "no such file")),
    FakeBluez(connect_error=ConnectionRefusedError(111, "connection refused")),
    FakeBluez(bluez(powered=())),  # no adapter
]


@pytest.mark.parametrize(
    ("fake", "words"),
    [
        *[(fake, OFF) for fake in BLUEZ_OUT_OF_REACH],
        (FakeBluez(error=bluez_names.ACCESS_DENIED), DENIED),
        (FakeBluez(connect_error=PermissionError(13, "permission denied")), DENIED),
        (FakeBluez(bluez(powered=(False, False))), OFF),
    ],
)
def test_linux_bluez_trouble_is_a_linux_hint(
    classic, tmp_path, monkeypatch, on_linux, fake, words
):
    driver = load_driver(classic, tmp_path)
    kernel(driver, monkeypatch)  # with bluetooth, as on any linux with a radio
    fake.install(monkeypatch)
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_paired()
    expected = {
        OFF: harald_says("bluetooth_off"),
        DENIED: harald_says("permission"),
    }[words]
    assert (raised.value.message, raised.value.hint) == expected


@pytest.mark.parametrize("fake", BLUEZ_OUT_OF_REACH)
def test_linux_bluez_out_of_reach_asks_the_kernel_with_one_closed_socket(
    classic, tmp_path, monkeypatch, on_linux, fake
):
    driver = load_driver(classic, tmp_path)
    made = kernel(driver, monkeypatch)
    fake.install(monkeypatch)
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_paired()
    assert (raised.value.message, raised.value.hint) == harald_says("bluetooth_off")
    assert [(s.kind, s.proto, s.closed) for s in made] == [
        (socket.SOCK_STREAM, 3, True)
    ]


@pytest.mark.parametrize("err", [errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT])
@pytest.mark.parametrize("fake", BLUEZ_OUT_OF_REACH)
def test_linux_bluez_out_of_reach_on_a_kernel_without_bluetooth(
    classic, tmp_path, monkeypatch, on_linux, fake, err
):
    # wsl, or a container: what harald says, not a bluetoothd hint that cannot help
    driver = load_driver(classic, tmp_path)
    kernel(driver, monkeypatch, err)
    fake.install(monkeypatch)
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_paired()
    words = (raised.value.message, raised.value.hint)
    assert words == harald_says("unsupported") == hints.no_bluetooth_support()


@pytest.mark.parametrize(
    ("fake", "words"),
    [
        (FakeBluez(bluez(powered=(False,))), OFF),  # an adapter: bluetooth is off
        (FakeBluez(error=bluez_names.ACCESS_DENIED), DENIED),
        (FakeBluez(connect_error=PermissionError(13, "permission denied")), DENIED),
    ],
)
def test_linux_bluez_in_reach_never_asks_the_kernel(
    classic, tmp_path, monkeypatch, on_linux, fake, words
):
    driver = load_driver(classic, tmp_path)
    kernel(driver, monkeypatch, errno.EAFNOSUPPORT)
    fake.install(monkeypatch)
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_paired()
    expected = harald_says("bluetooth_off" if words == OFF else "permission")
    assert (raised.value.message, raised.value.hint) == expected


@pytest.mark.parametrize(
    "error",
    [
        ConnectionResetError(errno.ECONNRESET, "Connection reset by peer"),
        OSError(errno.EIO, "Input/output error"),
    ],
)
def test_linux_other_bus_errors_say_what_harald_says(
    classic, tmp_path, monkeypatch, on_linux, error
):
    # only a missing or refusing system bus means bluez is out of reach
    driver = load_driver(classic, tmp_path)
    made = kernel(driver, monkeypatch)
    FakeBluez(connect_error=error).install(monkeypatch)
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_paired()
    backend_error = harald.classic_linux._dbus_error(error)
    expected = harald.classic._mapped(backend_error, "", None)
    assert (raised.value.message, raised.value.hint) == (expected.message, "")
    assert raised.value.message == f"bluetooth error: {error.strerror.lower()}"
    assert made == []


def test_linux_bluez_failures_are_never_tracebacks(classic, tmp_path, monkeypatch):
    driver = load_driver(classic, tmp_path)
    FakeBluez(error="org.bluez.Error.Failed").install(monkeypatch)
    with pytest.raises(driver.DriverError, match="org.bluez.Error.Failed"):
        driver.linux_paired()
    FakeBluez(connect_error=ValueError("Auth Failed")).install(monkeypatch)
    with pytest.raises(driver.DriverError, match="^bluetooth error: auth failed$"):
        driver.linux_paired()
    monkeypatch.setattr(driver, "LINUX_SECONDS", 0.1)
    FakeBluez(delay=5).install(monkeypatch)
    started = time.monotonic()
    with pytest.raises(driver.DriverError, match="bluez did not answer in 0.1 s"):
        driver.linux_paired()
    assert time.monotonic() - started < 2
    monkeypatch.setitem(sys.modules, "dbus_fast", None)
    with pytest.raises(driver.DriverError, match="^dbus-fast is missing$") as raised:
        driver.linux_paired()
    assert "uv run driver.py" in raised.value.hint


@pytest.mark.parametrize("chunk", [1, 7, 4096])
def test_linux_sdp_finds_the_channel_for_the_service(linux, chunk):
    # whole, or split over many pdus with continuation states
    driver, sdp = linux.driver, linux.rig.sdp
    sdp.chunk = chunk
    assert driver.linux_sdp_channel(CLASSIC_ADDRESS, SPP, 1.0) == 5
    assert driver.linux_sdp_channel(CLASSIC_ADDRESS, VENDOR_UUID, 1.0) == 21
    assert sdp.closed
    if chunk == 1:
        assert len(sdp.requests) > 30
    sdp.records = XM5_RECORDS
    xm5 = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"
    assert driver.linux_sdp_channel(CLASSIC_ADDRESS, xm5, 1.0) == 9


@pytest.mark.parametrize(
    "records",
    [
        [ServiceRecord("Headset", [HEADSET], 2)],  # no record lists spp
        [ServiceRecord("Serial", [SPP], None)],  # not on rfcomm
        [ServiceRecord("Serial", [SPP], 0)],  # rfcomm can't reach these
        [ServiceRecord("Serial", [SPP], 31)],
        [ServiceRecord("Serial", [SPP], 255)],
    ],
)
def test_linux_sdp_without_a_usable_channel_is_a_driver_error(linux, records):
    linux.rig.sdp.records = records
    with pytest.raises(linux.driver.DriverError) as raised:
        linux.driver.linux_sdp_channel(CLASSIC_ADDRESS, SPP, 1.0)
    assert (
        raised.value.message == f"{CLASSIC_ADDRESS} lists no rfcomm channel for {SPP}"
    )
    assert linux.rig.sdp.closed


@pytest.mark.parametrize("channel", [1, 30])
def test_linux_sdp_takes_the_edge_channels(linux, channel):
    linux.rig.sdp.records = [ServiceRecord("Serial", [SPP], channel)]
    assert linux.driver.linux_sdp_channel(CLASSIC_ADDRESS, SPP, 1.0) == channel


def test_linux_sdp_parse_survives_any_cut_or_bad_byte(classic, tmp_path):
    driver = load_driver(classic, tmp_path)
    lists = encode_records(SPEAKER_RECORDS[1:2])
    assert driver.linux_sdp_lists_channel(lists) == 5
    assert driver.linux_sdp_lists_channel(encode_records([])) is None
    for cut in range(len(lists)):
        with pytest.raises(driver.DriverError, match="^bluetooth error: bad sdp reply"):
            driver.linux_sdp_lists_channel(lists[:cut])
    for at in range(len(lists)):
        for value in (0x00, 0x07, 0x0F, 0x35, 0x37, 0x3F, 0xFF, lists[at] ^ 1):
            bad = lists[:at] + bytes([value]) + lists[at + 1 :]
            try:
                channel = driver.linux_sdp_lists_channel(bad)
            except driver.DriverError:
                continue
            assert channel is None or 1 <= channel <= 30
    deep = b"\x35\x02" * 40  # sequences nested past any real record
    with pytest.raises(driver.DriverError, match="bad sdp reply"):
        driver.linux_sdp_lists_channel(deep)


def test_linux_sdp_reply_refuses_a_bad_pdu(classic, tmp_path):
    driver = load_driver(classic, tmp_path)
    lists = encode_records(SPEAKER_RECORDS)
    pdu = response(3, lists[:20], b"\x00\x00\x00\x14")
    assert driver.linux_sdp_reply(pdu, 3) == (lists[:20], b"\x00\x00\x00\x14")
    for cut in range(len(pdu)):
        with pytest.raises(driver.DriverError, match="sdp"):
            driver.linux_sdp_reply(pdu[:cut], 3)
    bad = [
        pdu + b"\x00",  # longer than it says
        response(4, lists, b""),  # another transaction
        b"\x05" + pdu[1:],  # not a ServiceSearchAttributeResponse
        response(3, lists, bytes(17)),  # a continuation state over 16 bytes
        bytes.fromhex("01 0003 0002 0003"),  # an sdp error response
    ]
    for each in bad:
        with pytest.raises(driver.DriverError, match="^bluetooth error: "):
            driver.linux_sdp_reply(each, 3)


def test_linux_sdp_gives_up_on_a_reply_that_never_ends(linux, monkeypatch):
    def endless(pdu):
        transaction = int.from_bytes(pdu[1:3], "big")
        linux.rig.sdp.replies.append(response(transaction, b"\x35", b"\x01"))
        return len(pdu)

    monkeypatch.setattr(linux.rig.sdp, "send", endless)
    with pytest.raises(linux.driver.DriverError, match="bad sdp reply"):
        linux.driver.linux_sdp_channel(CLASSIC_ADDRESS, SPP, 1.0)
    assert linux.rig.sdp.closed


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (TimeoutError("timed out"), "timeout"),
        (ConnectionResetError(errno.ECONNRESET, "reset"), "failed"),
    ],
)
def test_linux_sdp_trouble_is_a_driver_error(linux, error, code):
    linux.rig.sdp.recv_error = error
    with pytest.raises(linux.driver.DriverError) as raised:
        linux.driver.linux_sdp_channel(CLASSIC_ADDRESS, SPP, 1.0)
    detail = "the channel is closed" if code == "failed" else ""
    expected = harald.classic._mapped(BackendError(code, detail), CLASSIC_ADDRESS, 1)
    assert (raised.value.message, raised.value.hint) == (
        expected.message,
        expected.hint,
    )
    assert linux.rig.sdp.closed


class Unready:
    """A socket mid-connect: select sees `sock`, and SO_ERROR says `err`."""

    def __init__(self, sock, err):
        self.sock, self.err, self.closed = sock, err, False

    def fileno(self):
        return self.sock.fileno()

    def setblocking(self, flag):
        pass

    def getsockopt(self, level, name):
        assert (level, name) == (socket.SOL_SOCKET, socket.SO_ERROR)
        return self.err

    def close(self):
        self.closed = True


def test_linux_connect_waits_out_a_connect_in_progress(linux, monkeypatch):
    driver, rig = linux.driver, linux.rig
    monkeypatch.setattr(
        driver, "linux_libc_connect", lambda fd, addr: errno.EINPROGRESS
    )
    assert driver.linux_connect(CLASSIC_ADDRESS, 5, 1.0) is rig.ours
    # the connect then fails: the gadget is out of reach
    pending = Unready(rig.ours, errno.EHOSTDOWN)
    monkeypatch.setattr(driver, "linux_new_socket", lambda kind, proto: pending)
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_connect(CLASSIC_ADDRESS, 5, 1.0)
    assert (raised.value.message, raised.value.hint) == harald_says(
        "not_connected", CLASSIC_ADDRESS
    )
    assert pending.closed


def test_linux_connect_that_never_finishes_times_out(linux, monkeypatch):
    driver, rig = linux.driver, linux.rig
    rig.ours.setblocking(False)
    with contextlib.suppress(BlockingIOError):
        while True:  # a full send buffer: select never says writable
            rig.ours.send(bytes(65536))
    monkeypatch.setattr(
        driver, "linux_libc_connect", lambda fd, addr: errno.EINPROGRESS
    )
    started = time.monotonic()
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_connect(CLASSIC_ADDRESS, 5, 0.1)
    assert time.monotonic() - started < 1
    words = (raised.value.message, raised.value.hint)
    assert words == harald_says("timeout", CLASSIC_ADDRESS)
    assert rig.ours.fileno() == -1  # closed


def reopening(driver, monkeypatch, sockets, errnos):
    """Hands `driver`'s linux link `sockets` in turn, has its connects end with
    `errnos` in turn, and keeps its pauses instead of sleeping them."""
    pauses = []
    monkeypatch.setattr(driver, "linux_new_socket", lambda kind, proto: sockets.pop(0))
    monkeypatch.setattr(driver, "linux_libc_connect", lambda fd, addr: errnos.pop(0))
    clock = types.SimpleNamespace(monotonic=time.monotonic, sleep=pauses.append)
    monkeypatch.setattr(driver, "time", clock)
    return pauses


@pytest.mark.parametrize("err", [errno.EBUSY, errno.ECONNRESET])
def test_linux_connect_tries_once_more_when_a_channel_is_still_closing(
    linux, monkeypatch, err
):
    # as harald's btsock does: a channel just closed is busy until the gadget
    # confirms the close, and closing the last one resets a connect made meanwhile
    driver, rig = linux.driver, linux.rig
    first = Unready(rig.ours, 0)
    pauses = reopening(driver, monkeypatch, [first, rig.ours], [err, 0])
    assert driver.linux_connect(CLASSIC_ADDRESS, 5, 1.0) is rig.ours
    assert first.closed
    assert pauses == [driver.LINUX_RETRY_PAUSE] == [btsock.RETRY_PAUSE]


@pytest.mark.parametrize("err", [errno.EBUSY, errno.ECONNRESET])
def test_linux_connect_still_closing_twice_says_what_harald_says(
    linux, monkeypatch, on_linux, err
):
    driver, rig = linux.driver, linux.rig
    first, again = Unready(rig.ours, 0), Unready(rig.ours, 0)
    pauses = reopening(driver, monkeypatch, [first, again], [err, err])
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_connect(CLASSIC_ADDRESS, 5, 1.0)
    code, detail = btsock.error_code(err, connecting=True)
    expected = harald.classic._mapped(BackendError(code, detail), CLASSIC_ADDRESS, 5)
    assert (raised.value.message, raised.value.hint) == (
        expected.message,
        expected.hint,
    )
    assert first.closed and again.closed
    assert pauses == [driver.LINUX_RETRY_PAUSE]


def test_linux_connect_without_a_bluetooth_socket(linux, monkeypatch, on_linux):
    driver = linux.driver

    def refused(err):
        def new_socket(kind, proto):
            raise OSError(err, "nope")

        return new_socket

    monkeypatch.setattr(driver, "linux_new_socket", refused(errno.EAFNOSUPPORT))
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_connect(CLASSIC_ADDRESS, 5, 1.0)
    assert (raised.value.message, raised.value.hint) == hints.unsupported_classic()
    # making the socket is not the connect: eacces here is permission, not pairing
    monkeypatch.setattr(driver, "linux_new_socket", refused(errno.EACCES))
    with pytest.raises(driver.DriverError) as raised:
        driver.linux_connect(CLASSIC_ADDRESS, 5, 1.0)
    assert (raised.value.message, raised.value.hint) == harald_says("permission")


def test_linux_link_reads_every_piece_and_closes_at_once(linux):
    driver, rig = linux.driver, linux.rig
    answer = bytes(range(40))  # comes in 7-byte pieces
    peer = rig.serve(lambda data: answer, piece=7)
    link = driver.LinuxLink(rig.ours, CLASSIC_ADDRESS)
    link.write(b"\x01")
    assert link.read(0.5) == answer
    assert link.read(0) == b""
    link.write(b"\x02")
    started = time.monotonic()
    first = link.read(5, first=True)  # ends once anything came
    assert time.monotonic() - started < 1
    assert first == answer[: len(first)] and first
    started = time.monotonic()
    link.close()
    link.close()
    assert peer.hung_up.wait(1)
    assert time.monotonic() - started < 1
    assert bytes(peer.received) == b"\x01\x02"
    with pytest.raises(
        driver.DriverError, match="^bluetooth error: the channel is closed$"
    ):
        link.write(b"\x03")
    assert link.read(5) == b""


def test_linux_link_after_the_gadget_hangs_up(linux):
    driver, rig = linux.driver, linux.rig
    link = driver.LinuxLink(rig.ours, CLASSIC_ADDRESS)
    rig.theirs.sendall(b"\x09")
    rig.theirs.close()
    started = time.monotonic()
    assert link.read(5) == b"\x09"  # what came before the hang-up, without waiting
    assert time.monotonic() - started < 1
    with pytest.raises(
        driver.DriverError, match="^bluetooth error: the channel is closed$"
    ):
        link.write(b"\x01")
    link.close()


def test_linux_link_write_the_gadget_never_takes_times_out(
    linux, monkeypatch, on_linux
):
    driver, rig = linux.driver, linux.rig
    monkeypatch.setattr(driver, "LINUX_WRITE_SECONDS", 0.1)
    link = driver.LinuxLink(rig.ours, CLASSIC_ADDRESS)
    with pytest.raises(driver.DriverError) as raised:
        link.write(bytes(10_000_000))
    words = (raised.value.message, raised.value.hint)
    assert words == harald_says("timeout", CLASSIC_ADDRESS)
    link.close()


def test_classic_driver_runs_a_command_on_linux(linux, capsys):
    driver, rig = linux.driver, linux.rig
    reply = bytes(range(1, 13))  # sent back in 5-byte pieces
    got = bytearray()
    replies = [reply]

    def answer(data):
        got.extend(data)
        return replies.pop() if len(got) >= 20 and replies else b""

    peer = rig.serve(answer)
    assert driver.main(["on"]) == 0
    assert (
        capsys.readouterr().out
        == f"sent on to {CLASSIC_ADDRESS}\nreply: {reply.hex()}\n"
    )
    assert peer.hung_up.wait(1)  # closed once it was done
    sent = bytes(peer.received)
    assert sent[:4] == b"\xaa\x01\xaa\x02"  # the init payloads, as they are
    assert aes_decrypt(sent[4:], modes.ECB()) == b"\x7e\x00\x04\x01".ljust(16, b"\0")
    assert rig.bluez.calls == [GET_MANAGED_OBJECTS]
    assert rig.connects == [
        btsock.sockaddr_l2(CLASSIC_ADDRESS, btsock.SDP_PSM),
        btsock.sockaddr_rc(CLASSIC_ADDRESS, 5),
    ]
    assert rig.sdp.closed


def test_classic_driver_on_linux_finds_the_gadget_by_its_service(
    classic, tmp_path, monkeypatch, capsys
):
    plain = replace(classic, address_hint="", init_payloads=[], reply_seconds=0)
    driver = load_driver(plain, tmp_path)
    objects = bluez(
        device("11:22:33:44:55:66", alias="phone", uuids=[HEADSET]),
        device(CLASSIC_ADDRESS, alias="Speaker 7f", uuids=[SPP]),
    )
    rig = Rig(driver, monkeypatch, objects, SPEAKER_RECORDS)
    try:
        peer = rig.serve(lambda data: b"")
        assert driver.main(["off"]) == 0
        assert capsys.readouterr().out == f"sent off to {CLASSIC_ADDRESS}\n"
        assert peer.hung_up.wait(1)
    finally:
        rig.close()


def test_classic_driver_on_linux_prints_errors_with_linux_hints(
    linux, monkeypatch, capsys
):
    driver, rig = linux.driver, linux.rig

    def printed(code, channel=None):
        message, hint = harald_says(code, CLASSIC_ADDRESS, channel)
        return f"error: {message}\n  hint: {hint}\n"

    rig.bluez.error = bluez_names.NOT_RUNNING[0]
    assert driver.main(["on"]) == 2
    assert capsys.readouterr().err == printed("bluetooth_off")
    rig.bluez.error = None
    rig.bluez.objects = bluez()  # nothing paired
    assert driver.main(["on"]) == 2
    assert capsys.readouterr().err == printed("not_paired")
    # the gadget has forgotten the pairing: sdp works, rfcomm's connect gets eacces
    rig.bluez.objects = bluez(device(CLASSIC_ADDRESS, uuids=[SPP]))

    def connect(fd, addr):
        return errno.EACCES if addr == btsock.sockaddr_rc(CLASSIC_ADDRESS, 5) else 0

    monkeypatch.setattr(driver, "linux_libc_connect", connect)
    assert driver.main(["on"]) == 2
    assert capsys.readouterr().err == printed("pairing")
    assert rig.ours.fileno() == -1  # the socket was closed
