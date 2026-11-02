"""Output templates: a protocol write-up and a standalone driver, rendered from a spec.

The rendered driver is loaded as a module and driven with the bleak fakes, so no
test needs a radio.
"""

import ast
import contextlib
import importlib.util
import re
import sys
import time
import tomllib
import types
import uuid
from dataclasses import replace
from importlib.resources import files

import pytest
from bleak.exc import BleakError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService, advert

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


def test_classic_driver_declares_pyobjc_and_not_bleak(classic):
    source = render_driver(classic)
    assert source.startswith("# /// script\n")
    meta = metadata(source)
    assert meta["requires-python"] == ">=3.11"
    assert meta["dependencies"] == ["cryptography>=44", PYOBJC]
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


def pick(driver, paired, address="", name_hint=""):
    return driver.pick_device(
        paired, address, name_hint, lambda device: SPP in device.services, SPP
    )


def test_classic_lookup_by_address_takes_only_that_address(classic, tmp_path):
    driver = load_driver(classic, tmp_path)
    speaker = FakeDevice("AA-BB-CC-11-22-33", "Speaker 7f", connected=False)
    bose = FakeDevice("aa-bb-cc-dd-ee-ff", "Bose QC35", services=(SPP,))
    paired = [bose, speaker]
    assert pick(driver, paired, "aa:bb:cc:11:22:33", "Bose") is speaker
    assert pick(driver, paired, "AA-BB-CC-DD-EE-FF", "Speaker") is bose
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, paired, "00:00:00:00:00:01", "Speaker")
    assert raised.value.message == "00:00:00:00:00:01 is not paired with this mac"
    assert raised.value.hint == "pair it in system settings > bluetooth"


def test_classic_lookup_by_name_ignores_devices_that_only_list_the_service(
    classic, tmp_path
):
    # the speaker is paired but off, and a connected headset also lists the serial
    # port service: the driver must not write the speaker's commands to the headset
    driver = load_driver(classic, tmp_path)
    speaker = FakeDevice("AA-BB-CC-11-22-33", "Speaker 7f", connected=False)
    bose = FakeDevice("aa-bb-cc-dd-ee-ff", "Bose QC35", services=(SPP,))
    assert pick(driver, [bose, speaker], name_hint="Speaker") is speaker
    # among name matches, a connected one comes first, whatever the paired order
    spare = FakeDevice("11-22-33-44-55-66", "Speaker 80")
    assert pick(driver, [speaker, bose, spare], name_hint="Speaker") is spare
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, [bose, speaker], name_hint="Lamp")
    assert raised.value.message == "no paired device named Lamp* found"
    assert raised.value.hint == "pair it in system settings > bluetooth"


def test_classic_lookup_by_service_needs_exactly_one_device(classic, tmp_path):
    driver = load_driver(classic, tmp_path)
    speaker = FakeDevice("AA-BB-CC-11-22-33", "Speaker 7f", services=(SPP,))
    bose = FakeDevice("aa-bb-cc-dd-ee-ff", "Bose QC35", services=(SPP,))
    phone = FakeDevice("11-22-33-44-55-66", "phone")
    assert pick(driver, [phone, speaker]) is speaker
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, [speaker, phone, bose])
    assert raised.value.message == (
        f"more than one paired device lists service {SPP}: "
        "aa:bb:cc:11:22:33, aa:bb:cc:dd:ee:ff"
    )
    assert raised.value.hint == "pass --address with the one to use"
    with pytest.raises(driver.DriverError) as raised:
        pick(driver, [phone])
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
    pyobjc is blocked as well, so a missed patch fails rather than reach bluetooth."""
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
