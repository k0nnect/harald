"""The wh-1000xm5 driver, through a fake link: no test opens a real channel.

Byte strings marked "real" were seen on real headphones (the spike and h2). The linux
path runs against a fake bluez, sdp server and rfcomm peer (tests/linux_fakes.py).
"""

import ast
import contextlib
import errno
import importlib.util
import socket
import sys
import types
from pathlib import Path

import pytest
from classic_fakes import XM5_ADDRESS, XM5_RECORDS
from linux_fakes import Rig, bluez, device, names_needed

from harald import btsock, hints
from harald.templates import linux_link

DRIVER = Path(__file__).resolve().parents[1] / "devices" / "wh-1000xm5" / "driver.py"
# the lines around the driver's copy of harald's linux link
LINK_START = (
    "# --- linux link: copied from harald's templates/linux_link.py.tmpl as it is ---\n"
)
LINK_END = "\n# --- end of the linux link "


def _load():
    spec = importlib.util.spec_from_file_location("wh1000xm5_driver", DRIVER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


drv = _load()

# real: the ack (next seq 1) and the handshake reply, in one rfcomm chunk
HANDSHAKE_REPLY = bytes.fromhex("3e010100000000023c3e0c010000000801000300201600004f3c")
# what the driver may send: the handshake, 66 17, 68 17 01 .., 22 00, and acks
ALLOWED = (bytes.fromhex("0000"), bytes.fromhex("6617"), bytes.fromhex("2200"))


def ack(seq):
    return drv.frame(0x01, seq, b"")


def data(seq, payload_hex):
    return drv.frame(0x0C, seq, bytes.fromhex(payload_hex))


class FakeLink:
    """Hands out scripted reads in order (b"" once they run out: nothing came in
    time) and records every write, checking it is one the driver may send."""

    def __init__(self, *reads):
        self.reads = list(reads)
        self.writes = []
        self.waits = []

    def write(self, raw):
        frames = drv.Deframer().feed(raw)
        assert len(frames) == 1, raw.hex()
        data_type, _, payload = frames[0]
        if data_type == 0x01:
            assert payload == b""
        else:
            assert data_type == 0x0C
            assert payload in ALLOWED or (
                payload[:3] == bytes.fromhex("681701") and len(payload) == 7
            ), payload.hex()
        self.writes.append(bytes(raw))

    def read(self, seconds):
        self.waits.append(seconds)
        return self.reads.pop(0) if self.reads else b""


def sent(link):
    """The (data type, seq, payload) of every frame written, in order."""
    return [drv.Deframer().feed(raw)[0] for raw in link.writes]


def sent_payloads(link):
    return [payload.hex() for data_type, _, payload in sent(link) if data_type == 0x0C]


def state_reply(state_hex):
    """After the handshake: the ack for 66 17 (sent with seq 1), then the state."""
    return ack(0) + data(0, state_hex)


def test_frame_matches_real_frames():
    assert drv.frame(0x0C, 0, bytes.fromhex("0000")).hex() == "3e0c000000000200000e3c"
    assert drv.frame(0x0C, 1, bytes.fromhex("2200")).hex() == "3e0c01000000022200313c"
    assert (
        drv.frame(0x0C, 0, bytes.fromhex("68170101000014")).hex()
        == "3e0c000000000768170101000014a83c"
    )


def test_frame_escapes_markers():
    assert drv.frame(0x0C, 0, b"\x3e").hex() == "3e0c00000000013d2e4b3c"


def test_deframer_two_frames_in_one_chunk():
    assert drv.Deframer().feed(HANDSHAKE_REPLY) == [
        (1, 1, b""),
        (0x0C, 1, bytes.fromhex("0100030020160000")),
    ]


def test_deframer_split_escape():
    raw = drv.frame(0x0C, 0, b"\x3e")
    cut = raw.index(0x3D) + 1
    deframer = drv.Deframer()
    assert deframer.feed(raw[:cut]) == []
    assert deframer.feed(raw[cut:]) == [(0x0C, 0, b"\x3e")]


def test_deframer_keeps_a_partial_frame_and_drops_bad_ones():
    deframer = drv.Deframer()
    good = data(1, "23005600")
    bad = bytearray(data(0, "23005600"))
    bad[-2] ^= 0xFF  # the checksum
    assert deframer.feed(b"\x00" + bytes(bad) + good[:5]) == []
    assert deframer.feed(good[5:]) == [(0x0C, 1, bytes.fromhex("23005600"))]


def test_handshake_reads_the_reply_and_acks_it():
    link = FakeLink(HANDSHAKE_REPLY)
    mdr = drv.Mdr(link)
    mdr.handshake()
    assert sent(link) == [(0x0C, 0, bytes.fromhex("0000")), (0x01, 0, b"")]
    assert mdr.seq == 1  # the seq the ack carried


def test_unsolicited_frame_acked_and_ignored():
    # a real ambient run: an unsolicited a5 frame came before the 67 reply
    link = FakeLink(
        HANDSHAKE_REPLY,
        ack(0),
        data(0, "a501000201"),
        data(1, "67170101010014"),
    )
    mdr = drv.Mdr(link)
    mdr.handshake()
    assert mdr.read_nc() == drv.NcState(
        switch=True, ambient=True, voice=False, level=20
    )
    assert sent(link)[2:] == [
        (0x0C, 1, bytes.fromhex("6617")),
        (0x01, 1, b""),  # the a5 frame's ack
        (0x01, 0, b""),  # the 67 reply's ack
    ]


@pytest.mark.parametrize(
    ("state", "payload"),
    [
        ("67170101000014", "68170101010014"),  # from noise cancelling, level 20
        ("67170101010107", "68170101010107"),  # voice focus and level 7 kept
    ],
)
def test_ambient_on_keeps_level_and_voice(state, payload):
    link = FakeLink(
        HANDSHAKE_REPLY, state_reply(state), ack(1) + data(1, "69" + payload[2:])
    )
    assert drv.run(["ambient", "on"], link) == "ambient on"
    assert sent_payloads(link) == ["0000", "6617", payload]


@pytest.mark.parametrize("args", [["anc", "off"], ["ambient", "off"]])
def test_anc_off(args):
    link = FakeLink(HANDSHAKE_REPLY, state_reply("67170101010014"), ack(1))
    assert drv.run(args, link) == "noise control off"
    assert sent_payloads(link) == ["0000", "6617", "68170100000014"]


def test_anc_on():
    link = FakeLink(HANDSHAKE_REPLY, state_reply("67170101010114"), ack(1))
    assert drv.run(["anc", "on"], link) == "noise cancelling on"
    assert sent_payloads(link) == ["0000", "6617", "68170101000014"]


def test_set_acks_the_change_notification():
    link = FakeLink(
        HANDSHAKE_REPLY,
        state_reply("67170101010014"),
        ack(1) + data(1, "69170100000014"),
    )
    drv.run(["anc", "off"], link)
    assert sent(link)[-1] == (0x01, 0, b"")


def test_set_without_an_ack_raises():
    link = FakeLink(HANDSHAKE_REPLY, state_reply("67170101010014"))
    with pytest.raises(drv.DriverError) as e:
        drv.run(["anc", "off"], link)
    assert e.value.message == "the headphones did not take the setting"
    assert "move closer" in e.value.hint


@pytest.mark.parametrize(
    ("reply", "line"),
    [
        (data(0, "23005600"), "battery 86%, not charging"),
        (data(0, "23001401"), "battery 20%, charging"),
        (data(0, "23006403"), "battery 100%, charged"),
        # real (h2): escaped on the air, 62% and not charging
        (bytes.fromhex("3e0c000000000423003d2e00713c"), "battery 62%, not charging"),
    ],
)
def test_battery(reply, line):
    link = FakeLink(HANDSHAKE_REPLY, ack(0) + reply)
    assert drv.run(["battery"], link) == line
    assert sent_payloads(link) == ["0000", "2200"]


@pytest.mark.parametrize(
    ("state", "line"),
    [
        ("67170100000014", "noise control off"),
        ("67170100010014", "noise control off"),
        ("67170101000014", "noise cancelling on"),
        ("67170101010014", "ambient on, level 20"),
        ("67170101010105", "ambient on, level 5, voice focus"),
    ],
)
def test_status_lines(state, line):
    link = FakeLink(HANDSHAKE_REPLY, state_reply(state))
    assert drv.run(["status"], link) == line
    assert sent_payloads(link) == ["0000", "6617"]


def test_no_state_reply_raises():
    link = FakeLink(HANDSHAKE_REPLY, ack(0))
    with pytest.raises(drv.DriverError) as e:
        drv.run(["status"], link)
    assert e.value.message == "the headphones did not answer"
    assert "move closer" in e.value.hint


def test_handshake_unanswered_raises(on_mac):
    link = FakeLink()
    with pytest.raises(drv.DriverError) as e:
        drv.Mdr(link).handshake()
    assert e.value.message == "the headphones did not answer the handshake"
    assert e.value.hint == (
        "close the sony app on your phone, then turn the mac's bluetooth off and on"
    )
    assert sent(link) == [(0x0C, 0, bytes.fromhex("0000"))] * 2
    assert 1.2 < link.waits[0] <= 1.25  # resent after 1.25 s
    assert 2.9 < link.waits[1] <= 3.0  # then the reply timeout


def test_handshake_answered_on_the_resend():
    link = FakeLink(b"", HANDSHAKE_REPLY)
    drv.Mdr(link).handshake()
    assert sent_payloads(link) == ["0000", "0000"]


def sent_seqs(link):
    """The seq of every data frame written, in order."""
    return [seq for data_type, seq, _ in sent(link) if data_type == 0x0C]


def test_a_stale_ack_is_ignored_and_the_right_one_used():
    # the handshake went out twice and the headphones acked both copies: the second
    # ack (seq 1 again) lands in the 66 17 exchange, which was sent with seq 1 and
    # waits for an ack carrying 0
    link = FakeLink(
        b"",
        HANDSHAKE_REPLY,
        ack(1),  # stale
        state_reply("67170101010014"),
        ack(1),
    )
    assert drv.run(["anc", "off"], link) == "noise control off"
    assert sent_payloads(link) == ["0000", "0000", "6617", "68170100000014"]
    assert sent_seqs(link) == [0, 0, 1, 0]  # 68 17 goes out with the fresh seq


def test_a_set_answered_only_by_a_stale_ack_is_not_reported_as_done():
    # 68 17 is sent with seq 0; an ack carrying 0 is not its ack, so nothing says
    # the headphones took the setting
    link = FakeLink(HANDSHAKE_REPLY, state_reply("67170101010014"), ack(0))
    with pytest.raises(drv.DriverError) as e:
        drv.run(["anc", "off"], link)
    assert e.value.message == "the headphones did not take the setting"


def test_a_frame_with_seq_2_does_not_crash():
    link = FakeLink(
        HANDSHAKE_REPLY,
        drv.frame(0x01, 2, b"")  # an ack with a seq that can't be next: ignored
        + ack(0)
        + drv.frame(0x0C, 2, bytes.fromhex("a501000201"))
        + data(0, "23005600"),
    )
    mdr = drv.Mdr(link)
    mdr.handshake()
    assert mdr.battery() == (86, "not charging")
    assert mdr.seq == 0
    assert sent(link)[-2:] == [(0x01, 3, b""), (0x01, 1, b"")]


def test_only_a_command_data_frame_counts_as_the_reply():
    other = drv.frame(0x0E, 0, bytes.fromhex("23000100"))  # not type 0c
    link = FakeLink(HANDSHAKE_REPLY, ack(0) + other + data(0, "23005600"))
    assert drv.run(["battery"], link) == "battery 86%, not charging"
    assert sent(link)[-2:] == [(0x01, 1, b""), (0x01, 1, b"")]  # both acked


@pytest.mark.parametrize(
    ("args", "reads"),
    [
        (["status"], [HANDSHAKE_REPLY, state_reply("67170101000014")]),
        (["battery"], [HANDSHAKE_REPLY, ack(0) + data(0, "23005600")]),
        (
            ["anc", "off"],
            [
                HANDSHAKE_REPLY,
                state_reply("67170101010014"),
                ack(1) + data(1, "69170100000014"),
            ],
        ),
        # the reply first, its ack in a later chunk
        (["status"], [HANDSHAKE_REPLY, data(0, "67170101000014"), ack(0)]),
    ],
)
def test_each_exchange_stops_reading_once_it_has_its_ack_and_reply(args, reads):
    spare = data(0, "a501000201")  # there to be read only by an exchange that overstays
    link = FakeLink(*reads, spare)
    drv.run(args, link)
    assert len(link.waits) == len(reads)
    assert link.reads == [spare]


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["anc"], "anc needs on or off"),
        (["ambient", "maybe"], "ambient needs on or off"),
        (["anc", "on", "now"], "anc needs on or off"),
        (["battery", "on"], "battery takes no on or off"),
        (["louder"], "unknown command: louder"),
        ([], "no command"),
    ],
)
def test_cli_requires_on_or_off(monkeypatch, capsys, argv, message):
    def no_link(address):
        raise AssertionError("opened a link for a bad command")

    monkeypatch.setattr(drv, "open_link", no_link)
    assert drv.main(argv) == 2
    err = capsys.readouterr().err.splitlines()
    assert err[0] == f"error: {message}"
    assert err[1].startswith("  hint: ")


def test_main_prints_the_line_and_passes_the_address(monkeypatch, capsys):
    opened = []

    @contextlib.contextmanager
    def fake_open(address):
        opened.append(address)
        yield FakeLink(HANDSHAKE_REPLY, ack(0) + data(0, "23005600"))

    monkeypatch.setattr(drv, "open_link", fake_open)
    assert drv.main(["--address", "AA-BB-CC-11-22-33", "battery"]) == 0
    assert capsys.readouterr().out == "battery 86%, not charging\n"
    assert opened == ["AA-BB-CC-11-22-33"]


def test_main_prints_driver_errors(monkeypatch, capsys, on_mac):
    @contextlib.contextmanager
    def fake_open(address):
        yield FakeLink()

    monkeypatch.setattr(drv, "open_link", fake_open)
    assert drv.main(["status"]) == 2
    assert capsys.readouterr().err == (
        "error: the headphones did not answer the handshake\n"
        "  hint: close the sony app on your phone, "
        "then turn the mac's bluetooth off and on\n"
    )


def test_driver_is_standalone():
    source = DRIVER.read_text(encoding="utf-8")
    assert source.startswith("# /// script\n")
    header = source.split("# ///\n", 1)[0]
    assert "pyobjc-framework-IOBluetooth>=11; sys_platform == 'darwin'" in header
    assert "dbus-fast>=2; sys_platform == 'linux'" in header
    tree = ast.parse(source)
    everywhere = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        for alias in getattr(node, "names", [])
        if isinstance(node, ast.Import)
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    top = {
        name
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for name in (
            [node.module or ""]
            if isinstance(node, ast.ImportFrom)
            else [alias.name for alias in node.names]
        )
    }
    assert "harald" not in everywhere
    assert "IOBluetooth" in everywhere  # inside open_link
    assert not top & {"IOBluetooth", "objc", "Foundation"}
    assert drv.SERVICE_UUID == "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"
    assert drv.NAME_HINT == "WH-1000XM5"


# --- on linux, through the linux link -----------------------------------------


def test_xm5_linux_link_matches_template():
    # the driver cannot import harald, so it carries the block; it must not drift
    source = DRIVER.read_text(encoding="utf-8")
    assert source.count(LINK_START) == source.count(LINK_END) == 1
    copy = source.split(LINK_START)[1].split(LINK_END)[0]
    assert copy.strip("\n") == linux_link()
    assert names_needed(linux_link(), source) == set()


def test_docstring_says_it_runs_on_a_mac_or_linux():
    assert "mac or linux" in drv.__doc__
    assert "paired with this mac" not in drv.__doc__


def test_linux_words_say_nothing_of_a_mac(on_linux):
    with pytest.raises(drv.DriverError) as e:
        drv.Mdr(FakeLink()).handshake()
    assert e.value.hint == (
        "close the sony app on your phone, "
        "then restart bluetooth with sudo systemctl restart bluetooth"
    )
    with pytest.raises(drv.DriverError) as e:
        drv.run(["status"], FakeLink(HANDSHAKE_REPLY, ack(0)))
    assert e.value.message == "the headphones did not answer"
    assert e.value.hint == hints.timeout()


@pytest.fixture
def linux(monkeypatch):
    """The driver on linux: bluez has the headphones paired, their sdp server holds
    the real records (control channel 9), and a socketpair is the channel."""
    objects = bluez(
        device("11:22:33:44:55:66", alias="phone"),
        device(XM5_ADDRESS, alias="WH-1000XM5", uuids=[drv.SERVICE_UUID]),
    )
    rig = Rig(drv, monkeypatch, objects, XM5_RECORDS)
    yield rig
    rig.close()


def replay(*replies):
    """A peer's answer: the next of `replies` for each data frame the driver sends,
    nothing for its acks."""
    deframer, left = drv.Deframer(), list(replies)

    def answer(raw):
        frames = deframer.feed(raw)
        return b"".join(left.pop(0) for t, _, _ in frames if t == 0x0C and left)

    return answer


def test_battery_on_linux(linux, capsys):
    peer = linux.serve(replay(HANDSHAKE_REPLY, ack(0) + data(0, "23005600")))
    assert drv.main(["battery"]) == 0
    assert capsys.readouterr().out == "battery 86%, not charging\n"
    assert peer.hung_up.wait(1)  # the channel closed after the one command
    frames = drv.Deframer().feed(bytes(peer.received))
    assert [(t, s, p.hex()) for t, s, p in frames] == [
        (0x0C, 0, "0000"),
        (0x01, 0, ""),  # the handshake reply's ack
        (0x0C, 1, "2200"),
        (0x01, 1, ""),
    ]
    assert linux.connects == [
        btsock.sockaddr_l2(XM5_ADDRESS, btsock.SDP_PSM),
        btsock.sockaddr_rc(XM5_ADDRESS, 9),
    ]


def test_linux_by_address_and_errors(linux, capsys):
    peer = linux.serve(replay(HANDSHAKE_REPLY, ack(0) + data(0, "23001401")))
    assert drv.main(["--address", XM5_ADDRESS.upper(), "battery"]) == 0
    assert capsys.readouterr().out == "battery 20%, charging\n"
    assert peer.hung_up.wait(1)
    assert drv.main(["--address", "aa:bb:cc:dd:ee:ff", "battery"]) == 2
    assert capsys.readouterr().err == (
        "error: aa:bb:cc:dd:ee:ff is not paired with this computer\n"
        f"  hint: {hints.pair('aa:bb:cc:dd:ee:ff')}\n"
    )
    linux.bluez.objects = bluez(powered=(False,))
    assert drv.main(["battery"]) == 2
    assert capsys.readouterr().err == (
        f"error: {hints.bluetooth_off_message()}\n  hint: {hints.bluetooth_off()}\n"
    )


@pytest.mark.parametrize("has_bluetooth", [True, False])
def test_linux_without_a_system_bus(linux, capsys, has_bluetooth):
    # with no system bus, a kernel with no bluetooth at all (wsl, a container) is
    # told so; any other linux gets the bluetoothd hint
    linux.bluez.connect_error = FileNotFoundError(2, "No such file or directory")
    linux.kernel_bluetooth = has_bluetooth
    assert drv.main(["battery"]) == 2
    if has_bluetooth:
        message, hint = hints.bluetooth_off_message(), hints.bluetooth_off()
    else:
        message, hint = hints.no_bluetooth_support()
    assert capsys.readouterr().err == f"error: {message}\n  hint: {hint}\n"
    assert linux.probes == 1
    assert linux.connects == []  # nothing was opened


@pytest.mark.parametrize("err", [errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, None])
def test_linux_kernel_probe_makes_one_socket_and_closes_it(monkeypatch, err):
    made = []

    def new_socket(kind, proto):
        if err is not None:
            raise OSError(err, "no bluetooth here")
        made.append((kind, proto))
        return types.SimpleNamespace(close=lambda: made.append("closed"))

    monkeypatch.setattr(drv, "linux_new_socket", new_socket)
    assert drv.linux_kernel_has_bluetooth() is (err is None)
    if err is None:
        assert made == [(socket.SOCK_STREAM, btsock.BTPROTO_RFCOMM), "closed"]


def test_linux_when_the_headphones_hang_up(linux, capsys):
    # they read the handshake, then close the channel instead of answering
    linux.serve(lambda raw: linux.theirs.shutdown(socket.SHUT_RDWR) or b"")
    assert drv.main(["status"]) == 2
    assert capsys.readouterr().err == (
        f"error: the headphones closed the control channel\n  hint: {hints.timeout()}\n"
    )
