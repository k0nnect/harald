"""The human cli, driven through `main([...])` with fake ble and classic backends and
a fake runner."""

import re
import subprocess
import sys

import pytest
from bleak.exc import BleakError
from capture_helpers import mixed_capture, write_capture
from classic_fakes import XM5_ADDRESS, XM5_RECORDS, FakeBackend
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService

import harald
from harald import arm, cli, library
from harald.apk import ApkReport, Candidate
from harald.classic import ClassicDevice, ServiceRecord

HPC = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"  # the xm5's vendor channel, 9
SPP = "00001101-0000-1000-8000-00805f9b34fb"
M1 = bytes.fromhex("3e0c000000000200000e3c")
M2 = bytes.fromhex("3e010000000000013c")
ACK = bytes.fromhex("3e010100000000023c")
HELLO = bytes.fromhex("3e0c000000000801000300201600004f3c")
BATTERY = bytes.fromhex("3e0c010000000623005a00983c")


@pytest.fixture(autouse=True)
def fake_backends(monkeypatch):
    """Fake radios, and a driver runner that fails the test if anything shells out.

    run_main is a pass-through, so no classic command starts the mac's run loop pump.
    """

    def no_shell(*args, **kwargs):
        raise AssertionError(f"unexpected subprocess: {args}")

    monkeypatch.setattr(cli, "scanner_cls", FakeScanner)
    monkeypatch.setattr(cli, "client_cls", FakeClient)
    monkeypatch.setattr(cli, "runner", no_shell)
    monkeypatch.setattr(cli, "classic_backend", FakeBackend())
    monkeypatch.setattr("harald.classic_mac.run_main", lambda fn: fn())


def timed(out: str) -> list[str]:
    """The output's lines, with each chunk's `+0.123s` replaced by `+<t>s`."""
    return [re.sub(r"\+\d+\.\d{3}s", "+<t>s", line) for line in out.splitlines()]


def spaced(data: bytes) -> str:
    return data.hex(" ")


def at_terminal(monkeypatch, reply: str = "arm", *, stdin=True, stdout=True):
    """Make stdin and stdout report a terminal where the person types `reply` when
    asked. Returns the prompts shown.

    Call it in the test body, not from a fixture: capsys swaps in a fresh sys.stdout
    once setup is over, so a fixture would patch the wrong one.
    """
    prompts: list[str] = []

    def type_reply(prompt: str = "") -> str:
        prompts.append(prompt)
        return reply

    monkeypatch.setattr(sys.stdin, "isatty", lambda: stdin)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: stdout)
    monkeypatch.setattr("builtins.input", type_reply)
    return prompts


def test_scan_prints_sorted_table(capsys):
    assert cli.main(["scan", "--timeout", "0.1"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["address", "rssi", "name"]
    assert lines[1].split() == ["BB-22", "-40", "scale"]
    assert [line.split()[0] for line in lines[1:]] == ["BB-22", "AA-11", "CC-33"]


def test_arm_then_status_shows_grant(monkeypatch, capsys):
    at_terminal(monkeypatch)
    assert cli.main(["arm", "aa-11", "--writes", "5"]) == 0
    capsys.readouterr()
    assert cli.main(["status"]) == 0
    rows = [line.split() for line in capsys.readouterr().out.splitlines()]
    grant = next(row for row in rows if row[0] == "aa-11")
    assert grant[1] == "5"


def test_arm_shows_the_grant_and_asks_first(monkeypatch, capsys):
    prompts = at_terminal(monkeypatch)
    assert cli.main(["arm", "aa-11", "--writes", "5", "--minutes", "10"]) == 0
    assert prompts == ["type arm to confirm: "]
    shown = capsys.readouterr().out.splitlines()[0]
    assert shown == "this lets harald write to aa-11: up to 5 writes in the next 10 min"


@pytest.mark.parametrize("reply", ["", "yes", "ARM", "arm it"])
def test_arm_without_the_word_arms_nothing(monkeypatch, capsys, reply):
    at_terminal(monkeypatch, reply)
    assert cli.main(["arm", "aa-11"]) == 1
    assert capsys.readouterr().out.endswith("\nnot armed\n")
    assert arm.status() == []


@pytest.mark.parametrize(("stdin", "stdout"), [(False, True), (True, False)])
def test_arm_refuses_without_a_terminal(monkeypatch, capsys, stdin, stdout):
    prompts = at_terminal(monkeypatch, stdin=stdin, stdout=stdout)
    assert cli.main(["arm", "aa-11"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: harald arm only runs in an interactive terminal\n")
    assert "hint: run it yourself, in your own terminal" in err
    assert "ask the human" in err
    assert "cannot arm" not in err  # a fake terminal could get past this check
    assert err == err.lower()
    assert prompts == []  # refused before asking
    assert arm.status() == []


@pytest.mark.parametrize("stream", ["stdin", "stdout"])
def test_arm_without_stdin_or_stdout_refuses_cleanly(monkeypatch, capsys, stream):
    # pythonw and some launchers start with no stdin or stdout at all
    prompts = at_terminal(monkeypatch)
    with monkeypatch.context() as m:  # undone before capsys restores its streams
        m.setattr(sys, stream, None)
        assert cli.main(["arm", "aa-11"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: harald arm only runs in an interactive terminal\n")
    assert prompts == []
    assert arm.status() == []


def test_capture_open_prints_timeline(tmp_path, capsys):
    path = write_capture(tmp_path, discovery=True, writes=[b"\x01\x02", b"\x03"])
    assert cli.main(["capture", "open", str(path)]) == 0
    out = capsys.readouterr().out
    assert "phone->device  write_cmd  h=0x0012  ffe1  01 02" in out
    assert out.rstrip().endswith("showing 1–2 of 2 events")


def test_capture_open_filters_by_connection(tmp_path, capsys):
    path = write_capture(tmp_path, discovery=True, writes=[b"\x01\x02", b"\x03"])
    assert cli.main(["capture", "open", str(path), "--conn", "0x0040"]) == 0
    out = capsys.readouterr().out
    assert "c=0x0040  phone->device  write_cmd  h=0x0012  ffe1  01 02" in out
    assert out.rstrip().endswith("showing 1–2 of 2 events with c=0x0040")
    assert cli.main(["capture", "open", str(path), "--conn", "65"]) == 0
    assert capsys.readouterr().out == "showing 0 of 0 events with c=0x0041\n"


def test_capture_open_filters_by_rfcomm_channel(tmp_path, capsys):
    path = mixed_capture(tmp_path)
    assert cli.main(["capture", "open", str(path), "--channel", "9"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [line.split("  ")[0] for line in lines[:-1]] == ["#1", "#3", "#6", "#8"]
    assert "c=0x000b  phone->device  rfcomm  ch=9  -  3e 0c 00" in lines[1]
    assert lines[-1] == "showing 1–4 of 4 events with ch=9"
    argv = ["capture", "open", str(path), "--conn", "0x000b", "--channel", "0x2"]
    assert cli.main(argv) == 0
    assert capsys.readouterr().out.endswith(
        "showing 1–2 of 2 events with c=0x000b and ch=2\n"
    )


def test_capture_open_help_names_the_channel_filter(capsys):
    assert cli.main(["capture", "open", "--help"]) == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--channel n only rfcomm events on this channel, e.g. 9" in help_text


def test_bluetooth_off_exits_2_with_hint(on_mac, capsys):
    FakeClient.reset(connect_error=BleakError("Bluetooth device is turned off"))
    assert cli.main(["connect", "AA-11"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: bluetooth is off")
    assert "privacy & security" in captured.err
    assert "Traceback" not in captured.err


def test_write_without_arm_exits_2(capsys):
    assert cli.main(["write", "AA-11", CHR, "0102"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: writes to AA-11 are locked")
    assert "harald arm" in err
    assert FakeClient.writes == []


def test_write_after_arm_reaches_device(monkeypatch, capsys):
    at_terminal(monkeypatch)
    assert cli.main(["arm", "AA-11", "--writes", "5"]) == 0
    assert cli.main(["write", "AA-11", CHR, "0102"]) == 0
    assert "writes left: 4" in capsys.readouterr().out
    # the default fake characteristic allows write-without-response, so that is used
    assert FakeClient.writes == [(CHR, b"\x01\x02", False)]


def test_failing_disconnect_keeps_the_result_and_the_error(capsys):
    FakeClient.reset(disconnect_error=BleakError("Not connected"))
    assert cli.main(["write", "AA-11", CHR, "0102"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: writes to AA-11 are locked\n  hint: ")
    assert "harald arm" in err
    arm.arm("AA-11", writes=5)
    assert cli.main(["write", "AA-11", CHR, "0102"]) == 0
    assert capsys.readouterr().out == f"wrote 0102 to {CHR}; writes left: 4\n"
    assert FakeClient.writes == [(CHR, b"\x01\x02", False)]


@pytest.mark.parametrize(
    ("properties", "flags", "response"),
    [
        (["write-without-response"], [], False),
        (["write"], [], True),
        (["write-without-response"], ["--response"], True),
        (["write"], ["--no-response"], False),
    ],
)
def test_write_type_is_auto_unless_chosen(properties, flags, response):
    FakeClient.reset(services=[FakeService(SVC, [FakeChar(CHR, 0x12, properties)])])
    arm.arm("AA-11")
    assert cli.main(["write", "AA-11", CHR, "01", *flags]) == 0
    assert FakeClient.writes == [(CHR, b"\x01", response)]


def test_drive_unknown_slug_exits_2(capsys):
    assert cli.main(["drive", "nope", "color", "pink"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: unknown device: nope")
    assert "harald devices" in err


def test_writes_and_minutes_must_be_positive(capsys):
    assert cli.main(["arm", "aa-11", "--writes", "0"]) == 2
    assert cli.main(["arm", "aa-11", "--minutes", "-5"]) == 2
    assert "positive integer" in capsys.readouterr().err
    assert cli.main(["status"]) == 0
    assert "aa-11" not in capsys.readouterr().out


def test_drive_runs_library_driver_with_uv(tmp_path, monkeypatch):
    root = tmp_path / "devices"
    (root / "demo-lamp").mkdir(parents=True)
    (root / "demo-lamp" / "device.toml").write_text(
        'name = "demo lamp"\nvendor = "acme"\nstatus = "decoded"\nkey_scope = "none"\n'
    )
    driver = root / "demo-lamp" / "driver.py"
    driver.write_text("print('on')\n")
    monkeypatch.setattr(library, "devices_root", lambda: root)
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 3)

    monkeypatch.setattr(cli, "runner", runner)
    assert cli.main(["drive", "demo-lamp", "color", "--hex", "ff00aa"]) == 3
    assert calls == [["uv", "run", str(driver), "color", "--hex", "ff00aa"]]


def test_devices_and_device_show_the_transport(tmp_path, monkeypatch, capsys):
    root = tmp_path / "devices"
    base = 'vendor = "acme"\nstatus = "wanted"\nkey_scope = "none"\n'
    entries = {
        "demo-lamp": 'name = "demo lamp"\n',
        "headset": 'name = "headset"\ntransport = "classic"\nname_hint = "acme hs"\n',
    }
    for slug, extra in entries.items():
        (root / slug).mkdir(parents=True)
        (root / slug / "device.toml").write_text(extra + base)
    monkeypatch.setattr(library, "devices_root", lambda: root)
    assert cli.main(["devices"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "slug       status       transport  name",
        "demo-lamp  wanted       ble        demo lamp",
        "headset    wanted       classic    headset",
    ]
    assert cli.main(["device", "headset"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "transport: classic" in lines
    assert "name hint: acme hs" in lines
    assert cli.main(["device", "demo-lamp"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "transport: ble" in lines
    assert not any(line.startswith("name hint:") for line in lines)


def test_apk_prints_the_totals_beside_the_capped_lists(tmp_path, monkeypatch, capsys):
    uuid = "0000ffe1-0000-1000-8000-00805f9b34fb"
    report = ApkReport(
        path=tmp_path / "app.apk",
        package="com.example.gadget",
        framework="native",
        gatt_uuids=[uuid],
        candidates=[Candidate("char-uuid", "sources/a/Ble.java:3", "UUID u = x;")],
        jadx_dir=tmp_path / "jadx",
        warnings=["the report lists at most 50 gatt uuids"],
        totals={"gatt_uuids": 61, "char-uuid": 61, "aes-key": 0},
    )
    monkeypatch.setattr(cli, "analyze_apk", lambda path: report)
    assert cli.main(["apk", str(report.path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "warning: the report lists at most 50 gatt uuids"
    assert "totals: gatt_uuids 61, char-uuid 61, aes-key 0" in lines
    assert f"  {uuid}" in lines
    assert "  char-uuid  sources/a/Ble.java:3  UUID u = x;" in lines


def test_missing_file_exits_2_with_path(tmp_path, capsys):
    missing = tmp_path / "Missing.pklg"
    assert cli.main(["capture", "open", str(missing)]) == 2
    err = capsys.readouterr().err
    assert err == f"error: no such file or directory: {missing}\n"


def test_playbook_install_writes_doc_into_dest(tmp_path, capsys):
    dest = tmp_path / ".claude" / "skills" / "harald"
    assert cli.main(["playbook", "install", "claude-code", "--dest", str(dest)]) == 0
    assert (dest / "SKILL.md").is_file()
    assert capsys.readouterr().out == f"installed {dest / 'SKILL.md'}\n"


def test_playbook_install_unknown_agent_exits_2(tmp_path, capsys):
    assert cli.main(["playbook", "install", "cursor", "--dest", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert err == (
        "error: unknown agent: cursor\n  hint: choose one of: claude-code, codex\n"
    )


def test_arm_shows_and_stores_a_hyphen_mac_in_colon_form(monkeypatch, capsys):
    prompts = at_terminal(monkeypatch)
    argv = ["arm", "AA-BB-CC-11-22-33", "--writes", "5", "--minutes", "10"]
    assert cli.main(argv) == 0
    assert prompts == ["type arm to confirm: "]
    out = capsys.readouterr().out
    assert out.splitlines()[:2] == [
        f"this lets harald write to {XM5_ADDRESS}: up to 5 writes in the next 10 min",
        f"armed {XM5_ADDRESS}: write budget 5, expires in 10 min",
    ]
    assert "aa-bb-cc-11-22-33" not in out  # the colon form only, in any case
    assert out == out.lower()
    assert [g.device for g in arm.status()] == [XM5_ADDRESS]


def test_classic_devices_prints_a_table(monkeypatch, capsys):
    devices = [
        ClassicDevice(XM5_ADDRESS, "WH-1000XM5", True),
        ClassicDevice("00:1a:7d:da:71:13", None, False),
    ]
    monkeypatch.setattr(cli, "classic_backend", FakeBackend(devices=devices))
    assert cli.main(["classic", "devices"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "address            connected  name",
        "aa:bb:cc:11:22:33  yes        WH-1000XM5",
        "00:1a:7d:da:71:13  no         -",
    ]


def test_classic_devices_with_none_paired(on_mac, capsys):
    assert cli.main(["classic", "devices"]) == 0
    assert capsys.readouterr().out == (
        "no paired classic devices; pair one in system settings > bluetooth\n"
    )


def test_classic_devices_with_none_paired_on_linux(on_linux, capsys):
    assert cli.main(["classic", "devices"]) == 0
    assert capsys.readouterr().out == (
        "no paired classic devices; pair one: bluetoothctl pairable on, "
        "bluetoothctl scan on until the gadget shows up, "
        "then bluetoothctl pair <address> and bluetoothctl trust <address>\n"
    )


@pytest.mark.parametrize(
    ("platform", "devices_help", "refresh_help"),
    [
        (
            "darwin",
            "list the bluetooth classic devices paired with this mac",
            "ask the device again instead of trusting the mac's cache",
        ),
        (
            "linux",
            "list the bluetooth classic devices paired with this computer",
            "ask the device again instead of trusting this computer's cache",
        ),
    ],
)
def test_classic_help_names_the_platform(
    monkeypatch, capsys, platform, devices_help, refresh_help
):
    monkeypatch.setattr(sys, "platform", platform)
    assert cli.main(["classic", "--help"]) == 0
    assert devices_help in " ".join(capsys.readouterr().out.split())
    assert cli.main(["classic", "services", "--help"]) == 0
    assert refresh_help in " ".join(capsys.readouterr().out.split())


def test_classic_services_prints_one_line_per_record(monkeypatch, capsys):
    backend = FakeBackend()
    monkeypatch.setattr(cli, "classic_backend", backend)
    assert cli.main(["classic", "services", "AA-BB-CC-11-22-33"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(XM5_RECORDS)
    assert lines[0] == (
        "ch=1   0000111e-0000-1000-8000-00805f9b34fb  Hands-Free unit  protected"
    )
    assert f"ch=9   {HPC}  Serial HPC" in lines
    assert "ch=19  f8d1fbe4-7966-4334-8024-ff96c9330e15  -" in lines
    assert (
        "ch=21  8901dfa8-5c7e-4d8f-9f0c-c2b70683f5f0  Airoha_APP  firmware update"
        in lines
    )
    assert (
        "ch=30  00000000-deca-fade-deca-deafdecacaff  Airoha_IAP2  protected" in lines
    )
    assert [line for line in lines if line.endswith("  protected")] == [
        lines[0],
        "ch=2   00001203-0000-1000-8000-00805f9b34fb  Headset  protected",
        "ch=2   00001108-0000-1000-8000-00805f9b34fb  Headset  protected",
        "ch=30  00000000-deca-fade-deca-deafdecacaff  Airoha_IAP2  protected",
    ]
    assert backend.asked == [(XM5_ADDRESS, False)]


def test_classic_services_joins_extra_uuids_and_marks_a_missing_channel(
    monkeypatch, capsys
):
    records = [ServiceRecord("SPP", [SPP, HPC], 3), ServiceRecord(None, [HPC], None)]
    backend = FakeBackend(records=records)
    monkeypatch.setattr(cli, "classic_backend", backend)
    assert cli.main(["classic", "services", XM5_ADDRESS, "--refresh"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        f"ch=3   {SPP},{HPC}  SPP",
        f"ch=-   {HPC}  -",
    ]
    assert backend.asked == [(XM5_ADDRESS, True)]


def test_classic_services_says_when_there_are_none(monkeypatch, capsys):
    monkeypatch.setattr(cli, "classic_backend", FakeBackend(records=[]))
    assert cli.main(["classic", "services", XM5_ADDRESS]) == 0
    assert capsys.readouterr().out == (
        f"no service records for {XM5_ADDRESS}; "
        f"run: harald classic services {XM5_ADDRESS} --refresh\n"
    )
    assert cli.main(["classic", "services", XM5_ADDRESS, "--refresh"]) == 0
    assert capsys.readouterr().out == f"no service records for {XM5_ADDRESS}\n"


def test_classic_send_prints_each_chunk_after_its_message(monkeypatch, capsys):
    backend = FakeBackend(on_open=[HELLO], replies={M1: [ACK], M2: [ACK, BATTERY]})
    monkeypatch.setattr(cli, "classic_backend", backend)
    arm.arm(XM5_ADDRESS, writes=50)
    argv = ["classic", "send", "AA-BB-CC-11-22-33", HPC, M1.hex(), M2.hex().upper()]
    assert cli.main([*argv, "--listen", "0.5"]) == 0
    assert timed(capsys.readouterr().out) == [
        f"after #0  +<t>s  {spaced(HELLO)}",
        "after #1  +<t>s  3e 01 01 00 00 00 00 02 3c",
        f"after #2  +<t>s  {spaced(ACK)}",
        f"after #2  +<t>s  {spaced(BATTERY)}",
        "sent 2 messages; writes left: 48",
    ]
    assert backend.opened == [(XM5_ADDRESS, 9)]
    assert backend.writes == [M1, M2]
    assert backend.channel.drains == [0.0, 0.5, 0.5]


def test_classic_send_says_why_it_stopped_early(monkeypatch, capsys):
    # a partial send exits 1, so a script can tell it from a whole one (0) and from
    # an error that sent nothing (2)
    backend = FakeBackend(replies={M1: [ACK]})
    monkeypatch.setattr(cli, "classic_backend", backend)
    arm.arm(XM5_ADDRESS, writes=1)
    assert cli.main(["classic", "send", XM5_ADDRESS, "9", M1.hex(), M2.hex()]) == 1
    out, err = capsys.readouterr()
    assert timed(out) == [
        f"after #1  +<t>s  {spaced(ACK)}",
        "sent 1 message; writes left: 0",
    ]
    assert err.startswith(f"stopped: writes to {XM5_ADDRESS} are locked; ")
    assert len(err.splitlines()) == 1
    assert backend.writes == [M1]
    assert backend.channel.drains == [0.0, 2.0]  # --listen defaults to 2 s


def test_classic_send_that_loses_the_link_partway_exits_1(monkeypatch, capsys):
    backend = FakeBackend(replies={M1: [ACK]}, write_error_at=2)
    monkeypatch.setattr(cli, "classic_backend", backend)
    arm.arm(XM5_ADDRESS, writes=5)
    assert cli.main(["classic", "send", XM5_ADDRESS, HPC, M1.hex(), M2.hex()]) == 1
    out, err = capsys.readouterr()
    assert timed(out) == [
        f"after #1  +<t>s  {spaced(ACK)}",
        "sent 1 message; writes left: 3",
    ]
    assert err.startswith("stopped: ")
    assert len(err.splitlines()) == 1


def test_classic_send_without_arm_exits_2(monkeypatch, capsys):
    backend = FakeBackend()
    monkeypatch.setattr(cli, "classic_backend", backend)
    assert cli.main(["classic", "send", "AA-BB-CC-11-22-33", HPC, M1.hex()]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"error: writes to {XM5_ADDRESS} are locked\n  hint: ")
    assert f"harald arm {XM5_ADDRESS}" in err
    assert backend.opened == []


@pytest.mark.parametrize("bad", ["3e0", "zz", "0x3e", ""])
def test_classic_send_checks_every_hex_before_the_backend(monkeypatch, capsys, bad):
    backend = FakeBackend()
    monkeypatch.setattr(cli, "classic_backend", backend)
    arm.arm(XM5_ADDRESS, writes=5)
    assert cli.main(["classic", "send", XM5_ADDRESS, HPC, M1.hex(), bad]) == 2
    err = capsys.readouterr().err
    assert f"must be hex bytes such as 3e010000000000013c, got {bad!r}" in err
    assert backend.asked == []
    assert backend.opened == []
    assert arm.status()[0].writes_left == 5


@pytest.mark.parametrize("command", ["send", "listen"])
def test_classic_protected_channel_exits_2(monkeypatch, capsys, command):
    backend = FakeBackend()
    monkeypatch.setattr(cli, "classic_backend", backend)
    arm.arm(XM5_ADDRESS, writes=5)
    messages = [M1.hex()] if command == "send" else []
    assert cli.main(["classic", command, XM5_ADDRESS, "1", *messages]) == 2
    err = capsys.readouterr().err
    assert err.startswith(
        f"error: channel 1 on {XM5_ADDRESS} is a standard profile\n  hint: "
    )
    assert backend.opened == []
    assert arm.status()[0].writes_left == 5


def test_classic_listen_prints_each_chunk(monkeypatch, capsys):
    backend = FakeBackend(on_open=[HELLO, ACK])
    monkeypatch.setattr(cli, "classic_backend", backend)
    assert cli.main(["classic", "listen", "AA-BB-CC-11-22-33", HPC]) == 0
    assert timed(capsys.readouterr().out) == [
        f"+<t>s  {spaced(HELLO)}",
        f"+<t>s  {spaced(ACK)}",
    ]
    assert backend.opened == [(XM5_ADDRESS, 9)]
    assert backend.channel.drains == [5.0]  # --seconds defaults to 5
    assert backend.writes == []


@pytest.mark.parametrize(
    ("flags", "shown", "drained"),
    [([], "5s", 5.0), (["--seconds", "1.5"], "1.5s", 1.5)],
)
def test_classic_listen_says_when_nothing_came(
    monkeypatch, capsys, flags, shown, drained
):
    backend = FakeBackend()
    monkeypatch.setattr(cli, "classic_backend", backend)
    assert cli.main(["classic", "listen", XM5_ADDRESS, "9", *flags]) == 0
    assert capsys.readouterr().out == f"nothing received in {shown}\n"
    assert backend.channel.drains == [drained]


@pytest.mark.parametrize(
    "argv",
    [
        ["listen", XM5_ADDRESS, "9", "--seconds", "-1"],
        ["listen", XM5_ADDRESS, "9", "--seconds", "inf"],
        ["send", XM5_ADDRESS, "9", "01", "--listen", "nan"],
    ],
)
def test_classic_seconds_must_be_finite_and_not_negative(monkeypatch, capsys, argv):
    backend = FakeBackend()
    monkeypatch.setattr(cli, "classic_backend", backend)
    arm.arm(XM5_ADDRESS, writes=5)
    assert cli.main(["classic", *argv]) == 2
    assert "must be a number of seconds, 0 or more" in capsys.readouterr().err
    assert backend.asked == []


@pytest.mark.parametrize(
    ("argv", "name"),
    [
        (["listen", XM5_ADDRESS, "9", "--seconds", "45"], "seconds"),
        (["send", XM5_ADDRESS, "9", "01", "--listen", "45"], "listen"),
    ],
)
def test_classic_listening_over_30_seconds_exits_2(monkeypatch, capsys, argv, name):
    backend = FakeBackend()
    monkeypatch.setattr(cli, "classic_backend", backend)
    arm.arm(XM5_ADDRESS, writes=5)
    assert cli.main(["classic", *argv]) == 2
    assert capsys.readouterr().err.startswith(
        f"error: {name} must be from 0 to 30 s, got 45\n"
    )
    assert backend.opened == []
    assert arm.status()[0].writes_left == 5


@pytest.mark.parametrize("platform", ["darwin", "linux"])
@pytest.mark.parametrize(
    "command",
    [
        ["devices"],
        ["services", XM5_ADDRESS],
        ["send", XM5_ADDRESS, "9", "01"],
        ["listen", XM5_ADDRESS, "9"],
    ],
)
def test_classic_commands_run_under_run_main_only_on_darwin(
    monkeypatch, capsys, platform, command
):
    ran = []

    class LoggedBackend(FakeBackend):
        def paired(self):
            ran.append("backend")
            return super().paired()

        def records(self, address, refresh):
            ran.append("backend")
            return super().records(address, refresh)

    def run_main(fn):
        ran.append("enter")
        result = fn()
        ran.append("exit")
        return result

    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr("harald.classic_mac.run_main", run_main)
    monkeypatch.setattr(cli, "classic_backend", LoggedBackend())
    arm.arm(XM5_ADDRESS)
    assert cli.main(["classic", *command]) == 0
    if platform == "darwin":  # the classic work happens inside run_main
        assert ran[0] == "enter"
        assert ran[-1] == "exit"
        assert "backend" in ran[1:-1]
    else:
        assert "enter" not in ran
        assert "backend" in ran
    ran.clear()
    assert cli.main(["scan", "--timeout", "0.1"]) == 0  # ble commands never do
    assert ran == []


def test_classic_runs_directly_when_the_mac_backend_cannot_load(monkeypatch, capsys):
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
    assert cli.main(["classic", "devices"]) == 0
    assert ran == []
    assert capsys.readouterr().out.startswith("no paired classic devices")
