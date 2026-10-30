"""The human cli, driven through `main([...])` with fake ble backends and runner."""

import subprocess
import sys

import pytest
from bleak.exc import BleakError
from capture_helpers import write_capture
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService

from harald import arm, cli, library
from harald.apk import ApkReport, Candidate


@pytest.fixture(autouse=True)
def fake_backends(monkeypatch):
    """Fake radios, and a driver runner that fails the test if anything shells out."""

    def no_shell(*args, **kwargs):
        raise AssertionError(f"unexpected subprocess: {args}")

    monkeypatch.setattr(cli, "scanner_cls", FakeScanner)
    monkeypatch.setattr(cli, "client_cls", FakeClient)
    monkeypatch.setattr(cli, "runner", no_shell)


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


def test_bluetooth_off_exits_2_with_hint(capsys):
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
