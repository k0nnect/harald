"""The human cli, driven through `main([...])` with fake ble backends and runner."""

import subprocess

import pytest
from bleak.exc import BleakError
from capture_helpers import write_capture
from fakes import CHR, FakeClient, FakeScanner

from harald import cli, library


@pytest.fixture(autouse=True)
def fake_backends(monkeypatch):
    """Fake radios, and a driver runner that fails the test if anything shells out."""

    def no_shell(*args, **kwargs):
        raise AssertionError(f"unexpected subprocess: {args}")

    monkeypatch.setattr(cli, "scanner_cls", FakeScanner)
    monkeypatch.setattr(cli, "client_cls", FakeClient)
    monkeypatch.setattr(cli, "runner", no_shell)


def test_scan_prints_sorted_table(capsys):
    assert cli.main(["scan", "--timeout", "0.1"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["address", "rssi", "name"]
    assert lines[1].split() == ["BB-22", "-40", "scale"]
    assert [line.split()[0] for line in lines[1:]] == ["BB-22", "AA-11", "CC-33"]


def test_arm_then_status_shows_grant(capsys):
    assert cli.main(["arm", "aa-11", "--writes", "5"]) == 0
    capsys.readouterr()
    assert cli.main(["status"]) == 0
    rows = [line.split() for line in capsys.readouterr().out.splitlines()]
    grant = next(row for row in rows if row[0] == "aa-11")
    assert grant[1] == "5"


def test_capture_open_prints_timeline(tmp_path, capsys):
    path = write_capture(tmp_path, discovery=True, writes=[b"\x01\x02", b"\x03"])
    assert cli.main(["capture", "open", str(path)]) == 0
    out = capsys.readouterr().out
    assert "phone->device  write_cmd  h=0x0012  ffe1  01 02" in out
    assert out.rstrip().endswith("showing 1–2 of 2 events")


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


def test_write_after_arm_reaches_device(capsys):
    assert cli.main(["arm", "AA-11", "--writes", "5"]) == 0
    assert cli.main(["write", "AA-11", CHR, "0102"]) == 0
    assert "writes left: 4" in capsys.readouterr().out
    assert FakeClient.writes == [(CHR, b"\x01\x02", False)]


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


def test_missing_file_exits_2_with_path(tmp_path, capsys):
    missing = tmp_path / "Missing.pklg"
    assert cli.main(["capture", "open", str(missing)]) == 2
    err = capsys.readouterr().err
    assert err == f"error: no such file or directory: {missing}\n"
