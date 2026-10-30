import io
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import pytest

from harald import apk
from harald.errors import HaraldError, ToolMissing

FIXTURES = Path(__file__).parent / "fixtures" / "apk"
JADX_FIXTURE = FIXTURES / "jadx-output"
SIG_TAIL = "-0000-1000-8000-00805f9b34fb"


@pytest.fixture(autouse=True)
def temp_root(tmp_path, monkeypatch):
    """Send harald's temp dirs into the test's tmp dir, so tests can inspect them."""
    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def _apk_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _write_apk(path: Path, members: dict[str, bytes]) -> Path:
    path.write_bytes(_apk_bytes(members))
    return path


def _write_xapk(path: Path, apks: dict[str, dict[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, members in apks.items():
            z.writestr(name, _apk_bytes(members))
    return path


def _fake_jadx(cmd, **kwargs):
    """Stand in for jadx: copy the fixture decompiled tree into the handed out dir."""
    out = Path(cmd[cmd.index("-d") + 1])
    out.mkdir(parents=True, exist_ok=True)
    shutil.copytree(JADX_FIXTURE, out, dirs_exist_ok=True)
    return subprocess.CompletedProcess(cmd, 0, "", "")


def _missing_jadx(cmd, **kwargs):
    raise FileNotFoundError(2, "No such file or directory", "jadx")


def _partial_jadx(cmd, **kwargs):
    """jadx that writes usable sources but exits non-zero, as it often does."""
    _fake_jadx(cmd)
    stderr = "INFO  - loading ...\nERROR - finished with errors, count: 2\n"
    return subprocess.CompletedProcess(cmd, 3, "", stderr)


def _broken_jadx(cmd, **kwargs):
    """jadx that fails outright and writes no sources."""
    return subprocess.CompletedProcess(cmd, 1, "", "ERROR - failed to load dex\n")


def _native_report(tmp_path, runner=_fake_jadx):
    apk_path = _write_apk(
        tmp_path / "app.apk",
        {"classes.dex": b"dex", "AndroidManifest.xml": b"<manifest/>"},
    )
    return apk.analyze_apk(apk_path, jadx_runner=runner)


def test_detect_flutter(tmp_path):
    (tmp_path / "lib" / "arm64-v8a").mkdir(parents=True)
    (tmp_path / "lib" / "arm64-v8a" / "libapp.so").write_bytes(b"\x00")
    assert apk.detect_framework(tmp_path) == "flutter"


def test_detect_react_native(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "index.android.bundle").write_bytes(b"// bundle")
    assert apk.detect_framework(tmp_path) == "react-native"


def test_xapk_bundle_unpacks_base_apk(tmp_path):
    base = _apk_bytes({"classes.dex": b"dex", "AndroidManifest.xml": b"<manifest/>"})
    config = _apk_bytes({"lib/arm64-v8a/libfoo.so": b"\x00"})
    xapk = tmp_path / "app.xapk"
    with zipfile.ZipFile(xapk, "w") as z:
        z.writestr("base.apk", base)
        z.writestr("config.arm64_v8a.apk", config)

    out = apk.unpack(xapk, tmp_path / "unpacked")

    assert out.name == "base.apk"
    assert out.exists()
    with zipfile.ZipFile(out) as z:
        assert "classes.dex" in z.namelist()


def test_native_apk_scans_sources(tmp_path):
    apk_path = _write_apk(
        tmp_path / "app.apk",
        {"classes.dex": b"dex", "AndroidManifest.xml": b"<manifest/>"},
    )

    report = apk.analyze_apk(apk_path, jadx_runner=_fake_jadx)

    assert report.framework == "native"
    assert "0000ffe0-0000-1000-8000-00805f9b34fb" in report.gatt_uuids
    assert any(c.kind == "aes-key" for c in report.candidates)


def test_flutter_app_reports_logic_not_in_jadx(tmp_path):
    apk_path = _write_apk(
        tmp_path / "flutter.apk",
        {"lib/arm64-v8a/libapp.so": b"\x00", "classes.dex": b"dex"},
    )

    report = apk.analyze_apk(apk_path, jadx_runner=_fake_jadx)

    assert report.framework == "flutter"
    assert report.candidates == []
    assert "logic not in jadx output" in report.warnings[0]


def test_jadx_missing_raises_tool_missing(tmp_path):
    apk_path = _write_apk(tmp_path / "native.apk", {"classes.dex": b"dex"})

    with pytest.raises(ToolMissing) as excinfo:
        apk.analyze_apk(apk_path, jadx_runner=_missing_jadx)

    assert "brew install jadx" in excinfo.value.hint


def test_split_bundle_flutter_app_is_flutter(tmp_path):
    # split bundles keep native libs in config.<abi>.apk, not in base.apk (ruling r16).
    xapk = _write_xapk(
        tmp_path / "flutter.xapk",
        {
            "base.apk": {"classes.dex": b"dex"},
            "config.arm64_v8a.apk": {"lib/arm64-v8a/libapp.so": b"\x00"},
        },
    )
    calls = []

    report = apk.analyze_apk(xapk, jadx_runner=lambda cmd, **kw: calls.append(cmd))

    assert report.framework == "flutter"
    assert report.candidates == []
    assert "logic not in jadx output" in report.warnings[0]
    assert calls == []


def test_jadx_nonzero_exit_with_sources_warns(tmp_path):
    report = _native_report(tmp_path, runner=_partial_jadx)

    assert "0000ffe0" + SIG_TAIL in report.gatt_uuids
    assert any(
        "code 3" in w and "finished with errors, count: 2" in w for w in report.warnings
    )


def test_jadx_without_sources_raises_with_stderr_hint(tmp_path, temp_root):
    with pytest.raises(HaraldError) as excinfo:
        _native_report(tmp_path, runner=_broken_jadx)

    assert "failed to load dex" in excinfo.value.hint
    assert excinfo.value.message == excinfo.value.message.lower()
    assert list(temp_root.iterdir()) == []


def test_native_run_keeps_only_jadx_dir(tmp_path, temp_root):
    xapk = _write_xapk(
        tmp_path / "native.xapk",
        {
            "base.apk": {"classes.dex": b"dex", "AndroidManifest.xml": b"<manifest/>"},
            "config.arm64_v8a.apk": {"lib/arm64-v8a/libfoo.so": b"\x00"},
        },
    )

    report = apk.analyze_apk(xapk, jadx_runner=_fake_jadx)

    assert list(temp_root.iterdir()) == [report.jadx_dir]
    assert any(report.jadx_dir.rglob("*.java"))


def test_hex_masks_are_not_uuids(tmp_path):
    # ruling r15: 0xff000000 and 0xffffffffl are masks, not 16-bit uuids.
    report = _native_report(tmp_path)

    assert "0000ff00" + SIG_TAIL not in report.gatt_uuids
    assert "0000ffff" + SIG_TAIL not in report.gatt_uuids
    assert "0000ffe2" + SIG_TAIL in report.gatt_uuids


def test_uuid_kind_reads_the_whole_statement(tmp_path):
    # the declaration names the uuid on one line and holds it on the next.
    report = _native_report(tmp_path)
    found = {(c.kind, c.location.rsplit("/", 1)[-1]) for c in report.candidates}

    assert ("service-uuid", "BleController.java:10") in found
    assert ("char-uuid", "BleController.java:12") in found
