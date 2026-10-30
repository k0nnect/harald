import io
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from harald import apk
from harald.errors import ToolMissing

FIXTURES = Path(__file__).parent / "fixtures" / "apk"
JADX_FIXTURE = FIXTURES / "jadx-output"


def _apk_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _write_apk(path: Path, members: dict[str, bytes]) -> Path:
    path.write_bytes(_apk_bytes(members))
    return path


def _fake_jadx(cmd, **kwargs):
    """Stand in for jadx: copy the fixture decompiled tree into the handed out dir."""
    out = Path(cmd[cmd.index("-d") + 1])
    out.mkdir(parents=True, exist_ok=True)
    shutil.copytree(JADX_FIXTURE, out, dirs_exist_ok=True)
    return subprocess.CompletedProcess(cmd, 0, "", "")


def _missing_jadx(cmd, **kwargs):
    raise FileNotFoundError(2, "No such file or directory", "jadx")


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
