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
GADGET = "sources/com/example/gadget"  # the fixture app's own package
UUID_LINE = 'UUID c = UUID.fromString("0000ffe1-0000-1000-8000-00805f9b34fb");\n'
SPP = "00001101-0000-1000-8000-00805f9b34fb"
VENDOR_RFCOMM = "8901dfa8-5c7e-4d8f-9f0c-c2b70683f5f0"
# a classic serial link in the app's own package: the standard spp uuid on line 4,
# and a socket opened on a vendor uuid on line 7.
SPP_LINK = (
    "package com.example.gadget;\n"
    "\n"
    "public class SppLink {\n"
    f'    static final UUID SPP = UUID.fromString("{SPP}");\n'
    "\n"
    "    BluetoothSocket open(BluetoothDevice device) throws IOException {\n"
    "        return device.createRfcommSocketToServiceRecord("
    f'UUID.fromString("{VENDOR_RFCOMM}"));\n'
    "    }\n"
    "}\n"
)


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


def _jadx_writing(files: dict[str, str], package: str = "com.example.gadget"):
    """A fake jadx that writes `files` under sources/ and a manifest naming `package`."""

    def run(cmd, **kwargs):
        out = Path(cmd[cmd.index("-d") + 1])
        manifest = out / "resources" / "AndroidManifest.xml"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(f'<manifest package="{package}"/>\n')
        for rel, text in files.items():
            source = out / "sources" / rel
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(text)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return run


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
    assert report.package == "com.example.gadget"
    assert "0000ffe0-0000-1000-8000-00805f9b34fb" in report.gatt_uuids
    # only the lines that build a key or a cipher: no import, no method signature
    keys = [c.location for c in report.candidates if c.kind == "aes-key"]
    assert keys == [
        f"{GADGET}/BleController.java:15",
        f"{GADGET}/BleController.java:25",
    ]


def test_flutter_app_reports_logic_not_in_jadx(tmp_path):
    apk_path = _write_apk(
        tmp_path / "flutter.apk",
        {"lib/arm64-v8a/libapp.so": b"\x00", "classes.dex": b"dex"},
    )

    report = apk.analyze_apk(apk_path, jadx_runner=_fake_jadx)

    assert report.framework == "flutter"
    assert report.candidates == []
    assert report.totals == {}
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


def test_base64_blobs_must_decode_to_an_aes_key_size(tmp_path):
    # flagged: 16- and 32-byte keys. not flagged: two paths that happen to decode to
    # 24 bytes, and a 20-byte string.
    report = _native_report(tmp_path)
    blobs = [c.location for c in report.candidates if c.kind == "base64-blob"]
    assert blobs == [f"{GADGET}/Constants.java:12", f"{GADGET}/Constants.java:13"]


def test_library_tree_fixture_yields_no_candidates(tmp_path):
    report = _native_report(tmp_path)

    assert "0000aaa0" + SIG_TAIL not in report.gatt_uuids
    assert "0000ffa1" + SIG_TAIL not in report.gatt_uuids
    assert [c for c in report.candidates if "/androidx/" in c.location] == []


@pytest.mark.parametrize(
    "tree",
    [
        "android/bluetooth",
        "androidx/core",
        "kotlin/io",
        "kotlinx/coroutines",
        "com/google/gson",
        "okhttp3/internal",
        "okio",
        "io/reactivex/internal",
        "org/jetbrains/annotations",
        "com/facebook/react",
        "com/squareup/moshi",
    ],
)
def test_library_trees_are_skipped(tmp_path, tree):
    report = _native_report(
        tmp_path, runner=_jadx_writing({f"{tree}/Gatt.java": UUID_LINE})
    )

    assert report.gatt_uuids == []
    assert report.candidates == []


def test_own_package_is_scanned_even_inside_a_library_tree(tmp_path):
    runner = _jadx_writing(
        {"com/facebook/gadget/Ble.java": UUID_LINE}, package="com.facebook.gadget"
    )
    report = _native_report(tmp_path, runner=runner)

    assert report.gatt_uuids == ["0000ffe1" + SIG_TAIL]


def test_totals_count_every_kind_and_nothing_is_cut(tmp_path):
    report = _native_report(tmp_path)

    assert report.totals == {
        "gatt_uuids": 3,
        "service-uuid": 1,
        "char-uuid": 2,
        "aes-key": 2,
        "base64-blob": 2,
        "command-builder": 2,
        "rfcomm-uuid": 0,
        "rfcomm-socket": 0,
    }
    assert report.warnings == []
    assert not (report.jadx_dir / "harald-candidates.txt").exists()


def test_caps_keep_the_own_package_first_and_list_everything_in_a_file(tmp_path):
    # 60 uuids in obfuscated vendor code that sorts before the app's own package
    many = "".join(
        f'UUID u{i} = UUID.fromString("{i:08x}{SIG_TAIL}");\n' for i in range(60)
    )
    runner = _jadx_writing(
        {"a/b/Obf.java": many, "com/example/gadget/Ble.java": UUID_LINE}
    )

    report = _native_report(tmp_path, runner=runner)

    chars = [c for c in report.candidates if c.kind == "char-uuid"]
    assert len(report.gatt_uuids) == len(chars) == 50
    assert report.totals["gatt_uuids"] == report.totals["char-uuid"] == 61
    assert chars[0].location == f"{GADGET}/Ble.java:1"
    assert "0000ffe1" + SIG_TAIL in report.gatt_uuids
    listing = report.jadx_dir / "harald-candidates.txt"
    [warning] = [
        w.replace(str(listing), "") for w in report.warnings if str(listing) in w
    ]
    assert "at most 50" in warning
    assert warning == warning.lower()  # the path itself may hold capitals
    text = listing.read_text()
    assert all(f"{i:08x}{SIG_TAIL}" in text for i in range(60))
    assert text.count("char-uuid") == 61


def test_rfcomm_sockets_and_their_uuids_are_flagged(tmp_path):
    runner = _jadx_writing({"com/example/gadget/SppLink.java": SPP_LINK})

    report = _native_report(tmp_path, runner=runner)

    found = [(c.kind, c.location) for c in report.candidates]
    assert found == [
        ("rfcomm-uuid", f"{GADGET}/SppLink.java:4"),
        ("rfcomm-uuid", f"{GADGET}/SppLink.java:7"),
        ("rfcomm-socket", f"{GADGET}/SppLink.java:7"),
    ]
    # gatt_uuids keeps its name and holds every uuid found, classic ones included
    assert report.gatt_uuids == [SPP, VENDOR_RFCOMM]
    assert report.totals["rfcomm-uuid"] == 2
    assert report.totals["rfcomm-socket"] == 1


@pytest.mark.parametrize(
    "call",
    [
        "createRfcommSocketToServiceRecord(SPP)",
        "createInsecureRfcommSocketToServiceRecord(SPP)",
        'listenUsingRfcommWithServiceRecord("spp", SPP)',
        'listenUsingInsecureRfcommWithServiceRecord("spp", SPP)',
    ],
)
def test_every_rfcomm_socket_call_is_flagged(tmp_path, call):
    runner = _jadx_writing({"com/example/gadget/Link.java": f"s = link.{call};\n"})

    report = _native_report(tmp_path, runner=runner)

    assert [(c.kind, c.location) for c in report.candidates] == [
        ("rfcomm-socket", f"{GADGET}/Link.java:1")
    ]
