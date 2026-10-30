"""Static analysis of a vendor android app the user already has on disk.

harald never downloads apps: `analyze_apk` reads only the local file it is given.
The flow is: unpack the apk (or the base apk inside a .xapk/.apks bundle), decide
which framework the app is built with, and — only for a plain native app — run
`jadx` to decompile it and point the reader at the lines worth reading.

flutter and react-native apps keep their ble logic in a compiled blob (a dart or
javascript bundle), so jadx never sees it; for those the report just says so.

The scan references the android gatt api (`BluetoothGattCharacteristic`,
`writeCharacteristic`) and `javax.crypto` (`SecretKeySpec`, `"AES"`) by name to
find places worth reading. It does not reproduce how those apis are used; it only
reports file:line locations an agent should open.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from harald.errors import HaraldError, ToolMissing

Framework = Literal["native", "flutter", "react-native"]
CandidateKind = Literal[
    "service-uuid", "char-uuid", "aes-key", "base64-blob", "command-builder"
]

# bluetooth sig base uuid; a 16-bit uuid 0xffXX expands to 0000ffXX-<base tail>.
_SIG_BASE = "0000{:04x}-0000-1000-8000-00805f9b34fb"

_UUID128 = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# only the custom 0xffXX short uuids vendors tend to use for private services.
_UUID16 = re.compile(r"0x[fF][fF][0-9a-fA-F]{2}")
# a long quoted base64 constant (hyphen-free, so it never matches a 128-bit uuid).
_BASE64 = re.compile(r'"[A-Za-z0-9+/]{24,}={0,2}"')
_BYTE_ARRAY = re.compile(r"new\s+byte\s*\[")

_SNIPPET_MAX = 200


@dataclass
class Candidate:
    """A place in the decompiled source worth reading. `location` is file:line."""

    kind: str
    location: str
    snippet: str


@dataclass
class ApkReport:
    path: Path
    package: str | None
    framework: str
    gatt_uuids: list[str]
    candidates: list[Candidate]
    jadx_dir: Path | None
    warnings: list[str]


def unpack(path: Path, dest: Path) -> Path:
    """Resolve an apk bundle to a single apk file path.

    A plain `.apk` is already an apk, so its own path is returned. A `.xapk` or
    `.apks` is a zip of apks: the base apk (the member named `base.apk`, else the
    largest `*.apk`) is extracted into `dest` and that path is returned.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in (".xapk", ".apks"):
        return path

    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as bundle:
        apk_members = [n for n in bundle.namelist() if n.lower().endswith(".apk")]
        if not apk_members:
            raise HaraldError("no apk inside this bundle")
        member = _pick_base_apk(bundle, apk_members)
        extracted = dest / Path(member).name
        with bundle.open(member) as src, extracted.open("wb") as out:
            shutil.copyfileobj(src, out)
    return extracted


def _pick_base_apk(bundle: zipfile.ZipFile, members: list[str]) -> str:
    for name in members:
        if Path(name).name.lower() == "base.apk":
            return name
    return max(members, key=lambda n: bundle.getinfo(n).file_size)


def detect_framework(apk_root: Path) -> str:
    """Classify an unzipped apk tree as flutter, react-native, or native."""
    apk_root = Path(apk_root)
    if any(apk_root.glob("lib/**/libapp.so")):
        return "flutter"
    if (apk_root / "assets" / "index.android.bundle").is_file():
        return "react-native"
    return "native"


def run_jadx(apk: Path, out_dir: Path, *, runner=subprocess.run) -> Path:
    """Decompile `apk` into `out_dir` with jadx and return `out_dir`.

    Raises `ToolMissing` when jadx is not installed. The runner is injected so
    tests never shell out.
    """
    apk = Path(apk)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["jadx", "-d", str(out_dir), str(apk)]
    try:
        runner(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ToolMissing(
            "jadx not found", hint="install jadx: brew install jadx"
        ) from exc
    return out_dir


def analyze_apk(path: Path, *, jadx_runner=subprocess.run) -> ApkReport:
    """Unpack a local apk, detect its framework, and scan native sources."""
    path = Path(path)
    if not path.is_file():
        raise HaraldError("apk file not found", hint=f"no file at {path}")

    work = Path(tempfile.mkdtemp(prefix="harald-apk-"))
    try:
        apk = unpack(path, work / "bundle")
        root = work / "root"
        root.mkdir()
        with zipfile.ZipFile(apk) as z:
            z.extractall(root)
        framework = detect_framework(root)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise

    if framework in ("flutter", "react-native"):
        shutil.rmtree(work, ignore_errors=True)
        warning = (
            f"logic not in jadx output: this app is {framework} "
            f"and its ble code is compiled; use capture analysis"
        )
        return ApkReport(
            path=path,
            package=None,
            framework=framework,
            gatt_uuids=[],
            candidates=[],
            jadx_dir=None,
            warnings=[warning],
        )

    try:
        jadx_dir = run_jadx(apk, work / "jadx", runner=jadx_runner)
        gatt_uuids, candidates = _scan_sources(jadx_dir)
        package = _read_package(jadx_dir) or _read_package(root)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise

    return ApkReport(
        path=path,
        package=package,
        framework=framework,
        gatt_uuids=gatt_uuids,
        candidates=candidates,
        jadx_dir=jadx_dir,
        warnings=[],
    )


def _scan_sources(jadx_dir: Path) -> tuple[list[str], list[Candidate]]:
    """Collect gatt uuids and flag lines worth reading across decompiled sources."""
    uuids: set[str] = set()
    candidates: list[Candidate] = []

    for java in sorted(jadx_dir.rglob("*.java")):
        try:
            text = java.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = java.relative_to(jadx_dir)
        writes_chars = "writeCharacteristic" in text

        for lineno, line in enumerate(text.splitlines(), start=1):
            location = f"{rel}:{lineno}"
            snippet = line.strip()[:_SNIPPET_MAX]

            found = _uuids_in(line)
            if found:
                uuids.update(found)
                kind = "service-uuid" if "service" in line.lower() else "char-uuid"
                candidates.append(Candidate(kind, location, snippet))

            if (
                "SecretKeySpec" in line
                or '"AES"' in line
                or "javax.crypto" in line
            ):
                candidates.append(Candidate("aes-key", location, snippet))

            if _BASE64.search(line):
                candidates.append(Candidate("base64-blob", location, snippet))

            if writes_chars and (
                _BYTE_ARRAY.search(line) or "writeCharacteristic" in line
            ):
                candidates.append(Candidate("command-builder", location, snippet))

    return sorted(uuids), candidates


def _uuids_in(line: str) -> list[str]:
    """Return every gatt uuid on a line, lowercased, 16-bit forms expanded."""
    out = [m.group(0).lower() for m in _UUID128.finditer(line)]
    out += [_SIG_BASE.format(int(m.group(0), 16)) for m in _UUID16.finditer(line)]
    return out


def _read_package(root: Path) -> str | None:
    """Best-effort package name from a decoded AndroidManifest.xml, if present."""
    for manifest in root.rglob("AndroidManifest.xml"):
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r'package="([^"]+)"', text)
        if match:
            return match.group(1)
    return None
