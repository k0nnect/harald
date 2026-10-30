"""Static analysis of a vendor android app the user already has on disk.

harald never downloads apps: `analyze_apk` reads only the local file it is given.
The flow is: decide which framework the app is built with from the zip member
names (for a .xapk/.apks bundle, the names inside every member apk), and only
for a native app unpack the base apk, run `jadx` on it, and point the reader at
the lines worth reading. Only the jadx output dir is kept afterwards.

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
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from harald.errors import HaraldError, ToolMissing

Framework = Literal["native", "flutter", "react-native"]
CandidateKind = Literal[
    "service-uuid", "char-uuid", "aes-key", "base64-blob", "command-builder"
]

_BUNDLE_SUFFIXES = (".xapk", ".apks")
_RN_BUNDLE = "assets/index.android.bundle"

# bluetooth sig base uuid; a 16-bit uuid 0xffXX expands to 0000ffXX-<base tail>.
_SIG_BASE = "0000{:04x}-0000-1000-8000-00805f9b34fb"

_UUID128 = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# ruling r15: a standalone 0xffXX literal, the custom short uuids vendors use for
# private services; never the head of a longer hex number such as 0xff000000.
_UUID16 = re.compile(r"\b0x[fF]{2}[0-9a-fA-F]{2}(?![0-9a-fA-F])")
# a long quoted base64 constant (hyphen-free, so it never matches a 128-bit uuid).
_BASE64 = re.compile(r'"[A-Za-z0-9+/]{24,}={0,2}"')
_BYTE_ARRAY = re.compile(r"new\s+byte\s*\[")

_SNIPPET_MAX = 200
# how many earlier lines a wrapped statement may span when labelling a uuid.
_STATEMENT_LOOKBACK = 3
_HINT_TAIL_LINES = 3


@dataclass
class Candidate:
    """A place in the decompiled source worth reading. `location` is file:line."""

    kind: CandidateKind
    location: str
    snippet: str


@dataclass
class ApkReport:
    path: Path
    package: str | None
    framework: Framework
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
    if not _is_bundle(path):
        return path

    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as bundle:
        apk_members = _apk_members(bundle)
        if not apk_members:
            raise HaraldError("no apk inside this bundle")
        member = _pick_base_apk(bundle, apk_members)
        extracted = dest / Path(member).name
        with bundle.open(member) as src, extracted.open("wb") as out:
            shutil.copyfileobj(src, out)
    return extracted


def _is_bundle(path: Path) -> bool:
    return path.suffix.lower() in _BUNDLE_SUFFIXES


def _apk_members(bundle: zipfile.ZipFile) -> list[str]:
    return [n for n in bundle.namelist() if n.lower().endswith(".apk")]


def _pick_base_apk(bundle: zipfile.ZipFile, members: list[str]) -> str:
    for name in members:
        if Path(name).name.lower() == "base.apk":
            return name
    return max(members, key=lambda n: bundle.getinfo(n).file_size)


def detect_framework(apk_root: Path) -> str:
    """Classify an unzipped apk tree as flutter, react-native, or native."""
    root = Path(apk_root)
    names = (p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    return _framework_from_names(names)


def _framework_from_names(names: Iterable[str]) -> str:
    """The same rule as `detect_framework`, applied to zip member names."""
    names = set(names)
    if any(n.startswith("lib/") and n.endswith("/libapp.so") for n in names):
        return "flutter"
    if _RN_BUNDLE in names:
        return "react-native"
    return "native"


def _app_names(path: Path) -> set[str]:
    """Member names of an apk, or of every apk inside a bundle (ruling r16).

    Split bundles keep `lib/<abi>/` in `config.<abi>.apk`, so the base apk alone
    would make a flutter app look native. Nothing is extracted to disk.
    """
    with zipfile.ZipFile(path) as outer:
        if not _is_bundle(path):
            return set(outer.namelist())
        names: set[str] = set()
        for member in _apk_members(outer):
            with outer.open(member) as inner, zipfile.ZipFile(inner) as split:
                names.update(split.namelist())
        return names


def run_jadx(apk: Path, out_dir: Path, *, runner=subprocess.run) -> Path:
    """Decompile `apk` into `out_dir` with jadx and return `out_dir`.

    Raises `ToolMissing` when jadx is not installed and `HaraldError` when it
    writes no java sources. The runner is injected so tests never shell out.
    """
    out_dir = Path(out_dir)
    _jadx(Path(apk), out_dir, runner)
    return out_dir


def _jadx(apk: Path, out_dir: Path, runner) -> tuple[int, str]:
    """Run jadx; return its exit code and last output line."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["jadx", "-d", str(out_dir), str(apk)]
    try:
        result = runner(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ToolMissing(
            "jadx not found", hint="install jadx: brew install jadx"
        ) from exc

    # jadx's logger may print errors on stdout, so fall back to it.
    lines = _output_lines(result.stderr) or _output_lines(result.stdout)
    if not any(out_dir.rglob("*.java")):
        raise HaraldError(
            f"jadx produced no java sources (exit code {result.returncode})",
            hint="; ".join(lines[-_HINT_TAIL_LINES:])
            or "jadx printed nothing; check that the file is a complete apk",
        )
    return result.returncode, lines[-1] if lines else ""


def _output_lines(text: str | None) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def analyze_apk(path: Path, *, jadx_runner=subprocess.run) -> ApkReport:
    """Detect a local apk's framework and, for a native app, scan its sources."""
    path = Path(path)
    if not path.is_file():
        raise HaraldError("apk file not found", hint=f"no file at {path}")

    framework = _framework_from_names(_app_names(path))
    if framework != "native":
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

    jadx_dir = Path(tempfile.mkdtemp(prefix="harald-jadx-"))
    try:
        with tempfile.TemporaryDirectory(prefix="harald-apk-") as unpacked:
            apk = unpack(path, Path(unpacked))
            code, last_line = _jadx(apk, jadx_dir, jadx_runner)
        gatt_uuids, candidates = _scan_sources(jadx_dir)
        package = _read_package(jadx_dir)
    except BaseException:
        shutil.rmtree(jadx_dir, ignore_errors=True)
        raise

    warnings = []
    if code != 0:
        warning = f"jadx exited with code {code}; its output may be partial"
        warnings.append(f"{warning}: {last_line}" if last_line else warning)

    return ApkReport(
        path=path,
        package=package,
        framework=framework,
        gatt_uuids=gatt_uuids,
        candidates=candidates,
        jadx_dir=jadx_dir,
        warnings=warnings,
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
        rel = java.relative_to(jadx_dir).as_posix()
        writes_chars = "writeCharacteristic" in text
        lines = text.splitlines()

        for idx, line in enumerate(lines):
            location = f"{rel}:{idx + 1}"
            snippet = line.strip()[:_SNIPPET_MAX]

            uuid_kinds: list[str] = []
            for start, uuid in _uuids_in(line):
                uuids.add(uuid)
                head = f"{_statement_head(lines, idx)} {line[:start]}"
                kind = _uuid_kind(head)
                if kind not in uuid_kinds:
                    uuid_kinds.append(kind)
            candidates.extend(Candidate(k, location, snippet) for k in uuid_kinds)

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


def _uuids_in(line: str) -> list[tuple[int, str]]:
    """(column, uuid) for every gatt uuid on a line, lowercased, 16-bit expanded."""
    out = [(m.start(), m.group(0).lower()) for m in _UUID128.finditer(line)]
    out += [
        (m.start(), _SIG_BASE.format(int(m.group(0), 16)))
        for m in _UUID16.finditer(line)
    ]
    return out


def _statement_head(lines: list[str], idx: int) -> str:
    """Earlier lines of a statement wrapped onto `lines[idx]`, such as
    `UUID SERVICE_UUID =` above the line that holds the uuid."""
    head: list[str] = []
    j = idx - 1
    while j >= 0 and len(head) < _STATEMENT_LOOKBACK:
        prev = lines[j].strip()
        if not prev or prev.endswith((";", "{", "}")):
            break
        head.insert(0, prev)
        j -= 1
    return " ".join(head)


def _uuid_kind(head: str) -> str:
    """Label a uuid by the nearest of "service" or "char" before it in its statement."""
    lowered = head.lower()
    if lowered.rfind("service") > lowered.rfind("char"):
        return "service-uuid"
    return "char-uuid"


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
