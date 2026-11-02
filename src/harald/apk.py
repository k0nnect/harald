"""Static analysis of a vendor android app the user already has on disk.

harald never downloads apps: `analyze_apk` reads only the local file it is given.
The flow is: decide which framework the app is built with from the zip member
names (for a .xapk/.apks bundle, the names inside every member apk), and only
for a native app unpack the base apk, run `jadx` on it, and point the reader at
the lines worth reading. Only the jadx output dir is kept afterwards.

flutter and react-native apps keep their ble logic in a compiled blob (a dart or
javascript bundle), so jadx never sees it; for those the report just says so.

The scan references the android gatt api (`BluetoothGattCharacteristic`,
`writeCharacteristic`), the classic rfcomm socket calls
(`createRfcommSocketToServiceRecord`, `listenUsingRfcommWithServiceRecord`) and
`javax.crypto` (`SecretKeySpec`, `Cipher`) by name to find places worth reading. It does not reproduce how those apis are used; it only
reports file:line locations an agent should open.

A real app decompiles to tens of thousands of files, mostly third-party libraries.
The scan skips those library trees, reads the app's own package first, and keeps at
most `MAX_PER_KIND` gatt uuids and candidates of each kind, so the report fits in an
mcp tool result. `ApkReport.totals` has the full counts; when anything was cut, the
whole list goes to `<jadx_dir>/harald-candidates.txt` and a warning says so.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import re
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, get_args

from harald.analyze import AES_KEY_SIZES
from harald.errors import HaraldError, ToolMissing

Framework = Literal["native", "flutter", "react-native"]
CandidateKind = Literal[
    "service-uuid",
    "char-uuid",
    "aes-key",
    "base64-blob",
    "command-builder",
    "rfcomm-uuid",
    "rfcomm-socket",
]

_BUNDLE_SUFFIXES = (".xapk", ".apks")
_RN_BUNDLE = "assets/index.android.bundle"

# the report keeps at most this many gatt uuids, and this many candidates per kind.
MAX_PER_KIND = 50
# written into the jadx output when the report was cut; it lists every hit.
CANDIDATES_FILE = "harald-candidates.txt"

# third-party library trees under jadx's sources/. their generic gatt, crypto and
# base64 code would bury the vendor's own, so they are not scanned, unless the app's
# own package lives inside one. `kotlin*` also covers kotlinx.
_LIBRARY_TREES = (
    "android/",
    "androidx/",
    "kotlin*/",
    "java/",
    "javax/",
    "dagger/",
    "okhttp3/",
    "okio/",
    "retrofit2/",
    "rx/",
    "io/reactivex/",
    "com/google/",
    "com/facebook/",
    "com/squareup/",
    "com/airbnb/",
    "com/bumptech/",
    "com/fasterxml/",
    "com/alibaba/",
    "com/tencent/",
    "com/umeng/",
    "com/huawei/hms/",
    "org/jetbrains/",
    "org/intellij/",
    "org/apache/",
    "org/json/",
    "org/slf4j/",
    "org/greenrobot/",
    "org/bouncycastle/",
    "no/nordicsemi/",
)

# bluetooth sig base uuid; a 16-bit uuid 0xffXX expands to 0000ffXX-<base tail>.
_SIG_BASE = "0000{:04x}-0000-1000-8000-00805f9b34fb"
# the serial port profile uuid, the one most classic gadgets open an rfcomm socket on.
SPP_UUID = "00001101-0000-1000-8000-00805f9b34fb"

_UUID128 = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# ruling r15: a standalone 0xffXX literal, the custom short uuids vendors use for
# private services; never the head of a longer hex number such as 0xff000000.
_UUID16 = re.compile(r"\b0x[fF]{2}[0-9a-fA-F]{2}(?![0-9a-fA-F])")
# a quoted base64 constant as long as an encoded aes key (hyphen-free, so it never
# matches a 128-bit uuid). _key_blob then checks that it decodes to a key size.
_BASE64 = re.compile(r'"([A-Za-z0-9+/]{22,44}={0,2})"')
# a path segment, as in androidx/core/app/ActivityCompat or Android/data/...: a
# lowercase word of two or more letters, then `/`. paths can decode as base64 but are
# never keys; a random base64 key holds one by chance under 1% of the time.
_PATH_SEGMENT = re.compile(r"(?:^|/)[a-z]{2,}/")
# code that builds a key or a cipher; an import or a type in a signature is not that.
_KEY_OR_CIPHER = re.compile(
    r"\bnew\s+(?:[\w$]+\.)*SecretKeySpec\s*\(|\bCipher\s*\.\s*getInstance\s*\("
)
_BYTE_ARRAY = re.compile(r"new\s+byte\s*\[")
# the android calls that open a classic rfcomm socket, as a client or a server.
_RFCOMM_CALL = re.compile(
    r"\bcreate(?:Insecure)?RfcommSocketToServiceRecord\("
    r"|\blistenUsing(?:Insecure)?RfcommWithServiceRecord\("
)

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
    """`gatt_uuids` and `candidates` are capped at `MAX_PER_KIND` per kind.

    `gatt_uuids` keeps its v0.1 name but holds every uuid found, rfcomm ones too;
    the candidates label each one as a service, char or rfcomm uuid.

    `totals` counts everything the scan found, before the cap: `gatt_uuids` and one
    entry per candidate kind. It stays empty when no sources were scanned.
    """

    path: Path
    package: str | None
    framework: Framework
    gatt_uuids: list[str]
    candidates: list[Candidate]
    jadx_dir: Path | None
    warnings: list[str]
    totals: dict[str, int] = field(default_factory=dict)


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
        package = _read_package(jadx_dir)
        all_uuids, all_candidates = _scan_sources(jadx_dir, package)
        gatt_uuids, candidates = _capped(all_uuids, all_candidates)
        cut = len(gatt_uuids) < len(all_uuids) or len(candidates) < len(all_candidates)
        if cut:
            listing = jadx_dir / CANDIDATES_FILE
            _write_listing(listing, all_uuids, all_candidates)
    except BaseException:
        shutil.rmtree(jadx_dir, ignore_errors=True)
        raise

    warnings = []
    if code != 0:
        warning = f"jadx exited with code {code}; its output may be partial"
        warnings.append(f"{warning}: {last_line}" if last_line else warning)
    if cut:
        warnings.append(
            f"the report lists at most {MAX_PER_KIND} gatt uuids and "
            f"{MAX_PER_KIND} candidates per kind, the app's own package first; "
            f"totals has the full counts and {listing} lists them all"
        )

    return ApkReport(
        path=path,
        package=package,
        framework=framework,
        gatt_uuids=sorted(gatt_uuids),
        candidates=candidates,
        jadx_dir=jadx_dir,
        warnings=warnings,
        totals=_totals(all_uuids, all_candidates),
    )


def _capped(
    uuids: list[str], candidates: list[Candidate]
) -> tuple[list[str], list[Candidate]]:
    """The first `MAX_PER_KIND` uuids, and the first `MAX_PER_KIND` of each kind."""
    kept: list[Candidate] = []
    seen: dict[str, int] = {}
    for c in candidates:
        seen[c.kind] = seen.get(c.kind, 0) + 1
        if seen[c.kind] <= MAX_PER_KIND:
            kept.append(c)
    return uuids[:MAX_PER_KIND], kept


def _totals(uuids: list[str], candidates: list[Candidate]) -> dict[str, int]:
    totals = {"gatt_uuids": len(uuids)}
    for kind in get_args(CandidateKind):
        totals[kind] = sum(c.kind == kind for c in candidates)
    return totals


def _write_listing(path: Path, uuids: list[str], candidates: list[Candidate]) -> None:
    """Every gatt uuid and candidate the scan found, in the cli's layout."""
    lines = [f"gatt uuids ({len(uuids)}):"]
    lines += [f"  {uuid}" for uuid in sorted(uuids)]
    lines.append(f"candidates ({len(candidates)}, file:line under the jadx output):")
    lines += [f"  {c.kind}  {c.location}  {c.snippet}" for c in candidates]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _source_files(jadx_dir: Path, package: str | None) -> list[tuple[Path, str]]:
    """(file, path under jadx_dir) for every java file worth scanning.

    The app's own package comes first, then the rest by path. Files in third-party
    library trees are left out, unless they are in the app's own package.
    """
    own = package.replace(".", "/") + "/" if package else None
    found: list[tuple[bool, str, Path]] = []
    for java in jadx_dir.rglob("*.java"):
        rel = java.relative_to(jadx_dir).as_posix()
        source = rel.removeprefix("sources/")  # the java package path
        mine = own is not None and source.startswith(own)
        if not mine and _is_library(source):
            continue
        found.append((not mine, rel, java))
    return [(java, rel) for _, rel, java in sorted(found)]


def _is_library(source: str) -> bool:
    return any(fnmatch.fnmatchcase(source, tree + "*") for tree in _LIBRARY_TREES)


def _scan_sources(
    jadx_dir: Path, package: str | None
) -> tuple[list[str], list[Candidate]]:
    """Collect uuids and flag lines worth reading across decompiled sources.

    Both lists are in scan order: the app's own package first. Nothing is capped.
    """
    uuids: dict[str, None] = {}  # an ordered set
    candidates: list[Candidate] = []

    for java, rel in _source_files(jadx_dir, package):
        try:
            text = java.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        writes_chars = "writeCharacteristic" in text
        lines = text.splitlines()

        for idx, line in enumerate(lines):
            location = f"{rel}:{idx + 1}"
            snippet = line.strip()[:_SNIPPET_MAX]

            uuid_kinds: list[str] = []
            for start, uuid in _uuids_in(line):
                uuids[uuid] = None
                head = f"{_statement_head(lines, idx)} {line[:start]}"
                kind = _uuid_kind(head, uuid)
                if kind not in uuid_kinds:
                    uuid_kinds.append(kind)
            candidates.extend(Candidate(k, location, snippet) for k in uuid_kinds)

            if _RFCOMM_CALL.search(line):
                candidates.append(Candidate("rfcomm-socket", location, snippet))

            if _KEY_OR_CIPHER.search(line):
                candidates.append(Candidate("aes-key", location, snippet))

            if any(_key_blob(m.group(1)) for m in _BASE64.finditer(line)):
                candidates.append(Candidate("base64-blob", location, snippet))

            if writes_chars and (
                _BYTE_ARRAY.search(line) or "writeCharacteristic" in line
            ):
                candidates.append(Candidate("command-builder", location, snippet))

    return list(uuids), candidates


def _key_blob(text: str) -> bool:
    """True for padded base64 that decodes to an aes key size and is not a path."""
    if _PATH_SEGMENT.search(text):
        return False
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error:
        return False
    return len(raw) in AES_KEY_SIZES


def _uuids_in(line: str) -> list[tuple[int, str]]:
    """(column, uuid) for every uuid on a line, lowercased, 16-bit expanded."""
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


def _uuid_kind(head: str, uuid: str) -> str:
    """Label a uuid by what comes before it in its statement.

    It is an rfcomm uuid when its statement mentions rfcomm before it, or when it is
    the spp uuid; otherwise the nearest of "service" or "char" decides.
    """
    lowered = head.lower()
    if "rfcomm" in lowered or uuid == SPP_UUID:
        return "rfcomm-uuid"
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
