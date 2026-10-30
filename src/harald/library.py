"""The device library: finished entries, one folder per gadget.

Each entry `devices/<slug>/` holds `device.toml` (metadata), `protocol.md` (the
protocol written up) and `driver.py` (a standalone driver). The library lives at
the repo root so it is visible on GitHub; the wheel force-includes it as
`harald/devices/`. In a dev checkout `devices_root()` falls back to the repo root.

Keys rule: an entry may carry a key only when `key_scope = "app-wide"` (identical
on every unit, shipped in the vendor app). Per-unit and pairing keys never belong
here, so `validate_meta` refuses any other entry that has `key_hex` set.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Literal

import harald
from harald.errors import LibraryError

KeyScope = Literal["app-wide", "none"]
Status = Literal["decoded", "in progress", "wanted"]

REQUIRED = ("name", "vendor", "status", "key_scope")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]*")


@dataclass
class DeviceMeta:
    slug: str
    name: str
    vendor: str
    status: Status
    key_scope: KeyScope
    key_hex: str | None
    cipher: str | None
    service_uuids: list[str]
    summary: str


def check_slug(slug: str) -> str:
    """Return `slug` if it is a plain library slug; refuse anything that could be a path."""
    if not _SLUG.fullmatch(slug):
        raise LibraryError(
            f"invalid device slug: {slug!r}",
            hint="use lowercase letters, digits and hyphens, e.g. demo-lamp",
        )
    return slug


def validate_meta(data: dict, slug: str) -> DeviceMeta:
    """Turn a parsed `device.toml` into a `DeviceMeta`, enforcing the keys rule."""
    for field in REQUIRED:
        if field not in data:
            raise LibraryError(f"{slug}: missing {field}")
    key_hex = data.get("key_hex") or None
    if key_hex is not None and data["key_scope"] != "app-wide":
        raise LibraryError(
            f"{slug}: per-unit keys must not be published",
            hint="only app-wide keys (identical on every unit, shipped in the vendor app) "
            "may live in devices/",
        )
    return DeviceMeta(
        slug=slug,
        name=data["name"],
        vendor=data["vendor"],
        status=data["status"],
        key_scope=data["key_scope"],
        key_hex=key_hex,
        cipher=data.get("cipher") or None,
        service_uuids=list(data.get("service_uuids", [])),
        summary=data.get("summary", ""),
    )


def devices_root() -> Path:
    """The packaged `harald/devices/` when installed, else `<repo>/devices/`."""
    packaged = files("harald") / "devices"
    if packaged.is_dir():
        return Path(str(packaged))
    for parent in Path(harald.__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file():
            return parent / "devices"
    raise LibraryError("device library not found", hint="reinstall harald")


def device_dir(slug: str, *, root: Path | None = None) -> Path:
    return (devices_root() if root is None else root) / check_slug(slug)


def driver_path(slug: str, *, root: Path | None = None) -> Path:
    return device_dir(slug, root=root) / "driver.py"


def protocol_path(slug: str, *, root: Path | None = None) -> Path:
    return device_dir(slug, root=root) / "protocol.md"


def load_device(slug: str, *, root: Path | None = None) -> DeviceMeta:
    toml_path = device_dir(slug, root=root) / "device.toml"
    if not toml_path.is_file():
        raise LibraryError(f"unknown device: {slug}", hint="run: harald devices")
    with toml_path.open("rb") as f:
        return validate_meta(tomllib.load(f), slug)


def list_devices(*, root: Path | None = None) -> list[DeviceMeta]:
    """Every entry under the library root that has a `device.toml`, sorted by slug."""
    base = devices_root() if root is None else root
    if not base.is_dir():
        return []
    slugs = sorted(p.name for p in base.iterdir() if (p / "device.toml").is_file())
    return [load_device(slug, root=base) for slug in slugs]
