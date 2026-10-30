"""A readable, paged timeline of the att events in a capture file."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from harald.capture.att import SIG_BASE_SUFFIX, AttEvent, decode_att
from harald.capture.files import read_capture

NO_DISCOVERY_WARNING = (
    "no gatt discovery in this capture: handles are shown raw. toggle bluetooth off "
    "and on on the phone, then open the app, and capture again"
)


@dataclass
class Timeline:
    events: list[AttEvent]
    handle_map: dict[int, str]
    warnings: list[str]


def build_timeline(path: Path) -> Timeline:
    """Decode a capture into a timeline; reused until the file's mtime changes."""
    path = Path(path).resolve()
    return _build(path, path.stat().st_mtime_ns)


@lru_cache(maxsize=8)
def _build(path: Path, mtime_ns: int) -> Timeline:  # mtime_ns is only the cache key
    events, handle_map = decode_att(read_capture(path))
    warnings = []
    if not handle_map and any(e.handle is not None for e in events):
        warnings.append(NO_DISCOVERY_WARNING)
    return Timeline(events, handle_map, warnings)


def render(
    tl: Timeline, *, limit: int = 200, offset: int = 0, handle: int | None = None
) -> str:
    """Warnings, then one line per event in the window, then a `showing a–b of n` footer.

    `handle` keeps only events on that handle; the footer then counts those.
    """
    events = (
        tl.events if handle is None else [e for e in tl.events if e.handle == handle]
    )
    offset, limit = max(offset, 0), max(limit, 0)
    shown = events[offset : offset + limit]
    start = tl.events[0].ts if tl.events else 0.0
    lines = [f"warning: {w}" for w in tl.warnings]
    lines += [_line(e, start) for e in shown]
    span = f"{offset + 1}–{offset + len(shown)}" if shown else "0"
    scope = "" if handle is None else f" with h=0x{handle:04x}"
    lines.append(f"showing {span} of {len(events)} events{scope}")
    return "\n".join(lines)


def _line(e: AttEvent, start: float) -> str:
    handle = "-" if e.handle is None else f"0x{e.handle:04x}"
    fields = [
        f"#{e.index}",
        f"+{e.ts - start:.3f}s",
        e.direction,
        e.op,
        f"h={handle}",
        _short_uuid(e.uuid),
        e.value.hex(" ") or "-",
    ]
    return "  ".join(fields)


def _short_uuid(uuid: str | None) -> str:
    if uuid is None:
        return "-"
    if uuid.startswith("0000") and uuid.endswith(SIG_BASE_SUFFIX):
        return uuid[4:8]
    return uuid
