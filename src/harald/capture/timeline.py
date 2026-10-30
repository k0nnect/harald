"""A readable, paged timeline of the att events in a capture file."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from harald.capture.att import SIG_BASE_SUFFIX, AttEvent, decode_att
from harald.capture.files import read_capture_with_warnings

NO_DISCOVERY_WARNING = (
    "no gatt discovery on connection c=0x{conn:04x}: its handles are shown raw. "
    "toggle bluetooth off and on on the phone, then open the app, and capture again"
)


@dataclass
class Timeline:
    events: list[AttEvent]
    handle_maps: dict[int, dict[int, str]]  # acl connection -> att handle -> uuid
    warnings: list[str]


def build_timeline(path: Path) -> Timeline:
    """Decode a capture into a timeline; reused until the file's mtime changes."""
    path = Path(path).resolve()
    return _build(path, path.stat().st_mtime_ns)


@lru_cache(maxsize=8)
def _build(path: Path, mtime_ns: int) -> Timeline:  # mtime_ns is only the cache key
    records, warnings = read_capture_with_warnings(path)
    events, handle_maps = decode_att(records)
    # one warning per connection whose writes and notifications have no uuids
    unmapped = dict.fromkeys(
        e.conn
        for e in events
        if e.handle is not None and e.addresses_device() and e.conn not in handle_maps
    )
    warnings += [NO_DISCOVERY_WARNING.format(conn=conn) for conn in unmapped]
    return Timeline(events, handle_maps, warnings)


def render(
    tl: Timeline,
    *,
    limit: int = 200,
    offset: int = 0,
    handle: int | None = None,
    conn: int | None = None,
) -> str:
    """Warnings, then one line per event in the window, then a `showing a–b of n` footer.

    `handle` keeps only events on that att handle and `conn` only events on that acl
    connection; the footer then counts those.
    """
    events = [
        e
        for e in tl.events
        if (handle is None or e.handle == handle) and (conn is None or e.conn == conn)
    ]
    offset, limit = max(offset, 0), max(limit, 0)
    shown = events[offset : offset + limit]
    start = tl.events[0].ts if tl.events else 0.0
    lines = [f"warning: {w}" for w in tl.warnings]
    lines += [_line(e, start) for e in shown]
    span = f"{offset + 1}–{offset + len(shown)}" if shown else "0"
    filters = [] if conn is None else [f"c=0x{conn:04x}"]
    filters += [] if handle is None else [f"h=0x{handle:04x}"]
    scope = f" with {' and '.join(filters)}" if filters else ""
    lines.append(f"showing {span} of {len(events)} events{scope}")
    return "\n".join(lines)


def _line(e: AttEvent, start: float) -> str:
    handle = "-" if e.handle is None else f"0x{e.handle:04x}"
    fields = [
        f"#{e.index}",
        f"+{e.ts - start:.3f}s",
        f"c=0x{e.conn:04x}",
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
