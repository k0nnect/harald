"""The per-device working area: `harald-work/<slug>/` (gitignored).

While an agent works out a gadget's protocol it keeps dated notes in `notes.md`
and writes its driver to `driver.py`, so the finish line is
`uv run harald-work/<slug>/driver.py ...`. A finished workspace gets promoted into
the device library (`devices/<slug>/`) by hand.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_ROOT = Path("harald-work")


def workspace_dir(slug: str, *, root: Path | None = None) -> Path:
    """`<root>/<slug>/`, created if it does not exist yet."""
    path = _base(root) / slug
    path.mkdir(parents=True, exist_ok=True)
    return path


def driver_target(slug: str, *, root: Path | None = None) -> Path:
    """Where the agent-written driver for `slug` goes."""
    return workspace_dir(slug, root=root) / "driver.py"


def read_notes(slug: str, *, root: Path | None = None) -> str:
    """The workspace notes for `slug`, or an empty string when there are none."""
    path = _base(root) / slug / "notes.md"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def append_note(
    slug: str, text: str, *, root: Path | None = None, now: float | None = None
) -> None:
    """Append `## <iso-8601 utc>` and `text` to the workspace `notes.md`."""
    stamp = datetime.fromtimestamp(time.time() if now is None else now, UTC)
    with (workspace_dir(slug, root=root) / "notes.md").open("a", encoding="utf-8") as f:
        f.write(f"## {stamp.isoformat(timespec='seconds')}\n{text}\n")


def _base(root: Path | None) -> Path:
    return DEFAULT_ROOT if root is None else root
