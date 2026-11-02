"""The agent playbook: the method for working out a gadget's protocol, per agent.

Each supported agent gets one doc, shipped as package data: a skill for claude code
(`claude-code/SKILL.md`) and an `AGENTS.md` for codex. Cursor and other mcp clients
use the server's tools directly. Both docs teach the same method, the same for every
gadget. `BANNED_HINTS` lists strings that would tie the docs, or any other file under
`src/harald/`, to one particular device; a test keeps them out. This file is the only
one exempt from that test, because it has to name what it bans.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from harald.errors import HaraldError

PLAYBOOK_AGENTS: tuple[str, ...] = ("claude-code", "codex")

BANNED_HINTS: tuple[str, ...] = ("istrip", "wh-1000xm5", "sony", "mdr")

_FILENAMES = {"claude-code": "SKILL.md", "codex": "AGENTS.md"}


def playbook_path(agent: str) -> Path:
    """The packaged doc for `agent`: `SKILL.md` for claude-code, `AGENTS.md` for codex."""
    if agent not in PLAYBOOK_AGENTS:
        raise HaraldError(
            f"unknown agent: {agent}",
            hint=f"choose one of: {', '.join(PLAYBOOK_AGENTS)}",
        )
    return Path(str(files(__name__) / agent / _FILENAMES[agent]))


def install_playbook(agent: str, dest: Path) -> Path:
    """Copy `agent`'s doc into the folder `dest`, creating it, and return the new path.

    A file already there with other content is left alone and refused, since a
    project often has its own `AGENTS.md`; the same content again is a no-op.
    """
    source = playbook_path(agent)
    target = Path(dest) / source.name
    data = source.read_bytes()
    if target.exists() and target.read_bytes() != data:
        raise HaraldError(
            f"{target} already exists",
            hint="move it aside first, or choose another folder with --dest",
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target
