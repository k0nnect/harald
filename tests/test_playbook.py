"""The agent playbook: device-agnostic docs per agent, and their installer."""

import re
from pathlib import Path

import pytest

from harald.errors import HaraldError
from harald.playbook import (
    BANNED_HINTS,
    PLAYBOOK_AGENTS,
    install_playbook,
    playbook_path,
)

SRC = Path(__file__).resolve().parents[1] / "src" / "harald"
# BANNED_HINTS is defined here, so this one file has to name what it bans.
HINTS_FILE = SRC / "playbook" / "__init__.py"
# emoji blocks: misc technical, misc symbols and dingbats, arrows and shapes,
# the emoji variation selector, and everything from mahjong tiles to symbols
# and pictographs extended-a.
EMOJI_RANGES = (
    (0x2300, 0x23FF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE0F, 0xFE0F),
    (0x1F000, 0x1FAFF),
)
NUMBERED = re.compile(r"\d+\.\s")
METHOD_START = "## before you start"  # both docs carry the method from here on


def _source_files() -> list[Path]:
    return [
        p
        for p in SRC.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p != HINTS_FILE
    ]


def _first_step(text: str) -> str:
    """The first numbered item: its line plus continuation lines up to a blank line."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("1. "))
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.strip() or NUMBERED.match(line):
            break
        block.append(line.strip())
    return " ".join(block).lower()


def test_no_device_specific_strings():
    files = _source_files()
    docs = {
        SRC / "playbook" / "claude-code" / "SKILL.md",
        SRC / "playbook" / "codex" / "AGENTS.md",
    }
    assert docs <= set(files)  # the scan really covers both docs
    assert "istrip" in BANNED_HINTS
    for path in files:
        text = path.read_bytes().decode("utf-8", errors="ignore").lower()
        for hint in BANNED_HINTS:
            assert hint not in text, f"{path} contains {hint!r}"


def test_playbook_has_no_emoji():
    for agent in PLAYBOOK_AGENTS:
        text = playbook_path(agent).read_text(encoding="utf-8")
        found = [c for c in text if any(lo <= ord(c) <= hi for lo, hi in EMOJI_RANGES)]
        assert found == [], agent


def test_first_step_is_check_library():
    for agent in PLAYBOOK_AGENTS:
        step = _first_step(playbook_path(agent).read_text(encoding="utf-8"))
        assert "devices/" in step, agent
        assert "prior art" in step, agent


def _method(agent: str) -> str:
    """Everything from the shared `## before you start` heading to the end."""
    _, heading, body = (
        playbook_path(agent).read_text(encoding="utf-8").partition(METHOD_START)
    )
    assert heading, f"{agent} has no {METHOD_START!r}"
    return heading + body


def test_docs_share_one_method():
    assert _method("claude-code") == _method("codex")


def test_human_only_commands_are_left_to_the_human():
    for agent in PLAYBOOK_AGENTS:
        rules = _method(agent).split("## the method", 1)[0]
        rule = " ".join(rules.split())  # unwrap the bullet's lines
        assert (
            "never run `harald arm`, `harald write`, `harald drive` or a generated "
            "driver from your own shell"
        ) in rule, agent


def test_install_matches_the_readme():
    for agent in PLAYBOOK_AGENTS:
        rules = " ".join(_method(agent).split("## the method", 1)[0].split())
        assert "`uv tool install harald`" in rules, agent
        assert "`uvx harald" in rules, agent


def test_driver_step_covers_gadgets_that_hide_their_service():
    for agent in PLAYBOOK_AGENTS:
        method = " ".join(_method(agent).split())
        step = method[method.index("7. write the protocol") :]
        assert "`service_uuids`" in step, agent
        assert "set `name_hint`" in step, agent


def test_install_writes_expected_filename(tmp_path):
    skill = install_playbook("claude-code", tmp_path)
    assert skill == tmp_path / "SKILL.md"
    assert skill.read_bytes() == playbook_path("claude-code").read_bytes()
    agents = install_playbook("codex", tmp_path)
    assert agents == tmp_path / "AGENTS.md"
    assert agents.read_bytes() == playbook_path("codex").read_bytes()
    assert install_playbook("codex", tmp_path) == agents  # same content: no-op


def test_unknown_agent_raises(tmp_path):
    dest = tmp_path / "project"
    with pytest.raises(HaraldError) as exc:
        install_playbook("cursor", dest)
    assert exc.value.message == "unknown agent: cursor"
    assert exc.value.hint == "choose one of: claude-code, codex"
    assert not dest.exists()


def test_install_keeps_a_different_existing_file(tmp_path):
    existing = tmp_path / "AGENTS.md"
    existing.write_text("the project's own agent notes\n")
    with pytest.raises(HaraldError) as exc:
        install_playbook("codex", tmp_path)
    assert exc.value.message == f"{existing} already exists"
    assert existing.read_text() == "the project's own agent notes\n"
