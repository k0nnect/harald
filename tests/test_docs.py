"""The public face of the repo: README.md, CONTRIBUTING.md and the banner."""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"
CONTRIBUTING = REPO / "CONTRIBUTING.md"
BANNER = REPO / "assets" / "banner.svg"

# emoji blocks: misc technical, misc symbols and dingbats, arrows and shapes,
# the emoji variation selector, the zero-width joiner, and everything from mahjong
# tiles to symbols and pictographs extended-a.
EMOJI_RANGES = (
    (0x2300, 0x23FF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE0F, 0xFE0F),
    (0x200D, 0x200D),
    (0x1F000, 0x1FAFF),
)
SECTIONS = (
    "一 how it works",
    "二 install",
    "三 devices",
    "四 agent setup",
    "五 safety",
    "六 contributing a device",
)
FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)


def _prose(path: Path) -> str:
    """The file without fenced code blocks, so a `#` comment is not a heading."""
    return FENCE.sub("", path.read_text(encoding="utf-8"))


def _headings(path: Path) -> list[str]:
    return [line for line in _prose(path).splitlines() if line.startswith("#")]


def _section(text: str, title: str) -> str:
    """The body of the `## <title>` section, up to the next level-2 heading."""
    start = text.index(f"## {title}\n")
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else len(text)]


def test_readme_has_no_emoji():
    for path in (README, CONTRIBUTING):
        text = path.read_text(encoding="utf-8")
        found = [c for c in text if any(lo <= ord(c) <= hi for lo, hi in EMOJI_RANGES)]
        assert not found, f"{path.name} contains emoji: {found!r}"


def test_readme_headings_lowercase():
    titles = [h.lstrip("#").strip() for h in _headings(README)]
    numbered = [t for t in titles if t[:1] in "一二三四五六七八九十"]
    assert numbered == list(SECTIONS)
    for path in (README, CONTRIBUTING):
        headings = _headings(path)
        assert headings, f"{path.name} has no headings"
        for heading in headings:
            assert not re.search("[A-Z]", heading), f"{path.name}: {heading!r}"


def test_banner_is_outlined_paths():
    svg = BANNER.read_text(encoding="utf-8")
    assert "<path" in svg
    assert "<text" not in svg
    assert "<tspan" not in svg


def test_readme_claims_tested_on_mac():
    text = README.read_text(encoding="utf-8").lower()
    assert "tested on mac" in text
    for system in ("linux", "windows"):
        assert system not in text, f"README.md mentions {system}"


def test_speak_promises_script_not_home_assistant():
    section = _section(_prose(README), SECTIONS[0])
    rows = [line for line in section.splitlines() if line.startswith("|")]
    header = [cell.strip(" *_").lower() for cell in rows[0].strip("|").split("|")]
    assert header == ["listen", "decode", "speak"]
    speak = rows[2].strip("|").split("|")[header.index("speak")].lower()
    assert "driver script" in speak
    assert "home assistant" not in section.lower()


def test_contributing_states_keys_rule():
    text = " ".join(CONTRIBUTING.read_text(encoding="utf-8").lower().split())
    assert "app-wide" in text
    assert re.search(r"never[^.]*per-unit", text)
    assert re.search(r"never[^.]*pairing key", text)
