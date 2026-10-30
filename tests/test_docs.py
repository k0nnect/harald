"""The public face of the repo: README.md, CONTRIBUTING.md and the banner."""

import re
import tomllib
from pathlib import Path

from harald.library import validate_meta

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
# an html <img src="..."> or a markdown ![alt](src)
IMAGE_SRC = re.compile(r'<img\b[^>]*\bsrc="([^"]+)"|!\[[^\]]*\]\(([^)\s]+)\)')
RAW_ASSETS = "https://raw.githubusercontent.com/k0nnect/harald/main/assets/"
# an html <a href="..."> or a markdown [text](target) that is not an image
LINK = re.compile(r'<a\b[^>]*\bhref="([^"]+)"|(?<!!)\[[^\]]*\]\(([^)\s]+)\)')
REPO_URL = "https://github.com/k0nnect/harald/"


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


def test_readme_images_have_absolute_urls():
    # pypi renders the readme away from the repo, where a relative src finds nothing
    srcs = [html or md for html, md in IMAGE_SRC.findall(_prose(README))]
    assert len(srcs) >= 6
    assert all(src.startswith("https://") for src in srcs), srcs
    ours = [src for src in srcs if "assets/" in src]
    assert ours == [RAW_ASSETS + "banner.svg", RAW_ASSETS + "demo.gif"]


def test_readme_links_work_off_github():
    # pypi renders the readme away from the repo, where a relative link finds nothing
    targets = [html or md for html, md in LINK.findall(_prose(README))]
    assert [t for t in targets if not t.startswith(("https://", "#"))] == []
    assert REPO_URL + "blob/main/LICENSE" in targets
    assert REPO_URL + "tree/main/devices" in targets
    assert REPO_URL + "blob/main/CONTRIBUTING.md" in targets


def test_readme_claims_tested_on_mac():
    text = README.read_text(encoding="utf-8").lower()
    assert "tested on mac" in text
    for system in ("linux", "windows"):
        assert system not in text, f"README.md mentions {system}"


def test_install_puts_harald_on_the_path():
    # every later block runs bare `harald`, so the install step has to provide it
    section = _section(README.read_text(encoding="utf-8"), SECTIONS[1])
    first_block = FENCE.search(section).group()
    assert first_block.splitlines()[1:-1] == ["uv tool install harald"]
    assert "`uvx harald" in _prose(README)  # the way to try it without installing


def test_devices_table_asks_for_protocol_and_driver():
    # ci needs a decoded entry's protocol.md and driver.py, not a protocol file alone
    section = _section(_prose(README), SECTIONS[2])
    row = next(line for line in section.splitlines() if "your device" in line)
    assert "`protocol.md`" in row and "`driver.py`" in row


def test_speak_promises_script_not_home_assistant():
    section = _section(_prose(README), SECTIONS[0])
    rows = [line for line in section.splitlines() if line.startswith("|")]
    header = [cell.strip(" *_").lower() for cell in rows[0].strip("|").split("|")]
    assert header == ["listen", "decode", "speak"]
    speak = rows[2].strip("|").split("|")[header.index("speak")].lower()
    assert "driver script" in speak
    assert "home assistant" not in section.lower()


def test_safety_says_what_the_arm_gate_stops_and_what_it_cannot():
    safety = _section(README.read_text(encoding="utf-8"), SECTIONS[4])
    section = " ".join(safety.split())
    assert "type `arm`" in section  # harald arm asks the person at the terminal
    assert "there is no mcp tool that arms" in section
    # the gate stops a casual or accidental arm, not an agent set on getting round it
    assert "stops casual or accidental arming by an agent" in section
    assert "`~/.harald/arm.json`" in section
    assert (
        "any agent that can run arbitrary commands or write files on your machine "
        "could get around"
    ) in section
    assert "the playbook's rule" in section
    for overstated in ("can never approve", "can't be piped"):
        assert overstated not in section


def test_contributing_states_keys_rule():
    text = " ".join(CONTRIBUTING.read_text(encoding="utf-8").lower().split())
    assert "app-wide" in text
    assert re.search(r"never[^.]*per-unit", text)
    assert re.search(r"never[^.]*pairing key", text)


def test_contributing_example_entry_is_valid():
    text = CONTRIBUTING.read_text(encoding="utf-8")
    block = next(b for b in FENCE.findall(text) if b.startswith("```toml\n"))
    data = tomllib.loads("\n".join(block.splitlines()[1:-1]))
    assert validate_meta(data, "demo-lamp").cipher == "aes-ecb"


def test_contributing_names_the_driver_constants():
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert "`ADDRESS_HINT`" in text and "`NAME_HINT`" in text
    assert "address_hint" not in text  # the spec field, not what driver.py holds
