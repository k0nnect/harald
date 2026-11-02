"""The public face of the repo: README.md, CONTRIBUTING.md and the banner."""

import re
import tomllib
from pathlib import Path

from harald.arm import normalize_uuid
from harald.classic import PROTECTED_CLASSES
from harald.cli import _build_parser
from harald.library import list_devices, load_device, validate_meta

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"
CONTRIBUTING = REPO / "CONTRIBUTING.md"
BANNER = REPO / "assets" / "banner.svg"
LIBRARY = REPO / "devices"
PYPROJECT = REPO / "pyproject.toml"

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
    "五 bluetooth classic",
    "六 safety",
    "七 contributing a device",
)
CLASSIC, SAFETY = SECTIONS[4], SECTIONS[5]
FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
# an html <img src="..."> or a markdown ![alt](src)
IMAGE_SRC = re.compile(r'<img\b[^>]*\bsrc="([^"]+)"|!\[[^\]]*\]\(([^)\s]+)\)')
RAW_ASSETS = "https://raw.githubusercontent.com/k0nnect/harald/main/assets/"
# an html <a href="..."> or a markdown [text](target) that is not an image
LINK = re.compile(r'<a\b[^>]*\bhref="([^"]+)"|(?<!!)\[[^\]]*\]\(([^)\s]+)\)')
REPO_URL = "https://github.com/k0nnect/harald/"
# the shields badge in the header, its alt text and its url both carry the count
BADGE = re.compile(
    r'<img alt="devices: (\d+) decoded" '
    r'src="https://img\.shields\.io/badge/devices-(\d+)%20decoded-'
)
XM5_ROW = (
    "| sony wh-1000xm5 headphones | noise cancelling, ambient and battery over "
    "bluetooth classic | {status} |"
)
# the safety section's names for the protected classic profiles, by assigned number
PROTECTED_NAMES = {
    "hands-free": ("111e", "111f"),
    "headset": ("1108", "1112", "1131"),
    "dial-up networking": ("1103",),
    "obex object push": ("1105",),
    "file transfer": ("1106",),
    "phonebook": ("112f", "1130"),
    "messages": ("1132", "1133", "1134"),
    "sim access": ("112d",),
    "apple iap2": (),
}
IAP2 = "00000000-deca-fade-deca-deafdecacaff"


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


def _image_srcs(text: str) -> list[str]:
    return [html or md for html, md in IMAGE_SRC.findall(FENCE.sub("", text))]


def _pypi_description() -> str:
    """README.md as the build's readme hook rewrites it for pypi."""
    with PYPROJECT.open("rb") as f:
        hooks = tomllib.load(f)["tool"]["hatch"]["metadata"]["hooks"]
    hook = hooks["fancy-pypi-readme"]
    assert hook["fragments"] == [{"path": "README.md"}]
    text = README.read_text(encoding="utf-8")
    for sub in hook["substitutions"]:
        flags = re.IGNORECASE if sub.get("ignore-case") else 0
        text = re.sub(sub["pattern"], sub["replacement"], text, flags=flags)
    return text


def test_readme_images_are_repo_relative():
    # relative, so github renders them on any branch, before main has them
    srcs = _image_srcs(README.read_text(encoding="utf-8"))
    assert len(srcs) >= 6
    ours = [src for src in srcs if not src.startswith("https://")]
    assert ours == ["assets/banner.svg", "assets/demo.gif"]


def test_pypi_description_has_absolute_image_urls():
    # pypi renders the readme away from the repo, where a relative src finds nothing
    text = _pypi_description()
    srcs = _image_srcs(text)
    assert len(srcs) >= 6
    assert all(src.startswith("https://") for src in srcs), srcs
    ours = [src for src in srcs if "assets/" in src]
    assert ours == [RAW_ASSETS + "banner.svg", RAW_ASSETS + "demo.gif"]
    # only the image srcs change; the rest of the readme goes to pypi as it is
    assert text.replace(RAW_ASSETS, "assets/") == README.read_text(encoding="utf-8")


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
    safety = _section(README.read_text(encoding="utf-8"), SAFETY)
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
    # the same commands the playbook keeps out of the agent's shell
    assert (
        "never runs `harald arm`, `harald write`, `harald drive`, "
        "`harald classic send` or a driver from its own shell"
    ) in section
    for overstated in ("can never approve", "can't be piped"):
        assert overstated not in section


def test_contributing_states_keys_rule():
    text = " ".join(CONTRIBUTING.read_text(encoding="utf-8").lower().split())
    assert "app-wide" in text
    assert re.search(r"never[^.]*per-unit", text)
    assert re.search(r"never[^.]*pairing key", text)


def test_contributing_example_entry_is_valid():
    # one bluetooth le example with a cipher, one bluetooth classic example
    text = CONTRIBUTING.read_text(encoding="utf-8")
    blocks = [b for b in FENCE.findall(text) if b.startswith("```toml\n")]
    entries = [
        validate_meta(tomllib.loads("\n".join(block.splitlines()[1:-1])), slug)
        for block, slug in zip(blocks, ("demo-lamp", "demo-speaker"), strict=True)
    ]
    lamp, speaker = entries
    assert lamp.cipher == "aes-ecb"
    assert lamp.transport == "ble"
    assert speaker.transport == "classic"
    assert speaker.service_uuids and speaker.name_hint


def test_contributing_names_the_driver_constants():
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert "`ADDRESS_HINT`" in text and "`NAME_HINT`" in text
    assert "address_hint" not in text  # the spec field, not what driver.py holds


def test_badge_counts_decoded_library_entries():
    decoded = sum(m.status == "decoded" for m in list_devices(root=LIBRARY))
    badges = BADGE.findall(README.read_text(encoding="utf-8"))
    assert badges == [(str(decoded), str(decoded))]


def test_devices_table_matches_library_status():
    status = load_device("wh-1000xm5", root=LIBRARY).status
    section = _section(_prose(README), SECTIONS[2])
    rows = [line for line in section.splitlines() if "wh-1000xm5" in line]
    assert rows == [XM5_ROW.format(status=status)]


def test_readme_has_classic_section():
    section = " ".join(_section(README.read_text(encoding="utf-8"), CLASSIC).split())
    for phrase in (
        "bluetooth classic",
        "mac only",
        "system settings > bluetooth",
        "harald classic devices",
        "harald classic services",
        "harald classic send",
        "harald classic listen",
        "btsnoop",
        "iap2",
    ):
        assert phrase in section, phrase


def test_safety_covers_the_classic_gates():
    section = " ".join(_section(README.read_text(encoding="utf-8"), SAFETY).split())
    assert "every message spends one write" in section
    assert "missing from" in section  # channels the device does not list
    assert "need no arming" in section  # library drivers
    # the protected profiles: the readme's names cover harald.classic.PROTECTED_CLASSES,
    # no more and no less
    shorts = [short for numbers in PROTECTED_NAMES.values() for short in numbers]
    assert {normalize_uuid(s) for s in shorts} | {IAP2} == PROTECTED_CLASSES
    assert (
        "never opens a channel whose service record lists hands-free, headset, "
        "dial-up networking, obex object push and file transfer, phonebook, "
        "messages, sim access or apple iap2"
    ) in section
    assert all(name in section for name in PROTECTED_NAMES)
    # spp is not protected: many gadgets' control channels use it
    assert "the serial port profile is allowed" in section
    # firmware: only the classic firmware-update channels harald knows are blocked
    assert "the same goes for bluetooth classic" not in section
    assert "blocks the classic firmware-update channels it knows" in section
    assert "airoha's tooling channel" in section
    assert "`--allow-dfu`" in section
    # the rest take firmware over the control channel, where harald can't tell
    assert "over their normal control channel" in section
    assert "can't tell an update from any other message" in section
    assert "never send a message whose purpose it doesn't know" in section


def test_scope_covers_le_and_classic():
    for path in (README, CONTRIBUTING, LIBRARY / "README.md"):
        text = " ".join(path.read_text(encoding="utf-8").split())
        assert re.search("bluetooth le (and|or) classic", text), path.name
        assert "bluetooth le protocol" not in text, path.name


def test_descriptions_cover_classic():
    with PYPROJECT.open("rb") as f:
        description = tomllib.load(f)["project"]["description"]
    assert description == (
        "helps coding agents work out the bluetooth le and classic protocol of "
        "gadgets you own"
    )
    assert _build_parser().description == (
        "work out the bluetooth le and classic protocol of gadgets you own"
    )
