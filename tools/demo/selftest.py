# /// script
# requires-python = ">=3.11"
# dependencies = ["pillow>=10.1", "numpy>=1.26"]
# ///
"""End-to-end check of the demo redaction pipeline on synthetic footage.

Run by hand on a Mac (CI is Linux, without Vision):

    uv run tools/demo/selftest.py

It draws 1920x1200 terminal frames in a macOS monospace font at 30 px (15 pt on
Retina) holding the example address aa:bb:cc:11:22:33 in every context the real
clip has, plus harald's framed hex and uuids that must survive. It encodes them as
an h.264 mp4, runs assemble.py with dummy cream title and outro frames, and checks:
every address is under a solid box in every gif frame, the hex frames and uuids
are uncovered and still OCR-readable, verification passed, the gif loops. Then it
runs the --frames-only mode too. Output goes to .superpowers/demo/work/selftest/.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageSequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import redact

ROOT = HERE.parents[1]
WORK = ROOT / ".superpowers" / "demo" / "work" / "selftest"
UV = "/opt/homebrew/bin/uv" if Path("/opt/homebrew/bin/uv").exists() else "uv"
INK, CREAM = redact.PALETTE["ink"], redact.PALETTE["cream"]
TEXT = (0xE4, 0xE0, 0xD6)  # terminal text, close to cream but not a box colour
DIM = (0x8A, 0x86, 0x7E)
STATE_SECONDS = 1.2
FONT_PX, PITCH, LEFT = 30, 38, 20
COLS = 99  # SF Mono advances 19 px at 30 px: 99 columns fit in 1920 px

# [[...]] marks text that must end up under a box, {{...}} text that must not
HANDSHAKE = "3e0c000000000200000e3c"
ACK = "3e010000000000013c"
BATTERY = "3e0c01000000022200313c"
NC_ON = "3e0c010000000768170101000014a93c"
UUID = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"
READABLE = (HANDSHAKE, ACK, BATTERY, NC_ON, UUID)

TOP = [
    "> find my WH-1000XM5 and turn noise cancelling on",
    "",
    "● harald - scan (MCP)(seconds: 5)",
    "  └ {{LE_WH-1000XM5}}  -52  {{" + UUID + "}}",
]
SERVICES = [
    "● harald - classic_services (MCP)",
    '  └ {"address": "[[aa:bb:cc:11:22:33]]", "service": "Serial HPC", "channel": {{9}}}',
]
REFUSAL = [
    "● harald - classic_send (MCP)",
    "  └ not armed. ask the human to run: harald arm [[aa:bb:cc:11:22:33]] --writes 50",
]
SEND = [
    "● harald - classic_send (MCP)(messages_hex:",
    '    ["{{' + HANDSHAKE + '}}", "{{' + ACK + '}}",',
    '     "{{' + NC_ON + '}}"])',
    '  └ {"replies": ["{{' + HANDSHAKE + '}}", "{{' + BATTERY + '}}"]}',
]
# a line that wraps in the middle of the address, as a terminal does at the last
# column: the second half alone has only two pairs
WRAP = [
    (
        "● Sent all 3 writes on the control channel (Serial HPC, channel #9) of the "
        "WH-1000XM5 at [[aa:bb:cc:1]]"
    ),
    "[[1:22:33]], also known as [[AA-BB-CC-11-22-33]]; noise cancelling is on.",
]
PARTIAL = ["● the battery reads {{80%}}; the address was [[aa:bb:]]"]
DONE = ["● the battery reads {{80%}}; the address was [[aa:bb:cc:11:22:33]]."]
# an address cut by the right edge of the frame (as a crop could do): only
# "aa:bb:c" and a sliver are visible
CLIP_AT = (1920 - LEFT) // 19 - 7
CUT = ["  device list:" + " " * (CLIP_AT - 14) + "[[aa:bb:cc:11:22:33]]"]
CLIPPED = {CUT[0]}

ARM = [
    "% harald arm $XM5 --writes {{8}} --minutes {{10}}",
    "this lets harald write to [[aa:bb:cc:11:22:33]]: up to {{8}} writes in the next 10 min",
    "type arm to confirm: arm",
    "armed [[AA:BB:CC:11:22:33]]: write budget 8, expires in 10 min",
]

STATES = [
    (TOP, ["% "]),
    (TOP + SERVICES, ["% "]),
    (TOP + SERVICES + REFUSAL, ["% "]),
    (TOP + SERVICES + REFUSAL, ARM),
    (TOP + SERVICES + REFUSAL + SEND, ARM),
    (TOP + SERVICES + REFUSAL + SEND + WRAP, ARM),
    (TOP + SERVICES + REFUSAL + SEND + WRAP + PARTIAL, ARM),
    (TOP + SERVICES + REFUSAL + SEND + WRAP + DONE + CUT, ARM),
]
BEATS = {
    "fps": 12,
    "segments": [
        {"start": 0, "end": 4.8, "speed": 1},
        {"hold": 5.4, "seconds": 1.0},
        {"start": 4.8, "end": "0:09.6", "speed": 2},
    ],
}

results: list[tuple[bool, str]] = []


def check(ok: bool, what: str) -> bool:
    results.append((bool(ok), what))
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    return bool(ok)


def parse_marks(line: str) -> tuple[str, list[tuple[str, int, int]]]:
    """Strip [[..]] and {{..}}; return plain text and (kind, start, end) spans."""
    plain, marks, pos = "", [], 0
    for m in re.finditer(r"\[\[(.+?)\]\]|\{\{(.+?)\}\}", line):
        plain += line[pos : m.start()]
        kind = "secret" if m.group(1) is not None else "keep"
        body = m.group(1) if m.group(1) is not None else m.group(2)
        marks.append((kind, len(plain), len(plain) + len(body)))
        plain += body
        pos = m.end()
    plain += line[pos:]
    return plain, marks


def render_state(top: list[str], bottom: list[str]):
    """One tmux-like frame: agent pane on top, the human's shell below."""
    font = redact.mono_font(FONT_PX)
    im = Image.new("RGB", (1920, 1200), INK)
    draw = ImageDraw.Draw(im)
    divider = 900
    draw.line((0, divider, 1920, divider), fill=DIM, width=2)
    marks = []
    for lines, y0 in ((top, 20), (bottom, divider + 16)):
        for n, line in enumerate(lines):
            plain, spans = parse_marks(line)
            if line not in CLIPPED:
                assert len(plain) <= COLS, f"line too long ({len(plain)}): {plain}"
            y = y0 + n * PITCH
            draw.text((LEFT, y), plain, font=font, fill=TEXT)
            for kind, s, e in spans:
                # the ink of exactly this substring, where it sits in the line
                x = LEFT + font.getlength(plain[:s])
                bx0, by0, bx1, by1 = draw.textbbox((x, y), plain[s:e], font=font)
                marks.append((kind, plain[s:e], (bx0, by0, min(1920.0, bx1), by1)))
    return im, marks


def make_recording(folder: Path) -> tuple[Path, list]:
    rendered = []
    lines = ["ffconcat version 1.0"]
    for i, (top, bottom) in enumerate(STATES):
        im, marks = render_state(top, bottom)
        path = folder / f"state_{i}.png"
        im.save(path)
        rendered.append((im, marks))
        lines += [f"file '{path.name}'", f"duration {STATE_SECONDS}"]
    lines.append(f"file 'state_{len(STATES) - 1}.png'")
    (folder / "states.txt").write_text("\n".join(lines) + "\n")
    rec = folder / "synthetic.mp4"
    subprocess.run(
        ["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0"]
        + ["-i", str(folder / "states.txt"), "-r", "30", "-c:v", "libx264"]
        + ["-crf", "20", "-pix_fmt", "yuv420p", str(rec)],
        check=True,
    )
    return rec, rendered


def make_card(folder: Path, frames: int) -> Path:
    """Dummy cream title/outro: an ink bar slides in, then holds."""
    folder.mkdir(parents=True, exist_ok=True)
    for i in range(frames):
        im = Image.new("RGB", (960, 600), CREAM)
        draw = ImageDraw.Draw(im)
        x = 120 + min(i, frames // 2) * 20
        draw.rectangle((120, 270, x, 330), fill=INK)
        draw.rectangle(
            (120, 340, 120 + min(i, frames // 2) * 8, 352), fill=redact.PALETTE["red"]
        )
        im.save(folder / f"{i + 1:04d}.png")
    return folder


def matcher_checks() -> None:
    def hit(text: str) -> bool:
        chars = list(text)
        strict = redact.fold_text(chars, loose=False)
        loose = redact.fold_text(chars, loose=True)
        return bool(redact._spans(strict, loose, chars=chars))

    def covers(text: str, part: str) -> bool:
        chars = list(text)
        strict = redact.fold_text(chars, loose=False)
        loose = redact.fold_text(chars, loose=True)
        spans = redact._spans(strict, loose, chars=chars)
        start = text.index(part)
        return all(
            any(s <= i < e for s, e, _ in spans)
            for i in range(start, start + len(part))
        )

    must = [
        "aa:bb:cc:11:22:33",
        "AA:BB:CC:11:22:33",
        "aa-bb-cc-11-22-33",
        "aa;bb;cc;11;22;33",
        "aa.bb.cc.11.22.33",
        "aa: bb :cc:11:22:33",
        "aa bb cc 11 22 33",
        "AA:BB:CC:lI:22:33",
        "aa:bb:cc:11:22:SS",
        "OO:bb:cc:11:22:33",
        "aa:bb:cc:11:22:З3",
        '"aa:bb:cc:11:22:33",',
        "to aa:bb:cc:11:22:33: up to 8 writes",
        "aabb:cc:11:22:33",
        "aa:bb:cc",
        "run: harald arm aa:bb:",
    ]
    never = [
        HANDSHAKE,
        ACK,
        BATTERY,
        NC_ON,
        UUID,
        f'["{HANDSHAKE}", "{ACK}"]',
        "--writes 8 --minutes 10",
        "battery 80%",
        "level 20 (seq 1)",
        "2026-11-02",
        "LE_WH-1000XM5",
        "192.168.1.10",
    ]
    bad = [t for t in must if not hit(t)] + [t for t in never if hit(t)]
    # OCR noise at the ends of an address must stay inside the box
    whole = [
        ("aa:bb:cc:11:22 SS", "aa:bb:cc:11:22 SS"),
        ("OO bb:cc:11:22:33", "OO bb:cc:11:22:33"),
        ("aabb:cc:11:22:33", "aabb:cc:11:22:33"),
        ("the address is aa:bb:cc:11:22:33", "aa:bb:cc:11:22:33"),
        ("also known as AA-BB-CC-11-22-33;", "AA-BB-CC-11-22-33"),
    ]
    bad += [t for t, part in whole if not covers(t, part)]
    # a wrap away from the frame edge: only joining the two rows finds it
    a = _line("sent to aa:bb:cc:1", 400, 100)
    b = _line("1:22:33 now", 400, 138)
    page = redact.Page("wrap", 1920, 1200, [a, b])
    kinds = [h.kind for h in redact.detect(page) if h.core[1] >= 138]
    if "wrap" not in kinds:
        bad.append("wrap join")
    # --redact-text: a literal such as a host name is boxed too
    page = redact.Page("text", 1920, 1200, [_line("user@somehost ~ % ls", 20, 20)])
    if [h.kind for h in redact.detect(page, ["SomeHost"])] != ["text"]:
        bad.append("--redact-text")
    check(
        not bad,
        f"matcher: {len(must)} noisy forms caught, {len(never)} kept, "
        f"{len(whole)} fully covered, wrap join, literal text"
        + (f" (wrong: {[redact.mask(b) for b in bad]})" if bad else ""),
    )


def _line(text: str, x: float, y: float) -> redact.Line:
    """A fake OCR line with one 19 x 30 px box per character."""
    boxes = [(x + 19 * i, y, x + 19 * (i + 1), y + 30) for i in range(len(text))]
    box = (x, y, x + 19 * len(text), y + 30)
    return redact.Line("fast3", text, box, list(text), boxes)


def solid(region: np.ndarray) -> bool:
    if region.size == 0:
        return False
    flat = region.reshape(-1, 3)
    colours = {tuple(c) for c in redact.PALETTE.values()}
    first = tuple(int(v) for v in flat[0])
    return first in colours and bool((flat == flat[0]).all())


def boxed_fraction(region: np.ndarray) -> float:
    """Share of pixels that are exactly a palette colour other than the ink
    background, i.e. box paint (the terminal text colour is not a palette one)."""
    if region.size == 0:
        return 0.0
    flat = region.reshape(-1, 3)
    paint = [c for name, c in redact.PALETTE.items() if name != "ink"]
    hit = np.zeros(len(flat), bool)
    for c in paint:
        hit |= (flat == np.array(c, np.uint8)).all(axis=1)
    return float(hit.mean())


def best_state(frame: np.ndarray, smalls: list[np.ndarray]) -> int:
    scores = [np.abs(frame.astype(np.int16) - s).mean() for s in smalls]
    return int(np.argmin(scores))


def gif_checks(gif: Path, rendered, vision) -> None:
    with Image.open(gif) as im:
        loop = im.info.get("loop")
        frames = [np.asarray(f.convert("RGB")) for f in ImageSequence.Iterator(im)]
    check(loop == 0, f"gif loops forever (loop={loop})")
    smalls = [
        np.asarray(im.resize((960, 600), Image.LANCZOS)).astype(np.int16)
        for im, _ in rendered
    ]
    verify = json.loads((WORK / "verify.json").read_text())
    parts = [row["part"] for row in verify["gif_frames"]]
    terminal = [i for i, p in enumerate(parts) if p == "terminal"]
    check(bool(terminal), f"{len(terminal)} terminal frames in the gif")
    secrets_seen, secrets_bad, keeps_seen, keeps_bad = 0, [], 0, []
    seen_states = set()
    for i in terminal:
        frame = frames[i]
        state = best_state(frame, smalls)
        seen_states.add(state)
        for kind, text, (x0, y0, x1, y1) in rendered[state][1]:
            # the gif is half size; shrink by a pixel for the lanczos edge
            box = frame[
                int(y0 / 2) + 1 : int(y1 / 2) - 1, int(x0 / 2) + 1 : int(x1 / 2) - 1
            ]
            if kind == "secret":
                secrets_seen += 1
                if not solid(box):
                    secrets_bad.append((i, redact.mask(text)))
            else:
                keeps_seen += 1
                if boxed_fraction(box) > 0.2:
                    keeps_bad.append((i, text))
    check(len(seen_states) == len(STATES), f"gif shows all {len(STATES)} states")
    check(
        secrets_seen > 0 and not secrets_bad,
        f"every address form is under a solid box ({secrets_seen} occurrences "
        f"over {len(terminal)} frames)"
        + (f" missed: {secrets_bad}" if secrets_bad else ""),
    )
    check(
        keeps_seen > 0 and not keeps_bad,
        f"hex frames, uuids and plain numbers are not boxed ({keeps_seen} occurrences)"
        + (f" boxed: {keeps_bad}" if keeps_bad else ""),
    )
    # OCR the finished gif (2x) and look for the survivors and the address
    tmp = WORK / "ocr_gif"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    paths = []
    for i in terminal:
        p = tmp / f"{i:04d}.png"
        Image.fromarray(frames[i]).resize((1920, 1200), Image.LANCZOS).save(p)
        paths.append(p)
    pages = vision.read(paths)
    texts = [
        redact.fold_text(list(ln.text), loose=True) for pg in pages for ln in pg.lines
    ]
    blob = "\n".join(texts)
    missing = [s for s in READABLE if redact.fold_text(list(s), loose=True) not in blob]
    check(
        not missing,
        "hex frames and uuid are OCR-readable in the gif"
        + (f" (unread: {missing})" if missing else ""),
    )
    leaked = [t for t in texts if "aa:bb" in t or "11:22:33" in t]
    check(not leaked, "OCR of the gif finds no address text")
    hits = sum(len(redact.blocking(redact.detect(pg))) for pg in pages)
    check(hits == 0, f"detector on the gif frames: {hits} matches")


def raw_detection_checks(rendered, vision, folder: Path) -> None:
    """The detector must see the addresses in the unredacted frames, so a leak in
    the output could not hide behind a blind detector."""
    paths = []
    for i, (im, _) in enumerate(rendered):
        p = folder / f"raw_{i}.png"
        im.save(p)
        paths.append(p)
    blind = []
    for i, page in enumerate(vision.read(paths)):
        expected = any(k == "secret" for k, _, _ in rendered[i][1])
        if expected and not redact.detect(page):
            blind.append(i)
    check(not blind, f"detector sees the addresses in every raw state (blind: {blind})")


def main() -> int:
    started = time.time()
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    src = WORK / "src"
    src.mkdir()
    matcher_checks()
    vision = redact.healthy_vision(WORK, None, lambda m: print(f"[selftest] {m}"))
    rec, rendered = make_recording(src)
    raw_detection_checks(rendered, vision, src)
    title = make_card(src / "title", 24)
    outro = make_card(src / "outro", 16)
    beats = src / "beats.json"
    beats.write_text(json.dumps(BEATS))
    gif = WORK / "demo.gif"
    cmd = [UV, "run", "-q", str(HERE / "assemble.py"), "--recording", str(rec)]
    cmd += ["--beats", str(beats), "--title", str(title), "--outro", str(outro)]
    cmd += ["--out", str(gif), "--work", str(WORK)]
    t0 = time.time()
    code = subprocess.run(cmd, check=False).returncode
    check(code == 0, f"assemble.py exited {code} in {time.time() - t0:.0f} s")
    if not gif.exists() or not (WORK / "verify.json").exists():
        check(False, "assemble.py wrote the gif and verify.json")
        return report(started)
    verify = json.loads((WORK / "verify.json").read_text())
    check(verify["ok"], "verify.json says ok")
    check(
        len(verify["gif_frames"]) == verify["frames"]
        and len(verify["terminal_full_res"]) > 0,
        f"verify.json has a row per frame ({verify['frames']} gif, "
        f"{len(verify['terminal_full_res'])} full-res)",
    )
    check(verify["contact_sheets"] > 0, f"{verify['contact_sheets']} contact sheets")
    gif_checks(gif, rendered, vision)
    size = gif.stat().st_size
    print(
        f"[selftest] gif: {size / 1e6:.3f} MB, {verify['frames']} frames, "
        f"{verify['seconds']} s"
    )
    check(size < 4e6, f"gif under 4 MB ({size} bytes)")

    cmd = [UV, "run", "-q", str(HERE / "assemble.py"), "--frames-only"]
    cmd += ["--recording", str(rec), "--work", str(WORK)]
    code = subprocess.run(cmd, check=False).returncode
    index = WORK / "frames" / "index.json"
    rows = json.loads(index.read_text()) if index.exists() else []
    check(
        code == 0 and len(rows) >= len(STATES),
        f"--frames-only wrote {len(rows)} frames",
    )
    check(
        all(r["clean"] for r in rows) and all("_t" in r["file"] for r in rows),
        "--frames-only frames are clean and carry timestamps",
    )
    return report(started)


def report(started: float) -> int:
    failed = [w for ok, w in results if not ok]
    print(
        f"[selftest] {len(results) - len(failed)}/{len(results)} checks passed "
        f"in {time.time() - started:.0f} s"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
