"""Find bluetooth classic addresses in terminal frames, for the readme demo gif.

OCR is macOS Vision, through the small swift tool next to this file (ocr.swift),
compiled once with /usr/bin/swiftc into the work directory. Every frame is read by
three recogniser passes (accurate revisions 3 and 2, fast revision 3), because no
single pass reads everything: revision 3 silently drops whole lines dense with JSON
punctuation. Detection unions all passes.

What counts as an address (over-redaction is acceptable, under-redaction is not):

- six hex pairs with separators, and also any run of three or more separated pairs,
  so a partial address is covered too;
- separators are : ; . - (and look-alikes) or spaces, with spaces allowed around them;
- OCR confusions are folded first: O/o to 0, l/I/i/| to 1, S/s to 5, Z to 2, G to 6,
  g/q to 9, and cyrillic or greek look-alikes such as a cyrillic ze for 3;
- two or more pairs at either end of a line also count, since that is how a wrapped
  or half-printed address looks;
- a run split across a line end is joined with the line below (or the chunk to the
  right) before matching.

Hex with no separators (harald's framed messages such as 3e0c000000000200000e3c),
uuids (groups of 4, 8 and 12) and plain numbers never match.

Nothing here writes the text that OCR read: callers only persist masked text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
OCR_SOURCE = HERE / "ocr.swift"
OCR_NAME = "harald-demo-ocr"
PASSES = "accurate3,accurate2,fast3"
EXAMPLE_ADDRESS = "aa:bb:cc:11:22:33"

# the banner palette (scripts/make_banner.py)
PALETTE = {
    "cream": (0xF3, 0xEF, 0xE6),
    "ink": (0x16, 0x16, 0x16),
    "red": (0xC8, 0x10, 0x2E),
    "blue": (0x2B, 0x4B, 0xD8),
}

HEX = "0123456789abcdef"
SEP = ":"  # every separator look-alike folds to this

# one character in, one character out, so indices still line up with the char boxes
_STRICT = {
    # cyrillic and greek look-alikes that Vision returns for latin hex glyphs
    "а": "a",
    "А": "a",
    "α": "a",
    "в": "b",
    "В": "b",
    "Ь": "b",
    "ь": "b",
    "с": "c",
    "С": "c",
    "ϲ": "c",
    "ԁ": "d",
    "е": "e",
    "Е": "e",
    "ε": "e",
    "є": "e",
    "ƒ": "f",
    "З": "3",
    "з": "3",
    "Ʒ": "3",
    "ʒ": "3",
}
_LOOSE = {
    "o": "0",
    "q": "9",
    "l": "1",
    "i": "1",
    "|": "1",
    "!": "1",
    "¡": "1",
    "s": "5",
    "$": "5",
    "z": "2",
    "g": "9",
    "о": "0",
    "О": "0",
    "ο": "0",
    "Ο": "0",
    "І": "1",
    "і": "1",
    "ӏ": "1",
    "Ѕ": "5",
    "ѕ": "5",
}
_UPPER_LOOSE = {"G": "6", "O": "0", "Q": "0", "D": "0"}
_SEPARATORS = set(":;.-_,·•∶꞉‐‑‒–—−⁃˸ː")


def fold(ch: str, loose: bool) -> str:
    """Fold one OCR character to a hex digit, ':' for a separator, else itself."""
    if len(ch) != 1:
        return "~"
    if ch in _SEPARATORS:
        return SEP
    if ch.isspace():
        return " "
    if ch in _STRICT:
        return _STRICT[ch]
    if loose:
        if ch in _UPPER_LOOSE:
            return _UPPER_LOOSE[ch]
        if ch in _LOOSE:
            return _LOOSE[ch]
        if ch.lower() in _LOOSE:
            return _LOOSE[ch.lower()]
    norm = unicodedata.normalize("NFKC", ch)
    if len(norm) == 1:
        if norm in _SEPARATORS:
            return SEP
        low = norm.lower()
        if len(low) == 1:
            return low
    return "~"


def fold_text(chars: Sequence[str], loose: bool) -> str:
    return "".join(fold(c, loose) for c in chars)


_PAIR = r"[0-9a-f]{2}"
# a pair is a whole token: no letter or digit glued to it, so "armed AA:" keeps "ed"
_TOK = r"(?<![0-9a-z])[0-9a-f]{2}(?![0-9a-z])"
_GAP = r"(?: *: *| +)"
# three or more separated pairs
RUN = re.compile(rf"{_TOK}(?:{_GAP}{_TOK}){{2,}}")
# two or more separated pairs at the end or the start of a line
TAIL = re.compile(rf"{_TOK}(?:{_GAP}{_TOK})+(?: *:)? *$")
HEAD = re.compile(rf"^ *(?:: *)?{_TOK}(?:{_GAP}{_TOK})+")


def _spans(
    text_strict: str, text_loose: str, extend: bool = True, chars=None
) -> list[tuple[int, int, str]]:
    """Address-like spans in one line, as (start, end, kind)."""
    chars = list(chars) if chars is not None else list(text_strict)
    found: list[tuple[int, int, str]] = []
    # loose folding (O/0, l/1, S/5 ...) only counts when a real separator is there,
    # so prose such as "if so, do" stays rare; strict folding takes spaces alone
    for m in RUN.finditer(text_loose):
        if SEP in m.group(0):
            s, e = _trim_words(chars, text_strict, text_loose, m.start(), m.end())
            if _pairs(text_loose[s:e]) >= 3:
                found.append((s, e, _kind(text_loose[s:e])))
    for m in RUN.finditer(text_strict):
        found.append((m.start(), m.end(), _kind(m.group(0))))
    for rx in (TAIL, HEAD):
        for m in rx.finditer(text_loose):
            s, e = _trim_words(chars, text_strict, text_loose, m.start(), m.end())
            if _pairs(text_loose[s:e]) >= 2 and SEP in text_loose[s:e].strip(" :"):
                found.append((s, e, "edge"))
    if not extend:
        return found
    out = []
    for s, e, k in found:
        s2, e2, _ = _extend(text_loose, s, e, k)
        # two pairs at a line edge glued to a longer hex group is a date or a
        # uuid tail, not a cut address
        if k == "edge" and any(
            len(g) > 2 for g in re.split(r"[ :]+", text_loose[s2:e2])
        ):
            continue
        out.append((s2, e2, k))
    return out


# lowercase english words that loose folding turns into a pair ("as" -> a5); only
# these are trimmed off a match, never OCR noise such as "SS" or "lI"
_WORDS = {"as", "is", "so", "do", "of", "if", "go", "id", "io", "oz"}


def _trim_words(
    chars: Sequence[str], strict: str, loose: str, start: int, end: int
) -> tuple[int, int]:
    """Drop a word at either end of a loose match that joins the rest by spaces
    only and is a pair only after loose folding: "as" in "as aa:bb:cc:..."."""

    def word(i: int) -> bool:
        return "".join(chars[i : i + 2]) in _WORDS and not re.fullmatch(
            _PAIR, strict[i : i + 2]
        )

    while (m := re.match(r"[0-9a-f]{2}( +)", loose[start:end])) and word(start):
        start += m.end()
    while (m := re.search(r"( +)[0-9a-f]{2}$", loose[start:end])) and word(end - 2):
        end = start + m.start()
    return start, end


def _pairs(span: str) -> int:
    return len(re.findall(_TOK, span))


def _kind(span: str) -> str:
    return "address" if _pairs(span) >= 6 else "fragment"


def _extend(text: str, start: int, end: int, kind: str) -> tuple[int, int, str]:
    """Grow a span over hex digits and separators glued to it (aabb:cc:11 ...)."""
    keep = set(HEX) | {SEP}
    while start > 0 and text[start - 1] in keep:
        start -= 1
    while end < len(text) and text[end] in keep:
        end += 1
    while start < end and text[start] == " ":
        start += 1
    while end > start and text[end - 1] == " ":
        end -= 1
    return start, end, kind


Box = tuple[float, float, float, float]


@dataclass
class Line:
    pass_name: str
    text: str
    box: Box
    chars: list[str]
    char_boxes: list[Box | None]

    @property
    def height(self) -> float:
        return max(1.0, self.box[3] - self.box[1])

    @property
    def cell(self) -> float:
        """Rough width of one character cell (the terminal font is monospace)."""
        widths = sorted(b[2] - b[0] for b in self.char_boxes if b is not None)
        if widths:
            return max(4.0, widths[len(widths) // 2])
        return max(4.0, (self.box[2] - self.box[0]) / max(1, len(self.chars)))


@dataclass
class Hit:
    kind: str  # address, fragment, edge, wrap
    box: Box  # padded, what gets painted
    core: Box  # unpadded union of the matched characters
    masked: str
    source: str = "ocr"


@dataclass
class Page:
    image: str
    width: int
    height: int
    lines: list[Line] = field(default_factory=list)


def _interpolate(raw: list[Box | None]) -> list[Box | None]:
    """Vision at the accurate level gives every character its word's box; split the
    word box evenly across its characters, which is right for monospace text."""
    out: list[Box | None] = list(raw)
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b is None:
            i += 1
            continue
        j = i
        while j + 1 < n and raw[j + 1] == b:
            j += 1
        count = j - i + 1
        if count > 1:
            x0, y0, x1, y1 = b
            w = (x1 - x0) / count
            for k in range(count):
                out[i + k] = (x0 + k * w, y0, x0 + (k + 1) * w, y1)
        i = j + 1
    return out


def parse_page(obj: dict) -> Page:
    page = Page(obj["image"], int(obj.get("width", 0)), int(obj.get("height", 0)))
    if obj.get("error"):
        raise RuntimeError(f"ocr failed on {obj['image']}: {obj['error']}")
    for ln in obj.get("lines", []):
        chars = [c["c"] for c in ln["chars"]]
        boxes = [tuple(c["box"]) if c.get("box") else None for c in ln["chars"]]
        page.lines.append(
            Line(ln["pass"], ln["text"], tuple(ln["box"]), chars, _interpolate(boxes))
        )
    return page


def mask(text: str) -> str:
    return re.sub(r"[0-9A-Za-zЀ-ӿͰ-Ͽ]", "*", text)


def _span_box(line: Line, start: int, end: int) -> Box:
    boxes = [b for b in line.char_boxes[start:end] if b is not None]
    if not boxes:
        return line.box
    return (
        min(b[0] for b in boxes),
        min(b[1] for b in boxes),
        max(b[2] for b in boxes),
        max(b[3] for b in boxes),
    )


def pad_box(core: Box, cell: float, height: float, size: tuple[int, int]) -> Box:
    """At least 4 px all round, plus a third of a cell sideways for word-box slop."""
    px = 4 + 0.3 * cell
    py = 4 + 0.15 * height
    w, h = size
    return (
        max(0.0, core[0] - px),
        max(0.0, core[1] - py),
        min(float(w), core[2] + px),
        min(float(h), core[3] + py),
    )


# a pair touching a separator: what is left of an address the frame edge cut off
_CLIPPED = re.compile(rf"{_PAIR} *:|: *{_PAIR}")


def _clipped_spans(line: Line, loose: str, width: int) -> list[tuple[int, int, str]]:
    """A line running into the left or right edge of the frame may hold an address
    cut by the edge (aa:b|b...). Box the token at that edge if it has a pair
    touching a separator."""
    spans = []
    slack = 1.5 * line.cell
    tokens = list(re.finditer(r"[^ ]+", loose))
    if not tokens:
        return spans
    if line.box[2] >= width - slack and _CLIPPED.search(tokens[-1].group(0)):
        spans.append((tokens[-1].start(), tokens[-1].end(), "edge"))
    if line.box[0] <= slack and _CLIPPED.search(tokens[0].group(0)):
        spans.append((tokens[0].start(), tokens[0].end(), "edge"))
    return spans


def _line_hits(line: Line, size: tuple[int, int]) -> list[Hit]:
    strict = fold_text(line.chars, loose=False)
    loose = fold_text(line.chars, loose=True)
    hits = []
    spans = _spans(strict, loose, chars=line.chars)
    for s, e, kind in spans + _clipped_spans(line, loose, size[0]):
        core = _span_box(line, s, e)
        hits.append(
            Hit(
                kind,
                pad_box(core, line.cell, line.height, size),
                core,
                mask("".join(line.chars[s:e])),
            )
        )
    return hits


def _neighbours(a: Line, b: Line) -> bool:
    """Is b the text that continues a: the next row down, or the next chunk right?"""
    ah = a.height
    below = a.box[1] + 0.5 * ah < b.box[1] < a.box[3] + 1.2 * ah and b.box[0] < a.box[2]
    right = (
        abs((a.box[1] + a.box[3]) / 2 - (b.box[1] + b.box[3]) / 2) < 0.5 * ah
        and 0 <= b.box[0] - a.box[2] < 2.5 * a.cell
    )
    return below or right


def _wrap_hits(lines: list[Line], size: tuple[int, int]) -> list[Hit]:
    """Runs that only appear once a line is joined with the line it wraps into."""
    hits: list[Hit] = []
    for a in lines:
        for b in lines:
            if a is b or not _neighbours(a, b):
                continue
            joined = a.chars + b.chars
            cut = len(a.chars)
            strict = fold_text(joined, loose=False)
            loose = fold_text(joined, loose=True)
            for s, e, kind in _spans(strict, loose, extend=False, chars=joined):
                # the match itself must cross the line end, not just its extension
                if not (s < cut < e):
                    continue
                s, e, _ = _extend(loose, s, e, kind)
                for line, ls, le in ((a, s, cut), (b, 0, e - cut)):
                    if le <= ls:
                        continue
                    core = _span_box(line, ls, le)
                    hits.append(
                        Hit(
                            "wrap",
                            pad_box(core, line.cell, line.height, size),
                            core,
                            mask("".join(joined[s:e])),
                        )
                    )
    return hits


def _literal_hits(lines: list[Line], words: Sequence[str], size) -> list[Hit]:
    """Extra literal strings to redact (case-insensitive), such as a name."""
    hits: list[Hit] = []
    for line in lines:
        low = "".join(c.lower() if len(c.lower()) == 1 else "~" for c in line.chars)
        for word in words:
            if not word:
                continue
            for m in re.finditer(re.escape(word.lower()), low):
                core = _span_box(line, m.start(), m.end())
                hits.append(
                    Hit(
                        "text",
                        pad_box(core, line.cell, line.height, size),
                        core,
                        mask(word),
                    )
                )
    return hits


def detect(page: Page, words: Sequence[str] = ()) -> list[Hit]:
    size = (page.width, page.height)
    hits: list[Hit] = []
    for line in page.lines:
        hits.extend(_line_hits(line, size))
    hits.extend(_wrap_hits(page.lines, size))
    hits.extend(_literal_hits(page.lines, words, size))
    return hits


def blocking(hits: Iterable[Hit]) -> list[Hit]:
    """Hits that fail verification: an address, a 3+ pair fragment, a wrapped run,
    or an extra literal. Two pairs at a line edge are only a warning there."""
    return [h for h in hits if h.kind in ("address", "fragment", "wrap", "text")]


def _same_row(a: Sequence[float], b: Sequence[float]) -> bool:
    overlap = min(a[3], b[3]) - max(a[1], b[1])
    return overlap >= 0.5 * min(a[3] - a[1], b[3] - b[1])


def merge_boxes(boxes: Iterable[Box], gap: float = 2.0) -> list[Box]:
    """Union boxes that overlap or touch on the same text row, so each redaction
    is one clean slab; boxes on different rows stay separate (they may overlap)."""
    out: list[list[float]] = [list(b) for b in boxes]
    changed = True
    while changed:
        changed = False
        result: list[list[float]] = []
        while out:
            cur = out.pop()
            i = 0
            while i < len(out):
                o = out[i]
                if (
                    cur[0] - gap <= o[2]
                    and o[0] - gap <= cur[2]
                    and cur[1] - gap <= o[3]
                    and o[1] - gap <= cur[3]
                    and _same_row(cur, o)
                ):
                    cur = [
                        min(cur[0], o[0]),
                        min(cur[1], o[1]),
                        max(cur[2], o[2]),
                        max(cur[3], o[3]),
                    ]
                    out.pop(i)
                    changed = True
                else:
                    i += 1
            result.append(cur)
        out = result
    return [(b[0], b[1], b[2], b[3]) for b in out]


class Vision:
    """Runs the compiled swift OCR tool over batches of png files."""

    def __init__(self, work: Path, jobs: int | None = None, log=print) -> None:
        self.work = work
        self.jobs = jobs or max(1, (os.cpu_count() or 4) // 2)
        self.log = log
        self.binary = self._build()

    def _build(self) -> Path:
        if sys.platform != "darwin":
            raise SystemExit("the redaction pass needs macOS Vision (darwin only)")
        swiftc = Path("/usr/bin/swiftc")
        if not swiftc.exists():
            raise SystemExit("needs /usr/bin/swiftc (xcode command line tools)")
        bindir = self.work / "bin"
        bindir.mkdir(parents=True, exist_ok=True)
        binary = bindir / OCR_NAME
        digest = hashlib.sha256(OCR_SOURCE.read_bytes()).hexdigest()
        stamp = bindir / f"{OCR_NAME}.sha256"
        if binary.exists() and stamp.exists() and stamp.read_text() == digest:
            return binary
        self.log(f"compiling {OCR_SOURCE.name}")
        subprocess.run(
            [str(swiftc), "-O", str(OCR_SOURCE), "-o", str(binary)],
            check=True,
            capture_output=True,
        )
        stamp.write_text(digest)
        return binary

    def read(self, paths: Sequence[Path], passes: str = PASSES) -> list[Page]:
        if not paths:
            return []
        proc = subprocess.run(
            [str(self.binary), "--jobs", str(self.jobs), "--passes", passes],
            check=False,
            input="\n".join(str(p) for p in paths) + "\n",
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"ocr exited {proc.returncode}: {proc.stderr[-500:]}")
        pages = [parse_page(json.loads(ln)) for ln in proc.stdout.splitlines() if ln]
        if len(pages) != len(paths):
            raise RuntimeError(f"ocr returned {len(pages)} pages for {len(paths)}")
        return pages

    def model_cache(self) -> Path:
        return Path.home() / "Library" / "Caches" / OCR_NAME

    def reset_cache(self) -> None:
        """Vision keeps compiled models per executable name. A bad compile there
        silently drops lines (seen while building this), so the canary can ask
        for this tool's own cache to be rebuilt."""
        cache = self.model_cache()
        if cache.is_dir() and cache.name == OCR_NAME:
            shutil.rmtree(cache)


# --- canary: prove the OCR still reads what we rely on, before trusting it


MONO_FONTS = (
    "/System/Library/Fonts/SFNSMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
)
CANARY_LINES = (
    '{"address": "aa:bb:cc:11:22:33", "service": "Serial HPC", "channel": 9}',
    "ask the human to run: harald arm aa:bb:cc:11:22:33 --writes 50 --minutes 30",
    "this lets harald write to aa:bb:cc:11:22:33: up to 8 writes in the next 10 min",
    "armed AA:BB:CC:11:22:33: write budget 8, expires in 10 min",
    "device aa-bb-cc-11-22-33 paired",
    'replies: ["3e0c000000000200000e3c", "3e010000000000013c"]',
    "battery 3e0c01000000022200313c  nc 3e0c010000000768170101000014a93c",
    "uuid 956c7b26-d49a-4ba8-b03f-b17d393cb6e2 battery 80%",
)
SECRETS = ("aa:bb:cc:11:22:33", "AA:BB:CC:11:22:33", "aa-bb-cc-11-22-33")
SURVIVORS = (
    "3e0c000000000200000e3c",
    "3e010000000000013c",
    "3e0c01000000022200313c",
    "3e0c010000000768170101000014a93c",
    "956c7b26-d49a-4ba8-b03f-b17d393cb6e2",
)


def mono_font(size: int):
    from PIL import ImageFont

    for path in MONO_FONTS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    raise SystemExit("no macOS monospace font found (SF Mono or Menlo)")


def render_lines(
    lines: Sequence[str],
    size: tuple[int, int] = (1920, 1200),
    font_px: int = 30,
    bg=PALETTE["ink"],
    fg=PALETTE["cream"],
    origin: tuple[int, int] = (36, 48),
    pitch: int = 44,
):
    """Draw terminal-like text; return the image and the box of every secret and
    every survivor that was drawn, as (text, box)."""
    from PIL import Image, ImageDraw

    font = mono_font(font_px)
    im = Image.new("RGB", size, bg)
    draw = ImageDraw.Draw(im)
    marks: list[tuple[str, Box]] = []
    x0, y = origin
    for text in lines:
        draw.text((x0, y), text, font=font, fill=fg)
        for needle in SECRETS + SURVIVORS:
            for m in re.finditer(re.escape(needle), text):
                left = x0 + font.getlength(text[: m.start()])
                right = x0 + font.getlength(text[: m.end()])
                top, bottom = draw.textbbox((x0, y), text, font=font)[1::2]
                marks.append((needle, (left, top, right, bottom)))
        y += pitch
    return im, marks


def covered(target: Box, boxes: Sequence[Box]) -> bool:
    """Is every pixel of target inside the union of boxes? (checked on a 2 px grid)"""
    x0, y0, x1, y1 = target
    xs = [x0 + i * 2 for i in range(int((x1 - x0) / 2) + 1)] + [x1]
    ys = [y0 + i * 2 for i in range(int((y1 - y0) / 2) + 1)] + [y1]
    for y in ys:
        for x in xs:
            if not any(b[0] <= x <= b[2] and b[1] <= y <= b[3] for b in boxes):
                return False
    return True


def overlaps(a: Box, b: Box) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def check_canary(vision: Vision, tmp: Path) -> list[str]:
    """OCR a frame we drew ourselves; return what went wrong (empty when healthy)."""
    im, marks = render_lines(CANARY_LINES)
    path = tmp / "canary.png"
    im.save(path)
    page = vision.read([path])[0]
    boxes = [h.box for h in detect(page)]
    problems = []
    for text, box in marks:
        if text in SECRETS and not covered(box, boxes):
            problems.append(f"missed {mask(text)} at y={box[1]:.0f}")
        if text in SURVIVORS and any(overlaps(box, b) for b in boxes):
            problems.append(f"covered survivor {text} at y={box[1]:.0f}")
    return problems


def healthy_vision(work: Path, jobs: int | None = None, log=print) -> Vision:
    """Build the OCR tool and prove it on the canary; rebuild its model cache once
    if the first try is degraded."""
    vision = Vision(work, jobs, log)
    tmp = work / "canary"
    tmp.mkdir(parents=True, exist_ok=True)
    problems = check_canary(vision, tmp)
    if problems:
        log(
            "ocr canary failed, rebuilding the Vision model cache: "
            + "; ".join(problems)
        )
        vision.reset_cache()
        problems = check_canary(vision, tmp)
    if problems:
        raise SystemExit(
            "ocr canary failed twice, not trusting OCR: " + "; ".join(problems)
        )
    log("ocr canary ok")
    return vision
