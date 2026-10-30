"""Build assets/banner.svg, the readme banner, with every glyph outlined as a path.

Viewers may lack fonts for katakana or runes, so the svg carries no text at all: each
glyph is drawn with fonttools (`TTFont.getGlyphSet` at a variable-font location,
`TransformPen` to place and scale it, `SVGPathPen` to turn it into path data). The
fonts are open-licensed (sil ofl 1.1) files from the google/fonts repository, pinned
to one commit and cached in scripts/.fonts/, which is gitignored. Only the svg is
committed.

Run with: uv run python scripts/make_banner.py
"""

from __future__ import annotations

import urllib.request
from pathlib import Path

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "assets" / "banner.svg"
FONT_DIR = HERE / ".fonts"
FONT_BASE = (
    "https://raw.githubusercontent.com/google/fonts/"
    "6c1dbe27dcf7d817d4b62cec033ba77fa8e2a5ec/ofl/"
)
FONTS = {
    "inter": "inter/Inter%5Bopsz,wght%5D.ttf",
    "noto-sans-jp": "notosansjp/NotoSansJP%5Bwght%5D.ttf",
    "noto-sans-runic": "notosansrunic/NotoSansRunic-Regular.ttf",
}

# palette, from the approved design
PAPER = "#f3efe6"
VERMILION = "#c8102e"
INK = "#161616"
BLUE = "#2b4bd8"
LIBRARY_INK = "#4a4640"

# layout in css pixels, measured from the approved mockup ("version 2")
WIDTH, HEIGHT = 840, 330
LEFT = 30
TITLE_BASELINE = 112
RULE_Y = 141
RUNES_BASELINE = 182.5  # 179 in css; these runes sit on it, the mockup's hung below
TAGLINE_BASELINE = 212
STAMP = (760, 30, 50)  # left, top, outer size; 3px border, 30px from the corner
# the mockup set these in system fonts; the open fonts here are sized and tracked
# so their ink matches it: katakana 44px, runes 24px + 16px, stamp rune 26px bold.
KATA_SIZE = 41
RUNES_SIZE, RUNES_TRACKING = 27, 20.5
STAMP_RUNE_SIZE, STAMP_RUNE_BOLD = 31, 0.4


def _number(value: float) -> str:
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return "0" if text == "-0" else text


def font_path(name: str) -> Path:
    """The cached font file for `name`, downloaded on first use."""
    path = FONT_DIR / f"{name}.ttf"
    if not path.is_file():
        FONT_DIR.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(FONT_BASE + FONTS[name], timeout=60) as response:
            data = response.read()
        partial = path.with_suffix(".part")
        partial.write_bytes(data)
        partial.replace(path)
    return path


def outline(
    font: TTFont,
    text: str,
    size: float,
    x: float,
    baseline: float,
    *,
    tracking: float = 0.0,
    location: dict[str, float] | None = None,
) -> tuple[str, float]:
    """Path data for `text` set at (`x`, `baseline`), and the pen's x afterwards.

    Like css letter-spacing, `tracking` is added after every glyph.
    """
    glyphs = font.getGlyphSet(location=location)
    cmap = font.getBestCmap()
    scale = size / font["head"].unitsPerEm
    pen = SVGPathPen(glyphs, ntos=_number)
    for char in text:
        glyph = glyphs[cmap[ord(char)]]
        glyph.draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
        x += glyph.width * scale + tracking
    return pen.getCommands(), x


def centered(font: TTFont, char: str, size: float, cx: float, cy: float) -> str:
    """Path data for one glyph with its ink box centred on (`cx`, `cy`)."""
    glyphs = font.getGlyphSet()
    glyph = glyphs[font.getBestCmap()[ord(char)]]
    bounds = BoundsPen(glyphs)
    glyph.draw(bounds)
    xmin, ymin, xmax, ymax = bounds.bounds
    scale = size / font["head"].unitsPerEm
    dx = cx - (xmin + xmax) / 2 * scale
    dy = cy + (ymin + ymax) / 2 * scale
    pen = SVGPathPen(glyphs, ntos=_number)
    glyph.draw(TransformPen(pen, (scale, 0, 0, -scale, dx, dy)))
    return pen.getCommands()


def build_banner(out: Path = OUT) -> Path:
    """Write the banner svg to `out` and return `out`."""
    inter = TTFont(font_path("inter"))
    jp = TTFont(font_path("noto-sans-jp"))
    runic = TTFont(font_path("noto-sans-runic"))

    name, name_end = outline(
        inter,
        "harald",
        82,
        LEFT,
        TITLE_BASELINE,
        tracking=-3,
        location={"wght": 200, "opsz": 32},
    )
    kata, _ = outline(
        jp,
        "ハーラル",
        KATA_SIZE,
        name_end + 18,
        TITLE_BASELINE,
        tracking=4,
        location={"wght": 700},
    )
    runes, _ = outline(
        runic,
        "ᚼᛅᚱᛅᛚᛏᚱ",
        RUNES_SIZE,
        LEFT,
        RUNES_BASELINE,
        tracking=RUNES_TRACKING,
    )
    tagline, _ = outline(
        inter,
        "teach your agent to speak bluetooth.",
        14,
        LEFT,
        TAGLINE_BASELINE,
        location={"wght": 400, "opsz": 14},
    )
    left, top, size = STAMP
    cx, cy = left + size / 2, top + size / 2
    rune = centered(runic, "ᚼ", STAMP_RUNE_SIZE, cx, cy)

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" \
width="{WIDTH}" height="{HEIGHT}">
  <title>harald</title>
  <defs>
    <pattern id="dots" width="4" height="4" patternUnits="userSpaceOnUse">
      <circle cx="2" cy="2" r="1" fill="#000" fill-opacity="0.035"/>
    </pattern>
  </defs>
  <rect width="{WIDTH}" height="{HEIGHT}" rx="6" fill="{PAPER}"/>
  <rect width="{WIDTH}" height="{HEIGHT}" rx="6" fill="url(#dots)"/>
  <path fill="{INK}" d="{name}"/>
  <path fill="{VERMILION}" d="{kata}"/>
  <rect x="{LEFT}" y="{RULE_Y}" width="{WIDTH - 2 * LEFT}" height="1" fill="{INK}"/>
  <path fill="{BLUE}" d="{runes}"/>
  <path fill="{LIBRARY_INK}" d="{tagline}"/>
  <g transform="rotate(-5 {_number(cx)} {_number(cy)})" opacity="0.92">
    <rect x="{left + 1.5}" y="{top + 1.5}" width="{size - 3}" height="{size - 3}" \
rx="3.5" fill="none" stroke="{VERMILION}" stroke-width="3"/>
    <path fill="{VERMILION}" stroke="{VERMILION}" stroke-width="{STAMP_RUNE_BOLD}" \
stroke-linejoin="round" d="{rune}"/>
  </g>
</svg>
"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(svg, encoding="utf-8")
    return out


if __name__ == "__main__":
    print(f"wrote {build_banner()}")
