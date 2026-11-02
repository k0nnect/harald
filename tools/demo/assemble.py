# /// script
# requires-python = ">=3.11"
# dependencies = ["pillow>=10.1", "numpy>=1.26"]
# ///
"""Cut, redact and assemble the readme demo gif (assets/demo.gif).

Pipeline: (a) extract the kept beats from the OBS recording, (b) OCR every frame at
full resolution and paint an opaque palette-coloured box over every bluetooth
classic address (see redact.py), (c) downscale to 960x600 with lanczos, (d) join
the Blender title, the terminal part and the outro, (e) encode a looping gif with
one global palette, no dither and identical frames collapsed, (f) verify: OCR every
redacted full-resolution frame and every frame of the finished gif (upscaled 2x),
fail loudly on any address or 3+ pair fragment, write verify.json and contact
sheets for a human to eyeball.

    uv run tools/demo/assemble.py --recording REC --beats beats.json \\
        --title .superpowers/demo/title --outro .superpowers/demo/outro \\
        --out assets/demo.gif
    uv run tools/demo/assemble.py --frames-only --recording REC [--fps 4]

The beats file is JSON: {"fps": 12, "crop": [x, y, w, h], "segments": [...]}, or
just the list. Each segment is {"start": s, "end": s, "speed": 2} or
{"hold": s, "seconds": 1.5}; times are seconds or "m:ss.s".

Unredacted frames only live in a temporary folder under the work directory, which
is removed at the end. Nothing written to disk carries the text OCR read.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageSequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import redact

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".superpowers" / "demo" / "work"
FULL = (1920, 1200)
CANVAS = (960, 600)
PART_FPS = 24.0
CREAM = redact.PALETTE["cream"]


def log(msg: str) -> None:
    print(f"[assemble] {msg}", flush=True)


# --- beats


@dataclass
class Segment:
    start: float
    end: float
    speed: float = 1.0


@dataclass
class Hold:
    at: float
    seconds: float


def parse_time(value) -> float:
    if isinstance(value, int | float):
        return float(value)
    total = 0.0
    for part in str(value).split(":"):
        total = total * 60 + float(part)
    return total


def load_beats(path: Path | None, duration: float) -> tuple[dict, list]:
    if path is None:
        return {}, [Segment(0.0, duration, 1.0)]
    spec = json.loads(path.read_text())
    if isinstance(spec, list):
        spec = {"segments": spec}
    items: list[Segment | Hold] = []
    for raw in spec.get("segments", []):
        if "hold" in raw:
            items.append(Hold(parse_time(raw["hold"]), float(raw["seconds"])))
        else:
            seg = Segment(
                parse_time(raw["start"]),
                parse_time(raw["end"]),
                float(raw.get("speed", 1)),
            )
            if seg.end <= seg.start or seg.speed <= 0:
                raise SystemExit(f"bad segment in {path}: {raw}")
            items.append(seg)
    if not items:
        raise SystemExit(f"{path} has no segments")
    return spec, items


# --- extraction


@dataclass
class Frame:
    path: Path
    t: float  # source time, seconds
    dur: float  # display time in the gif, seconds


def run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"{cmd[0]} failed: {proc.stderr.strip()[-800:]}")


def probe(rec: Path) -> tuple[float, int, int]:
    proc = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=width,height:format=duration",
            "-of",
            "json",
            str(rec),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    info = json.loads(proc.stdout)
    stream = info["streams"][0]
    return float(info["format"]["duration"]), stream["width"], stream["height"]


def extract(rec: Path, items: list, fps: float, crop, out: Path) -> list[Frame]:
    pre = ""
    if crop:
        x, y, w, h = (int(v) for v in crop)
        pre = f"crop={w}:{h}:{x}:{y},"
    post = f"scale={FULL[0]}:{FULL[1]}:flags=lanczos,format=rgb24"
    frames: list[Frame] = []
    for i, item in enumerate(items):
        if isinstance(item, Hold):
            path = out / f"b{i:03d}_hold.png"
            run(
                ["ffmpeg", "-v", "error", "-y", "-ss", f"{item.at:.3f}", "-i", str(rec)]
                + ["-frames:v", "1", "-vf", pre + post, str(path)]
            )
            frames.append(Frame(path, item.at, item.seconds))
            continue
        rate = fps / item.speed
        pattern = out / f"b{i:03d}_%05d.png"
        run(
            ["ffmpeg", "-v", "error", "-y", "-ss", f"{item.start:.3f}"]
            + ["-to", f"{item.end:.3f}", "-i", str(rec)]
            + ["-vf", f"{pre}fps={rate:.6f},{post}", "-start_number", "0"]
            + [str(pattern)]
        )
        paths = sorted(out.glob(f"b{i:03d}_[0-9]*.png"))
        if not paths:
            raise SystemExit(f"no frames in {item}; is it inside the recording?")
        for k, path in enumerate(paths):
            frames.append(Frame(path, item.start + k / rate, 1.0 / fps))
    return frames


def gray(path: Path) -> np.ndarray:
    return np.asarray(Image.open(path).convert("L"), dtype=np.int16)


def block_diff(a: np.ndarray, b: np.ndarray, block: int) -> np.ndarray:
    """Mean absolute difference per block x block tile."""
    d = np.abs(a.astype(np.int16) - b.astype(np.int16))
    if d.ndim == 3:
        d = d.max(axis=2)
    h, w = d.shape
    h2, w2 = h - h % block, w - w % block
    d = d[:h2, :w2].reshape(h2 // block, block, w2 // block, block)
    return d.mean(axis=(1, 3))


@dataclass
class Rep:
    """One distinct terminal frame (a run of near-identical frames)."""

    path: Path
    t: float
    dur: float
    hits: list = field(default_factory=list)
    boxes: list = field(default_factory=list)
    extra: list = field(default_factory=list)  # boxes added by verification


def dedupe(frames: list[Frame], threshold: float = 2.0) -> list[Rep]:
    """Collapse runs of frames whose every 16 px block differs by less than
    threshold (video noise), keeping the first frame and summing durations."""
    reps: list[Rep] = []
    anchor = None
    for f in frames:
        g = gray(f.path)
        if anchor is not None and block_diff(anchor, g, 16).max() < threshold:
            reps[-1].dur += f.dur
            continue
        reps.append(Rep(f.path, f.t, f.dur))
        anchor = g
    return reps


# --- redaction


def down_up(src: Path, dst: Path) -> Path:
    """The frame as the gif will show it, scaled back up for OCR."""
    im = Image.open(src).convert("RGB")
    im.resize(CANVAS, Image.LANCZOS).resize(im.size, Image.LANCZOS).save(dst)
    return dst


def ocr_hits(vision, paths: list[Path], words, label: str) -> list[list]:
    """detect() over many images, in batches so progress shows."""
    out: list[list] = []
    batch = max(8, vision.jobs * 4)
    for i in range(0, len(paths), batch):
        pages = vision.read(paths[i : i + batch])
        out.extend(redact.detect(p, words) for p in pages)
        log(f"{label}: ocr {min(i + batch, len(paths))}/{len(paths)}")
    return out


def _inside(a, b, slack: float = 1.0) -> bool:
    return (
        a[0] >= b[0] - slack
        and a[1] >= b[1] - slack
        and a[2] <= b[2] + slack
        and a[3] <= b[3] + slack
    )


def unique_hits(hits: list) -> list:
    """The passes and views mostly agree; keep one hit per box."""
    seen, out = set(), []
    for h in hits:
        key = tuple(round(v) for v in h.box)
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def propagate(reps: list[Rep], steps: int = 6) -> int:
    """Carry a box to neighbouring frames whose pixels at the start of the matched
    text are the same: that catches a frame where the address is still being
    typed or streamed, or where OCR flaked on unchanged text."""
    cache: dict[int, np.ndarray] = {}

    def g(i: int) -> np.ndarray:
        if i not in cache:
            cache[i] = gray(reps[i].path)
        return cache[i]

    added = 0
    for j, rep in enumerate(reps):
        for hit in [h for h in rep.hits if h.source == "ocr"]:
            x0, y0, x1, y1 = (round(v) for v in hit.core)
            width = min(x1 - x0, int(1.5 * (y1 - y0)))
            if width < 4 or y1 - y0 < 4:
                continue
            ref = g(j)[y0:y1, x0 : x0 + width]
            if ref.std() < 12:  # no ink there, nothing to anchor on
                continue
            for step in (1, -1):
                k = j + step
                while 0 <= k < len(reps) and abs(k - j) <= steps:
                    other = g(k)[y0:y1, x0 : x0 + width]
                    if np.abs(other - ref).mean() >= 8:
                        break
                    if not any(_inside(hit.box, b) for b in reps[k].boxes):
                        reps[k].boxes.append(hit.box)
                        reps[k].hits.append(
                            redact.Hit(
                                hit.kind, hit.box, hit.core, hit.masked, "carried"
                            )
                        )
                        added += 1
                    k += step
    return added


def snap(hit, g: np.ndarray):
    """Fit a box's height to the ink of the matched text, plus 6 px.

    Vision's accurate-level word boxes are taller than the row pitch, so a padded
    box would cover half of the rows above and below. The rows of ink under the
    match (searched a little above and below the OCR box) give the real glyph
    band; the sides keep the OCR extent and its padding."""
    x0, y0, x1, y1 = hit.core
    h = max(4.0, y1 - y0)
    top, bottom = max(0, int(y0 - 0.35 * h)), min(g.shape[0], int(y1 + 0.35 * h) + 1)
    left, right = max(0, int(x0)), min(g.shape[1], int(np.ceil(x1)))
    region = g[top:bottom, left:right]
    if region.size == 0:
        return hit
    diff = np.abs(region - np.median(region))
    ink = diff > max(24.0, 0.3 * float(diff.max()))
    rows = ink.any(axis=1)
    mid = int((y0 + y1) / 2) - top
    band = [r for r in range(len(rows)) if rows[r]]
    if not band:
        return hit
    # the run of ink rows (gaps of up to 2 px) that reaches the middle of the match
    runs, start, prev = [], band[0], band[0]
    for r in band[1:]:
        if r - prev > 3:
            runs.append((start, prev))
            start = r
        prev = r
    runs.append((start, prev))
    near = [ru for ru in runs if ru[0] - h / 6 <= mid <= ru[1] + h / 6]
    if not near:
        return hit
    lo, hi = min(r[0] for r in near), max(r[1] for r in near)
    pad = 6
    box = (
        hit.box[0],
        max(0.0, top + lo - pad),
        hit.box[2],
        min(float(g.shape[0]), top + hi + 1 + pad),
    )
    return replace(hit, box=box)


def parse_colour(choice: str) -> tuple[int, int, int] | None:
    """A palette name or #rrggbb; None for auto."""
    if choice == "auto":
        return None
    if choice in redact.PALETTE:
        return redact.PALETTE[choice]
    value = choice.lstrip("#")
    return (int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16))


def colour_arg(value: str) -> str:
    ok = value == "auto" or value in redact.PALETTE
    ok = ok or (value.startswith("#") and len(value) == 7)
    if ok and value.startswith("#"):
        try:
            int(value[1:], 16)
        except ValueError:
            ok = False
    if not ok:
        raise argparse.ArgumentTypeError("auto, a palette name or #rrggbb")
    return value


def box_colour(region: np.ndarray, choice: str) -> tuple[int, int, int]:
    fixed = parse_colour(choice)
    if fixed is not None:
        return fixed
    lum = float(np.median(region.mean(axis=2))) if region.size else 0.0
    return redact.PALETTE["ink"] if lum > 128 else redact.PALETTE["cream"]


def paint(src: Path, boxes: list, dst: Path, choice: str) -> None:
    im = Image.open(src).convert("RGB")
    arr = np.asarray(im)
    draw = ImageDraw.Draw(im)
    for b in redact.merge_boxes(boxes):
        x0, y0 = int(b[0]), int(b[1])
        x1, y1 = int(np.ceil(b[2])), int(np.ceil(b[3]))
        colour = box_colour(arr[y0:y1, x0:x1], choice)
        draw.rectangle((x0, y0, x1 - 1, y1 - 1), fill=colour)
    im.save(dst)


def redact_reps(reps: list[Rep], vision, words, tmp: Path, out: Path, choice: str):
    """OCR two views of every frame, box what was found, then OCR the boxed frames
    and box again until nothing is left (at most three rounds)."""
    views = [down_up(r.path, tmp / f"view_{i:05d}.png") for i, r in enumerate(reps)]
    full = ocr_hits(vision, [r.path for r in reps], words, "full-res")
    small = ocr_hits(vision, views, words, "960 view")
    for rep, a, b in zip(reps, full, small, strict=True):
        g = gray(rep.path)
        rep.hits = unique_hits([snap(h, g) for h in a + b])
        rep.boxes = [h.box for h in rep.hits]
    carried = propagate(reps)
    log(f"carried {carried} boxes to neighbouring frames")
    redacted = [out / f"{i:05d}.png" for i in range(len(reps))]
    todo = list(range(len(reps)))
    for round_no in range(1, 4):
        for i in todo:
            paint(reps[i].path, reps[i].boxes + reps[i].extra, redacted[i], choice)
        found = ocr_hits(vision, [redacted[i] for i in todo], words, "verify full-res")
        left = []
        for i, hits in zip(todo, found, strict=True):
            if hits:
                g = gray(reps[i].path)
                reps[i].extra.extend(snap(h, g).box for h in hits)
                left.append(i)
        if not left:
            log(f"full-res frames clean after round {round_no}")
            return redacted, []
        log(f"round {round_no}: {len(left)} frames still showed a match, boxing")
        todo = left
    for i in todo:
        paint(reps[i].path, reps[i].boxes + reps[i].extra, redacted[i], choice)
    found = ocr_hits(vision, [redacted[i] for i in todo], words, "verify full-res")
    left = [i for i, h in zip(todo, found, strict=True) if redact.blocking(h)]
    return redacted, left


# --- composing and encoding


@dataclass
class Entry:
    image: np.ndarray  # 600 x 960 x 3 uint8
    dur: float
    part: str
    ref: int  # index into reps for the terminal part, else frame number
    label: str


def stabilise(prev: np.ndarray, cur: np.ndarray, noise: int = 8) -> np.ndarray:
    """Copy back 8 px blocks in which no pixel moved by more than video noise, so
    the gif does not re-encode them every frame. Every pixel must be within noise:
    a mean test would let a lone pixel of old text linger as a ghost."""
    d = np.abs(prev.astype(np.int16) - cur.astype(np.int16)).max(axis=2)
    h, w = d.shape[0] - d.shape[0] % 8, d.shape[1] - d.shape[1] % 8
    peak = d[:h, :w].reshape(h // 8, 8, w // 8, 8).max(axis=(1, 3))
    still = peak <= noise
    mask = np.repeat(np.repeat(still, 8, axis=0), 8, axis=1)
    out = cur.copy()
    h, w = mask.shape
    out[:h, :w][mask] = prev[:h, :w][mask]
    return out


def flatten_background(arr: np.ndarray, tolerance: int = 3) -> np.ndarray:
    """Video noise leaves the flat terminal background a few levels off here and
    there; snap pixels within tolerance of the dominant colour back onto it, so
    flat areas stay flat in the gif. Invisible, and nothing else changes."""
    flat = arr.reshape(-1, 3).astype(np.int32)
    packed = (flat[:, 0] << 16) | (flat[:, 1] << 8) | flat[:, 2]
    keys, counts = np.unique(packed[::5], return_counts=True)
    top = int(keys[counts.argmax()])
    bg = np.array([(top >> 16) & 255, (top >> 8) & 255, top & 255], np.int32)
    near = np.abs(flat - bg).max(axis=1) <= tolerance
    out = flat.copy()
    out[near] = bg
    return out.reshape(arr.shape).astype(np.uint8)


def terminal_entries(reps: list[Rep], redacted: list[Path]) -> list[Entry]:
    entries: list[Entry] = []
    prev = None
    for i, (rep, path) in enumerate(zip(reps, redacted, strict=True)):
        im = Image.open(path).convert("RGB").resize(CANVAS, Image.LANCZOS)
        arr = flatten_background(np.asarray(im))
        if prev is not None:
            arr = stabilise(prev, arr)
        prev = arr
        entries.append(Entry(arr, rep.dur, "terminal", i, f"t{rep.t:.2f}s"))
    return entries


def part_entries(folder: Path | None, part: str) -> list[Entry]:
    if folder is None:
        return []
    paths = sorted(folder.glob("*.png"))
    if not paths:
        raise SystemExit(f"no png frames in {folder}")
    entries = []
    for k, path in enumerate(paths):
        im = Image.open(path).convert("RGB")
        if im.size != CANVAS:
            log(f"{path.name} is {im.size}, scaling to {CANVAS}")
            im = im.resize(CANVAS, Image.LANCZOS)
        entries.append(Entry(np.asarray(im), 1 / PART_FPS, part, k, path.stem))
    return entries


def cream_entry(seconds: float) -> Entry:
    arr = np.empty((CANVAS[1], CANVAS[0], 3), np.uint8)
    arr[:] = CREAM
    return Entry(arr, seconds, "cut", 0, "cut")


def collapse(entries: list[Entry]) -> list[Entry]:
    out: list[Entry] = []
    for e in entries:
        if out and np.array_equal(out[-1].image, e.image):
            out[-1].dur += e.dur
        else:
            out.append(Entry(e.image, e.dur, e.part, e.ref, e.label))
    return out


def centiseconds(entries: list[Entry]) -> list[int]:
    """Gif delays are in 1/100 s; spread the rounding so the total stays right."""
    out, clock, done = [], 0.0, 0
    for e in entries:
        clock += e.dur
        end = max(done + 2, round(clock * 100))
        out.append(end - done)
        done = end
    return out


def build_palette(entries: list[Entry], tmp: Path, extra=()) -> Image.Image:
    """255 colours from ffmpeg palettegen, with the most common exact colours
    forced in so flat areas stay flat. One index is left for transparency."""
    folder = tmp / "pal"
    folder.mkdir(exist_ok=True)
    for i, e in enumerate(entries):
        Image.fromarray(e.image).save(folder / f"{i:05d}.png", compress_level=1)
    pal_png = tmp / "palette.png"
    run(
        ["ffmpeg", "-v", "error", "-y", "-i", str(folder / "%05d.png")]
        + ["-vf", "palettegen=max_colors=255:stats_mode=full:reserve_transparent=0"]
        + ["-frames:v", "1", "-update", "1", str(pal_png)]
    )
    shutil.rmtree(folder)
    pal_rgb = np.asarray(Image.open(pal_png).convert("RGB")).reshape(-1, 3)
    colours = list(dict.fromkeys(tuple(int(v) for v in c) for c in pal_rgb))
    # exact colours that cover the most pixels (backgrounds, flat title areas)
    counts: dict[int, int] = {}
    for e in entries:
        packed = e.image[::2, ::2].reshape(-1, 3).astype(np.uint32)
        keys, n = np.unique(
            (packed[:, 0] << 16) | (packed[:, 1] << 8) | packed[:, 2],
            return_counts=True,
        )
        for k, c in zip(keys.tolist(), n.tolist(), strict=True):
            counts[k] = counts.get(k, 0) + c
    top = sorted(counts, key=counts.get, reverse=True)[:24]
    forced = [((k >> 16) & 255, (k >> 8) & 255, k & 255) for k in top]
    forced += list(redact.PALETTE.values()) + list(extra)
    forced = list(dict.fromkeys(forced))
    rest = [c for c in colours if c not in forced]
    final = (forced + rest)[:255]
    pal = Image.new("P", (1, 1))
    pal.putpalette([v for c in final for v in c])
    return pal


def quantise(image: np.ndarray, palette: np.ndarray) -> np.ndarray:
    """Exact nearest-colour mapping, no dither: a colour that is in the palette
    maps to itself (Pillow's own lookup is approximate and shifts flat colours)."""
    flat = image.reshape(-1, 3).astype(np.int32)
    packed = (flat[:, 0] << 16) | (flat[:, 1] << 8) | flat[:, 2]
    keys, inverse = np.unique(packed, return_inverse=True)
    rgb = np.stack([(keys >> 16) & 255, (keys >> 8) & 255, keys & 255], axis=1)
    dist = ((rgb[:, None, :] - palette[None, :, :].astype(np.int32)) ** 2).sum(axis=2)
    index = dist.argmin(axis=1).astype(np.uint8)
    return index[inverse.reshape(-1)].reshape(image.shape[:2])


def write_gif(entries: list[Entry], out: Path, tmp: Path, extra=()) -> list[Entry]:
    pal = build_palette(entries, tmp, extra)
    palette = np.array(pal.getpalette()[: 3 * 255], np.int32).reshape(-1, 3)
    frames: list[Image.Image] = []
    kept: list[Entry] = []
    last = None
    for e in entries:
        idx = quantise(e.image, palette)
        if last is not None and np.array_equal(last, idx):
            kept[-1].dur += e.dur
            continue
        last = idx
        q = Image.fromarray(idx, mode="P")
        q.putpalette(pal.getpalette()[: 3 * 255])
        frames.append(q)
        kept.append(Entry(e.image, e.dur, e.part, e.ref, e.label))
    delays = [cs * 10 for cs in centiseconds(kept)]
    out.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        out,
        save_all=True,
        append_images=frames[1:],
        duration=delays,
        loop=0,
        disposal=1,
        optimize=False,
    )
    return kept


# --- verification


def label_font() -> str:
    for path in redact.MONO_FONTS:
        if Path(path).exists():
            return path
    return "Courier"


def contact_sheets(folder: Path, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("sheet_*.png"):
        old.unlink()
    files = sorted(folder.glob("*.png"))
    if not files:
        return 0
    run(
        ["magick", "montage", "-label", "%t", "-font", label_font(), "-pointsize", "20"]
        + [str(f) for f in files]
        + ["-tile", "3x3", "-geometry", "+8+8", "-background", "#f3efe6"]
        + [str(out / "sheet_%03d.png")]
    )
    return len(list(out.glob("sheet_*.png")))


def gif_frames(path: Path) -> tuple[list[np.ndarray], list[int], int | None]:
    with Image.open(path) as im:
        loop = im.info.get("loop")
        frames, delays = [], []
        for f in ImageSequence.Iterator(im):
            delays.append(int(f.info.get("duration", 0)))
            frames.append(np.asarray(f.convert("RGB")))
    return frames, delays, loop


def verify_gif(gif: Path, kept: list[Entry], vision, words, tmp: Path, work: Path):
    frames, delays, loop = gif_frames(gif)
    if len(frames) != len(kept):
        raise SystemExit(f"gif has {len(frames)} frames, expected {len(kept)}")
    folder = work / "gif_frames"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    ups = []
    for i, arr in enumerate(frames):
        name = f"{i:04d}_{kept[i].part}_{kept[i].label}"
        Image.fromarray(arr).save(folder / f"{name}.png")
        up = tmp / f"gif_{i:05d}.png"
        Image.fromarray(arr).resize(FULL, Image.LANCZOS).save(up)
        ups.append(up)
    found = ocr_hits(vision, ups, words, "verify gif")
    return frames, delays, loop, found


def report_frames(found: list[list], labels: list[dict]) -> tuple[list[dict], int]:
    rows, bad = [], 0
    for meta, hits in zip(labels, found, strict=True):
        blocking = redact.blocking(hits)
        bad += bool(blocking)
        rows.append(
            meta
            | {
                "ok": not blocking,
                "hits": [{"kind": h.kind, "text": h.masked} for h in blocking],
                "warnings": [
                    {"kind": h.kind, "text": h.masked}
                    for h in hits
                    if h not in blocking
                ],
            }
        )
    return rows, bad


# --- modes


def frames_only(args, vision, work: Path, tmp: Path) -> int:
    duration, _, _ = probe(args.recording)
    spec, items = load_beats(args.beats, duration)
    fps = args.fps or 4.0
    raw = tmp / "raw"
    raw.mkdir()
    frames = extract(args.recording, items, fps, spec.get("crop"), raw)
    reps = dedupe(frames)
    log(f"{len(frames)} frames, {len(reps)} distinct")
    redacted_dir = tmp / "redacted"
    redacted_dir.mkdir()
    redacted, left = redact_reps(
        reps, vision, args.redact_text, tmp, redacted_dir, args.box_color
    )
    out = work / "frames"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    index = []
    for i, (rep, path) in enumerate(zip(reps, redacted, strict=True)):
        name = f"{i:05d}_t{rep.t:08.3f}.png"
        Image.open(path).convert("RGB").resize(CANVAS, Image.LANCZOS).save(out / name)
        index.append(
            {
                "file": name,
                "t": round(rep.t, 3),
                "seconds_shown": round(rep.dur, 3),
                "boxes": len(redact.merge_boxes(rep.boxes + rep.extra)),
                "clean": i not in left,
            }
        )
    (out / "index.json").write_text(json.dumps(index, indent=1))
    sheets = contact_sheets(out, out / "sheets")
    log(f"wrote {len(index)} redacted frames and {sheets} sheets to {out}")
    if left:
        log(f"FAIL: {len(left)} frames still show a match after three rounds")
        return 1
    return 0


def assemble(args, vision, work: Path, tmp: Path) -> int:
    duration, w, h = probe(args.recording)
    if (w, h) != FULL:
        log(f"recording is {w}x{h}; frames are scaled to {FULL[0]}x{FULL[1]}")
    spec, items = load_beats(args.beats, duration)
    fps = float(args.fps or spec.get("fps", 12))
    raw = tmp / "raw"
    raw.mkdir()
    frames = extract(args.recording, items, fps, spec.get("crop"), raw)
    reps = dedupe(frames)
    log(f"terminal: {len(frames)} frames at {fps:g} fps, {len(reps)} distinct")
    redacted_dir = tmp / "redacted"
    redacted_dir.mkdir()
    redacted, left = redact_reps(
        reps, vision, args.redact_text, tmp, redacted_dir, args.box_color
    )
    if left:
        log(f"FAIL: {len(left)} full-res frames still show a match; no gif written")
        return 1

    title = part_entries(args.title, "title")
    outro = part_entries(args.outro, "outro")
    # start on title frame k (a settled one, since frame 1 is what viewers with
    # autoplay off see); the frames before k play after the outro, so the loop
    # stays seamless: title[k..], terminal, outro, title[..k-1]
    k = max(1, min(args.title_start, len(title))) if title else 1
    head, tail = title[k - 1 :], title[: k - 1]
    fixed = parse_colour(args.box_color)
    for attempt in range(1, 4):
        terminal = terminal_entries(reps, redacted)
        seq = list(head)
        if head and args.cut == "cream":
            seq.append(cream_entry(0.12))
        seq += terminal
        if outro and args.cut == "cream":
            seq.append(cream_entry(0.12))
        seq += outro + tail
        kept = write_gif(collapse(seq), args.out, tmp, [fixed] if fixed else [])
        frames, delays, loop, found = verify_gif(
            args.out, kept, vision, args.redact_text, tmp, work
        )
        # box every match in a terminal frame, two-pair edges included; title and
        # outro frames cannot be fixed here and fail verification below
        fix = [
            (kept[i], hits)
            for i, hits in enumerate(found)
            if hits and kept[i].part == "terminal"
        ]
        if not fix or attempt == 3:
            break
        log(f"gif check found {len(fix)} frames with a match; boxing and rebuilding")
        for e, hits in fix:  # gif frames were OCR'd at 2x, the full-res scale
            g = gray(reps[e.ref].path)
            reps[e.ref].extra.extend(snap(h, g).box for h in hits)
            paint(reps[e.ref].path, reps[e.ref].boxes + reps[e.ref].extra,
                  redacted[e.ref], args.box_color)  # fmt: skip

    # full-res check, recorded per frame
    full_found = ocr_hits(vision, redacted, args.redact_text, "final full-res")
    full_rows, full_bad = report_frames(
        full_found,
        [
            {
                "frame": i,
                "t": round(r.t, 3),
                "boxes": len(redact.merge_boxes(r.boxes + r.extra)),
                "found_before": sorted({h.kind for h in r.hits}),
            }
            for i, r in enumerate(reps)
        ],
    )
    meta = [
        {
            "frame": i,
            "part": kept[i].part,
            "source": kept[i].label,
            "delay_ms": delays[i],
        }
        for i in range(len(frames))
    ]
    gif_rows, gif_bad = report_frames(found, meta)
    size = args.out.stat().st_size
    sheets = contact_sheets(work / "gif_frames", work / "sheets")
    result = {
        "ok": full_bad == 0 and gif_bad == 0 and loop == 0,
        "gif": str(args.out),
        "bytes": size,
        "frames": len(frames),
        "seconds": round(sum(delays) / 1000, 2),
        "loop": loop,
        "contact_sheets": sheets,
        "terminal_full_res": full_rows,
        "gif_frames": gif_rows,
    }
    (work / "verify.json").write_text(json.dumps(result, indent=1))
    log(
        f"{args.out}: {size / 1e6:.2f} MB, {len(frames)} frames, "
        f"{result['seconds']} s, loop={loop}, {sheets} contact sheets"
    )
    if size > 4e6:
        log("WARNING: over the 4 MB target")
    if not result["ok"]:
        log(
            f"FAIL: {full_bad} full-res and {gif_bad} gif frames show a match "
            f"(see {work / 'verify.json'}); do not publish this gif"
        )
        return 1
    log("verify ok: no address or 3+ pair fragment in any frame")
    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--recording", type=Path, required=True, help="OBS mov/mkv")
    p.add_argument(
        "--beats", type=Path, help="beats JSON (required unless frames-only)"
    )
    p.add_argument("--title", type=Path, help="title frames dir (960x600 png, 24 fps)")
    p.add_argument("--outro", type=Path, help="outro frames dir (optional)")
    p.add_argument("--out", type=Path, help="gif to write, e.g. assets/demo.gif")
    p.add_argument("--work", type=Path, default=WORK, help="scratch and reports")
    p.add_argument("--fps", type=float, help="terminal frame rate (12; 4 frames-only)")
    p.add_argument(
        "--box-color",
        type=colour_arg,
        default="auto",
        help="redaction box colour: auto (ink on light text areas, cream on dark), "
        "a palette name (ink, cream, red, blue) or #rrggbb",
    )
    p.add_argument(
        "--title-start",
        type=int,
        default=1,
        metavar="K",
        help="open on title frame K; frames 1..K-1 play after the outro instead",
    )
    p.add_argument("--cut", choices=["hard", "cream"], default="hard")
    p.add_argument(
        "--redact-text",
        action="append",
        default=[],
        metavar="TEXT",
        help="also box this literal text wherever OCR reads it (repeatable)",
    )
    p.add_argument("--jobs", type=int, help="parallel OCR workers")
    p.add_argument(
        "--frames-only",
        action="store_true",
        help="dump redacted frames with timestamps to WORK/frames to choose beats",
    )
    args = p.parse_args(argv)
    if not args.frames_only:
        missing = [n for n in ("beats", "title", "out") if getattr(args, n) is None]
        if missing:
            p.error("needs --" + ", --".join(missing) + " (or --frames-only)")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    started = time.time()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    vision = redact.healthy_vision(work, args.jobs, log)
    tmp = Path(tempfile.mkdtemp(prefix=".unredacted-", dir=work))
    try:
        if args.frames_only:
            code = frames_only(args, vision, work, tmp)
        else:
            code = assemble(args, vision, work, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    log(f"done in {time.time() - started:.0f} s")
    return code


if __name__ == "__main__":
    sys.exit(main())
