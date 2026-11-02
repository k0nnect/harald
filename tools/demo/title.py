"""Render the readme gif's animated title and outro card from assets/banner.svg.

Blender's bundled svg importer brings the banner in. What it gets wrong is rebuilt
from the svg's own numbers: the stroke-only stamp square, the 1 px rule (snapped to
a pixel row), and the tagline and stamp rune, whose self-crossing outlines need
svg's nonzero fill. Flat workbench colour, an orthographic camera, the Standard
view transform, no dither and 4x supersampling put each banner hex exactly on the
pixels.

The title prints the banner: the rule draws, the wordmark settles, the runes are cut
in one by one, the tagline inks in, the stamp presses and lifts, and it all holds.
The outro holds the same card, then lets the ink go back to paper, so the loop runs
into the title's blank first frame.

From the repo root, with Blender 5.2:

    /Applications/Blender.app/Contents/MacOS/Blender --background --factory-startup \
        --python tools/demo/title.py -- --part title --out .superpowers/demo/title
    /Applications/Blender.app/Contents/MacOS/Blender --background --factory-startup \
        --python tools/demo/title.py -- --part outro --out .superpowers/demo/outro
"""

from __future__ import annotations

import argparse
import math
import re
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree

import addon_utils
import bpy
import numpy as np
from mathutils import Matrix, Vector
from mathutils.geometry import delaunay_2d_cdt

SVG = Path(__file__).resolve().parents[2] / "assets" / "banner.svg"

WIDTH, HEIGHT, FPS = 960, 600, 24
SUPERSAMPLE = 4  # rendered at 4x without aa, then box-filtered down

# banner.svg is 840 x 330 css px and its ink spans x 30-812, y 28-215. It is set at
# 1.1x, centred across the frame, with its ink a touch above the frame's middle.
BANNER_W, BANNER_H = 840, 330
SCALE = 1.1
LEFT = WIDTH / 2 - BANNER_W / 2 * SCALE
TOP = 292 - 121.5 * SCALE

# palette, as in scripts/make_banner.py. The banner's faint dot texture is left out
# on purpose: the clip is flat colour, without grain.
PAPER = "#f3efe6"
INK = "#161616"
VERMILION = "#c8102e"
BLUE = "#2b4bd8"
LIBRARY_INK = "#4a4640"

# the stamp: <g transform="rotate(-5 785 55)" opacity="0.92">, a 47 px square with a
# 3 px stroke and rx 3.5, and a rune path with a 0.4 px stroke of its own colour
STAMP_PIVOT = (785, 55)
STAMP_TURN = -5
STAMP_OPACITY = 0.92
STAMP_SQUARE = (761.5, 31.5, 47, 3.5)  # left, top, size, radius, on the stroke's axis
STAMP_STROKE = 3
STAMP_RUNE_STROKE = 0.4
RULE = (30, 141, 780, 1)  # x, y, width, height

# beats, in frames at 24 fps (frame 0 is the first png)
TITLE_FRAMES = 90
OUTRO_FRAMES = 48
RULE_DRAW = (4, 22)
WORDMARK_SETTLE = (8, 28)
KANA_DELAY = 4
SETTLE_DROP = 10  # px the wordmark settles down through
RUNES_START, RUNE_CARVE, RUNE_STAGGER = 26, 6, 3
TAGLINE_IN = (42, 54)
STAMP_DROP = (56, 60)  # comes down from STAMP_HEIGHT scale, meeting paper at 60
STAMP_PRESS = (60, 65)  # pressed in at the contact frame, released as it lifts
STAMP_HEIGHT = 1.2
STAMP_SQUASH = 0.965
OUTRO_FADE = (34, 44)


def srgb(hex_colour: str) -> tuple[float, float, float]:
    return tuple(int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5))


def linear(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def to_hex(linear_rgb) -> str:
    def encode(c: float) -> int:
        c = c * 12.92 if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055
        return round(min(1.0, max(0.0, c)) * 255)

    return "#" + "".join(f"{encode(c):02x}" for c in linear_rgb[:3])


def mix(a, b, t: float) -> tuple[float, float, float]:
    """Blend in display (srgb) space, the way svg opacity composites."""
    return tuple(x + (y - x) * t for x, y in zip(a, b))


STAMP_INK = mix(srgb(PAPER), srgb(VERMILION), STAMP_OPACITY)


def ramp(frame: float, span: tuple[float, float]) -> float:
    start, end = span
    return min(1.0, max(0.0, (frame - start) / (end - start)))


def ease_out(u: float) -> float:
    return 1 - (1 - u) ** 3


def ease_in(u: float) -> float:
    return u**2


def ease_in_out(u: float) -> float:
    return 4 * u**3 if u < 0.5 else 1 - (-2 * u + 2) ** 3 / 2


def at(x: float, y: float, z: float = 0.0) -> Vector:
    """Banner css px to world units: 1 unit is 1 output px, the frame centred on 0."""
    return Vector((LEFT + x * SCALE - WIDTH / 2, HEIGHT / 2 - (TOP + y * SCALE), z))


def link(obj):
    bpy.context.scene.collection.objects.link(obj)
    return obj


def material(name: str, colour) -> bpy.types.Material:
    mat = bpy.data.materials.new(name)
    paint(mat, colour)
    return mat


def paint(mat, colour) -> None:
    mat.diffuse_color = (*(linear(c) for c in colour), 1.0)


def wear(obj, mat) -> None:
    obj.data.materials.clear()
    obj.data.materials.append(mat)


def rectangle(name: str, width: float, height: float, mat, anchor=(0.0, 0.0)):
    """A flat quad; anchor is the corner, as a fraction of the size, at its origin."""
    ax, ay = anchor[0] * width, anchor[1] * height
    mesh = bpy.data.meshes.new(name)
    corners = [(0, 0), (width, 0), (width, height), (0, height)]
    mesh.from_pydata([(x - ax, y - ay, 0) for x, y in corners], [], [(0, 1, 2, 3)])
    obj = link(bpy.data.objects.new(name, mesh))
    wear(obj, mat)
    return obj


def points(spline):
    if spline.type == "BEZIER":
        for p in spline.bezier_points:
            yield from (p.co, p.handle_left, p.handle_right)
    else:
        yield from (p.co for p in spline.points)


def bounds(obj) -> tuple[float, float, float, float]:
    """Conservative world box (handles included) of a curve whose matrix is identity."""
    xs, ys = [], []
    for spline in obj.data.splines:
        for co in points(spline):
            xs.append(co[0])
            ys.append(co[1])
    return min(xs), max(xs), min(ys), max(ys)


def import_banner() -> dict[str, list]:
    """Import banner.svg and sort its curves by fill colour, in world units."""
    addon_utils.enable("io_curve_svg")
    before = set(bpy.data.objects)
    bpy.ops.import_curve.svg(filepath=str(SVG))
    curves = [o for o in bpy.data.objects if o not in before]

    def width(obj) -> float:
        xs = [(obj.matrix_world @ Vector(c)).x for c in obj.bound_box]
        return max(xs) - min(xs)

    # the importer's unit is whatever its full-width paper rect measures per css px
    unit = max(width(o) for o in curves) / BANNER_W
    to_world = Matrix.Translation(at(0, BANNER_H)) @ Matrix.Scale(SCALE / unit, 4)
    by_fill: dict[str, list] = {}
    for obj in curves:
        obj.data.transform(to_world @ obj.matrix_world)
        obj.matrix_world = Matrix.Identity(4)
        mats = [m for m in obj.data.materials if m]
        fill = to_hex(mats[0].diffuse_color) if mats else "none"
        by_fill.setdefault(fill, []).append(obj)
    return by_fill


def glyphs(spans: list[tuple[float, float]]) -> list[set[int]]:
    """Group outlines into glyphs, left to right: outlines whose x spans overlap
    belong together, so a counter stays with its letter."""
    groups: list[list] = []
    for low, high, index in sorted((lo, hi, i) for i, (lo, hi) in enumerate(spans)):
        if groups and low < groups[-1][1]:
            groups[-1][1] = max(groups[-1][1], high)
            groups[-1][2].add(index)
        else:
            groups.append([low, high, {index}])
    return [keep for _, _, keep in groups]


def split_glyphs(obj) -> list:
    """One object per glyph of a curve, left to right."""
    spans = []
    for spline in obj.data.splines:
        xs = [co[0] for co in points(spline)]
        spans.append((min(xs), max(xs)))
    parts = []
    for n, keep in enumerate(glyphs(spans)):
        data = obj.data.copy()
        for index in reversed(range(len(data.splines))):
            if index not in keep:
                data.splines.remove(data.splines[index])
        parts.append(link(bpy.data.objects.new(f"{obj.name}.{n}", data)))
    bpy.data.objects.remove(obj)
    return parts


def path_data(fill: str, stroke: str | None = None) -> str:
    """The d attribute of the banner's one path with this fill and stroke."""
    tag = "{http://www.w3.org/2000/svg}path"
    found = [
        e.get("d")
        for e in ElementTree.parse(SVG).iter(tag)
        if (e.get("fill"), e.get("stroke")) == (fill, stroke)
    ]
    if len(found) != 1:
        sys.exit(f"title.py: expected one {fill} path in {SVG.name}")
    return found[0]


def outlines(d: str, steps: int = 6) -> list[list[tuple[float, float]]]:
    """Flatten absolute path data (M L H V Q C Z, all fontTools writes) to rings."""
    tokens = re.findall(r"[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)", d)
    rings: list[list[tuple[float, float]]] = []
    ring: list[tuple[float, float]] = []
    pos = start = (0.0, 0.0)
    command, i = "M", 0

    def numbers(n: int) -> list[float]:
        nonlocal i
        i += n
        return [float(t) for t in tokens[i - n : i]]

    def curve(*controls: tuple[float, float]) -> None:
        degree = len(controls)
        for step in range(1, steps + 1):
            t = step / steps
            ring.append(
                tuple(
                    sum(
                        math.comb(degree, k) * (1 - t) ** (degree - k) * t**k * p[axis]
                        for k, p in enumerate((pos, *controls))
                    )
                    for axis in (0, 1)
                )
            )

    while i < len(tokens):
        if tokens[i].isalpha():
            command = tokens[i]
            i += 1
        if command not in "MLHVQCZ":
            sys.exit(f"title.py: unsupported path command {command!r}")
        if command in "MZ" and ring:
            if ring[-1] == ring[0]:
                ring.pop()
            rings.append(ring)
            ring, pos = [], start
        if command == "Z":
            continue
        if command == "M":
            pos = start = tuple(numbers(2))
            ring, command = [pos], "L"
            continue
        if not ring:
            ring = [pos]
        if command == "L":
            pos = tuple(numbers(2))
            ring.append(pos)
        elif command == "H":
            pos = (numbers(1)[0], pos[1])
            ring.append(pos)
        elif command == "V":
            pos = (pos[0], numbers(1)[0])
            ring.append(pos)
        else:
            values = numbers(4 if command == "Q" else 6)
            controls = list(zip(values[::2], values[1::2]))
            curve(*controls)
            pos = controls[-1]
    if ring:
        rings.append(ring)
    return rings


def winding(x: float, y: float, ring: list[tuple[float, float]]) -> int:
    turns = 0
    for (x0, y0), (x1, y1) in zip(ring, ring[1:] + ring[:1]):
        side = (x1 - x0) * (y - y0) - (x - x0) * (y1 - y0)
        if y0 <= y < y1 and side > 0:
            turns += 1
        elif y1 <= y < y0 and side < 0:
            turns -= 1
    return turns


def nonzero_mesh(name: str, d: str, stroke: float = 0.0, place=at):
    """Fill path data with svg's nonzero rule, glyph by glyph: a constrained
    triangulation of every outline, keeping the triangles that wind nonzero. A
    stroke adds a band of that width along each outline, with round joins."""
    rings = outlines(d)
    spans = [(min(x for x, _ in r), max(x for x, _ in r)) for r in rings]
    verts: list[Vector] = []
    faces: list[tuple[int, ...]] = []

    def polygon(corners) -> None:
        faces.append(tuple(range(len(verts), len(verts) + len(corners))))
        verts.extend(place(x, y) for x, y in corners)

    for keep in glyphs(spans):
        group = [rings[i] for i in sorted(keep)]
        co, edges = [], []
        for ring in group:
            base = len(co)
            co += [Vector(p) for p in ring]
            edges += [(base + k, base + (k + 1) % len(ring)) for k in range(len(ring))]
        out, _, tris, *_ = delaunay_2d_cdt(co, edges, [], 0, 1e-6)
        for tri in tris:
            cx = sum(out[v].x for v in tri) / len(tri)
            cy = sum(out[v].y for v in tri) / len(tri)
            if sum(winding(cx, cy, ring) for ring in group):
                polygon([tuple(out[v]) for v in tri])

    half = stroke / 2
    for ring in rings if stroke else []:
        for (x0, y0), (x1, y1) in zip(ring, ring[1:] + ring[:1]):
            length = math.hypot(x1 - x0, y1 - y0) or 1.0
            nx, ny = (y0 - y1) / length * half, (x1 - x0) / length * half
            polygon([(x0 + nx, y0 + ny), (x1 + nx, y1 + ny), (x1 - nx, y1 - ny)])
            polygon([(x0 + nx, y0 + ny), (x1 - nx, y1 - ny), (x0 - nx, y0 - ny)])
            angles = (math.tau * k / 8 for k in range(8))
            polygon(
                [(x0 + half * math.cos(a), y0 + half * math.sin(a)) for a in angles]
            )

    mesh = bpy.data.meshes.new(name)
    mesh.from_pydata(verts, [], faces)
    return link(bpy.data.objects.new(name, mesh))


def on_stamp(x: float, y: float) -> Vector:
    """A point of the stamp group: turned as its rotate() says, in world units
    relative to the stamp's pivot."""
    px, py = STAMP_PIVOT
    turn = math.radians(STAMP_TURN)
    dx, dy = x - px, y - py
    x = px + dx * math.cos(turn) - dy * math.sin(turn)
    y = py + dx * math.sin(turn) + dy * math.cos(turn)
    return at(x, y) - at(px, py)


def stamp_border(name: str) -> bpy.types.Curve:
    """The stamp's stroked square as a filled ring between its outer and inner
    rounded squares."""
    left, top, size, radius = STAMP_SQUARE
    half = STAMP_STROKE / 2
    data = bpy.data.curves.new(name, "CURVE")
    data.dimensions = "2D"
    data.fill_mode = "BOTH"
    for grow in (half, -half):
        x0, y0, side, r = left - grow, top - grow, size + 2 * grow, radius + grow
        corners = [
            (x0 + side - r, y0 + r, -90),
            (x0 + side - r, y0 + side - r, 0),
            (x0 + r, y0 + side - r, 90),
            (x0 + r, y0 + r, 180),
        ]
        ring = []
        for cx, cy, start in corners:
            for step in range(13):
                a = math.radians(start + 90 * step / 12)
                ring.append(on_stamp(cx + r * math.cos(a), cy + r * math.sin(a)))
        spline = data.splines.new("POLY")
        spline.points.add(len(ring) - 1)
        for point, co in zip(spline.points, ring):
            point.co = (co.x, co.y, 0.0, 1.0)
        spline.use_cyclic_u = True
    return data


def build_stamp(rune_data):
    """An empty at the stamp's pivot carrying its border and rune, so the whole seal
    scales about its own centre."""
    root = link(bpy.data.objects.new("stamp", None))
    root.location = at(*STAMP_PIVOT)
    mat = material("stamp", STAMP_INK)
    for part, data in (("border", stamp_border("stamp.border")), ("rune", rune_data)):
        child = link(bpy.data.objects.new(f"stamp.{part}", data))
        child.parent = root
        wear(child, mat)
    return root, mat


def build_scene() -> dict:
    bpy.ops.wm.read_factory_settings(use_empty=True)
    scene = bpy.context.scene
    by_fill = import_banner()

    def take(fill: str, count: int) -> list:
        found = by_fill.pop(fill, [])
        if len(found) != count:
            sys.exit(f"title.py: expected {count} {fill} path(s) in {SVG.name}")
        return sorted(found, key=lambda o: len(o.data.splines))

    # The importer brings the wordmark, the katakana and the runes in cleanly.
    # Rebuilt instead: the paper and its dot texture (one flat ground here), the
    # stroke-only stamp square (it imports unfilled), the rule (snapped, below),
    # and the tagline and stamp rune. Those two have overlapping, self-crossing
    # outlines (inter's "e" is one crossing contour) that svg fills by the nonzero
    # rule; blender's curve fill turns every crossing into a hole and drops whole
    # strokes, so they are filled from their path data with the nonzero rule.
    rule_curve, wordmark = take(INK, 2)
    stamp_rune, kana = take(VERMILION, 2)
    (runes,) = take(BLUE, 1)
    for obj in [*take(PAPER, 1), *take("none", 2), *take(LIBRARY_INK, 1)]:
        bpy.data.objects.remove(obj)
    for obj in (rule_curve, stamp_rune):
        bpy.data.objects.remove(obj)
    if by_fill:
        sys.exit(f"title.py: unexpected fills in {SVG.name}: {sorted(by_fill)}")

    rig: dict = {"mats": {}}
    ground = rectangle("paper", 4 * WIDTH, 4 * HEIGHT, material("paper", srgb(PAPER)))
    ground.location = (-2 * WIDTH, -2 * HEIGHT, -10)

    tagline = nonzero_mesh("tagline", path_data(LIBRARY_INK))

    for name, obj, colour in (
        ("wordmark", wordmark, INK),
        ("kana", kana, VERMILION),
        ("tagline", tagline, LIBRARY_INK),
    ):
        rig[name] = obj
        rig["mats"][name] = material(name, srgb(colour))
        wear(obj, rig["mats"][name])

    # the rule is 1 css px; at 1.1x it would straddle two pixel rows and blur, so
    # it is snapped to whole pixels
    x, y, w, h = RULE
    x0, x1 = round(LEFT + x * SCALE), round(LEFT + (x + w) * SCALE)
    y0, rows = round(TOP + y * SCALE), max(1, round(h * SCALE))
    rig["mats"]["rule"] = material("rule", srgb(INK))
    rule = rectangle("rule", x1 - x0, rows, rig["mats"]["rule"], anchor=(0, 1))
    rule.location = (x0 - WIDTH / 2, HEIGHT / 2 - y0, 0)
    rig["rule"] = rule

    # runes: one object each, and a paper-coloured mask over each that withdraws
    # downwards, so a rune is cut in from the top like a chiselled stave
    rig["mats"]["runes"] = material("runes", srgb(BLUE))
    paper_mask = material("mask", srgb(PAPER))
    rig["runes"], rig["masks"] = [], []
    for rune in split_glyphs(runes):
        wear(rune, rig["mats"]["runes"])
        x_lo, x_hi, y_lo, y_hi = bounds(rune)
        mask = rectangle("mask", x_hi - x_lo + 4, y_hi - y_lo + 4, paper_mask)
        mask.location = (x_lo - 2, y_lo - 2, 1)
        rig["runes"].append(rune)
        rig["masks"].append(mask)
    if len(rig["runes"]) != 7:
        sys.exit(f"title.py: expected 7 runes, found {len(rig['runes'])}")

    rune = nonzero_mesh(
        "stamp.rune",
        path_data(VERMILION, stroke=VERMILION),
        stroke=STAMP_RUNE_STROKE,
        place=on_stamp,
    )
    rune_data = rune.data
    bpy.data.objects.remove(rune)
    rig["stamp"], rig["mats"]["stamp"] = build_stamp(rune_data)

    setup_render(scene)
    return rig


def setup_render(scene) -> None:
    scene.render.engine = "BLENDER_WORKBENCH"
    shading = scene.display.shading
    shading.light = "FLAT"
    shading.color_type = "MATERIAL"
    shading.show_object_outline = False
    shading.show_cavity = False
    shading.show_shadows = False
    shading.show_specular_highlight = False
    # workbench's own aa smears a 1 px rule over three rows and dims light fills by
    # a step, so it is off; render() supersamples instead
    scene.display.render_aa = "OFF"

    world = bpy.data.worlds.new("paper")
    world.color = tuple(linear(c) for c in srgb(PAPER))
    scene.world = world

    camera = bpy.data.cameras.new("camera")
    camera.type = "ORTHO"
    camera.ortho_scale = WIDTH
    camera.clip_start, camera.clip_end = 1, 200
    scene.camera = link(bpy.data.objects.new("camera", camera))
    scene.camera.location = (0, 0, 100)

    render = scene.render
    render.resolution_x = WIDTH * SUPERSAMPLE
    render.resolution_y = HEIGHT * SUPERSAMPLE
    render.resolution_percentage = 100
    render.fps = FPS
    render.film_transparent = False
    render.use_motion_blur = False
    render.dither_intensity = 0.0  # dither is noise: keep flat fills flat
    render.use_compositing = False
    render.use_sequencer = False
    image = render.image_settings
    image.file_format = "PNG"
    image.color_mode = "RGB"
    image.color_depth = "8"
    image.compression = 0

    scene.display_settings.display_device = "sRGB"
    view = scene.view_settings
    view.view_transform = "Standard"  # AgX and Filmic would shift the palette
    view.look = "None"
    view.exposure = 0.0
    view.gamma = 1.0
    view.use_curve_mapping = False


def render(scene, path: Path, scratch: Path) -> None:
    """Render at SUPERSAMPLE x and box-filter it down in display space: flat fills
    keep their exact hex, edges get plain coverage aa, the rule stays one row."""
    scene.render.filepath = str(scratch)
    bpy.ops.render.render(write_still=True)
    big = bpy.data.images.load(str(scratch))
    pixels = np.empty(len(big.pixels), dtype=np.float32)
    big.pixels.foreach_get(pixels)
    bpy.data.images.remove(big)
    n = SUPERSAMPLE
    rgba = pixels.reshape(HEIGHT, n, WIDTH, n, 4).mean(axis=(1, 3))
    rgba = np.round(rgba * 255) / 255
    rgba[..., 3] = 1.0
    small = bpy.data.images.new(path.stem, WIDTH, HEIGHT, alpha=False)
    small.pixels.foreach_set(rgba.astype(np.float32).ravel())
    small.filepath_raw = str(path)
    small.file_format = "PNG"
    small.save()
    bpy.data.images.remove(small)


def show(obj, visible: bool) -> None:
    obj.hide_render = not visible
    for child in obj.children:
        child.hide_render = not visible


def pose_title(rig: dict, frame: int) -> None:
    """The print, beat by beat: rule, wordmark, runes, tagline, stamp, hold."""
    mats = rig["mats"]
    paper = srgb(PAPER)

    drawn = ease_in_out(ramp(frame, RULE_DRAW))
    show(rig["rule"], drawn > 0)
    rig["rule"].scale.x = max(drawn, 1e-4)

    for name, colour, delay in (("wordmark", INK, 0), ("kana", VERMILION, KANA_DELAY)):
        start, end = (f + delay for f in WORDMARK_SETTLE)
        settle = ease_out(ramp(frame, (start, end)))
        ink = ease_out(ramp(frame, (start, start + (end - start) * 0.7)))
        rig[name].location.y = SETTLE_DROP * (1 - settle)
        paint(mats[name], mix(paper, srgb(colour), ink))
        show(rig[name], ink > 0)

    for index, mask in enumerate(rig["masks"]):
        start = RUNES_START + index * RUNE_STAGGER
        carved = ease_in_out(ramp(frame, (start, start + RUNE_CARVE)))
        show(rig["runes"][index], carved > 0)
        show(mask, 0 < carved < 1)
        mask.scale.y = max(1 - carved, 1e-4)

    tagline = ease_in_out(ramp(frame, TAGLINE_IN))
    paint(mats["tagline"], mix(paper, srgb(LIBRARY_INK), tagline))
    show(rig["tagline"], tagline > 0)

    # the stamp comes down (larger and faint while it is above the paper), is
    # pressed in on the contact frame, and springs back to size as it lifts,
    # leaving the impression at the banner's full ink
    if frame < STAMP_DROP[1]:
        fall = ease_in(ramp(frame, STAMP_DROP))
        size = STAMP_HEIGHT - (STAMP_HEIGHT - 1) * fall
        ink = 0.2 + 0.5 * fall
    else:
        press = ease_out(ramp(frame, STAMP_PRESS))
        size, ink = STAMP_SQUASH + (1 - STAMP_SQUASH) * press, 1.0
    rig["stamp"].scale = (size, size, 1)
    paint(mats["stamp"], mix(paper, STAMP_INK, ink))
    show(rig["stamp"], frame >= STAMP_DROP[0])


def pose_outro(rig: dict, frame: int) -> None:
    """The finished card holds, then its ink goes back to paper for the loop."""
    pose_title(rig, TITLE_FRAMES - 1)
    fade = ease_in_out(ramp(frame, OUTRO_FADE))
    colours = {
        "wordmark": INK,
        "kana": VERMILION,
        "rule": INK,
        "runes": BLUE,
        "tagline": LIBRARY_INK,
    }
    for name, colour in colours.items():
        paint(rig["mats"][name], mix(srgb(colour), srgb(PAPER), fade))
    paint(rig["mats"]["stamp"], mix(STAMP_INK, srgb(PAPER), fade))


def main() -> None:
    argv = sys.argv[sys.argv.index("--") + 1 :] if "--" in sys.argv else []
    parser = argparse.ArgumentParser(
        prog="title.py", description=__doc__.split("\n")[0]
    )
    parser.add_argument("--part", choices=("title", "outro"), required=True)
    parser.add_argument("--out", type=Path, required=True, help="folder for the pngs")
    args = parser.parse_args(argv)

    rig = build_scene()
    scene = bpy.context.scene
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.glob("[0-9][0-9][0-9][0-9].png"):
        stale.unlink()
    frames, pose = (
        (TITLE_FRAMES, pose_title)
        if args.part == "title"
        else (OUTRO_FRAMES, pose_outro)
    )
    with tempfile.TemporaryDirectory() as tmp:
        for frame in range(frames):
            pose(rig, frame)
            render(scene, out / f"{frame + 1:04d}.png", Path(tmp) / "big.png")
    print(f"title.py: {frames} {args.part} frames in {out}")


if __name__ == "__main__":
    main()
