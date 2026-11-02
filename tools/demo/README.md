# demo gif tooling

how `assets/demo.gif` is made: a blender title, real terminal footage of a claude code session driving sony headphones through harald, and an outro. macos only, because the redaction pass uses apple's vision ocr.

## the scripts

- `title.py`: blender script that renders the title and outro cards from `assets/banner.svg` as 960×600 png frames at 24 fps.
- `assemble.py`: cuts the kept beats out of the obs recording, boxes every bluetooth classic address, scales to 960×600, joins title, terminal and outro, encodes a looping gif and verifies it. `--frames-only` dumps redacted frames named by timestamp, so you can pick beats.
- `redact.py`: the address detector that `assemble.py` uses. it runs the ocr, matches addresses and checks the ocr on a canary frame before each run.
- `ocr.swift`: a small vision cli (`VNRecognizeTextRequest`, language correction off). it is compiled with `/usr/bin/swiftc` into the work folder on first use.
- `selftest.py`: an end-to-end check on synthetic footage. run it by hand on a mac; ci is linux and has no vision.

needs ffmpeg, imagemagick (`magick`), xcode command line tools, uv and blender 5.

## regenerate

from the repo root:

```sh
# 1. title and outro frames
blender --background --python tools/demo/title.py -- --part title --out .superpowers/demo/title
blender --background --python tools/demo/title.py -- --part outro --out .superpowers/demo/outro

# 2. browse the recording as redacted, timestamped frames to choose beats
uv run tools/demo/assemble.py --frames-only --recording .superpowers/demo/rec/take.mov --fps 4
#    -> .superpowers/demo/work/frames/ (pngs, index.json, contact sheets)

# 3. build the gif (opens on settled title frame 34; frames 1-33 play after the outro)
uv run tools/demo/assemble.py --recording .superpowers/demo/rec/take.mov \
    --beats .superpowers/demo/work/beats.json \
    --title .superpowers/demo/title --outro .superpowers/demo/outro \
    --title-start 34 --box-color '#4a4640' --out assets/demo.gif

# check the tooling itself
uv run tools/demo/selftest.py
```

`beats.json` lists the kept parts of the recording in order. times are seconds or `m:ss.s`:

```json
{"fps": 12, "segments": [
  {"start": "0:04.0", "end": "0:11.5", "speed": 1},
  {"start": "0:11.5", "end": "0:40.0", "speed": 4},
  {"hold": "0:41.2", "seconds": 1.5}
]}
```

options: `"crop": [x, y, w, h]` in the beats file, `--box-color` (auto puts ink on light text and cream on dark; or a palette name, or `#rrggbb` such as the tagline tone `#4a4640`), `--title-start K` (open on title frame k so frame 1 is not blank paper; frames before k play after the outro, so the loop stays seamless), `--cut hard|cream`, and `--redact-text TEXT` to also box a literal such as a host name.

## privacy

no frame of the gif may show a bluetooth classic address. here is how that holds:

- every terminal frame is read at full resolution and again as the gif will show it (scaled down, then back up). each read makes three vision passes: accurate revisions 3 and 2, and fast. no single pass reads everything. revision 3 silently drops whole lines of json.
- these count as an address and are boxed:
  - six hex pairs with `: ; . -` or spaces between them;
  - any run of three or more such pairs, so a partial address is boxed too;
  - two pairs at either end of a line;
  - a line split across a wrap, once joined to its next line;
  - a token cut off by the frame edge.
- ocr misreads are allowed for: o/0, l/1, i/1, s/5, and cyrillic look-alikes.
- these never match: hex with no separators (harald's framed messages, `3e0c…3c`), uuids and plain numbers. they stay visible.
- each box is solid and opaque, in a banner palette colour. it is padded at least 4 px and fitted to the ink rows. blur and pixelation are never used, because both can be reversed.
- a box also carries over to neighbouring frames when the pixels where the address starts have not changed. that catches an address as it is typed or streamed.
- the boxed frames are read again, and anything still found is boxed, for up to three rounds.
- the finished gif is decoded and every frame is read at 2×. any address or 3+ pair fragment fails the run with a non-zero exit. results go to `.superpowers/demo/work/verify.json`, one row per frame. contact sheets of every gif frame go to `.superpowers/demo/work/sheets/` for a person to check by eye.
- before it trusts vision, every run reads a canary frame drawn with the example address in each context. vision keeps compiled models per executable. one bad compile once made it skip lines without any error, so if the canary fails, the tool deletes its own cache (`~/Library/Caches/harald-demo-ocr`), retries once, then stops.
- unredacted frames exist only in a temporary folder under the work directory. that folder is removed at the end of each run. nothing written to disk holds the text that ocr read: reports keep only masked text such as `**:**:**:**:**:**`.

the example address in code and tests is `aa:bb:cc:11:22:33`.
