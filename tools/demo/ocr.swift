// ocr: read text from png frames with macOS Vision, for the demo redaction pass.
//
// usage: ocr [--jobs N] [--passes accurate3,accurate2,fast3] image.png ...
//        (with no image arguments, it reads one path per line from stdin)
//
// Prints one JSON object per image, in input order, one per line:
//   {"image": path, "width": W, "height": H, "lines": [
//     {"pass": "accurate3", "text": "...", "confidence": 0.9, "box": [x0, y0, x1, y1],
//      "chars": [{"c": "a", "box": [x0, y0, x1, y1]}, ...]}]}
// Boxes are pixels with a top-left origin. A char box comes from
// VNRecognizedText.boundingBox(for:) on that one character's range; at the
// accurate level Vision answers with the box of the word holding the character,
// so the caller interpolates inside the word (the text is monospace).
//
// Every pass is VNRecognizeTextRequest with language correction off (hex and
// addresses are not words) and en-US. No single revision reads everything:
// revision 3 at the accurate level silently drops whole lines that are dense
// with JSON punctuation, revision 2 reads them, and the fast level splits them
// into words. The caller unions all passes.
//
// Build: /usr/bin/swiftc -O tools/demo/ocr.swift -o ocr

import CoreGraphics
import Foundation
import ImageIO
import Vision

struct CharBox: Encodable {
    let c: String
    let box: [Double]?
}

struct Line: Encodable {
    let pass: String
    let text: String
    let confidence: Double
    let box: [Double]
    let chars: [CharBox]
}

struct Page: Encodable {
    let image: String
    let width: Int
    let height: Int
    let lines: [Line]
    let error: String?
}

struct Pass {
    let name: String
    let level: VNRequestTextRecognitionLevel
    let revision: Int
}

func parsePass(_ name: String) -> Pass? {
    let levels: [String: VNRequestTextRecognitionLevel] = ["accurate": .accurate, "fast": .fast]
    guard let digit = name.last, let revision = Int(String(digit)),
        let level = levels[String(name.dropLast())],
        VNRecognizeTextRequest.supportedRevisions.contains(revision)
    else { return nil }
    return Pass(name: name, level: level, revision: revision)
}

func pixelBox(_ r: CGRect, _ w: Double, _ h: Double) -> [Double] {
    let x0 = Double(r.minX) * w
    let x1 = Double(r.maxX) * w
    let y0 = (1.0 - Double(r.maxY)) * h
    let y1 = (1.0 - Double(r.minY)) * h
    return [x0, y0, x1, y1].map { ($0 * 10).rounded() / 10 }
}

func recognise(_ path: String, _ passes: [Pass]) -> Page {
    let url = URL(fileURLWithPath: path)
    guard let src = CGImageSourceCreateWithURL(url as CFURL, nil),
        let image = CGImageSourceCreateImageAtIndex(src, 0, nil)
    else {
        return Page(image: path, width: 0, height: 0, lines: [], error: "cannot read image")
    }
    let w = Double(image.width)
    let h = Double(image.height)
    let requests = passes.map { pass -> VNRecognizeTextRequest in
        let request = VNRecognizeTextRequest()
        request.revision = pass.revision
        request.recognitionLevel = pass.level
        request.usesLanguageCorrection = false
        request.recognitionLanguages = ["en-US"]
        return request
    }
    let handler = VNImageRequestHandler(cgImage: image, options: [:])
    do {
        try handler.perform(requests)
    } catch {
        return Page(
            image: path, width: image.width, height: image.height, lines: [],
            error: "\(error)")
    }
    var lines: [Line] = []
    for (pass, request) in zip(passes, requests) {
        for obs in request.results ?? [] {
            guard let top = obs.topCandidates(1).first else { continue }
            let text = top.string
            var chars: [CharBox] = []
            var i = text.startIndex
            while i < text.endIndex {
                let next = text.index(after: i)
                var box: [Double]? = nil
                if let rect = (try? top.boundingBox(for: i..<next))??.boundingBox,
                    rect.width > 0, rect.height > 0
                {
                    box = pixelBox(rect, w, h)
                }
                chars.append(CharBox(c: String(text[i..<next]), box: box))
                i = next
            }
            lines.append(
                Line(
                    pass: pass.name, text: text, confidence: Double(top.confidence),
                    box: pixelBox(obs.boundingBox, w, h), chars: chars))
        }
    }
    return Page(image: path, width: image.width, height: image.height, lines: lines, error: nil)
}

var jobs = max(1, ProcessInfo.processInfo.activeProcessorCount / 2)
var passNames = "accurate3,accurate2,fast3"
var paths: [String] = []
var args = Array(CommandLine.arguments.dropFirst())
while !args.isEmpty {
    let a = args.removeFirst()
    if a == "--jobs", let n = args.first.flatMap({ Int($0) }) {
        jobs = max(1, n)
        args.removeFirst()
    } else if a == "--passes", let p = args.first {
        passNames = p
        args.removeFirst()
    } else {
        paths.append(a)
    }
}
let passes = passNames.split(separator: ",").compactMap { parsePass(String($0)) }
if passes.isEmpty || passes.count != passNames.split(separator: ",").count {
    FileHandle.standardError.write("ocr: bad --passes \(passNames)\n".data(using: .utf8)!)
    exit(2)
}
if paths.isEmpty {
    while let line = readLine() {
        let p = line.trimmingCharacters(in: .whitespaces)
        if !p.isEmpty { paths.append(p) }
    }
}

let encoder = JSONEncoder()
encoder.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
var results = [Page?](repeating: nil, count: paths.count)
let lock = NSLock()
let queue = OperationQueue()
queue.maxConcurrentOperationCount = jobs
var printed = 0
var failed = false
for (index, path) in paths.enumerated() {
    queue.addOperation {
        let page = autoreleasepool { recognise(path, passes) }
        lock.lock()
        defer { lock.unlock() }
        results[index] = page
        // stream pages out in input order as soon as the next one is ready
        while printed < results.count, let ready = results[printed] {
            guard let data = try? encoder.encode(ready), let s = String(data: data, encoding: .utf8)
            else {
                FileHandle.standardError.write("ocr: cannot encode \(ready.image)\n".data(using: .utf8)!)
                failed = true
                results[printed] = nil
                printed += 1
                continue
            }
            print(s)
            fflush(stdout)
            results[printed] = nil
            printed += 1
        }
    }
}
queue.waitUntilAllOperationsAreFinished()
exit(failed ? 1 : 0)
