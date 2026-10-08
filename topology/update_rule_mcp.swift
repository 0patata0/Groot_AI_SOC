// Rebuild the three MCP overlay images from the original PNGs in this folder.
// Run: swift topology/update_rule_mcp.swift
// The source pixels and canvas size stay unchanged outside the added labels.

import AppKit
import Foundation

private let folder = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

private struct RGB {
    let r: CGFloat
    let g: CGFloat
    let b: CGFloat
    var color: NSColor { NSColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: 1) }
}

private let amberFill = RGB(r: 255, g: 242, b: 219)
private let amberStroke = RGB(r: 199, g: 135, b: 46)
private let amberText = RGB(r: 104, g: 62, b: 17)
private let greenText = RGB(r: 58, g: 110, b: 22)
private let hermesFill = RGB(r: 237, g: 236, b: 254)
private let hermesText = RGB(r: 57, g: 47, b: 148)

private final class Canvas {
    let width: CGFloat
    let height: CGFloat
    private let bitmap: NSBitmapImageRep
    private let graphics: NSGraphicsContext

    init(_ filename: String) throws {
        let data = try Data(contentsOf: folder.appendingPathComponent(filename))
        guard let bitmap = NSBitmapImageRep(data: data),
              let graphics = NSGraphicsContext(bitmapImageRep: bitmap) else {
            throw NSError(domain: "topology", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot decode \(filename)"])
        }
        self.bitmap = bitmap
        self.graphics = graphics
        width = CGFloat(bitmap.pixelsWide)
        height = CGFloat(bitmap.pixelsHigh)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = graphics
        graphics.imageInterpolation = .none
    }

    deinit { NSGraphicsContext.restoreGraphicsState() }

    private func rect(_ x: CGFloat, _ top: CGFloat, _ w: CGFloat, _ h: CGFloat) -> NSRect {
        NSRect(x: x, y: height - top - h, width: w, height: h)
    }

    func panel(_ x: CGFloat, _ top: CGFloat, _ w: CGFloat, _ h: CGFloat,
               fill: RGB = amberFill, stroke: RGB = amberStroke,
               radius: CGFloat = 7, line: CGFloat = 1.5) {
        let path = NSBezierPath(roundedRect: rect(x, top, w, h), xRadius: radius, yRadius: radius)
        fill.color.setFill()
        path.fill()
        stroke.color.setStroke()
        path.lineWidth = line
        path.stroke()
    }

    func clear(_ x: CGFloat, _ top: CGFloat, _ w: CGFloat, _ h: CGFloat, fill: RGB) {
        fill.color.setFill()
        NSBezierPath(rect: rect(x, top, w, h)).fill()
    }

    func text(_ value: String, _ x: CGFloat, _ top: CGFloat, _ w: CGFloat,
              size: CGFloat, color: RGB, bold: Bool = false, centered: Bool = true) {
        let fontName = bold ? "AppleSDGothicNeo-Bold" : "AppleSDGothicNeo-Regular"
        let font = NSFont(name: fontName, size: size)
            ?? (bold ? NSFont.boldSystemFont(ofSize: size) : NSFont.systemFont(ofSize: size))
        let value = NSAttributedString(string: value, attributes: [
            .font: font,
            .foregroundColor: color.color
        ])
        let measured = value.size()
        value.draw(at: NSPoint(x: centered ? x + (w - measured.width) / 2 : x,
                               y: height - top - measured.height))
    }

    func write(_ filename: String) throws {
        graphics.flushGraphics()
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw NSError(domain: "topology", code: 2, userInfo: [NSLocalizedDescriptionKey: "Cannot encode \(filename)"])
        }
        try png.write(to: folder.appendingPathComponent(filename), options: .atomic)
    }
}

// 2090 × 1586 architecture preview. Keep the existing block-IP response path intact.
do {
    let c = try Canvas("groot_soc_network_architecture_preview.png")
    c.panel(430, 489, 289, 22, radius: 5, line: 1.2)
    c.text("rule-a MCP · WAF/Suricata · SSH", 434, 491, 281, size: 12, color: amberText, bold: true)

    c.panel(835, 975, 348, 33, radius: 5, line: 1.2)
    c.text("rule-b MCP · Wazuh 로컬 룰 · SSH", 840, 982, 338, size: 13.5, color: amberText, bold: true)

    c.text("룰 변경 HMAC 승인", 840, 940, 338, size: 13, color: greenText)

    c.clear(764, 1097, 317, 25, fill: hermesFill)
    c.text("MCP 5서버 · 조회/차단/승인형 룰 변경", 695, 1099, 455,
           size: 15, color: hermesText)
    try c.write("groot_soc_network_architecture_rule_mcp.png")
}

// 2834 × 790 logical bus preview. Preserve the original Attack Segment line
// and remove only its outdated subnet caption; the Kali subnet is unverified.
do {
    let c = try Canvas("groot_soc_topology_bus_preview.png")
    c.panel(443, 206, 298, 44, radius: 3, line: 1.3)
    c.text("rule-a MCP", 447, 210, 290, size: 17, color: amberText, bold: true)
    c.text("WAF · Suricata 로컬 룰", 447, 230, 290, size: 13, color: amberText)

    c.panel(1040, 206, 319, 44, radius: 3, line: 1.3)
    c.text("rule-b MCP", 1044, 210, 311, size: 17, color: amberText, bold: true)
    c.text("Wazuh 로컬 룰", 1044, 230, 311, size: 13, color: amberText)

    c.clear(837, 359, 181, 25, fill: RGB(r: 255, g: 255, b: 255))
    c.text("soc-bot · HMAC 승인", 835, 362, 187, size: 13, color: RGB(r: 30, g: 30, b: 30))

    let white = RGB(r: 255, g: 255, b: 255)
    let black = RGB(r: 30, g: 30, b: 30)
    c.clear(438, 565, 174, 24, fill: white)
    c.text("10.200.10.0/24", 442, 567, 170, size: 14, color: black, bold: true, centered: false)

    c.clear(438, 635, 166, 24, fill: white)
    try c.write("groot_soc_topology_bus_rule_mcp.png")
}

// 4560 × 1920 presentation slide. Add the two separate MCPs in unused space.
do {
    let c = try Canvas("groot_soc_topology_slide.png")
    c.panel(840, 629, 685, 54, radius: 11, line: 3)
    c.text("rule-a MCP", 848, 631, 669, size: 29, color: amberText, bold: true)
    c.text("WAF · Suricata 로컬 룰 · SSH rulechg", 848, 659, 669,
           size: 20, color: amberText)

    c.panel(2045, 1410, 656, 81, radius: 11, line: 3)
    c.text("rule-b MCP", 2055, 1418, 636, size: 31, color: amberText, bold: true)
    c.text("Wazuh 로컬 룰 · SSH rulechg", 2055, 1455, 636,
           size: 22, color: amberText)

    c.text("룰 변경 HMAC 승인", 2065, 1348, 615, size: 26, color: greenText)

    c.clear(1520, 1605, 1420, 69, fill: hermesFill)
    c.text("5분마다 새 경보 조사 · MCP 5서버 (조회/차단/승인형 룰 변경)",
           1210, 1617, 1610, size: 39, color: hermesText)
    try c.write("groot_soc_topology_slide_rule_mcp.png")
}
