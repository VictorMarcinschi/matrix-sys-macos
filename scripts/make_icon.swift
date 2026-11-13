// Draws the MatrixSys icon (glowing cyan wireframe octahedron on a dark rounded square with a faint grid) at every
// .iconset size; build.sh turns the set into MatrixSys.icns with iconutil. Same drawing as the Windows make_icon.py.
// Usage: swift make_icon.swift <output.iconset>
import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

func render(_ n: Int) -> CGImage {
    let N = Double(n)
    let yaw = 32.0 * .pi / 180, pitch = 24.0 * .pi / 180
    let verts: [(Double, Double, Double)] = [(1, 0, 0), (-1, 0, 0), (0, 1.25, 0), (0, -1.25, 0), (0, 0, 1), (0, 0, -1)]
    var pts: [(Double, Double, Double)] = []
    for (x0, y0, z0) in verts {
        let x = x0 * cos(yaw) + z0 * sin(yaw), z1 = -x0 * sin(yaw) + z0 * cos(yaw)
        let y = y0 * cos(pitch) - z1 * sin(pitch), z = y0 * sin(pitch) + z1 * cos(pitch)
        pts.append((N / 2 + x * N * 0.3, N / 2 - y * N * 0.3, z))
    }
    var segs: [(Double, Double, Double, Double, Double)] = []
    for a in 0..<6 { for b in (a + 1)..<6 where a / 2 != b / 2 { segs.append((pts[a].0, pts[a].1, pts[b].0, pts[b].1, 0.55 + 0.45 * ((pts[a].2 + pts[b].2) / 2 + 1) / 2)) } }
    let core = max(0.6, N / 110), glow = max(1.2, N / 22), rad = N * 0.2, grid = N / 8
    var px = [UInt8](repeating: 0, count: n * n * 4)
    for j in 0..<n { for i in 0..<n {
        let x = Double(i) + 0.5, y = Double(j) + 0.5
        let dx = max(abs(x - N / 2) - (N / 2 - rad), 0), dy = max(abs(y - N / 2) - (N / 2 - rad), 0)
        let a = min(1.0, max(0.0, rad - hypot(dx, dy) + 0.5)); if a <= 0 { continue }
        let edge = n >= 32 ? max(0.0, 1 - abs(rad - hypot(dx, dy) - N * 0.03) / max(1.0, N * 0.02)) : 0
        let t = y / N
        var r = 0.004 + 0.02 * t, g = 0.03 + 0.07 * t, b = 0.07 + 0.16 * t
        if n >= 48 { let gl = max(0.0, 1 - min(x.truncatingRemainder(dividingBy: grid), grid - x.truncatingRemainder(dividingBy: grid), y.truncatingRemainder(dividingBy: grid), grid - y.truncatingRemainder(dividingBy: grid)) / max(0.7, N / 256)); r += 0.02 * gl; g += 0.10 * gl; b += 0.16 * gl }
        r += 0.10 * edge; g += 0.45 * edge; b += 0.55 * edge
        for (x1, y1, x2, y2, w) in segs {
            let vx = x2 - x1, vy = y2 - y1
            let u = max(0.0, min(1.0, ((x - x1) * vx + (y - y1) * vy) / (vx * vx + vy * vy)))
            let d = hypot(x - x1 - u * vx, y - y1 - u * vy)
            let k = w * (max(0.0, min(1.0, core - d + 0.5)) + 0.55 * exp(-pow(d / glow, 2)))
            r += 0.31 * k; g += 0.89 * k; b += 1.0 * k
        }
        for (idx, p) in pts.enumerated() {   // vertices: one magenta "packet", the rest white-cyan
            let k = exp(-pow(hypot(x - p.0, y - p.1) / max(1.0, N / 34), 2)) * 1.3
            if idx == 2 { r += 1.0 * k; g += 0.31 * k; b += 0.85 * k } else { r += 0.8 * k; g += 0.95 * k; b += 1.0 * k }
        }
        let o = (j * n + i) * 4   // premultiplied RGBA
        px[o] = UInt8(min(1, r) * a * 255); px[o + 1] = UInt8(min(1, g) * a * 255); px[o + 2] = UInt8(min(1, b) * a * 255); px[o + 3] = UInt8(a * 255)
    } }
    let ctx = CGContext(data: &px, width: n, height: n, bitsPerComponent: 8, bytesPerRow: n * 4, space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    return ctx.makeImage()!
}
let out = CommandLine.arguments[1]
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)
for (n, name) in [(16, "16x16"), (32, "16x16@2x"), (32, "32x32"), (64, "32x32@2x"), (128, "128x128"), (256, "128x128@2x"), (256, "256x256"), (512, "256x256@2x"), (512, "512x512"), (1024, "512x512@2x")] {
    let img = render(n)
    let dst = CGImageDestinationCreateWithURL(URL(fileURLWithPath: out + "/icon_\(name).png") as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dst, img, nil); CGImageDestinationFinalize(dst)
}
print("iconset written")
