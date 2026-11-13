// Renderer: one dynamic vertex buffer refilled every frame (3D lines, 3D triangles, glowing dot quads, then the 2D overlay),
// one shader source with a 3D (additive, fogged) and a 2D (alpha-blended, glyph atlas) entry point. MSAA x4.
import AppKit
import Metal
import MetalKit
import simd

struct Col { var r: Float, g: Float, b: Float }
func hex(_ h: UInt32) -> Col { Col(r: Float((h >> 16) & 255) / 255, g: Float((h >> 8) & 255) / 255, b: Float(h & 255) / 255) }
func mix(_ a: Col, _ b: Col, _ k: Float) -> Col { Col(r: a.r + (b.r - a.r) * k, g: a.g + (b.g - a.g) * k, b: a.b + (b.b - a.b) * k) }

let C_CYAN = hex(0x4fe3ff), C_BLUE = hex(0x2a7fff), C_OUT = hex(0xff4fd8), C_IN = hex(0x5ff2ff), C_WARN = hex(0xffb347),
    C_UDP = hex(0x8f7bff), C_SAFE = hex(0x3dffc8), C_WHITE = hex(0xe8fbff), C_DEEP = hex(0x0d3a66), C_RED = hex(0xff4b5c)

// UI palette, same order as the Windows build
enum T: Int { case text = 0, cyan, dim, inn, out, warn, white, safe, red }
let UI_HEX: [UInt32] = [0xbfefff, 0x4fe3ff, 0x5d8aa8, 0x5ff2ff, 0xff4fd8, 0xffb347, 0xffffff, 0x3dffc8, 0xff4b5c]
struct RGBA { var r: Float, g: Float, b: Float, a: Float }
func rgba(_ h: UInt32, _ a: Float = 1) -> RGBA { let c = hex(h); return RGBA(r: c.r, g: c.g, b: c.b, a: a) }
func uiCol(_ t: T, _ a: Float = 1) -> RGBA { rgba(UI_HEX[t.rawValue], a) }

struct Vtx { var x, y, z, r, g, b, u, v: Float }

private let SHADER = """
#include <metal_stdlib>
using namespace metal;
struct V { packed_float3 p; packed_float3 c; packed_float2 uv; };
struct U { float4x4 vp; float4 fog; };
struct O { float4 pos [[position]]; float3 c; float3 uvd; };
vertex O vs3(uint id [[vertex_id]], const device V* v [[buffer(0)]], constant U& u [[buffer(1)]]) {
    O o; V x = v[id]; o.pos = u.vp * float4(float3(x.p), 1); o.c = float3(x.c); o.uvd = float3(float2(x.uv), o.pos.w); return o; }
fragment float4 fs3(O i [[stage_in]], constant U& u [[buffer(1)]]) {
    float f = exp(-pow(i.uvd.z * u.fog.x, 2.0)); float3 c = i.c * f;
    if (i.uvd.x < 5) { float d = length(i.uvd.xy); if (d > 1) discard_fragment(); float a = pow(1 - d, 1.6); c *= a * (0.6 + a * 1.6); }
    return float4(c, 1); }
struct V2 { packed_float2 p; packed_float4 c; packed_float2 uv; };
struct O2 { float4 pos [[position]]; float4 c; float2 uv; };
vertex O2 vs2(uint id [[vertex_id]], const device V2* v [[buffer(0)]], constant U& u [[buffer(1)]]) {
    O2 o; V2 x = v[id]; o.pos = u.vp * float4(float2(x.p), 0, 1); o.c = float4(x.c); o.uv = float2(x.uv); return o; }
fragment float4 fs2(O2 i [[stage_in]], texture2d<float> t [[texture(0)]]) {
    constexpr sampler s(filter::linear, address::clamp_to_edge);
    float a = i.uv.x < 0 ? 1.0 : t.sample(s, i.uv).r;
    return float4(i.c.rgb, i.c.a * a); }
"""

/// Monospaced glyph atlas built with CoreText at the backing scale: a regular and a bold face.
final class Atlas {
    var tex: MTLTexture!
    var cw: Float = 6.9, ch: Float = 15, bcw: Float = 8, bch: Float = 18
    var cellW = 0, cellH = 0, bCellW = 0, bCellH = 0, scale: CGFloat = 2
    var index: [UInt32: Int] = [:]
    var uv: [SIMD4<Float>] = []          // per glyph & face: u0 v0 u1 v1  (regular at i, bold at count + i)
    var glyphs: [UInt32] = []
    var ascent: CGFloat = 0, bAscent: CGFloat = 0

    init(device: MTLDevice, scale: CGFloat) {
        self.scale = scale
        var cps: [UInt32] = Array(32...126)
        for s in "▼▲●○…·→←↑↓›≈—–×✓░▒■□◆◇│─┃━⏸▶" { cps.append(s.unicodeScalars.first!.value) }
        glyphs = cps
        for (i, c) in cps.enumerated() { index[c] = i }
        let reg = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        let bold = NSFont.monospacedSystemFont(ofSize: 14, weight: .bold)
        func adv(_ f: NSFont) -> CGFloat { ("0" as NSString).size(withAttributes: [.font: f]).width }
        cw = Float(adv(reg)); bcw = Float(adv(bold))
        ch = 15; bch = 18
        cellW = Int(ceil(adv(reg) * scale)) + 2; cellH = Int(ceil(15 * scale))
        bCellW = Int(ceil(adv(bold) * scale)) + 2; bCellH = Int(ceil(18 * scale))
        let perRow = 32
        let rows = (cps.count + perRow - 1) / perRow
        let W = perRow * max(cellW, bCellW) + 4
        let H = rows * (cellH + bCellH) + 8
        var px = [UInt8](repeating: 0, count: W * H)
        let cs = CGColorSpaceCreateDeviceGray()
        px.withUnsafeMutableBytes { raw in
            let ctx = CGContext(data: raw.baseAddress, width: W, height: H, bitsPerComponent: 8, bytesPerRow: W, space: cs, bitmapInfo: CGImageAlphaInfo.none.rawValue)!
            ctx.setFillColor(gray: 1, alpha: 1); ctx.fill(CGRect(x: 0, y: H - 4, width: 4, height: 4))   // solid texel block at the top-left
            ctx.setShouldAntialias(true); ctx.setShouldSmoothFonts(false)
            let gctx = NSGraphicsContext(cgContext: ctx, flipped: false)
            NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = gctx
            uv = [SIMD4<Float>](repeating: .zero, count: cps.count * 2)
            for face in 0..<2 {
                let f = face == 0 ? reg : bold, cwp = face == 0 ? cellW : bCellW, chp = face == 0 ? cellH : bCellH
                let lineH = CGFloat(face == 0 ? 15 : 18)
                let asc = (lineH - (f.ascender - f.descender)) / 2 + f.ascender
                if face == 0 { ascent = asc } else { bAscent = asc }
                for (i, c) in cps.enumerated() {
                    let col = i % perRow, row = i / perRow
                    let x0 = 4 + col * max(cellW, bCellW)
                    let y0 = 4 + (face == 0 ? row * cellH : rows * cellH + row * bCellH)   // top-left in image rows
                    let s = String(Character(UnicodeScalar(c)!))
                    let attr = NSAttributedString(string: s, attributes: [.font: f, NSAttributedString.Key(kCTForegroundColorFromContextAttributeName as String): true])
                    let line = CTLineCreateWithAttributedString(attr)
                    // CG origin is bottom-left; image row y0 is at CG y = H - y0; CTLineDraw draws on the baseline
                    let baseY = CGFloat(H - y0) - asc * scale
                    ctx.saveGState(); ctx.translateBy(x: CGFloat(x0) + 1, y: baseY); ctx.scaleBy(x: scale, y: scale)
                    ctx.setFillColor(gray: 1, alpha: 1); ctx.textPosition = .zero
                    CTLineDraw(line, ctx)
                    ctx.restoreGState()
                    uv[face * cps.count + i] = SIMD4(Float(x0) / Float(W), Float(y0) / Float(H), Float(x0 + cwp) / Float(W), Float(y0 + chp) / Float(H))
                }
            }
            NSGraphicsContext.restoreGraphicsState()
        }
        let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .r8Unorm, width: W, height: H, mipmapped: false)
        tex = device.makeTexture(descriptor: td)
        tex.replace(region: MTLRegionMake2D(0, 0, W, H), mipmapLevel: 0, withBytes: px, bytesPerRow: W)
        solidUV = SIMD2(2 / Float(W), 2 / Float(H))
    }
    var solidUV = SIMD2<Float>(0, 0)
    func glyph(_ c: UInt32, bold: Bool) -> SIMD4<Float> {
        let i = index[c] ?? index[63]!
        return uv[(bold ? glyphs.count : 0) + i]
    }
}

final class Gfx {
    let device: MTLDevice, queue: MTLCommandQueue
    var p3: MTLRenderPipelineState!, p2: MTLRenderPipelineState!
    var buffers: [MTLBuffer] = []; var bufIdx = 0
    let inflight = DispatchSemaphore(value: 3)
    var atlas: Atlas!
    var VL: [Vtx] = [], VT: [Vtx] = [], VQ: [Vtx] = [], UI: [Vtx] = []
    var LW: Float = 1280, LH: Float = 800, scale: Float = 2
    var clip: (Float, Float, Float, Float)? = nil   // x0 y0 x1 y1 for 2D
    var pendingShot: String? = nil
    var shotDone: ((String, Bool) -> Void)? = nil

    init?(view: MTKView) {
        guard let d = MTLCreateSystemDefaultDevice(), let q = d.makeCommandQueue() else { return nil }
        device = d; queue = q
        view.device = d; view.colorPixelFormat = .bgra8Unorm; view.sampleCount = 4
        view.clearColor = MTLClearColor(red: 1 / 255, green: 6 / 255, blue: 15 / 255, alpha: 1)
        view.framebufferOnly = false
        do {
            let lib = try d.makeLibrary(source: SHADER, options: nil)
            let pd = MTLRenderPipelineDescriptor()
            pd.vertexFunction = lib.makeFunction(name: "vs3"); pd.fragmentFunction = lib.makeFunction(name: "fs3")
            pd.colorAttachments[0].pixelFormat = .bgra8Unorm; pd.rasterSampleCount = 4
            let ca = pd.colorAttachments[0]!
            ca.isBlendingEnabled = true; ca.rgbBlendOperation = .add; ca.alphaBlendOperation = .add
            ca.sourceRGBBlendFactor = .one; ca.destinationRGBBlendFactor = .one; ca.sourceAlphaBlendFactor = .one; ca.destinationAlphaBlendFactor = .one
            p3 = try d.makeRenderPipelineState(descriptor: pd)
            pd.vertexFunction = lib.makeFunction(name: "vs2"); pd.fragmentFunction = lib.makeFunction(name: "fs2")
            ca.sourceRGBBlendFactor = .sourceAlpha; ca.destinationRGBBlendFactor = .oneMinusSourceAlpha
            ca.sourceAlphaBlendFactor = .one; ca.destinationAlphaBlendFactor = .oneMinusSourceAlpha
            p2 = try d.makeRenderPipelineState(descriptor: pd)
        } catch { NSLog("MatrixSys shader error: \(error)"); return nil }
        for _ in 0..<3 { buffers.append(d.makeBuffer(length: 1 << 22, options: .storageModeShared)!) }
        scale = Float(view.window?.backingScaleFactor ?? NSScreen.main?.backingScaleFactor ?? 2)
        atlas = Atlas(device: d, scale: CGFloat(scale))
    }
    func rebuildAtlas(scale s: Float) { if s != scale { scale = s; atlas = Atlas(device: device, scale: CGFloat(s)) } }

    // ---- 3D primitives
    @inline(__always) func line(_ a: SIMD3<Float>, _ b: SIMD3<Float>, _ c: Col, _ f: Float) {
        VL.append(Vtx(x: a.x, y: a.y, z: a.z, r: c.r * f, g: c.g * f, b: c.b * f, u: 9, v: 9))
        VL.append(Vtx(x: b.x, y: b.y, z: b.z, r: c.r * f, g: c.g * f, b: c.b * f, u: 9, v: 9))
    }
    @inline(__always) func tri(_ p: SIMD3<Float>, _ c: Col, _ f: Float) { VT.append(Vtx(x: p.x, y: p.y, z: p.z, r: c.r * f, g: c.g * f, b: c.b * f, u: 9, v: 9)) }

    // ---- 2D primitives (points, top-left origin)
    @inline(__always) private func q2(_ x0: Float, _ y0: Float, _ x1: Float, _ y1: Float, _ c: RGBA, _ uv: SIMD4<Float>?) {
        var x0 = x0, y0 = y0, x1 = x1, y1 = y1
        var u0: Float = -1, v0: Float = -1, u1: Float = -1, v1: Float = -1
        if let t = uv { u0 = t.x; v0 = t.y; u1 = t.z; v1 = t.w }
        if let cl = clip {
            if uv != nil { if y0 < cl.1 - 0.5 || y1 > cl.3 + 0.5 || x1 < cl.0 || x0 > cl.2 { return } }
            else { x0 = max(x0, cl.0); y0 = max(y0, cl.1); x1 = min(x1, cl.2); y1 = min(y1, cl.3); if x1 <= x0 || y1 <= y0 { return } }
        }
        let a = Vtx(x: x0, y: y0, z: c.r, r: c.g, g: c.b, b: c.a, u: u0, v: v0)
        let b = Vtx(x: x1, y: y0, z: c.r, r: c.g, g: c.b, b: c.a, u: u1, v: v0)
        let cc = Vtx(x: x1, y: y1, z: c.r, r: c.g, g: c.b, b: c.a, u: u1, v: v1)
        let d = Vtx(x: x0, y: y1, z: c.r, r: c.g, g: c.b, b: c.a, u: u0, v: v1)
        UI.append(a); UI.append(b); UI.append(cc); UI.append(a); UI.append(cc); UI.append(d)
    }
    func fill(_ x: Float, _ y: Float, _ w: Float, _ h: Float, _ c: RGBA) { q2(x, y, x + w, y + h, c, nil) }
    func stroke(_ x: Float, _ y: Float, _ w: Float, _ h: Float, _ c: RGBA) {
        fill(x, y, w, 1, c); fill(x, y + h - 1, w, 1, c); fill(x, y + 1, 1, h - 2, c); fill(x + w - 1, y + 1, 1, h - 2, c)
    }
    var CW: Float { atlas.cw }
    var BCW: Float { atlas.bcw }
    func text(_ x: Float, _ y: Float, _ s: String, _ c: RGBA, bold: Bool = false) {
        let w = bold ? atlas.bcw : atlas.cw, h = bold ? atlas.bch : atlas.ch
        let cellW = Float(bold ? atlas.bCellW : atlas.cellW) / scale, cellH = Float(bold ? atlas.bCellH : atlas.cellH) / scale
        // snap to device pixels so glyphs stay crisp
        var cx = (x * scale).rounded() / scale - 1 / scale; let cy = ((y - 1) * scale).rounded() / scale
        if let cl = clip, cy + h < cl.1 || cy > cl.3 { return }
        for u in s.unicodeScalars {
            if u.value != 32 { q2(cx, cy, cx + cellW, cy + cellH, c, atlas.glyph(u.value, bold: bold)) }
            cx += w
            if cx > LW + 10 { break }
        }
    }
    func text(_ x: Float, _ y: Float, _ s: String, _ t: T, _ a: Float = 1) { text(x, y, s, uiCol(t, a)) }

    // ---- frame
    func draw(view: MTKView, vp: simd_float4x4, fog: Float) {
        guard let rpd = view.currentRenderPassDescriptor, let drawable = view.currentDrawable else { return }
        inflight.wait()
        let n3 = VL.count + VT.count + VQ.count, total = n3 + UI.count
        let need = total * MemoryLayout<Vtx>.stride
        bufIdx = (bufIdx + 1) % 3
        if buffers[bufIdx].length < need { buffers[bufIdx] = device.makeBuffer(length: need * 2, options: .storageModeShared)! }
        let buf = buffers[bufIdx]
        var off = 0
        for arr in [VL, VT, VQ, UI] {
            arr.withUnsafeBytes { raw in if raw.count > 0 { memcpy(buf.contents() + off, raw.baseAddress!, raw.count) } }
            off += arr.count * MemoryLayout<Vtx>.stride
        }
        guard let cb = queue.makeCommandBuffer(), let enc = cb.makeRenderCommandEncoder(descriptor: rpd) else { inflight.signal(); return }
        struct U { var vp: simd_float4x4; var fog: SIMD4<Float> }
        var u3 = U(vp: vp, fog: SIMD4(fog, 0, 0, 0))
        enc.setRenderPipelineState(p3)
        enc.setVertexBuffer(buf, offset: 0, index: 0)
        enc.setVertexBytes(&u3, length: MemoryLayout<U>.stride, index: 1)
        enc.setFragmentBytes(&u3, length: MemoryLayout<U>.stride, index: 1)
        if VL.count > 0 { enc.drawPrimitives(type: .line, vertexStart: 0, vertexCount: VL.count) }
        if VT.count + VQ.count > 0 { enc.drawPrimitives(type: .triangle, vertexStart: VL.count, vertexCount: VT.count + VQ.count) }
        if UI.count > 0 {
            // ortho in points, top-left origin
            let o = simd_float4x4(rows: [SIMD4(2 / LW, 0, 0, -1), SIMD4(0, -2 / LH, 0, 1), SIMD4(0, 0, 1, 0), SIMD4(0, 0, 0, 1)])
            var u2 = U(vp: o, fog: .zero)
            enc.setRenderPipelineState(p2)
            enc.setVertexBytes(&u2, length: MemoryLayout<U>.stride, index: 1)
            enc.setFragmentTexture(atlas.tex, index: 0)
            enc.drawPrimitives(type: .triangle, vertexStart: n3, vertexCount: UI.count)
        }
        enc.endEncoding()
        var shotTex: MTLTexture? = nil
        let shotPath = pendingShot; pendingShot = nil
        if shotPath != nil {
            let dt = drawable.texture
            let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: dt.pixelFormat, width: dt.width, height: dt.height, mipmapped: false)
            td.storageMode = .shared; td.usage = [.shaderRead]
            if let t = device.makeTexture(descriptor: td), let bl = cb.makeBlitCommandEncoder() {
                bl.copy(from: dt, to: t); bl.endEncoding(); shotTex = t
            }
        }
        cb.present(drawable)
        let sem = inflight
        cb.addCompletedHandler { [weak self] _ in
            sem.signal()
            if let p = shotPath, let t = shotTex { let ok = Gfx.savePNG(t, p); DispatchQueue.main.async { self?.shotDone?(p, ok) } }
        }
        cb.commit()
        VL.removeAll(keepingCapacity: true); VT.removeAll(keepingCapacity: true); VQ.removeAll(keepingCapacity: true); UI.removeAll(keepingCapacity: true)
    }

    static func savePNG(_ t: MTLTexture, _ path: String) -> Bool {
        let w = t.width, h = t.height
        var px = [UInt8](repeating: 0, count: w * h * 4)
        t.getBytes(&px, bytesPerRow: w * 4, from: MTLRegionMake2D(0, 0, w, h), mipmapLevel: 0)
        let cs = CGColorSpace(name: CGColorSpace.sRGB)!
        guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: cs,
                                  bitmapInfo: CGImageAlphaInfo.noneSkipFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue),
              let img = ctx.makeImage() else { return false }
        let rep = NSBitmapImageRep(cgImage: img)
        guard let data = rep.representation(using: .png, properties: [:]) else { return false }
        return (try? data.write(to: URL(fileURLWithPath: path))) != nil
    }
}

// ---- matrices (right-handed, Metal clip z 0..1)
func lookAtRH(_ eye: SIMD3<Float>, _ at: SIMD3<Float>, _ up: SIMD3<Float>) -> simd_float4x4 {
    let z = simd_normalize(eye - at), x = simd_normalize(simd_cross(up, z)), y = simd_cross(z, x)
    return simd_float4x4(rows: [SIMD4(x.x, x.y, x.z, -simd_dot(x, eye)), SIMD4(y.x, y.y, y.z, -simd_dot(y, eye)),
                                SIMD4(z.x, z.y, z.z, -simd_dot(z, eye)), SIMD4(0, 0, 0, 1)])
}
func perspectiveRH(_ fov: Float, _ aspect: Float, _ n: Float, _ f: Float) -> simd_float4x4 {
    let ys = 1 / tan(fov / 2), xs = ys / aspect
    return simd_float4x4(rows: [SIMD4(xs, 0, 0, 0), SIMD4(0, ys, 0, 0), SIMD4(0, 0, f / (n - f), n * f / (n - f)), SIMD4(0, 0, -1, 0)])
}
