// TraceUI.swift — the TRACE tab: input bar, the chain of hops as a scene, the replay of every message as an orb,
// the step list and the decoded detail panel.
import AppKit
import simd

// ---- what the view holds between frames
var TR = Trace()
var trVer = -1
var trInput = "", trProto = TP.https
var trAutoProto = false
var trSel = -1
var trPlay = 0.0, trEnd = 0.0
var trSt: [Double] = [], trDur: [Double] = []
var trPaused = false, trWantNext = false, trFollow = true, trReveal = false
var trListScroll: Float = 0, trDetScroll: Float = 0, trFullScroll: Float = 0
var trStepT = 0.0
var trHovOrb = -1
var trWebMsg = -1

func trCol(_ m: TrMsg) -> Col {
    switch m.kind {
    case TK.dnsq, TK.probe, TK.echoq, TK.syn, TK.tlsc, TK.httpq: return C_OUT
    case TK.dnsr: return C_UDP
    case TK.ttlx: return C_WARN
    case TK.echor: return C_IN
    case TK.synack: return hex(0x4d9bff)
    case TK.tlss: return C_SAFE
    case TK.banner: return C_WHITE
    case TK.httpr:
        let st = Int(m.title.split(separator: " ").dropFirst().first ?? "") ?? 0
        return st >= 400 ? hex(0xff4b5c) : st >= 300 ? hex(0xffe14f) : hex(0x7dff6b)
    case TK.refused, TK.lost: return hex(0xff4b5c)
    case TK.info: return m.ms > 0 ? hex(0x7dff6b) : m.ms == 0 ? hex(0xff4b5c) : C_WHITE
    case TK.fin: return m.out ? hex(0xb45fd0) : C_WHITE
    default: return C_OUT
    }
}
func trNodeName(_ i: Int) -> String {
    guard i >= 0 && i < TR.nodes.count else { return "?" }
    let n = TR.nodes[i]
    switch n.kind {
    case TN.me: return "this computer"
    case TN.silent: return "hop \(n.ttl) (silent)"
    case TN.dns: return n.ip == "system" ? n.name : "DNS server " + n.ip
    case TN.target: return n.name.isEmpty ? n.ip : "\(n.name) (\(n.ip))"
    default: return "hop \(n.ttl) · " + n.ip
    }
}

/// When each message is replayed. Route probes leave in a quick burst, as they really do; everything else is strictly
/// one after the other, and an answer starts once its request has arrived.
func trSchedule() {
    let n = TR.msgs.count
    trSt = [Double](repeating: 0, count: n); trDur = [Double](repeating: 0.6, count: n)
    var ci: [Int: Int] = [:]
    for (i, c) in TR.chain.enumerated() { ci[c] = i }
    var cur = 0.0, routeEnd = 0.0
    trEnd = 0
    for i in 0..<n {
        let m = TR.msgs[i]
        var segs = 1
        if m.from == m.to { segs = 0 }
        else if let a = ci[m.from], let b = ci[m.to] { segs = abs(a - b) }
        let d = segs == 0 ? 0.55 : min(1.9, 0.45 + 0.1 * Double(segs))
        let st = m.pair >= 0 && m.pair < i ? trSt[m.pair] + trDur[m.pair] : m.phase == 1 ? cur : max(cur, routeEnd)
        trSt[i] = st; trDur[i] = d
        if m.phase == 1 { if m.out { cur = st + 0.16 }; routeEnd = max(routeEnd, st + d + 0.15) }
        else { cur = st + d + (m.out ? 0 : 0.12) }
        trEnd = max(trEnd, st + d)
    }
}
/// "This computer" on the left, the target on the right, the hops between them along a bowed arc.
func trChainPos(_ i: Int, _ n: Int) -> V3 {
    let sp: Float = n > 1 ? max(min(15, 210 / Float(n - 1)), min(42, 84 / Float(n - 1))) : 0
    let half = sp * Float(n - 1) / 2, u: Float = n > 1 ? Float(i) / Float(n - 1) : 0.5
    return V3(-half + Float(i) * sp, 6 + sin(u * .pi) * 14, -sin(u * .pi) * 22)
}
func buildTrace() {
    let L = LY[6]; L.gen += 1
    var lanes: [Lane] = []
    let n = TR.chain.count
    var pos: [Int: V3] = [:]
    for (i, c) in TR.chain.enumerated() { pos[c] = trChainPos(i, n) }
    let me = n > 0 ? trChainPos(0, n) : V3(0, 6, 0), last = n > 0 ? trChainPos(n - 1, n) : V3(0, 6, 0)
    var kd = 0, kt = 0
    for i in 0..<TR.nodes.count where pos[i] == nil {
        if TR.nodes[i].kind == TN.dns {   // before the route is known everything stays close, so the first frames are not empty
            pos[i] = n > 2 ? V3(me.x + 3 + 14 * Float(kd), me.y + 30, me.z - 24) : V3(me.x - 26 - 14 * Float(kd), me.y + 12, me.z - 10); kd += 1
        } else {
            kt += 1
            pos[i] = n > 1 ? V3(last.x + 5, last.y + 8 + 15 * Float(kt), last.z - 20) : V3(me.x + 34, me.y + 10 * Float(kt - 1), me.z)
        }
    }
    let grow = max(1, min(Float(1.7), (last.x - me.x) / 110))      // long routes are seen from further away
    for i in 0..<TR.nodes.count {
        let t = TR.nodes[i]; let key = "tr:\(i)"
        let shape: Shape = t.kind == TN.me || t.kind == TN.target ? .ico : t.kind == TN.dns ? .box : t.kind == TN.silent ? .tetra : .octa
        var sz: Float = t.kind == TN.me ? 3.2 : t.kind == TN.target ? 3.6 : t.kind == TN.dns ? 4.2 : t.kind == TN.silent ? 1.1 : 1.9
        sz *= grow
        let c: Col = t.kind == TN.me ? C_CYAN : t.kind == TN.target ? C_SAFE : t.kind == TN.dns ? C_UDP : t.kind == TN.silent ? C_DEEP : C_BLUE
        let nd = up(L, key, shape, .tr, pos[i] ?? me, S3(sz), c, me)
        nd.cnt = i; nd.s1 = t.ip; nd.name = t.ip + " " + t.name
        nd.glow = t.kind == TN.silent ? 0.15 : t.kind == TN.hop ? 0.5 : 0.9
        nd.lp = t.kind == TN.hop ? 20 : t.kind == TN.silent ? 1 : 40
        nd.label = t.kind == TN.me ? (t.name.isEmpty ? "this computer" : t.name)
                 : t.kind == TN.silent ? "* hop \(t.ttl)"
                 : t.kind == TN.dns ? (t.ip == "system" ? t.name : "DNS " + t.ip)
                 : t.kind == TN.target ? (t.name.isEmpty ? t.ip : t.name) : t.ip
    }
    if n > 1 { for i in 0..<(n - 1) { lanes.append(mkLane("tl:\(i)", "tr:\(TR.chain[i])", "tr:\(TR.chain[i + 1])", C_BLUE, w: 0.9)) } }
    for k in TR.links { lanes.append(mkLane("tx:\(k.0)-\(k.1)", "tr:\(k.0)", "tr:\(k.1)", C_UDP, w: 0.6, lift: 0.22)) }
    L.ext = max(55, (last.x - me.x) / 2 + 22)
    endNodes(L); setLanes(L, lanes)
}
/// Takes over whatever the trace thread has produced so far.
func trSync() {
    if TrShared.i.version() == trVer { return }
    let t = TrShared.i.snapshot()
    let oldN = TR.msgs.count
    let fresh = t.msgs.count < TR.msgs.count || t.input != TR.input || (t.msgs.isEmpty && t.running)
    let before = TR.nodes.count + TR.chain.count
    TR = t; trVer = t.ver
    var next = -1
    if fresh {
        trPaused = t.live; trWantNext = false; trSel = -1; trPlay = 0
        trListScroll = 0; trDetScroll = 0; trFollow = true
        if view == 6 { sel = "" }
    } else if trWantNext && TR.msgs.count > oldN {
        trWantNext = false; next = oldN
    } else if !TR.running { trWantNext = false }
    if before != TR.nodes.count + TR.chain.count { LY[6].framed = false }
    trSchedule()
    if view == 6 && S != nil { rebuild() }
    if next >= 0 { trShow(next) }       // the step you asked for has happened: show its first message
}

// ---- running and stepping
func trGo(_ stepByStep: Bool = false) {
    if trInput.trimmingCharacters(in: .whitespaces).isEmpty { return }
    traceStart(trInput, trProto, live: stepByStep)
}
func trInputChanged() {
    if let p = trSchemeProto(trInput) { trAutoProto = true; trProto = p.proto } else { trAutoProto = false }
}
func trPick(_ i: Int) { trSel = i; sel = ""; computeFocus(); trDetScroll = 0; trFullScroll = 0; trFollow = false }
func trShow(_ idx: Int) {
    guard idx >= 0 && idx < trSt.count else { return }
    trPaused = true; trPick(idx); trPlay = trSt[idx]; trStepT = nowSec(); trReveal = true
}
/// Pauses the replay on one message and plays just that one. dir -1 / +1 moves to the previous / next, 0 stays.
func trStep(_ dir: Int) {
    let n = TR.msgs.count
    if n == 0 || trSt.count != n { return }
    var idx = trSel
    if idx < 0 { idx = 0; for i in 0..<n where trSt[i] <= trPlay { idx = i } }   // nothing picked yet: start from the one being replayed
    else { idx += dir }
    trShow(max(0, min(n - 1, idx)))
}
/// In a step-by-step run, stepping past the newest message lets the trace perform its next real step.
func trStepKey(_ dir: Int) {
    let n = TR.msgs.count
    if dir > 0 && TR.live && TR.running && (n == 0 || (trPaused && trSel >= n - 1)) {
        trPaused = true; trWantNext = true; TrShared.i.grant(); return
    }
    trStep(dir)
}
func trTogglePause() {
    if !trPaused { if TR.msgs.isEmpty { trPaused = true } else { trStep(0) }; return }
    trPaused = false; trWantNext = false
    if trSel >= 0 && trSel < trSt.count { trPlay = trSt[trSel] }
    if TR.live && TR.running { trSel = -1; trFollow = true; computeFocus() }   // a live run follows the newest step
}
func trCopy(_ s: String, _ what: String) {
    let pb = NSPasteboard.general; pb.clearContents(); pb.setString(s, forType: .string)
    toast("Copied " + what, .safe)
}

// ---- the orbs
func trNodePos(_ i: Int) -> V3? { LY[6].nodes["tr:\(i)"].map { $0.pos } }
/// Along the chain of hops when both ends are on it, otherwise an arc.
func trPath(_ m: TrMsg) -> [V3] {
    guard let a = trNodePos(m.from), let b = trNodePos(m.to) else { return [] }
    if m.from == m.to { return [a] }
    var ia = -1, ib = -1
    for (i, c) in TR.chain.enumerated() { if c == m.from { ia = i }; if c == m.to { ib = i } }
    if ia >= 0 && ib >= 0 {
        var p: [V3] = []; let st = ia < ib ? 1 : -1; var i = ia
        while true { if let q = trNodePos(TR.chain[i]) { p.append(q) }; if i == ib { break }; i += st }
        return p
    }
    var c = (a + b) * 0.5; c.y += 0.22 * len(a - b)
    return (0...14).map { bez(a, c, b, Float($0) / 14) }
}
func polyAt(_ p: [V3], _ f: Float) -> V3 {
    if p.isEmpty { return V3() }
    if p.count == 1 { return p[0] }
    var tot: Float = 0
    for i in 1..<p.count { tot += len(p[i] - p[i - 1]) }
    var want = max(0, min(1, f)) * tot
    for i in 1..<p.count {
        let l = len(p[i] - p[i - 1])
        if want <= l || i + 1 == p.count { return lerp(p[i - 1], p[i], l > 0 ? min(1, want / l) : 0) }
        want -= l
    }
    return p[p.count - 1]
}
private func trQuad(_ p: V3, _ hs: Float, _ c: Col, _ f: Float, _ r: V3, _ u: V3) {
    let q = [p - r * hs - u * hs, p + r * hs - u * hs, p + r * hs + u * hs, p - r * hs + u * hs]
    let uv: [(Float, Float)] = [(-1, -1), (1, -1), (1, 1), (-1, 1)]
    for j in [0, 1, 2, 0, 2, 3] { g.VQ.append(Vtx(x: q[j].x, y: q[j].y, z: q[j].z, r: c.r * f, g: c.g * f, b: c.b * f, u: uv[j].0, v: uv[j].1)) }
}
private var trSlowNow = false
func trOrbs(_ dt: Float) {
    trHovOrb = -1
    let n = TR.msgs.count
    // a live run: once everything received so far has been shown, the trace may take its next real step
    if TR.live && TR.running && !trPaused && !paused && TrShared.i.waiting && !TrShared.i.permitsPending() && (n == 0 || trPlay >= trEnd + 0.1) {
        TrShared.i.grant()
    }
    if n == 0 || trSt.count != n { return }
    let f = norm(camT - camEye), r = norm(simd_cross(f, V3(0, 1, 0))), u = simd_cross(r, f)
    trPlay += Double(dt) * (paused || trPaused ? 0 : trSlowNow ? 0.1 : 1)
    if TR.running { trPlay = min(trPlay, trEnd + 0.5) } else if trPlay > trEnd + 1.8 { trPlay = 0 }
    var best: Float = 20
    func hoverTest(_ q: V3, _ i: Int) {
        if let (sx, sy) = project(q) { let d = hypot(sx - UIS.mouseX, sy - UIS.mouseY); if d < best { best = d; trHovOrb = i } }
    }
    for i in 0..<n {
        let m = TR.msgs[i]
        let d = Float(trDur[i]), lt = Float(trPlay - trSt[i])
        let selM = i == trSel, active = !trPaused && lt >= 0 && lt < d + 0.45
        if !active && !selM { continue }
        let p = trPath(m); if p.isEmpty { continue }
        let c = trCol(m)
        if selM && trPaused {   // paused: this one message travels once, then rests pulsing where it arrived
            for k in 1..<max(1, p.count) { g.line(p[k - 1], p[k], c, 1.5) }
            let k = min(Float(1), Float((nowSec() - trStepT) / max(0.01, trDur[i]))), pulse = 1 + 0.22 * sin(Float(nowSec()) * 5)
            if p.count == 1 {
                let hs = max(Float(1.2), len(p[0] - camEye) * 0.012) * (k < 1 ? 0.6 + k * 1.6 : 2.2 * pulse)
                trQuad(p[0], hs, c, k < 1 ? 1.2 : 0.8, r, u); hoverTest(p[0], i); continue
            }
            let q = polyAt(p, k); let base = max(Float(1.1), len(q - camEye) * 0.011) * (k < 1 ? 1 : pulse)
            if k < 1 { for t in stride(from: 8, through: 1, by: -1) { let kk = k - Float(t) * 0.022; if kk < 0 { continue }
                trQuad(polyAt(p, kk), base * (1 - Float(t) * 0.09), c, 0.55 * (1 - Float(t) / 9), r, u) } }
            trQuad(q, base * 1.7, c, 1.2, r, u); trQuad(q, base * 0.6, C_WHITE, 0.9, r, u); hoverTest(q, i); continue
        }
        if selM {   // the selected message: its path glows and a marker keeps running along it
            for k in 1..<max(1, p.count) { g.line(p[k - 1], p[k], c, 1.5) }
            let lf = Float(fmod(nowSec() * 0.7, 1.0)); let q = polyAt(p, lf); let hs = max(Float(0.9), len(q - camEye) * 0.009)
            if p.count > 1 { trQuad(q, hs * 1.3, c, 0.9, r, u); trQuad(q, hs * 0.6, C_WHITE, 0.9, r, u) }
            else { trQuad(q, hs * (1 + lf * 3), c, 1 - lf, r, u) }
        }
        if !active { continue }
        if p.count == 1 {   // a message that stays on one node is an expanding pulse there
            let k = min(Float(1), lt / d); let hs = max(Float(1.2), len(p[0] - camEye) * 0.012) * (0.6 + k * 2.4)
            trQuad(p[0], hs, c, (1 - k) * 1.3, r, u); if k < 0.8 { hoverTest(p[0], i) }; continue
        }
        if lt < d {
            let k = lt / d; let q = polyAt(p, k); let base = max(Float(1.1), len(q - camEye) * 0.011)
            for t in stride(from: 8, through: 1, by: -1) { let kk = k - Float(t) * 0.022; if kk < 0 { continue }
                trQuad(polyAt(p, kk), base * (1 - Float(t) * 0.09), c, 0.55 * (1 - Float(t) / 9), r, u) }
            trQuad(q, base * 1.6, c, 1.2, r, u); trQuad(q, base * 0.6, C_WHITE, 0.9, r, u); hoverTest(q, i)
        } else {
            let k = (lt - d) / 0.45; let q = p[p.count - 1]; let base = max(Float(1.1), len(q - camEye) * 0.011)
            trQuad(q, base * (1.2 + k * 3), c, (1 - k) * 0.9, r, u)
        }
    }
    if UIS.mouseOverUi { trHovOrb = -1 }
    trSlowNow = trHovOrb >= 0
}
func trOrbTip(_ m: TrMsg) -> [TL] {
    var t = [TL(s: ellipsize(m.title, 100), c: m.out ? .out : .white),
             TL(s: m.from == m.to ? "at " + trNodeName(m.to) : trNodeName(m.from) + "  →  " + trNodeName(m.to), c: .text)]
    for f in m.f.prefix(5) { t.append(TL(s: ellipsize(f.0 + ": " + f.1, 100), c: .dim)) }
    t.append(TL(s: "click for everything that was said", c: .cyan))
    return t
}

// ---- detail lines: an optional key, the text, a colour, an indent, and the message a click opens
struct TDL { var k = "", s = ""; var c: RGBA = uiCol(.text); var ind: Float = 0; var link = -1 }
func tdlAdd(_ o: inout [TDL], _ s: String, _ c: RGBA, _ wrap: Int, _ ind: Float = 0, _ link: Int = -1) {
    let w = max(20, wrap - Int(ind / CW))
    for raw in s.components(separatedBy: "\n") {
        let line = raw.replacingOccurrences(of: "\t", with: "    ")
        for l in wrapText(line, w) { o.append(TDL(k: "", s: l, c: c, ind: ind, link: link)) }
    }
}
func tdlField(_ o: inout [TDL], _ k: String, _ v: String, _ wrap: Int) {
    let wk = k + "  "
    if wk.count + v.count <= wrap && !v.contains("\n") { o.append(TDL(k: wk, s: v, c: uiCol(.text))) }
    else { o.append(TDL(k: wk, s: "", c: uiCol(.text))); tdlAdd(&o, v, uiCol(.text), wrap, 14) }
}
func trMsgLines(_ m: TrMsg, _ o: inout [TDL], _ wrap: Int, _ full: Bool) {
    tdlAdd(&o, m.title, rgbaOf(mix(trCol(m), C_WHITE, 0.25)), wrap)
    let at = String(format: "at %.0f ms", m.t * 1000)
    tdlAdd(&o, (m.from == m.to ? "at " + trNodeName(m.to) : trNodeName(m.from) + "  →  " + trNodeName(m.to))
             + "  ·  " + at + (m.ms >= 0 && m.kind != TK.info ? "  ·  answered in " + trMs(m.ms) : ""), uiCol(.dim), wrap)
    o.append(TDL(c: uiCol(.dim)))
    for f in m.f { tdlField(&o, f.0, f.1, wrap) }
    if !m.body.isEmpty {
        o.append(TDL(c: uiCol(.dim))); tdlAdd(&o, "CONTENT", uiCol(.dim), wrap)
        var body = m.body
        if !full && body.count > 1200 { body = String(body.prefix(1200)) + "\n… open the full view for the rest" }
        tdlAdd(&o, body, uiCol(.white, 0.92), wrap)
    }
}
func drawTDL(_ d: TDL, _ x: Float, _ y: Float) {
    var tx = x + d.ind
    if !d.k.isEmpty { g.text(tx, y, d.k, uiCol(.cyan, 0.9)); tx += Float(d.k.unicodeScalars.count) * CW }
    if !d.s.isEmpty { g.text(tx, y, d.s, d.c) }
}

// ---- the input bar, full width under the top bar
func drawTraceBar() {
    let x0: Float = 12, y: Float = 54, w = G.LW - 24
    panelBg(x0, y, w, 34)
    var x = x0 + 12; let by = y + 6
    g.text(x, by + 3, "TARGET", .dim); x += 54
    let iw = max(150, min(460, w - 54 - 760))   // leaves room for the protocol, trace and replay buttons
    let maxc = max(8, Int((iw - 16) / CW))
    let caret = fmod(nowSec(), 1.0) < 0.55
    g.stroke(x, by, iw, 22, rgba(0x4fe3ff, 0.8))
    if trInput.isEmpty { g.text(x + 8, by + 3, (caret ? "_" : " ") + " host, IP or URL, then Enter", .dim) }
    else { g.text(x + 8, by + 3, ellipsizeLeft(trInput, maxc - 1) + (caret ? "_" : ""), .white) }
    x += iw + 10
    for (i, pn) in ["ICMP", "TCP", "HTTP", "HTTPS", "DNS"].enumerated() {
        if button(&x, by, pn, trProto == i) {
            if trAutoProto && trProto != i { toast("The address starts with a protocol, so that one is used. Remove the prefix to choose another.", .warn) }
            else { trProto = i }
        }
        x += 2
    }
    x += 8
    if TR.running { if button(&x, by, "STOP", false, .warn) { traceStop() } }
    else {
        if button(&x, by, "TRACE ▶", false, .safe) { trGo() }
        x += 2
        if button(&x, by, "STEP BY STEP", false, .safe) { trGo(true) }
    }
    if !TR.msgs.isEmpty || (TR.live && TR.running) {
        let lr = TR.live && TR.running
        x += 14
        g.text(x, by + 3, lr ? "LIVE" : "REPLAY", lr ? .warn : .dim); x += lr ? 38 : 52
        if button(&x, by, "◀", false) { trStepKey(-1) }
        x += 2
        if button(&x, by, trPaused ? "PLAY" : "PAUSE", trPaused, trPaused ? .warn : .cyan) { trTogglePause() }
        x += 2
        if button(&x, by, "▶", false) { trStepKey(1) }
    } else {
        x += 12
        if x + 30 * CW < x0 + w { g.text(x, by + 3, trAutoProto ? "protocol taken from the address" : "e.g. https://example.com", .dim) }
    }
}

func trHelpPanel(_ x: Float, _ y0: Float, _ wrap: Int) {
    var y = y0 + 10
    g.text(x + 12, y, "Trace", uiCol(.cyan), bold: true); y += 26
    var dl: [TDL] = []
    tdlAdd(&dl, "Type a host name, an IPv4 address or a URL, pick a protocol and press Enter. The view shows every step between this Mac and the target: the name lookup, each router on the way, and the conversation in the chosen protocol.", uiCol(.text), wrap)
    dl.append(TDL(c: uiCol(.dim)))
    tdlField(&dl, "ICMP", "ping: echo requests and replies", wrap)
    tdlField(&dl, "TCP", "opens a connection to a port (host:port) and reads the server's greeting", wrap)
    tdlField(&dl, "HTTP", "plain web request, redirects are followed", wrap)
    tdlField(&dl, "HTTPS", "TLS handshake, certificate check, then the web request", wrap)
    tdlField(&dl, "DNS", "asks the DNS server for every record type of the name", wrap)
    dl.append(TDL(c: uiCol(.dim)))
    tdlAdd(&dl, "A prefix selects the protocol by itself:", uiCol(.text), wrap)
    for e in ["https://example.com/page", "http://example.com", "tcp://example.com:22   or   ssh://example.com",
              "icmp://1.1.1.1", "dns://1.1.1.1/example.com   (ask that server)"] { tdlAdd(&dl, e, uiCol(.white), wrap, 14) }
    dl.append(TDL(c: uiCol(.dim)))
    tdlAdd(&dl, "Enter runs the trace at full speed and replays it. Shift+Enter runs it step by step: nothing is sent until you press → (one real step each time) or Space (runs live, each step performed as the view reaches it; Space pauses again). Waiting too long between steps can make the far side give up.", uiCol(.text), wrap)
    dl.append(TDL(c: uiCol(.dim)))
    tdlAdd(&dl, "This sends real packets to the target: about 30 ICMP probes for the route, then the protocol exchange. ⌘V pastes an address.", uiCol(.dim), wrap)
    for d in dl { drawTDL(d, x + 12, y); y += 15 }
}

func drawTracePanel() {
    let w = min(500, G.LW * 0.46), x = G.LW - w - 12, y0: Float = 94
    let h = max(220, legendTop - y0 - 8)
    panelBg(x, y0, w, h)
    let wrap = max(20, Int((w - 28) / CW))
    let inside = inR(x, y0, w, h); let wheel = inside ? UIS.wheelUi : 0; if inside { UIS.wheelUi = 0 }
    var y = y0 + 10
    let n = TR.msgs.count
    if TR.input.isEmpty { trHelpPanel(x, y0, wrap); return }
    g.text(x + 12, y, "TRACE · " + ellipsize(TR.input, 46), uiCol(.cyan), bold: true); y += 22
    do {
        let hops = max(0, TR.chain.count - 1)
        var s = "\(TR.running ? TR.status : TR.err.isEmpty ? "done" : "stopped") · \(n) messages · \(hops) hop\(hops == 1 ? "" : "s")"
        if !TR.running && TR.took > 0 { s += String(format: " · took %.1f s", TR.took) }
        g.text(x + 12, y, s, TR.running ? .warn : TR.err.isEmpty ? .safe : .red); y += 17
    }
    if !TR.err.isEmpty { for l in wrapText(TR.err, wrap) { g.text(x + 12, y, l, uiCol(.red)); y += 15 } }
    y += 4
    if TR.live && TR.running {
        g.text(x + 12, y, trPaused
            ? (TrShared.i.waiting ? "STEP BY STEP · → next real step · ← back · Space runs live" : "STEP BY STEP · waiting for the network…")
            : "LIVE · steps happen as the view reaches them · Space pauses", trPaused ? .warn : .safe)
    } else if trPaused && trSel >= 0 {
        g.text(x + 12, y, "REPLAY PAUSED · step \(trSel + 1) of \(n) · ← → step · Space plays", .warn)
    } else {
        g.text(x + 12, y, "STEPS   ← → step through the replay · Space pauses · ↑ ↓ select", .dim)
    }
    y += 18
    let ly = y
    let rows = max(4, Int((h - (y - y0)) * 0.40 / 15))
    let inList = inR(x, ly, w, Float(rows) * 15)
    if (navKey == NK.up || navKey == NK.down) && n > 0 {
        var cur = trSel < 0 ? (navKey == NK.up ? n : -1) : trSel
        _ = navList(&cur, &trListScroll, n, rows)
        if cur >= 0 && cur < n { trPick(cur); trPlay = trSt[cur] }
    }
    if inList && wheel != 0 { trListScroll -= wheel * 3; trFollow = false }
    if trFollow { trListScroll = Float(n - rows) }     // stays on the newest step until you scroll or pick one
    if trReveal && trSel >= 0 {
        if Float(trSel) < trListScroll { trListScroll = Float(trSel) }
        else if trSel >= Int(trListScroll) + rows { trListScroll = Float(trSel - rows + 1) }
    }
    trReveal = false
    trListScroll = max(0, min(trListScroll, Float(max(0, n - rows))))
    let first = Int(trListScroll)
    for i in 0..<rows where first + i < n {
        let idx = first + i; let m = TR.msgs[idx]; let yy = ly + Float(i) * 15
        let hot = inR(x + 6, yy, w - 12, 15) && inside, cur = idx == trSel
        let playing = idx < trSt.count && trPlay >= trSt[idx] && trPlay < trSt[idx] + trDur[idx]
        if hot || cur || playing { g.fill(x + 6, yy, w - 12, 15, rgba(0x4fe3ff, cur ? 0.26 : hot ? 0.13 : 0.07)) }
        g.text(x + 10, yy, String(format: "%6.0f", m.t * 1000), .dim)
        g.text(x + 10 + 7 * CW, yy, m.from == m.to ? "●" : m.out ? "▲" : "▼", rgbaOf(trCol(m)))
        g.text(x + 10 + 9 * CW, yy, ellipsize(m.title, wrap - 10), cur || hot ? uiCol(.white) : rgbaOf(mix(trCol(m), C_WHITE, 0.4)))
        if hot && UIS.clickNow { trPick(idx); trPlay = trSt[idx] }
    }
    if n == 0 { g.text(x + 12, ly, TR.running ? "working…" : "no messages", .dim) }
    y = ly + Float(rows) * 15 + 10
    g.fill(x + 10, y - 5, w - 20, 1, rgba(0x4fe3ff, 0.25))
    var dl: [TDL] = []
    var buttons = false
    var nodeIdx = sel.hasPrefix("tr:") ? Int(sel.dropFirst(3)) ?? -1 : -1
    if nodeIdx >= TR.nodes.count { nodeIdx = -1 }
    if trSel >= 0 && trSel < n {
        let m = TR.msgs[trSel]
        trMsgLines(m, &dl, wrap, false)
        buttons = true
        var bx = x + 12
        if !m.page.isEmpty { if button(&bx, y, "RENDERED PAGE", false, .safe) { trOpenRender() }; bx += 4 }
        if button(&bx, y, m.raw.isEmpty ? "FULL VIEW" : !m.page.isEmpty ? "TEXT + BYTES" : "FULL VIEW + BYTES", false) {
            hexClose(); hexMode = 5; trFullScroll = 0
        }
        bx += 4
        if button(&bx, y, "COPY TEXT", false) { trCopy(dl.map { $0.k + $0.s }.joined(separator: "\n"), "the decoded message") }
    } else if nodeIdx >= 0 {
        let t = TR.nodes[nodeIdx]
        let hasIp = !t.ip.isEmpty && t.ip != "system"
        tdlAdd(&dl, trNodeName(nodeIdx), uiCol(.white), wrap)
        tdlAdd(&dl, t.kind == TN.me ? "Where every request starts and every answer ends."
                  : t.kind == TN.dns ? "Translates names into addresses."
                  : t.kind == TN.target ? "The machine you asked for."
                  : t.kind == TN.silent ? "A router that forwards traffic but does not answer probes."
                  : "A router on the way. It forwards the packets and answered the probe sent with this hop count.", uiCol(.dim), wrap)
        dl.append(TDL(c: uiCol(.dim)))
        if hasIp {
            tdlField(&dl, "address", t.ip + (isPrivate(t.ip) ? "  (private network)" : ""), wrap)
            let nm = DNS.shared.lookup(t.ip)
            tdlField(&dl, "host name", nm.isEmpty ? "resolving…" : nm == "-" ? "none (no reverse DNS record)" : nm, wrap)
            if let wo = Whois.shared.result(t.ip) {
                tdlField(&dl, "owner", wo + (isPrivate(t.ip) ? "  — a reserved private range: the device belongs to your own network" : ""), wrap)
            }
        }
        if t.ttl > 0 { tdlField(&dl, "hop number", "\(t.ttl)", wrap) }
        if t.ms >= 0 { tdlField(&dl, "round trip", trMs(t.ms), wrap) }
        if !t.note.isEmpty { tdlField(&dl, "note", t.note, wrap) }
        dl.append(TDL(c: uiCol(.dim))); tdlAdd(&dl, "MESSAGES TO AND FROM IT", uiCol(.dim), wrap)
        for i in 0..<n where TR.msgs[i].from == nodeIdx || TR.msgs[i].to == nodeIdx {
            dl.append(TDL(k: "", s: "› " + ellipsize(TR.msgs[i].title, wrap - 4), c: rgbaOf(mix(trCol(TR.msgs[i]), C_WHITE, 0.4)), ind: 0, link: i))
        }
        if hasIp {   // every node with an address, private ones included: the registry names the reserved range
            buttons = true
            var bx = x + 12
            if button(&bx, y, "WHO OWNS IT", false) { requestAction("act:whois:" + t.ip) }
            bx += 4
            if button(&bx, y, "COPY ADDRESS", false) { requestAction("act:copy:" + t.ip) }
        }
    } else {
        tdlAdd(&dl, "ROUTE", uiCol(.dim), wrap)
        for (i, c) in TR.chain.enumerated() {
            let t = TR.nodes[c]
            var nm = t.ip.isEmpty || t.ip == "system" ? "" : DNS.shared.lookup(t.ip)
            if nm == "-" { nm = "" }
            if t.kind == TN.target && !t.name.isEmpty { nm = t.name }
            if t.kind == TN.me { nm = t.name + " (this computer)" }
            let line = String(format: "%2d  %-15@ %8@  %@", i, (t.kind == TN.silent ? "*" : t.ip) as NSString,
                              (t.ms >= 0 ? trMs(t.ms) : "") as NSString, nm as NSString)
            dl.append(TDL(k: "", s: ellipsize(line, wrap), c: uiCol(t.kind == TN.silent ? .dim : t.kind == TN.target ? .safe : .text)))
        }
        dl.append(TDL(c: uiCol(.dim)))
        tdlAdd(&dl, "Select a step above, or click a node or a moving orb, to see what was said. Hovering an orb slows the replay.", uiCol(.dim), wrap)
    }
    let dy = y + (buttons ? 30 : 2), dh = y0 + h - dy - 8
    let vis = max(1, Int(dh / 15))
    let inDet = inR(x, dy, w, dh)
    if inDet { trDetScroll -= wheel * 3 }
    trDetScroll = max(0, min(trDetScroll, Float(max(0, dl.count - vis))))
    let f0 = Int(trDetScroll)
    var pend = -1
    for i in 0...vis where f0 + i < dl.count {
        let d = dl[f0 + i]; let yy = dy + Float(i) * 15
        if yy + 15 > y0 + h { break }
        if d.link >= 0 {
            let hot = inDet && inR(x + 6, yy, w - 12, 15)
            if hot { g.fill(x + 6, yy, w - 12, 15, rgba(0x4fe3ff, 0.13)); if UIS.clickNow { pend = d.link } }
        }
        drawTDL(d, x + 12, yy)
    }
    if pend >= 0 { trPick(pend); trPlay = trSt[pend] }
}

// ---- one message over the whole window: everything decoded, then the bytes that were seen
func drawTraceFull(_ X0: Float, _ Y0: Float, _ Wd: Float, _ top: Float, _ rows: Int, _ wheel: Float) {
    let n = TR.msgs.count
    if trSel < 0 || trSel >= n { hexMode = 0; return }
    if navKey == NK.left && trSel > 0 { trSel -= 1; trFullScroll = 0 }
    else if navKey == NK.right && trSel + 1 < n { trSel += 1; trFullScroll = 0 }
    let m = TR.msgs[trSel]
    let wrap = max(20, Int((Wd - 30) / CW))
    var dl: [TDL] = []
    trMsgLines(m, &dl, wrap, true)
    g.text(X0 + 12, Y0 + 9, "MESSAGE \(trSel + 1) OF \(n)   ·   ← → previous / next   ·   ↑ ↓ PgUp PgDn scroll   ·   Esc closes", uiCol(.cyan), bold: true)
    if !m.page.isEmpty {
        var bx = X0 + Wd - 66 - 14 * CW - 30
        if button(&bx, Y0 + 8, "RENDERED PAGE", false, .safe) { trOpenRender(); return }
    }
    let hexN = (m.raw.count + 15) / 16
    let total = dl.count + (hexN > 0 ? hexN + 4 : 0)
    if navKey == NK.up { trFullScroll -= 1 } else if navKey == NK.down { trFullScroll += 1 }
    else if navKey == NK.pgUp { trFullScroll -= Float(rows - 1) } else if navKey == NK.pgDn { trFullScroll += Float(rows - 1) }
    else if navKey == NK.home { trFullScroll = 0 } else if navKey == NK.end { trFullScroll = Float(total) }
    trFullScroll = max(0, min(trFullScroll - wheel * 3, Float(max(0, total - rows))))
    for i in 0..<rows {
        let li = Int(trFullScroll) + i, yy = top + Float(i) * 15
        if li < dl.count { drawTDL(dl[li], X0 + 12, yy); continue }
        let hi = li - dl.count
        if hexN == 0 || hi >= hexN + 4 { break }
        if hi == 1 {
            g.text(X0 + 12, yy, "BYTES — " + (m.rawTotal > m.raw.count ? "first \(m.raw.count) of \(m.rawTotal)" : "\(m.raw.count)")
                + (m.kind == TK.httpq || m.kind == TK.httpr ? " (application data; on an HTTPS connection this is the content before / after encryption)" : ""), .dim)
        } else if hi == 3 { g.text(X0 + 12, yy, HEX_HDR, .dim) }
        else if hi >= 4 {
            let o = (hi - 4) * 16
            hexDump(X0 + 12, yy, UInt64(o), m.raw, nil, nil, min(16, m.raw.count - o), 0, o)
        }
    }
}
func trCanRender(_ i: Int) -> Bool { i >= 0 && i < TR.msgs.count && !TR.msgs[i].page.isEmpty }
func trOpenRender() { hexClose(); WebPage.shared.wantClose = false; hexMode = 6; trWebMsg = -1 }
