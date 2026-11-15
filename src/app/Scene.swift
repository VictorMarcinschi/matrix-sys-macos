// Scene model: six layers (views), each with its own nodes, lanes and framing; layouts; particles; camera; picking.
import Foundation
import simd

typealias V3 = SIMD3<Float>
func len(_ a: V3) -> Float { simd_length(a) }
func norm(_ a: V3) -> V3 { let l = simd_length(a); return l > 1e-6 ? a / l : V3(0, 1, 0) }
func lerp(_ a: V3, _ b: V3, _ k: Float) -> V3 { a + (b - a) * k }
func S3(_ s: Float) -> V3 { V3(s, s, s) }
func fnv(_ s: String) -> UInt32 { var h: UInt32 = 2166136261; for c in s.utf8 { h ^= UInt32(c); h = h &* 16777619 }; return h }
func hsl(_ h: Float, _ s: Float, _ l: Float) -> Col {
    func f(_ n: Float) -> Float { let k = fmodf(n + h * 12, 12), a = s * min(l, 1 - l); return l - a * max(-1, min(k - 3, 9 - k, 1)) }
    return Col(r: f(0), g: f(8), b: f(4))
}
/// Palette stays in the cyan-blue band; identity comes from hue + lightness inside it.
func nameColor(_ name: String) -> Col { let h = fnv(name.lowercased()); return hsl(Float(168 + h % 72) / 360, 0.85, 0.48 + Float((h >> 8) % 22) / 100) }

let SVC: [Int: String] = [20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 500: "IKE", 548: "AFP", 546: "DHCPv6", 587: "SMTP", 631: "IPP", 853: "DoT", 993: "IMAPS",
    995: "POP3S", 1900: "SSDP", 3283: "ARD", 3306: "MySQL", 3689: "DAAP", 4500: "IPsec", 5000: "AirPlay", 5223: "APNs", 5228: "Push", 5353: "mDNS", 5355: "LLMNR",
    5432: "Postgres", 5900: "VNC", 6379: "Redis", 7000: "AirPlay", 8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB", 62078: "lockdown"]
func svcName(_ p: Int) -> String { SVC[p] ?? "" }
func protoName(_ p: Int) -> String { p == 6 ? "TCP" : p == 17 ? "UDP" : p == 1 ? "ICMP" : p == 58 ? "ICMPv6" : "IP" }

enum Shape: Int { case octa = 0, ico, box, tetra }
enum Kind { case proc, hubnet, hubio, pc, port, host, group, free, other, file, disk, dir, dev, nb, vol, tr }
struct Geo { var v: [V3] = []; var e: [(Int, Int)] = []; var t: [(Int, Int, Int)] = [] }
var GEO: [Geo] = []
func buildGeo() {
    func finish(_ g: inout Geo) {
        var mn: Float = 1e9; let n = g.v.count
        for i in 0..<n { for j in (i + 1)..<n { mn = min(mn, len(g.v[i] - g.v[j])) } }
        func adj(_ i: Int, _ j: Int) -> Bool { len(g.v[i] - g.v[j]) < mn * 1.05 }
        for i in 0..<n { for j in (i + 1)..<n where adj(i, j) { g.e.append((i, j)); for k in (j + 1)..<n where adj(i, k) && adj(j, k) { g.t.append((i, j, k)) } } }
    }
    var o = Geo(); o.v = [V3(1, 0, 0), V3(-1, 0, 0), V3(0, 1, 0), V3(0, -1, 0), V3(0, 0, 1), V3(0, 0, -1)]; finish(&o)
    var ic = Geo(); let p: Float = 1.618034
    for a in stride(from: -1, through: 1, by: 2) { for b in stride(from: -1, through: 1, by: 2) {
        ic.v.append(norm(V3(0, Float(a), Float(b) * p))); ic.v.append(norm(V3(Float(a), Float(b) * p, 0))); ic.v.append(norm(V3(Float(a) * p, 0, Float(b)))) } }
    finish(&ic)
    var te = Geo(); te.v = [norm(V3(1, 1, 1)) * 1.2, norm(V3(1, -1, -1)) * 1.2, norm(V3(-1, 1, -1)) * 1.2, norm(V3(-1, -1, 1)) * 1.2]; finish(&te)
    var bx = Geo()
    for i in 0..<8 { bx.v.append(V3((i & 1) != 0 ? 0.5 : -0.5, (i & 2) != 0 ? 0.5 : -0.5, (i & 4) != 0 ? 0.5 : -0.5)) }
    for i in 0..<8 { for j in (i + 1)..<8 { let x = i ^ j; if x == 1 || x == 2 || x == 4 { bx.e.append((i, j)) } } }
    for f in [[0, 1, 3, 2], [4, 5, 7, 6], [0, 1, 5, 4], [2, 3, 7, 6], [0, 2, 6, 4], [1, 3, 7, 5]] { bx.t.append((f[0], f[1], f[2])); bx.t.append((f[0], f[2], f[3])) }
    GEO = [o, ic, bx, te]
}

final class Node {
    var key = "", name = "", label = "", owner = "", s1 = ""
    var shape = Shape.octa, kind = Kind.proc
    var pid: Int32 = -1, port = 0, proto = 0, more = 0, cnt = 0, gen = 0
    var pos = V3(), tpos = V3(), scale = V3(), tscale = V3()
    var color = C_CYAN
    var glow: Float = 0.4, op: Float = 1, rot: Float = 0, spin: Float = 0, lp: Float = 0
    var dead = false
    var v: Double = 0
}
final class Lane {
    var key = "", a = "", b = "", proto = "", from = "", to = ""
    var color = C_CYAN
    var w: Float = 1, lift: Float = 0, vis: Float = 1
    var out = 0.0, inn = 0.0, accO = 0.0, accI = 0.0
    var tree = false, estimated = true
}
struct Part { var lane: String; var dir: Int; var bytes: Double; var t: Float; var sp: Float; var p = V3(); var real = false, disk = false; var flow: Flow? = nil; var dpath = "" }
struct Lay { var r: Float = 0, R: Float = 0, sum: Float = 0; var pos = V3(); var spine = false; var big = -1; var er: Float = 0, r0: Float = 1.9 }
final class Layer {
    var nodes: [String: Node] = [:], lanes: [String: Lane] = [:]
    var gen = 0; var ext: Float = 0; var framed = false
    var sig: UInt64 = 0; var lay: [Int: Lay] = [:]; var kids: [Int: [Int]] = [:]
    // camera memory per view
    var camT = V3(0, 10, 0), camYaw: Float = 0, camPitch: Float = 0.55, camDist: Float = 200, hasCam = false
}

// ================================================================ app state
var LY: [Layer] = (0..<7).map { _ in Layer() }   // 0 processes, 1 network, 2 memory, 3 files, 4 disks, 5 devices, 6 trace
// Layout memory, so that one process appearing or leaving does not re-pack the whole scene.
var procKAng: [Int: (Int, Float)] = [:]                                   // child pid -> (parent pid, its angle on that parent's ring)
var procFloor: [Int: (x: Float, z: Float, r: Float, ord: Int)] = [:]      // root pid -> where its tree stands on the floor
var procFloorOrd = 0
var netPAng: [Int32: Float] = [:], netHAng: [String: Float] = [:]         // process and remote-host angles on the Network rings
var netRp: Float = 0, netRh: Float = 0                                    // ring radii, kept until clearly too wide
/// Pushes apart only the neighbours on a ring that are closer than minGap, by just what is missing; nobody else moves.
func relaxRing<K: Hashable>(_ a: inout [K: Float], _ minGap: Float) {
    if a.count < 2 { return }
    let TAU: Float = 6.2832
    for _ in 0..<40 {
        let v = a.map { (fmodf(fmodf($0.value, TAU) + TAU, TAU), $0.key) }.sorted { $0.0 < $1.0 }
        var moved = false
        for i in 0..<v.count {
            let p = v[i], q = v[(i + 1) % v.count]
            var d = q.0 - p.0; if i + 1 == v.count { d += TAU }
            if d < minGap - 1e-4 { let push = (minGap - d) * 0.5; a[p.1]! -= push; a[q.1]! += push; moved = true }
        }
        if !moved { break }
    }
    for k in a.keys { a[k] = fmodf(fmodf(a[k]!, TAU) + TAU, TAU) }
}
var parts: [Part] = []
var S: Snapshot? = nil
var hist: [Snapshot] = []
var flowHist: [Flow] = [], diskHist: [DiskIo] = []
var pending: [Flow] = []
var FH: [FileH]? = nil
var filesByPid: [Int32: [String]] = [:], fileOwners: [String: [Int32]] = [:]
var filesGen = -1
var view = 0, sel = "", hov = "", query = ""
var hovPart = -1
var paused = false, hasFocus = false
var focus = Set<String>()
var winSec = 1
var lastDiskT = -100.0
var capRate: [Int32: (Double, Double)] = [:], capAcc: [Int32: (Double, Double, Double)] = [:], capAccT = 0.0, capPps = 0
struct Live { var pid: Int32; var proto: Int; var lp: Int; var rp: Int; var lip: String; var rip: String; var t: Double }
var capLive: [String: Live] = [:], capDirty = false
var connRate: [String: (Double, Double)] = [:]
private var prevConn: [String: (UInt64, UInt64)] = [:], prevConnT = 0.0
var pendingSel: Int32 = -1

// socket model
struct SConn { var la: String; var ra: String; var lp: Int; var rp: Int; var st: String; var proto: String; var key: String }
var SM_listen: [Int32: [Listen]] = [:], SM_remote: [Int32: [SConn]] = [:], SM_est: [Int32: [SConn]] = [:], SM_loop: [String: LoopPair] = [:]
func capOn() -> Bool { Model.shared.captureLive }

// camera
var camT = V3(0, 10, 0), flyT = V3(0, 10, 0)
var camYaw: Float = 0, camPitch: Float = 0.55, camDist: Float = 200, flyDist: Float = 200, flying = false
var VP = matrix_identity_float4x4, camEye = V3()
let FOV: Float = 55 * .pi / 180
func eyePos() -> V3 { camT + V3(cos(camPitch) * sin(camYaw), sin(camPitch), cos(camPitch) * cos(camYaw)) * camDist }
func project(_ p: V3) -> (Float, Float)? {
    let c = VP * SIMD4(p.x, p.y, p.z, 1); if c.w <= 0.05 { return nil }
    return ((c.x / c.w * 0.5 + 0.5) * G.LW, (1 - (c.y / c.w * 0.5 + 0.5)) * G.LH)
}
let NCPU = Float(max(1, ProcessInfo.processInfo.activeProcessorCount))
/// What the size of a process in the Processes view stands for: 0 memory, 1 lane traffic, 2 CPU load.
var procSizeMode = 0
func procSize(_ p: ProcInfo, _ mode: Int = 0) -> Float {
    var v: Float
    switch mode {
    case 1: let r = procRate(p.pid)                                   // everything its lanes carry: disk and network
            v = log10(1 + Float(r.rd + r.wr + r.nin + r.nout) / 1024) * 0.32      // 1 MB/s is about 1.5, 100 MB/s reaches the cap
    case 2: v = sqrt(max(0, Float(p.cpu) / NCPU)) * 0.35              // ps gives percent of one core; the curve wants percent of the machine
    default: v = log10(1 + Float(p.rss) / 1048576) * 0.5
    }
    return min(2.1, max(0.5, 0.5 + v))
}
/// CPU as a share of the whole machine, which is what the panel and the list show.
func cpuAll(_ p: ProcInfo) -> Double { p.cpu / Double(NCPU) }
func procRate(_ pid: Int32) -> (rd: Double, wr: Double, nin: Double, nout: Double) { S?.rate[pid] ?? (0, 0, 0, 0) }

@discardableResult
func up(_ L: Layer, _ key: String, _ shape: Shape, _ kind: Kind, _ pos: V3, _ scale: V3, _ c: Col, _ spawn: V3? = nil) -> Node {
    let n: Node
    if let e = L.nodes[key] { n = e } else {
        n = Node(); n.key = key; n.pos = spawn ?? pos; n.scale = S3(0.001); let h = fnv(key)
        n.rot = shape == .box ? 0 : Float(h % 628) / 100; n.spin = shape == .box ? 0 : 0.15 + Float(h % 40) / 100
        L.nodes[key] = n
    }
    n.shape = shape; n.kind = kind; n.dead = false; n.gen = L.gen; n.tpos = pos; n.tscale = scale; n.color = c
    n.name = ""; n.label = ""; n.owner = ""; n.s1 = ""; n.pid = -1; n.port = 0; n.proto = 0; n.more = 0; n.cnt = 0; n.glow = 0.4; n.lp = 0; n.v = 0
    return n
}
func endNodes(_ L: Layer) { for n in L.nodes.values where n.gen != L.gen && !n.dead { n.dead = true; n.tscale = V3() } }
func setLanes(_ L: Layer, _ ls: [Lane]) {
    var next: [String: Lane] = [:]
    for l in ls {
        guard L.nodes[l.a] != nil, L.nodes[l.b] != nil else { continue }
        if let o = L.lanes[l.key] { l.accO = o.accO; l.accI = o.accI } else { l.accO = Double.random(in: 0..<1); l.accI = Double.random(in: 0..<1) }
        next[l.key] = l
    }
    L.lanes = next
}
func mkLane(_ key: String, _ a: String, _ b: String, _ c: Col, w: Float, lift: Float = 0, tree: Bool = false) -> Lane {
    let l = Lane(); l.key = key; l.a = a; l.b = b; l.color = c; l.w = w; l.lift = lift; l.tree = tree; return l
}

// ================================================================ socket model
func buildSM() {
    guard let S = S else { return }
    SM_listen = [:]; SM_remote = [:]; SM_est = [:]; SM_loop = [:]
    // per-connection byte rates from nettop's cumulative counters
    let dt = S.t - prevConnT
    if dt > 0.3 {
        var nr: [String: (Double, Double)] = [:], np: [String: (UInt64, UInt64)] = [:]
        for c in S.conns { let k = c.key; np[k] = (c.bin, c.bout); if let o = prevConn[k] { nr[k] = (Double(c.bin >= o.0 ? c.bin - o.0 : 0) / dt, Double(c.bout >= o.1 ? c.bout - o.1 : 0) / dt) } }
        if prevConnT > 0 { connRate = nr }; prevConn = np; prevConnT = S.t
    }
    struct LI { var pid: Int32; var rp: Int; var key: String }
    var loopIdx: [Int: LI] = [:]
    for c in S.conns {
        if c.proto == "TCP" && c.state == "Listen" { SM_listen[c.pid, default: []].append(Listen(proto: 0, addr: c.la, port: c.lp)); continue }
        if c.proto == "UDP" && (c.rp == 0 || isAny(c.ra)) { SM_listen[c.pid, default: []].append(Listen(proto: 1, addr: c.la, port: c.lp)); continue }
        if c.rp == 0 || isAny(c.ra) || c.state == "Closed" { continue }
        let x = SConn(la: c.la, ra: c.ra, lp: c.lp, rp: c.rp, st: c.state.isEmpty ? (c.proto == "UDP" ? "UDP flow" : "?") : c.state, proto: c.proto, key: c.key)
        SM_est[c.pid, default: []].append(x)
        if isLoop(c.ra) || c.ra == c.la { if c.proto == "TCP" { loopIdx[c.lp] = LI(pid: c.pid, rp: c.rp, key: c.key) } } else { SM_remote[c.pid, default: []].append(x) }
    }
    for (lp, e) in loopIdx {
        if let o = loopIdx[e.rp], o.rp == lp, o.pid != e.pid, lp < e.rp {
            let a = min(e.pid, o.pid), b = max(e.pid, o.pid), k = "\(a)-\(b)"
            let r = connRate[e.key].map { $0.0 + $0.1 } ?? 0
            if SM_loop[k] == nil { SM_loop[k] = LoopPair(a: a, b: b, n: 0, kind: "loopback TCP", bytes: 0) }
            SM_loop[k]!.n += 1; SM_loop[k]!.bytes += r
        }
    }
    for p in S.ipc {
        let k = "\(p.a)-\(p.b)-\(p.kind)"
        SM_loop[k] = p
    }
    for (pid, arr) in SM_listen {
        var u: [String: Listen] = [:]
        for x in arr { let k = "\(x.proto):\(x.port)"
            if var e = u[k] { if isAny(x.addr) || (!isLoop(x.addr) && isLoop(e.addr)) { e.addr = x.addr; u[k] = e } } else { u[k] = x } }
        SM_listen[pid] = u.values.sorted { ($0.proto, $0.port) < ($1.proto, $1.port) }
    }
    let now = nowSec()
    for (k, f) in capLive {
        if now - f.t > 12 { capLive[k] = nil; continue }
        let have = SM_remote[f.pid]?.contains { $0.ra == f.rip && $0.rp == f.rp && $0.lp == f.lp } ?? false
        if !have && !isLoop(f.rip) { SM_remote[f.pid, default: []].append(SConn(la: f.lip, ra: f.rip, lp: f.lp, rp: f.rp, st: f.proto == 6 ? "recent" : protoName(f.proto) + " flow", proto: protoName(f.proto), key: "")) }
    }
}

// ================================================================ processes view
func buildProc() {
    guard let S = S else { return }
    let L = LY[0]; L.gen += 1; L.kids = [:]
    var roots: [Int] = []; var sig: UInt64 = 1469598103934665603
    // launchd (pid 1) adopts nearly every process on macOS; drawn as one ring it would be hundreds of units wide,
    // so its children are laid out as separate trees and launchd sits at the centre with kernel_task.
    for p in S.procs {
        let pid = Int(p.pid), ppid = Int(p.ppid)
        if ppid > 1 && S.get(p.ppid) != nil && ppid != pid { L.kids[ppid, default: []].append(pid) } else { roots.append(pid) }
        sig = (sig ^ (UInt64(UInt32(bitPattern: p.pid)) << 32 | UInt64(UInt32(bitPattern: p.ppid)))) &* 1099511628211
    }
    var ex = Set<Int>(); var exRoots = false
    if sel.hasPrefix("p:"), let sp = Int32(sel.dropFirst(2)), let p = S.get(sp) {
        if let k = L.kids[Int(sp)], k.count > 1 { ex.insert(Int(sp)) }
        if p.ppid > 1 && S.get(p.ppid) != nil { ex.insert(Int(p.ppid)) } else { exRoots = true }
    }
    for e in ex.sorted() { sig = (sig ^ (UInt64(e) &* 31 &+ 17)) &* 1099511628211 }
    if exRoots { sig = (sig ^ 0x9e37) &* 1099511628211 }
    if sig != L.sig {
        let prev = L.lay                                  // the previous layout: the hysteresis below is measured against it
        L.lay = [:]; let LEAF: Float = 1.9, LEVEL: Float = 10
        func ringR(_ sum: Float, _ m: Float, _ s2: Float, _ n: Int, _ spine: inout Bool, _ R: inout Float) -> Float {
            spine = n >= 2 && m > LEAF * 2.5
            if spine { R = max((sum - m * 2) / 6.2832 * 1.08, m + s2 + 0.6); return R + s2 }
            R = n == 1 ? 0 : max(sum / 6.2832 * 1.08, m * 1.2 + 0.6); return max(LEAF, R + m)
        }
        func measure(_ pid: Int) -> Lay {
            var ks = L.kids[pid] ?? []; ks.sort(); L.kids[pid] = ks.isEmpty ? nil : ks
            var o = Lay(); o.r = LEAF; let wide = ex.contains(pid)
            var mx: Float = 0, sec: Float = 0, mx0: Float = 0, sec0: Float = 0, sum0: Float = 0; var big = -1
            for k in ks {
                var ko = measure(k); ko.er = wide ? max(ko.r, 5.5) : ko.r; L.lay[k] = ko
                o.sum += ko.er * 2
                if ko.er > mx { sec = mx; mx = ko.er; big = k } else { sec = max(sec, ko.er) }
                sum0 += ko.r0 * 2; if ko.r0 > mx0 { sec0 = mx0; mx0 = ko.r0 } else { sec0 = max(sec0, ko.r0) }
            }
            // A sibling that grows a little past the current spine child does not take its place: that would swap two whole subtrees.
            if let pv = prev[pid], pv.spine, pv.big >= 0, pv.big != big, ks.contains(pv.big), let ob = L.lay[pv.big], ob.er >= mx * 0.7 {
                big = pv.big; mx = ob.er; sec = 0
                for k in ks where k != big { sec = max(sec, L.lay[k]?.er ?? 0) }
            }
            if !ks.isEmpty {
                var sp = false, sp0 = false, R0: Float = 0
                o.r = ringR(o.sum, mx, sec, ks.count, &sp, &o.R)
                if sp { o.spine = true; o.big = big; o.sum -= mx * 2 }
                o.r0 = ringR(sum0, mx0, sec0, ks.count, &sp0, &R0)
                // The ring grows at once but only shrinks when it is clearly too wide, so one process leaving does not pull it in.
                if let pv = prev[pid], ks.count >= 2, pv.spine == o.spine, pv.R >= o.R, pv.R <= o.R * 1.25 { o.r += pv.R - o.R; o.R = pv.R }
            }
            L.lay[pid] = o; return o
        }
        func place(_ pid: Int, _ at: V3) {
            guard var o = L.lay[pid] else { return }
            o.pos = at; L.lay[pid] = o
            var a = Float(fnv(String(pid)) % 628) / 100; let R = o.R, sum = max(o.sum, 0.001)
            let ks = L.kids[pid] ?? []
            let big = o.spine ? o.big : -1
            if big >= 0 { place(big, V3(at.x, at.y + LEVEL, at.z)) }
            let ring = ks.filter { $0 != big }; let n = ring.count
            if n == 0 { return }
            var A = [Float](repeating: 0, count: n), hw = [Float](repeating: 0, count: n)
            var known = [Bool](repeating: false, count: n); var nk = 0
            for i in 0..<n {
                let er = L.lay[ring[i]]?.er ?? LEAF
                let half = er * 2 / sum * .pi
                a += half; A[i] = a; a += half
                hw[i] = R > 0 ? er / R * 1.05 : 0
                if let m = procKAng[ring[i]], m.0 == pid { known[i] = true; nk += 1 }
            }
            if nk > 0 && R > 0 {
                for i in 0..<n where known[i] { A[i] = procKAng[ring[i]]!.1 }
                var s0 = 0; while !known[s0] { s0 += 1 }   // walk the ring from a known child; each newcomer sits right after the one before it
                if n > 1 { for t in 1..<n { let i = (s0 + t) % n, p = (s0 + t - 1) % n; if !known[i] { A[i] = A[p] + hw[p] + hw[i] } } }
                if n > 1 { for _ in 0..<60 {   // then push apart only the pairs that actually overlap
                    for i in 0..<n { A[i] = fmodf(fmodf(A[i], 6.2832) + 6.2832, 6.2832) }
                    let ord = (0..<n).sorted { A[$0] < A[$1] }
                    var mv = false
                    for j in 0..<n {
                        let p = ord[j], q = ord[(j + 1) % n]
                        var d = A[q] - A[p]; if j + 1 == n { d += 6.2832 }
                        let need = hw[p] + hw[q]
                        if d < need - 1e-4 { let push = (need - d) * 0.5; A[p] -= push; A[q] += push; mv = true }
                    }
                    if !mv { break }
                } }
            }
            let wide = ex.contains(pid)   // an expanded ring is temporary: it is never remembered
            for i in 0..<n {
                if !wide { procKAng[ring[i]] = (pid, A[i]) }
                place(ring[i], V3(at.x + R * cos(A[i]), at.y + LEVEL, at.z + R * sin(A[i])))
            }
        }
        for r in roots { _ = measure(r) }
        var livePids = Set<Int>(); for p in S.procs { livePids.insert(Int(p.pid)) }
        let rootSet = Set(roots)
        procKAng = procKAng.filter { livePids.contains($0.key) }          // a process that is gone drops its remembered angle
        procFloor = procFloor.filter { rootSet.contains($0.key) }         // and its spot on the floor
        // known trees first, in the order they were first placed, then new trees, biggest first
        roots.sort {
            let ma = procFloor[$0], mb = procFloor[$1]
            if (ma != nil) != (mb != nil) { return ma != nil }
            if let ma = ma, let mb = mb { return ma.ord < mb.ord }
            let ra = L.lay[$0]!.r0, rb = L.lay[$1]!.r0; return ra != rb ? ra > rb : $0 < $1
        }
        struct P { var x: Float, z: Float, r: Float }
        var placed: [P] = []; L.ext = 60
        var grid: [Int64: [Int]] = [:]; let cell: Float = 24; var maxR: Float = 0
        func gk(_ x: Int, _ z: Int) -> Int64 { Int64(x) << 32 | Int64(UInt32(bitPattern: Int32(z))) }
        func freeAt(_ x: Float, _ z: Float, _ r: Float) -> Bool {
            let reach = r + maxR + 2.5
            let gx0 = Int(floor((x - reach) / cell)), gx1 = Int(floor((x + reach) / cell))
            let gz0 = Int(floor((z - reach) / cell)), gz1 = Int(floor((z + reach) / cell))
            for gx in gx0...gx1 { for gz in gz0...gz1 { for qi in grid[gk(gx, gz)] ?? [] {
                if hypot(placed[qi].x - x, placed[qi].z - z) < placed[qi].r + r + 2.5 { return false } } } }
            return true
        }
        var at: [Int: V3] = [:]
        for pid in roots {
            let r = L.lay[pid]!.r0; var x: Float = 0, z: Float = 0; var found = false
            if let m = procFloor[pid] {   // the free spot nearest to where it stood, in rings of growing radius
                if freeAt(m.x, m.z, r) { x = m.x; z = m.z; found = true }
                var ring = 1
                while ring <= 400 && !found {
                    let d = Float(ring) * 1.5; let steps = max(8, Int(d * 1.2)); var best: Float = 1e9
                    for s in 0..<steps {
                        let ang = Float(s) * 6.2832 / Float(steps), cx = m.x + d * cos(ang), cz = m.z + d * sin(ang)
                        if freeAt(cx, cz, r) { let pull = hypot(cx, cz); if pull < best { best = pull; x = cx; z = cz; found = true } }
                    }   // of the free spots at that distance, the one nearest the centre
                    ring += 1
                }
            }
            if !found {   // a tree seen for the first time goes on the golden-angle spiral
                var k = 0
                while k < 200000 && !found {
                    let rad = sqrt(Float(k)) * 2.2, ang = Float(k) * 2.39996
                    x = rad * cos(ang); z = rad * sin(ang); found = freeAt(x, z, r); k += 1
                }
            }
            if !found { var edge: Float = 0; for q in placed { edge = max(edge, q.x + q.r) }; x = edge + r + 3; z = 0 }   // still unique, just outside everything
            var ord = procFloor[pid]?.ord ?? -1
            if ord < 0 { procFloorOrd += 1; ord = procFloorOrd }
            placed.append(P(x: x, z: z, r: r)); maxR = max(maxR, r)
            let qi = placed.count - 1
            for gx in Int(floor((x - r) / cell))...Int(floor((x + r) / cell)) { for gz in Int(floor((z - r) / cell))...Int(floor((z + r) / cell)) { grid[gk(gx, gz), default: []].append(qi) } }
            procFloor[pid] = (x: x, z: z, r: r, ord: ord)
            at[pid] = V3(x, -20, z)
        }
        // A selected tree on the floor: the whole floor spreads out evenly so its neighbours make room. The remembered spots stay as they are.
        var spread: Float = 1
        if exRoots && placed.count > 1 {
            for i in 0..<placed.count { for j in (i + 1)..<placed.count {
                let d = hypot(placed[i].x - placed[j].x, placed[i].z - placed[j].z)
                if d > 0.01 { spread = max(spread, (placed[i].r + placed[j].r + 10.5) / d) }
            } }
        }
        spread = min(spread, 1.7)
        for pid in roots {
            var p = at[pid]!; p.x *= spread; p.z *= spread
            L.ext = max(L.ext, hypot(p.x, p.z) + (procFloor[pid]?.r ?? 0))
            place(pid, p)
        }
        L.sig = sig
    }
    var lanes: [Lane] = []
    do { let n = up(L, "hub:net", .ico, .hubnet, V3(0, 78, 0), S3(5), C_CYAN); n.glow = 1; n.label = "NETWORK"; n.lp = 9 }
    do { let n = up(L, "hub:io", .ico, .hubio, V3(0, -30, 0), S3(4.5), C_BLUE); n.glow = 0.8; n.label = "DISK · PIPES · DEVICES"; n.lp = 9 }
    let live = diskLive()
    for p in S.procs {
        guard let li = L.lay[Int(p.pid)] else { continue }
        let key = "p:\(p.pid)"
        let hasPar = p.ppid > 1 && L.lay[Int(p.ppid)] != nil && S.get(p.ppid) != nil
        let n = up(L, key, .octa, .proc, li.pos, S3(procSize(p, procSizeMode)), nameColor(p.name), hasPar ? L.lay[Int(p.ppid)]!.pos : nil)
        let hasKids = !(L.kids[Int(p.pid)] ?? []).isEmpty
        n.pid = p.pid; n.name = p.name; n.label = p.name; n.glow = 0.35 + min(1, Float(p.cpu) / 8)
        n.lp = procSize(p, procSizeMode) + min(2, Float(p.cpu) / 5) + (hasKids ? 0.6 : 0)
        if hasPar { lanes.append(mkLane("t:\(p.pid)", "p:\(p.ppid)", key, C_BLUE, w: 0.5, tree: true)) }
        let r = procRate(p.pid)
        if SM_remote[p.pid] != nil || r.nin + r.nout > 0 {
            // with capture on, network dots are captured packets; otherwise nettop's byte counters drive estimated dots
            let l = mkLane("net:\(p.pid)", key, "hub:net", C_CYAN, w: 0.3, lift: 0.12)
            l.out = capOn() ? 0 : r.nout; l.inn = capOn() ? 0 : r.nin; l.proto = "network, all connections"; l.from = p.name; l.to = "network"; lanes.append(l)
        }
        if r.rd + r.wr > 2048 || live {
            let l = mkLane("io:\(p.pid)", key, "hub:io", C_BLUE, w: 0.3, lift: 0.12)
            l.out = live ? 0 : r.wr; l.inn = live ? 0 : r.rd; l.proto = "disk I/O"; l.from = p.name; l.to = "local I/O"
            if r.rd + r.wr > 2048 || live && diskHist.contains(where: { $0.pid == p.pid }) { lanes.append(l) }
        }
    }
    for x in SM_loop.values {
        guard let a = S.get(x.a), let b = S.get(x.b) else { continue }
        let l = mkLane("ipc:\(x.a)-\(x.b)-\(x.kind)", "p:\(x.a)", "p:\(x.b)", C_UDP, w: x.kind == "loopback TCP" ? 0.75 : 0.45, lift: 0.3)
        l.out = x.bytes / 2; l.inn = x.bytes / 2; l.proto = "\(x.kind) x\(x.n)" + (x.kind == "loopback TCP" ? "" : " · no byte counters on macOS"); l.from = a.name; l.to = b.name
        l.estimated = x.kind == "loopback TCP"; lanes.append(l)
    }
    endNodes(L); setLanes(L, lanes)
}

// ================================================================ network view
func buildNet() {
    guard let S = S else { return }
    let L = LY[1]; L.gen += 1; var lanes: [Lane] = []
    var ps = Set<Int32>()
    for pid in SM_listen.keys where S.get(pid) != nil { ps.insert(pid) }
    for pid in SM_est.keys where S.get(pid) != nil { ps.insert(pid) }
    for pid in SM_remote.keys where S.get(pid) != nil { ps.insert(pid) }
    let pids = ps.sorted { let na = S.get($0)!.name.lowercased(), nb = S.get($1)!.name.lowercased(); return na != nb ? na < nb : $0 < $1 }
    let N = pids.count
    let rpT = max(46, Float(N) * 7.2 / 6.2832)
    if netRp < rpT || netRp > rpT * 1.25 { netRp = rpT }       // the ring grows at once and only shrinks when clearly too big
    let Rp = netRp; var ang: [Int32: Float] = [:]
    let liveP = Set(pids); netPAng = netPAng.filter { liveP.contains($0.key) }
    if netPAng.isEmpty { for (i, pid) in pids.enumerated() { netPAng[pid] = Float(i) / Float(max(1, N)) * 6.2832 } }
    else {   // a known process keeps its angle; runs of new ones are spread over the gap between their known neighbours in name order
        var i = 0
        while i < N {
            if netPAng[pids[i]] != nil { i += 1; continue }
            var b = i; while b + 1 < N && netPAng[pids[b + 1]] == nil { b += 1 }
            var lo = -1, hi = -1, k = 1
            while k <= N && lo < 0 { let j = ((i - k) % N + N) % N; if netPAng[pids[j]] != nil { lo = j }; k += 1 }
            k = 1
            while k <= N && hi < 0 { let j = (b + k) % N; if netPAng[pids[j]] != nil { hi = j }; k += 1 }
            if lo < 0 || hi < 0 { for j in i...b { netPAng[pids[j]] = Float(j) / Float(max(1, N)) * 6.2832 }; i = b + 1; continue }
            let a0 = netPAng[pids[lo]]!, a1 = netPAng[pids[hi]]!
            var gap = a1 - a0; while gap <= 0 { gap += 6.2832 }
            if lo == hi { gap = 6.2832 }
            for j in i...b { netPAng[pids[j]] = fmodf(a0 + gap * Float(j - i + 1) / Float(b - i + 2), 6.2832) }
            i = b + 1
        }
        if N > 0 { relaxRing(&netPAng, 6.2832 / Float(N) * 0.7) }
    }
    do { let n = up(L, "pc", .ico, .pc, V3(), S3(6), C_CYAN); n.glow = 1; n.label = S.host; n.lp = 9; n.cnt = N }
    for (i, pid) in pids.enumerated() {
        let p = S.get(pid)!; let a = netPAng[pid] ?? Float(i) / Float(max(1, N)) * 6.2832; ang[pid] = a
        let pos = V3(Rp * cos(a), 0, Rp * sin(a)); let key = "n:\(pid)"
        let ls = SM_listen[pid] ?? [], rs = SM_remote[pid] ?? []
        let n = up(L, key, .octa, .proc, pos, S3(procSize(p) + 0.3), nameColor(p.name)); n.pid = pid; n.name = p.name; n.label = p.name
        let r = procRate(pid)
        n.glow = 0.4 + min(1, Float((r.nin + r.nout) / 200000)); n.lp = 1 + Float(rs.count) * 0.3 + Float(ls.count) * 0.05
        lanes.append(mkLane("spoke:\(pid)", "pc", key, C_DEEP, w: 0.5, tree: true))
        let MAXL = 9
        for j in 0..<min(ls.count, MAXL) {
            let x = ls[j]; let more = (j == MAXL - 1 && ls.count > MAXL) ? ls.count - MAXL + 1 : 0
            let col = more > 0 ? C_BLUE : x.proto == 1 ? C_UDP : (isLoop(x.addr) ? C_SAFE : C_WARN)
            let pk = "port:\(pid):\(x.proto == 1 ? "UDP" : "TCP"):\(x.port)"
            let q = up(L, pk, x.proto == 1 ? .tetra : .box, .port, V3(pos.x, 3.6 + Float(j) * 2.3, pos.z), S3(more > 0 ? 1.1 : 0.85), col, pos)
            q.owner = key; q.name = p.name; q.pid = pid; q.port = x.port; q.proto = x.proto; q.s1 = x.addr; q.more = more; q.glow = 0.7; q.lp = 0.2
            q.label = more > 0 ? "+\(more) more" : "\(x.port)" + (svcName(x.port).isEmpty ? "" : " " + svcName(x.port))
        }
    }
    struct Host { var ip = ""; var conns = 0; var pids = Set<Int32>(); var sx: Float = 0, sz: Float = 0 }
    var hosts: [String: Host] = [:]
    for (pid, rs) in SM_remote { guard let a = ang[pid] else { continue }
        for c in rs { var h = hosts[c.ra] ?? Host(); h.ip = c.ra; h.conns += 1; h.pids.insert(pid); h.sx += cos(a); h.sz += sin(a); hosts[c.ra] = h } }
    let hl = hosts.values.sorted { $0.ip < $1.ip }
    let rhT = max(Rp + 58, Float(hl.count) * 6 / 6.2832)
    if netRh < rhT || netRh > rhT * 1.25 { netRh = rhT }
    let Rh = netRh; L.ext = Rh
    // a host keeps its angle; a new one appears beside the processes that talk to it
    var keepH: [String: Float] = [:]
    for h in hl { keepH[h.ip] = netHAng[h.ip] ?? (atan2(h.sz, h.sx) + (h.sx == 0 && h.sz == 0 ? Float(fnv(h.ip) % 628) / 100 : 0)) }
    netHAng = keepH
    if !hl.isEmpty { relaxRing(&netHAng, 6.2832 / Float(hl.count) * 0.6) }
    for h in hl {
        let a = netHAng[h.ip] ?? 0
        let priv = isPrivate(h.ip)
        // the height level comes from the address, not from a place in a sorted list, so a new neighbour does not move it
        let n = up(L, "host:" + h.ip, .ico, .host, V3(Rh * cos(a), 16 + Float(fnv(h.ip) % 3) * 11, Rh * sin(a)), S3(1.3 + min(2, Float(h.conns) * 0.25)), priv ? C_SAFE : C_CYAN)
        n.glow = 0.7; n.label = h.ip; n.s1 = h.ip; n.cnt = h.conns; n.more = h.pids.count; n.lp = 0.8 + Float(h.conns) * 0.2
    }
    for (pid, rs) in SM_remote {
        guard ang[pid] != nil, let p = S.get(pid) else { continue }
        var per: [String: [SConn]] = [:]; for c in rs { per[c.ra, default: []].append(c) }
        for (ip, cs) in per {
            let rp = cs[0].rp
            let l = mkLane("c:\(pid):\(ip)", "n:\(pid)", "host:" + ip, cs[0].proto == "UDP" ? C_UDP : C_CYAN, w: 0.55, lift: 0.22)
            var bi = 0.0, bo = 0.0; for c in cs { if let r = connRate[c.key] { bi += r.0; bo += r.1 } }
            l.out = capOn() ? 0 : bo; l.inn = capOn() ? 0 : bi
            l.proto = cs[0].proto + (svcName(rp).isEmpty ? "" : " · " + svcName(rp)) + " :\(rp)" + (cs.count > 1 ? " x\(cs.count)" : ""); l.from = p.name; l.to = ip
            lanes.append(l)
        }
    }
    for x in SM_loop.values where x.kind == "loopback TCP" {
        guard let a = S.get(x.a), let b = S.get(x.b), ang[x.a] != nil, ang[x.b] != nil else { continue }
        let l = mkLane("ipc:\(x.a)-\(x.b)", "n:\(x.a)", "n:\(x.b)", C_UDP, w: 0.6, lift: 0.28)
        l.out = x.bytes / 2; l.inn = x.bytes / 2; l.proto = "loopback TCP x\(x.n)"; l.from = a.name; l.to = b.name; lanes.append(l)
    }
    endNodes(L); setLanes(L, lanes)
}

// ================================================================ memory view (treemap)
struct Group { var name = ""; var v = 0.0; var pids: [Int32] = []; var misc = false }
var ramGroups: [String: Group] = [:]
struct TItem { var v: Double; var kind: Int; var g: String = ""; var pid: Int32 = 0 }   // kind 0 group, 1 other, 2 free, 3 pid, 4 rest
struct TRect { var it: TItem; var x: Float, z: Float, w: Float, d: Float }
func treemap(_ items: [TItem], _ b: Int, _ e: Int, _ x: Float, _ z: Float, _ w: Float, _ d: Float, _ out: inout [TRect]) {
    if e <= b { return }; if e - b == 1 { out.append(TRect(it: items[b], x: x, z: z, w: w, d: d)); return }
    var tot = 0.0; for i in b..<e { tot += items[i].v }
    var acc = items[b].v; var i = b + 1
    while i < e - 1 && acc + items[i].v / 2 < tot / 2 { acc += items[i].v; i += 1 }
    let f = Float(acc / max(tot, 1e-9))
    if w >= d { treemap(items, b, i, x, z, w * f, d, &out); treemap(items, i, e, x + w * f, z, w * (1 - f), d, &out) }
    else { treemap(items, b, i, x, z, w, d * f, &out); treemap(items, i, e, x, z + d * f, w, d * (1 - f), &out) }
}
func buildRam() {
    guard let S = S else { return }
    let L = LY[2]; L.gen += 1; L.ext = 125; ramGroups = [:]; var sum = 0.0
    for p in S.procs where p.rss > 0 { var g = ramGroups[p.name] ?? Group(name: p.name); g.v += Double(p.rss); g.pids.append(p.pid); ramGroups[p.name] = g; sum += Double(p.rss) }
    var gl = ramGroups.values.sorted { $0.v > $1.v }
    if gl.count > 70 {
        var m = Group(); m.misc = true; m.name = "\(gl.count - 70) smaller apps"
        for g in gl[70...] { m.v += g.v; m.pids += g.pids }
        gl = Array(gl[0..<70]); ramGroups[m.name] = m; gl.append(m)
    }
    var items = gl.map { TItem(v: $0.v, kind: 0, g: $0.name) }
    let used = Double(S.memTotal) - Double(S.memFree), other = max(0, used - sum)
    if other > 0 { items.append(TItem(v: other, kind: 1)) }
    items.append(TItem(v: max(1, Double(S.memFree)), kind: 2))
    items.sort { $0.v > $1.v }
    let W: Float = 170; var rects: [TRect] = []; treemap(items, 0, items.count, -W / 2, -W / 2, W, W, &rects)
    let tot = items.reduce(0) { $0 + $1.v }; func H(_ v: Double) -> Float { 1.2 + 46 * Float((v / tot).squareRoot()) }
    var selGroup = ""
    if sel.hasPrefix("g:") { selGroup = String(sel.dropFirst(2)) }
    else if sel.hasPrefix("rp:"), let pid = Int32(sel.dropFirst(3)), let p = S.get(pid) {
        selGroup = p.name
        if !gl.contains(where: { !$0.misc && $0.name == selGroup }), let m = gl.first(where: { $0.misc && $0.pids.contains(pid) }) { selGroup = m.name }
    }
    func box(_ key: String, _ kind: Kind, _ x: Float, _ z: Float, _ w: Float, _ d: Float, _ h: Float, _ c: Col, _ pad: Float, _ spawn: V3?) -> Node {
        up(L, key, .box, kind, V3(x + w / 2, -30 + h / 2, z + d / 2), V3(max(0.2, w - pad), h, max(0.2, d - pad)), c, spawn)
    }
    for r in rects {
        if r.it.kind == 2 { let n = box("free", .free, r.x, r.z, r.w, r.d, 0.6, C_DEEP, 0.5, nil); n.label = "FREE " + fmtB(r.it.v); n.lp = 5; n.glow = 0.25; n.v = r.it.v }
        else if r.it.kind == 1 { let n = box("other", .other, r.x, r.z, r.w, r.d, H(r.it.v) * 0.5, C_BLUE, 0.5, nil); n.label = "KERNEL · CACHE " + fmtB(r.it.v); n.lp = 4; n.glow = 0.3; n.v = r.it.v }
        else if let g = ramGroups[r.it.g] {
            let col = g.misc ? C_BLUE : nameColor(g.name)
            if g.name == selGroup && g.pids.count > 1 {
                var sub: [TItem] = []; for pid in g.pids { if let p = S.get(pid) { sub.append(TItem(v: max(1, Double(p.rss)), kind: 3, g: g.name, pid: pid)) } }
                sub.sort { $0.v > $1.v }
                var sr: [TRect] = []; treemap(sub, 0, sub.count, r.x + 0.4, r.z + 0.4, r.w - 0.8, r.d - 0.8, &sr); let c0 = V3(r.x + r.w / 2, -30, r.z + r.d / 2)
                for q in sr { guard let p = S.get(q.it.pid) else { continue }
                    let n = box("rp:\(p.pid)", .proc, q.x, q.z, q.w, q.d, H(Double(p.rss)) + 1.5, mix(nameColor(p.name), C_WHITE, 0.25), 0.25, c0)
                    n.pid = p.pid; n.name = p.name; n.label = "\(p.pid) · " + fmtB(Double(p.rss)); n.lp = 3 + Float(Double(p.rss) / g.v); n.glow = 0.8 }
            } else {
                let n = box("g:" + g.name, .group, r.x, r.z, r.w, r.d, H(g.v), col, 0.5, nil)
                n.name = g.name; n.label = g.name + " " + fmtB(g.v); n.lp = Float(g.v / tot * 40); n.v = g.v; n.cnt = g.pids.count; n.glow = 0.5
            }
        }
    }
    endNodes(L); setLanes(L, [])
}

// ================================================================ time-window statistics
func diskLive() -> Bool { nowSec() - lastDiskT < 5 }
func pastSnap() -> Snapshot? {
    guard let S = S else { return nil }; var best: Snapshot? = nil
    for h in hist { if h.t <= S.t - Double(winSec) + 0.5 { best = h } else { break } }
    if best == nil { best = hist.first }
    return best === S ? nil : best
}
struct IoWin { var rd = 0.0, wr = 0.0, dws = 0.0, dfp = 0.0, nin = 0.0, nout = 0.0; var ok = false, netOk = false }
func ioWin(_ pid: Int32, _ past: Snapshot?) -> IoWin {
    var w = IoWin(); guard let S = S, let c = S.get(pid), let past = past, let o = past.get(pid), abs(o.start - c.start) < 1 else { return w }
    w.ok = c.hasIO && o.hasIO || c.rss > 0
    if c.hasIO && o.hasIO { w.rd = c.diskR >= o.diskR ? Double(c.diskR - o.diskR) : 0; w.wr = c.diskW >= o.diskW ? Double(c.diskW - o.diskW) : 0 }
    w.dws = Double(c.rss) - Double(o.rss); w.dfp = Double(c.footprint) - Double(o.footprint)
    if let a = S.procNet[pid], let b = past.procNet[pid] { w.netOk = true; w.nin = a.0 >= b.0 ? Double(a.0 - b.0) : 0; w.nout = a.1 >= b.1 ? Double(a.1 - b.1) : 0 }
    return w
}
struct NetWin { var inn = 0.0, out = 0.0; var ev = 0; var per: [String: (Double, Double)] = [:] }
/// Captured traffic in the window: by remote endpoint for a process, by process for a host, by process overall.
func netWin(_ pid: Int32, _ host: String) -> NetWin {
    var w = NetWin(); let t0 = nowSec() - Double(winSec)
    for f in flowHist.reversed() {
        if f.t < t0 { break }
        if pid >= 0 && f.pid != pid { continue }; if !host.isEmpty && f.rip != host { continue }
        if f.out { w.out += Double(f.bytes) } else { w.inn += Double(f.bytes) }; w.ev += f.n
        let k = pid >= 0 ? "\(f.rip):\(f.rp) \(protoName(f.proto))" : "\(S?.get(f.pid)?.name ?? "?") \(f.pid)"
        var e = w.per[k] ?? (0, 0); if f.out { e.1 += Double(f.bytes) } else { e.0 += Double(f.bytes) }; w.per[k] = e
    }
    return w
}
/// Without capture: nettop's cumulative per-connection counters, differenced over the window (exact bytes, no packet counts).
func nettopWin(_ pid: Int32, _ host: String) -> NetWin {
    var w = NetWin(); guard let S = S, let past = pastSnap() else { return w }
    var old: [String: (UInt64, UInt64)] = [:]; for c in past.conns { old[c.key] = (c.bin, c.bout) }
    for c in S.conns {
        if pid >= 0 && c.pid != pid { continue }; if !host.isEmpty && c.ra != host { continue }
        if isAny(c.ra) && host.isEmpty && pid < 0 { continue }
        let o = old[c.key] ?? (c.bin, c.bout)
        let di = Double(c.bin >= o.0 ? c.bin - o.0 : 0), dout = Double(c.bout >= o.1 ? c.bout - o.1 : 0)
        if di + dout == 0 { continue }
        w.inn += di; w.out += dout
        let k = pid >= 0 ? "\(c.ra):\(c.rp) \(c.proto)" : "\(S.get(c.pid)?.name ?? "?") \(c.pid)"
        var e = w.per[k] ?? (0, 0); e.0 += di; e.1 += dout; w.per[k] = e
    }
    return w
}
func diskWin(_ pid: Int32, _ path: String) -> NetWin {
    var w = NetWin(); let t0 = nowSec() - Double(winSec)
    for d in diskHist.reversed() {
        if d.t < t0 { break }
        if pid >= 0 && d.pid != pid { continue }; if !path.isEmpty && d.path != path { continue }
        w.inn += Double(d.rd); w.out += Double(d.wr); w.ev += 1
        let k = pid >= 0 ? (d.path.isEmpty ? "(no path)" : d.path) : "\(S?.get(d.pid)?.name ?? "?") \(d.pid)"
        var e = w.per[k] ?? (0, 0); e.0 += Double(d.rd); e.1 += Double(d.wr); w.per[k] = e
    }
    return w
}

// ================================================================ files view
func indexFiles() {
    filesByPid = [:]; fileOwners = [:]
    guard let fh = FH else { return }
    for h in fh { filesByPid[h.pid, default: []].append(h.path); fileOwners[h.path, default: []].append(h.pid) }
}
func buildFiles() {
    guard let S = S else { return }
    let L = LY[3]; L.gen += 1; var lanes: [Lane] = []; let live = diskLive()
    var pids: [Int32] = []
    for p in S.procs { let r = procRate(p.pid); if filesByPid[p.pid] != nil || r.rd + r.wr > 50000 { pids.append(p.pid) } }
    pids.sort { let na = S.get($0)!.name.lowercased(), nb = S.get($1)!.name.lowercased(); return na != nb ? na < nb : $0 < $1 }
    let N = max(1, pids.count); let Rp = max(46, Float(N) * 4.2 / 6.2832); var ang: [Int32: Float] = [:], ppos: [Int32: V3] = [:]
    do { let n = up(L, "disk", .ico, .disk, V3(), S3(6), C_BLUE); n.glow = 1; n.label = "DISK"; n.lp = 9; n.cnt = FH?.count ?? 0 }
    for (i, pid) in pids.enumerated() {
        let p = S.get(pid)!; let a = Float(i) / Float(N) * 6.2832; ang[pid] = a
        let pos = V3(Rp * cos(a), 0, Rp * sin(a)); ppos[pid] = pos; let key = "f:\(pid)"
        let nf = filesByPid[pid]?.count ?? 0; let r = procRate(pid)
        let n = up(L, key, .octa, .proc, pos, S3(0.6 + log10(1 + Float(nf)) * 0.6), nameColor(p.name)); n.pid = pid; n.name = p.name; n.label = p.name; n.cnt = nf
        n.glow = 0.4 + min(1, Float((r.rd + r.wr) / 200000)); n.lp = 1 + log10(1 + Float(nf)) + (r.rd + r.wr > 50000 ? 1 : 0)
        let l = mkLane("d:\(pid)", key, "disk", C_DEEP, w: 0.5); l.out = live ? 0 : r.wr; l.inn = live ? 0 : r.rd
        l.proto = "disk I/O (process total)"; l.from = p.name; l.to = "disk"; lanes.append(l)
    }
    // files held open by two or more processes
    struct Sh { var path: String; var owners: [Int32] = []; var sx: Float = 0, sz: Float = 0 }
    var sh: [Sh] = []
    for (path, ow) in fileOwners {
        var s = Sh(path: path)
        for pid in ow where ang[pid] != nil && !s.owners.contains(pid) { s.owners.append(pid); s.sx += cos(ang[pid]!); s.sz += sin(ang[pid]!) }
        if s.owners.count >= 2 { sh.append(s) }
    }
    sh.sort { $0.owners.count != $1.owners.count ? $0.owners.count > $1.owners.count : $0.path < $1.path }
    if sh.count > 40 { sh = Array(sh[0..<40]) }
    sh.sort { atan2($0.sz, $0.sx) < atan2($1.sz, $1.sx) }
    let Rh = max(Rp + 58, Float(sh.count) * 6 / 6.2832); L.ext = Rh
    for (i, s) in sh.enumerated() {
        let a = -Float.pi + (Float(i) + 0.5) / Float(sh.count) * 6.2832; let k = s.owners.count
        let n = up(L, "file:" + s.path, .box, .file, V3(Rh * cos(a), 16 + Float(i % 3) * 11, Rh * sin(a)), S3(1.2 + min(2, Float(k) * 0.25)), C_SAFE)
        n.s1 = s.path; n.label = (s.path as NSString).lastPathComponent; n.cnt = k; n.lp = 0.6 + Float(k) * 0.3; n.glow = 0.6
        for j in 0..<min(k, 6) { lanes.append(mkLane("fl:\(s.owners[j]):" + s.path, "f:\(s.owners[j])", "file:" + s.path, C_CYAN, w: 0.2, lift: 0.2, tree: true)) }
    }
    // the selected process fans out into its own files (capped so the ring stays readable)
    var sp: Int32 = -1
    if sel.hasPrefix("f:") { sp = Int32(sel.dropFirst(2)) ?? -1 } else if sel.hasPrefix("pf:") { sp = Int32(sel.dropFirst(3).prefix { $0 != ":" }) ?? -1 }
    if sp >= 0, let pos = ppos[sp], let fs = filesByPid[sp] {
        let own = "f:\(sp)"
        for (i, path) in fs.prefix(160).enumerated() {
            let r = 1.7 * sqrt(Float(i) + 1), a = Float(i) * 2.39996
            let ext = (path as NSString).pathExtension
            let key = "pf:\(sp):" + path
            let n = up(L, key, .box, .file, V3(pos.x + r * cos(a), 7 + sqrt(Float(i)) * 1.1, pos.z + r * sin(a)), S3(0.75), mix(nameColor(ext), C_WHITE, 0.2), pos)
            n.owner = own; n.s1 = path; n.label = (path as NSString).lastPathComponent; n.lp = 0.3; n.pid = sp; n.glow = 0.7; n.cnt = fileOwners[path]?.count ?? 1
            lanes.append(mkLane("pfl:\(sp):" + path, own, key, C_BLUE, w: 0.5, tree: true))
        }
    }
    endNodes(L); setLanes(L, lanes)
}

// ================================================================ focus / selection / rebuild
func computeFocus() {
    let L = LY[view]; focus = []; hasFocus = false
    if !query.isEmpty {
        hasFocus = true
        for (k, n) in L.nodes where !n.name.isEmpty && n.name.lowercased().contains(query) { focus.insert(k) }
        if !sel.isEmpty { focus.insert(sel) }; return
    }
    if sel.isEmpty || view == 2 || view == 4 { return }
    hasFocus = true; focus.insert(sel)
    if let sn = L.nodes[sel], !sn.owner.isEmpty { focus.insert(sn.owner) }
    for (k, n) in L.nodes where n.owner == sel { focus.insert(k) }
    for l in L.lanes.values { if l.a == sel { focus.insert(l.b) }; if l.b == sel { focus.insert(l.a) } }
    if view == 0 && sel.hasPrefix("p:"), let S = S, let pid = Int32(sel.dropFirst(2)) {
        func down(_ p: Int) { for k in L.kids[p] ?? [] { focus.insert("p:\(k)"); down(k) } }
        down(Int(pid)); var p = S.get(pid); var guardN = 0
        if let pp = p, pp.ppid > 1 { for k in L.kids[Int(pp.ppid)] ?? [] { focus.insert("p:\(k)") } }
        while let pp = p, pp.ppid > 1, let par = S.get(pp.ppid), guardN < 64 { focus.insert("p:\(pp.ppid)"); p = par; guardN += 1 }
    }
}
func rebuild() {
    guard S != nil else { return }
    let t = nowSec(), dts = t - capAccT
    if dts > 0.8 {
        capRate = [:]; var n = 0.0
        for (pid, a) in capAcc { capRate[pid] = (a.0 / dts, a.1 / dts); n += a.2 }
        capPps = Int(n / dts); capAcc = [:]; capAccT = t
    }
    buildSM(); capDirty = false
    switch view { case 0: buildProc(); case 1: buildNet(); case 3: buildFiles(); case 4: buildDisks(); case 5: buildDevs(); case 6: buildTrace(); default: buildRam() }
    computeFocus()
    let L = LY[view]
    if !L.framed && L.ext > 0 {
        L.framed = true
        if sel.isEmpty {
            flyT = V3(0, view == 2 || view == 4 ? -20 : 10, 0)
            flyDist = min(1500, L.ext * (view == 2 || view == 4 ? 1.9 : view == 1 || view == 3 ? 1.8 : 1.15))
            if view == 6 {   // the chain is framed in the part of the window the panel leaves free
                let pf = min(Float(0.6), (min(500, G.LW * 0.46) + 24) / G.LW), kx = tan(FOV / 2) * G.LW / G.LH
                flyDist = max(120, L.ext / ((1 - pf) * 0.86 * kx))
                flyT = V3(pf * kx * flyDist, 4, 0)
            }
            flying = true
        }
    }
}
func selectKey(_ key: String, fly: Bool = true) {
    if key.hasPrefix("act:") { requestAction(key); return }
    if key.hasPrefix("dkroot:") { diskRoot = String(key.dropFirst(7)); sel = ""; LY[4].framed = false; rebuild(); return }
    if key.hasPrefix("hexmem:") { hexOpenMem(Int32(key.dropFirst(7)) ?? -1); return }
    if key.hasPrefix("hexpkt:") {
        let r = String(key.dropFirst(7))
        if r.hasPrefix("pid:") { hexOpenPkts(Int32(r.dropFirst(4)) ?? -1, "") }
        else if r.hasPrefix("ip:") { hexOpenPkts(-1, String(r.dropFirst(3))) }
        else if r.hasPrefix("port:") && r.count > 9 { hexOpenPkts(-1, "", port: Int(r.dropFirst(9)) ?? -1, proto: r.dropFirst(5).hasPrefix("UDP") ? 17 : 6) }
        else { hexOpenPkts(-1, "") }
        return
    }
    if key == "hexports" { hexClose(); hexMode = 3; portScroll = 0; listCur = 0; return }
    if key.hasPrefix("size:") { procSizeMode = max(0, min(2, Int(key.dropFirst(5)) ?? 0)); rebuild(); return }
    if key == "hexlanes" { hexClose(); if procSizeMode == 2 { laneSort = 4 } else if laneSort == 4 { laneSort = 0 }; hexMode = 4; portScroll = 0; listCur = 0; return }
    if key == "dkrescan" { Disks.shared.rescanAll(); diskRoot = ""; sel = ""; return }
    if view == 6 { sel = key; if !key.isEmpty { trSel = -1 }; trDetScroll = 0; computeFocus(); return }
    sel = key
    if S != nil { switch view { case 0: buildProc(); case 2: buildRam(); case 3: buildFiles(); case 4: buildDisks(); default: break } }
    computeFocus()
    if fly, let n = LY[view].nodes[key] { flyT = n.tpos; flyDist = view == 2 || view == 4 ? 90 : 48; flying = true }
}
func setView(_ v: Int, _ key: String = "") {
    // remember the camera of the view we leave
    let o = LY[view]; o.camT = camT; o.camYaw = camYaw; o.camPitch = camPitch; o.camDist = camDist; o.hasCam = true
    view = v; parts = []; hov = ""; hovPart = -1; sel = ""
    let L = LY[v]
    if L.hasCam && key.isEmpty { camT = L.camT; camYaw = L.camYaw; camPitch = L.camPitch; camDist = L.camDist; flyT = camT; flyDist = camDist; flying = false; rebuild() }
    else { L.framed = false; rebuild() }
    if !key.isEmpty { selectKey(key) }
}

// ================================================================ frame: simulation + 3D geometry
func bez(_ A: V3, _ C: V3, _ B: V3, _ t: Float) -> V3 { let u = 1 - t; return A * (u * u) + C * (2 * u * t) + B * (t * t) }
func ctrlPt(_ l: Lane, _ A: V3, _ B: V3) -> V3 { var c = (A + B) * 0.5; if l.lift != 0 { c.y += l.lift * len(A - B) }; return c }
func pps(_ r: Double) -> Float { r <= 0 ? 0 : min(16, 0.35 + log10(1 + Float(r) / 512) * 2.6) }
func spawnPart(_ L: Layer, _ l: Lane, _ dir: Int, _ bytes: Double, _ f: Flow? = nil) {
    if parts.count >= 7000 { return }
    guard let A = L.nodes[l.a], let B = L.nodes[l.b] else { return }
    let ln = len(A.pos - B.pos)
    var p = Part(lane: l.key, dir: dir, bytes: bytes, t: 0, sp: min(1.5, max(0.22, 42 / (ln + 1))) * (0.8 + Float.random(in: 0..<0.4)))
    if let f = f { p.real = true; p.flow = f }
    parts.append(p)
}

func pickHover() {
    hov = ""; hovPart = -1; if UIS.mouseOverUi { return }
    let L = LY[view]
    var best: Float = 14
    for (i, p) in parts.enumerated() { if let (sx, sy) = project(p.p) { let d = hypot(sx - UIS.mouseX, sy - UIS.mouseY); if d < best { best = d; hovPart = i } } }
    let f = norm(camT - camEye), r = norm(simd_cross(f, V3(0, 1, 0))), u = simd_cross(r, f)
    let th = tan(FOV / 2), nx = (UIS.mouseX / G.LW * 2 - 1) * th * (G.LW / G.LH), ny = (1 - UIS.mouseY / G.LH * 2) * th
    let d = norm(f + r * nx + u * ny); var bt: Float = 1e9
    for (k, n) in L.nodes where !n.dead {
        var t: Float = -1
        if n.shape == .box {
            let lo = n.pos - n.scale * 0.5, hi = n.pos + n.scale * 0.5; var t0: Float = 0, t1: Float = 1e9; var ok = true
            for i in 0..<3 where ok {
                if abs(d[i]) < 1e-6 { if camEye[i] < lo[i] || camEye[i] > hi[i] { ok = false }; continue }
                var a = (lo[i] - camEye[i]) / d[i], b = (hi[i] - camEye[i]) / d[i]; if a > b { swap(&a, &b) }
                t0 = max(t0, a); t1 = min(t1, b); if t0 > t1 { ok = false }
            }
            if ok { t = t0 }
        } else {
            let oc = n.pos - camEye; let tc = simd_dot(oc, d)
            if tc > 0 { let d2 = simd_dot(oc, oc) - tc * tc, rr = n.scale.x * 1.15 + tc * 0.004; if d2 < rr * rr { t = tc } }
        }
        if t >= 0 && t < bt { bt = t; hov = k }
    }
}

func frameScene(_ dt: Float) {
    let model = Model.shared
    Packets.shared.demoTick()
    model.wantFiles = view == 3
    Disks.shared.wanted = view == 4
    Devices.shared.wanted = view == 5
    if let d = Devices.shared.latest(), d !== DV, !paused { DV = d; devHist.append(d); if devHist.count > 70 { devHist.removeFirst() }; if view == 5 && S != nil { rebuild() } }
    if Disks.shared.changed() && view == 4 && S != nil { rebuild() }
    if !paused {
        if let s = model.latest(), s !== S {
            S = s; hist.append(s); if hist.count > 70 { hist.removeFirst() }
            rebuild()
            if pendingSel >= 0 { let k = pendingSel; pendingSel = -1; if view != 0 { setView(0, "p:\(k)") } else { selectKey("p:\(k)") } }
        }
        if let (fh, gen) = model.latestFiles(), gen != filesGen {
            let first = FH == nil || FH!.isEmpty; filesGen = gen; FH = fh; indexFiles()
            if view == 3 && S != nil { if first { LY[3].framed = false }; rebuild() }
        }
    }
    let L = LY[view]
    do {
        let (inF, din) = model.takeFlows()
        if !paused, let S = S {
            let now = nowSec()
            for var d in din {
                d.t = now; lastDiskT = now; diskHist.append(d)
                guard view == 3 || view == 0, d.pid > 0 else { continue }
                let pk = "\(d.pid)"
                guard let l = L.lanes["pfl:\(pk):" + d.path] ?? L.lanes["d:" + pk] ?? L.lanes["io:" + pk] else { continue }
                for k in 0..<2 { let b = k == 1 ? d.wr : d.rd; if b == 0 { continue }; let before = parts.count; spawnPart(L, l, k == 1 ? 1 : -1, Double(b))
                    if parts.count > before { parts[parts.count - 1].real = true; parts[parts.count - 1].disk = true; parts[parts.count - 1].dpath = d.path; parts[parts.count - 1].flow = Flow(t: now, pid: d.pid, proto: 0, lip: "", lp: 0, rip: "", rp: 0, out: k == 1, n: 1, bytes: b, iface: "") } }
            }
            while let f = flowHist.first, now - f.t > 62 { flowHist.removeFirst() }
            while let f = diskHist.first, now - f.t > 62 { diskHist.removeFirst() }
            for var f in inF {
                guard f.pid > 0, S.get(f.pid) != nil else { f.t = now; flowHist.append(f); continue }
                var a = capAcc[f.pid] ?? (0, 0, 0); if f.out { a.1 += Double(f.bytes) } else { a.0 += Double(f.bytes) }; a.2 += Double(f.n); capAcc[f.pid] = a
                let k = "\(f.pid)|\(f.rip)|\(f.rp)|\(f.lp)"
                if capLive[k] == nil { capLive[k] = Live(pid: f.pid, proto: f.proto, lp: f.lp, rp: f.rp, lip: f.lip, rip: f.rip, t: now); capDirty = true } else { capLive[k]!.t = now }
                f.t = now; flowHist.append(f); pending.append(f)
            }
            if capDirty && now - lastDirtyT > 0.25 { lastDirtyT = now; rebuild() }
            var keep: [Flow] = []
            for f in pending {
                let lk = view == 0 ? "net:\(f.pid)" : view == 5 ? "" : "c:\(f.pid):\(f.rip)"
                if view < 2, let l = L.lanes[lk] { spawnPart(L, l, f.out ? 1 : -1, Double(f.bytes), f) }
                else if view == 5 { devSpawnFlow(f) }
                else if view < 2 && now - f.t < 1.5 { keep.append(f) }
            }
            pending = keep
        }
    }
    let k = 1 - exp(-dt * 5)
    if flying { camT = lerp(camT, flyT, k * 0.8); camDist += (flyDist - camDist) * k * 0.8; if len(camT - flyT) < 0.2 && abs(camDist - flyDist) < 0.5 { flying = false } }
    camEye = eyePos()
    VP = perspectiveRH(FOV, G.LW / G.LH, 0.5, 4000) * lookAtRH(camEye, camT, V3(0, 1, 0))
    pickHover()
    let g = G.gfx!
    if view == 6 { trSync(); trOrbs(dt) } else if TrShared.i.version() != trVer { trSync() }
    // grid
    for pass in 0..<2 {
        let div = pass == 1 ? 240 : 60; let c = pass == 1 ? hex(0x0f5c9a) : hex(0x1b8fd6); let f: Float = pass == 1 ? 0.12 : 0.32, y: Float = -32, h: Float = 1200
        for i in 0...div { let p = -h + 2 * h * Float(i) / Float(div); g.line(V3(p, y, -h), V3(p, y, h), c, f); g.line(V3(-h, y, p), V3(h, y, p), c, f) }
    }
    // nodes
    var dead: [String] = []
    for (key, n) in L.nodes {
        n.pos = lerp(n.pos, n.tpos, k); n.scale = lerp(n.scale, n.tscale, k); n.rot += n.spin * dt
        let target: Float = n.dead ? 0 : (hasFocus && !focus.contains(key) ? 0.1 : 1); n.op += (target - n.op) * k
        if n.dead && n.scale.x < 0.02 { dead.append(key); continue }
        let hi: Float = (key == sel ? 0.9 : 0) + (key == hov ? 0.5 : 0)
        let eo = min(1, (0.45 + n.glow * 0.5 + hi) * n.op), fo = min(0.85, (0.07 + n.glow * 0.16 + hi * 0.25) * n.op) * 0.55
        let ec = key == sel ? C_WHITE : n.color; let geo = GEO[n.shape.rawValue]; let cs = cos(n.rot), sn = sin(n.rot)
        var w = [V3](repeating: V3(), count: geo.v.count)
        for (i, gv) in geo.v.enumerated() { let v = gv * n.scale; w[i] = V3(n.pos.x + v.x * cs + v.z * sn, n.pos.y + v.y, n.pos.z - v.x * sn + v.z * cs) }
        for e in geo.e { g.line(w[e.0], w[e.1], ec, eo) }
        for t in geo.t { g.tri(w[t.0], n.color, fo); g.tri(w[t.1], n.color, fo); g.tri(w[t.2], n.color, fo) }
    }
    for d in dead { L.nodes[d] = nil }
    // lanes + estimated particles
    let slow: Float = hovPart >= 0 ? 0.08 : 1
    for l in L.lanes.values {
        guard let a = L.nodes[l.a], let b = L.nodes[l.b] else { continue }
        let A = a.pos, B = b.pos, C = ctrlPt(l, A, B)
        let on = !hasFocus || (focus.contains(l.a) && focus.contains(l.b))
        let f: Float = (on ? 1 : 0.05) * l.w * (hasFocus && on && !l.tree ? 1.6 : 1); l.vis = on ? 1 : 0.08
        let segs = l.lift != 0 ? 14 : 1; var prev = A
        for s in 1...segs { let q = bez(A, C, B, Float(s) / Float(segs)); g.line(prev, q, l.color, f); prev = q }
        if !paused {
            let po = pps(l.out), pi = pps(l.inn)
            if po > 0 { l.accO += Double(po * dt * slow); while l.accO >= 1 { l.accO -= 1; spawnPart(L, l, 1, l.out / Double(po)) } }
            if pi > 0 { l.accI += Double(pi * dt * slow); while l.accI >= 1 { l.accI -= 1; spawnPart(L, l, -1, l.inn / Double(pi)) } }
        }
    }
    // particles
    let fw = norm(camT - camEye), rt = norm(simd_cross(fw, V3(0, 1, 0))), upv = simd_cross(rt, fw)
    let hp = hovPart; hovPart = -1
    let hpp: Part? = hp >= 0 && hp < parts.count ? parts[hp] : nil
    var i = 0
    while i < parts.count {
        var p = parts[i]
        let isHov = hpp != nil && p.lane == hpp!.lane && p.t == hpp!.t && p.dir == hpp!.dir
        p.t += p.sp * dt * slow
        guard let l = L.lanes[p.lane], let a = L.nodes[l.a], let b = L.nodes[l.b], p.t < 1 else { parts[i] = parts[parts.count - 1]; parts.removeLast(); continue }
        p.p = bez(a.pos, ctrlPt(l, a.pos, b.pos), b.pos, p.dir > 0 ? p.t : 1 - p.t)
        parts[i] = p
        if isHov { hovPart = i }
        let c = isHov ? C_WHITE : (p.dir > 0 ? C_OUT : C_IN); let fade = min(1, p.t * 8, (1 - p.t) * 8) * l.vis
        let sz = (1.6 + log10(1 + Float(p.bytes) / 1024) * 1.1) * (isHov ? 2.2 : 1), hs = max(sz * 0.2, len(p.p - camEye) * 0.0028)
        let q = [p.p - rt * hs - upv * hs, p.p + rt * hs - upv * hs, p.p + rt * hs + upv * hs, p.p - rt * hs + upv * hs]
        let uv: [(Float, Float)] = [(-1, -1), (1, -1), (1, 1), (-1, 1)]
        for j in [0, 1, 2, 0, 2, 3] { g.VQ.append(Vtx(x: q[j].x, y: q[j].y, z: q[j].z, r: c.r * fade, g: c.g * fade, b: c.b * fade, u: uv[j].0, v: uv[j].1)) }
        i += 1
    }
}
var lastDirtyT = 0.0
