// Devices view: the IOKit registry (service plane) reduced to the hardware a person recognises, plus network neighbours
// (ARP / NDP tables) and default gateways hanging off the interface they are reached through.
// Traffic: per-interface byte counters (NET_RT_IFLIST2) and per-disk counters (IOBlockStorageDriver "Statistics").
import Foundation
import IOKit
import Darwin
import SystemConfiguration

struct Dev { var id: String; var name: String; var cls: String; var parent: Int; var bsd = ""; var counters = false; var cumIn: UInt64 = 0; var cumOut: UInt64 = 0
    var rateIn = 0.0, rateOut = 0.0; var ejectable = false; var detail = ""; var up = true }   // in = towards the Mac
struct Nb { var dev: Int; var ip: String; var mac: String; var gw: Bool }
final class DevSnap { var devs: [Dev] = []; var nbs: [Nb] = []; var t = 0.0; var gwIf = "" }
var DV: DevSnap? = nil
var devHist: [DevSnap] = []

final class Devices {
    static let shared = Devices()
    var wanted = false { didSet { if wanted && !started { started = true; Thread { self.loop() }.start() } } }
    private var started = false
    private let lock = NSLock(); private var snap: DevSnap? = nil
    private var tree: [Dev] = [], lastTree = -100.0
    func latest() -> DevSnap? { lock.lock(); defer { lock.unlock() }; return snap }
    func isPrimary(_ ifn: String) -> Bool { latest()?.gwIf == ifn }

    private func loop() {
        var prev: DevSnap? = nil
        while true {
            if !wanted && prev != nil { usleep(500000); continue }
            if nowSec() - lastTree > 10 { tree = walkRegistry(); lastTree = nowSec() }
            let s = DevSnap(); s.t = nowSec(); s.devs = tree
            // counters
            let ifs = Dictionary(interfaceCounters().map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
            let disks = diskStats()
            for i in s.devs.indices {
                if s.devs[i].cls == "Network", let c = ifs[s.devs[i].bsd] { s.devs[i].counters = true; s.devs[i].cumIn = c.ib; s.devs[i].cumOut = c.ob; s.devs[i].up = c.up }
                if s.devs[i].cls == "Storage", let d = disks[s.devs[i].bsd] { s.devs[i].counters = true; s.devs[i].cumIn = d.0; s.devs[i].cumOut = d.1 }   // read = towards the Mac
                if let p = prev, let o = p.devs.first(where: { $0.id == s.devs[i].id }), o.counters, s.devs[i].counters, s.t > p.t {
                    let dt = s.t - p.t
                    s.devs[i].rateIn = Double(s.devs[i].cumIn >= o.cumIn ? s.devs[i].cumIn - o.cumIn : 0) / dt
                    s.devs[i].rateOut = Double(s.devs[i].cumOut >= o.cumOut ? s.devs[i].cumOut - o.cumOut : 0) / dt
                }
            }
            // neighbours and gateways
            var byIf: [String: Int] = [:]; for (i, d) in s.devs.enumerated() where d.cls == "Network" { byIf[d.bsd] = i }
            let gws = gateways(); s.gwIf = gws.first?.1 ?? ""
            var seen = Set<String>()
            for (ip, mac, ifn) in neighbours() {
                guard let di = byIf[ifn], !seen.contains(ip) else { continue }; seen.insert(ip)
                s.nbs.append(Nb(dev: di, ip: ip, mac: mac, gw: gws.contains { $0.0 == ip }))
            }
            for (ip, ifn) in gws where !seen.contains(ip) { if let di = byIf[ifn] { s.nbs.append(Nb(dev: di, ip: ip, mac: "?", gw: true)); seen.insert(ip) } }
            lock.lock(); snap = s; lock.unlock(); prev = s
            sleep(1)
        }
    }

    // ---- IOKit
    private func prop(_ e: io_registry_entry_t, _ k: String) -> Any? { IORegistryEntryCreateCFProperty(e, k as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() }
    private func category(_ e: io_registry_entry_t, _ cls: String) -> (String, String, String)? {   // (category, display name, bsd)
        func conforms(_ c: String) -> Bool { IOObjectConformsTo(e, c) != 0 }
        var nameBuf = [CChar](repeating: 0, count: 128); IORegistryEntryGetName(e, &nameBuf); let regName = String(cString: nameBuf)
        if conforms("IOPlatformExpertDevice") { return nil }
        if conforms("IONetworkInterface") {
            let bsd = prop(e, "BSD Name") as? String ?? regName
            return ("Network", bsd + (scNames[bsd].map { " · " + $0 } ?? ""), bsd)
        }
        if conforms("IOMedia"), (prop(e, "Whole") as? Bool) == true {
            let bsd = prop(e, "BSD Name") as? String ?? ""
            let sz = (prop(e, "Size") as? NSNumber)?.doubleValue ?? 0
            return ("Storage", "\(bsd) · " + fmtB(sz) + (cls == "AppleAPFSMedia" ? " APFS container" : ""), bsd)
        }
        if conforms("IOUSBHostDevice") { return ("USB", prop(e, "USB Product Name") as? String ?? prop(e, "kUSBProductString") as? String ?? regName, "") }
        if cls.contains("XHCI") && !cls.contains("Port") { return ("USB", "USB controller (\(regName))", "") }
        if conforms("IOThunderboltController") { return ("Thunderbolt", "Thunderbolt controller", "") }
        if conforms("IOPCIDevice") { return ("PCI", "PCIe · " + regName, "") }
        if conforms("IOMobileFramebuffer") || conforms("IODisplayConnect") {
            var nm = "Display"
            if let a = prop(e, "DisplayAttributes") as? [String: Any], let p = a["ProductAttributes"] as? [String: Any], let n = p["ProductName"] as? String { nm = n }
            if nm == "Display" && regName.contains("disp") { nm = "Display (\(regName))" }
            return ("Display", nm, "")
        }
        if conforms("IOBluetoothHostController") { return ("Bluetooth", "Bluetooth controller", "") }
        if conforms("IOHIDDevice"), let p = prop(e, "Product") as? String, !p.isEmpty, (prop(e, "Built-In") as? Bool) != nil || prop(e, "Transport") != nil {
            let page = (prop(e, "PrimaryUsagePage") as? NSNumber)?.intValue ?? 0, usage = (prop(e, "PrimaryUsage") as? NSNumber)?.intValue ?? 0
            if page == 1 && [1, 2, 6].contains(usage) { return ("Input", p, "") }
        }
        return nil
    }
    private var scNames: [String: String] = [:]
    private func walkRegistry() -> [Dev] {
        // the names System Settings uses ("Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN")
        scNames = [:]
        for i in (SCNetworkInterfaceCopyAll() as? [SCNetworkInterface]) ?? [] {
            if let b = SCNetworkInterfaceGetBSDName(i) as String?, let n = SCNetworkInterfaceGetLocalizedDisplayName(i) as String? { scNames[b] = n }
        }
        var devs: [Dev] = []
        var model = "this Mac"
        let root = IORegistryGetRootEntry(kIOMainPortDefault)
        let pe = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        if pe != 0 { if let d = prop(pe, "model") as? Data { model = String(decoding: d.prefix { $0 != 0 }, as: UTF8.self) }; IOObjectRelease(pe) }
        devs.append(Dev(id: "mac", name: (S?.host ?? Host.current().localizedName ?? "Mac") + " · " + model, cls: "Mac", parent: -1))
        var seenUSB = Set<String>()
        func visit(_ e: io_registry_entry_t, _ parent: Int, _ depth: Int) {
            if depth > 40 || devs.count > 600 { return }
            var cbuf = [CChar](repeating: 0, count: 128); IOObjectGetClass(e, &cbuf); let cls = String(cString: cbuf)
            var here = parent
            if let (cat, name, bsd) = category(e, cls) {
                var eid: UInt64 = 0; IORegistryEntryGetRegistryEntryID(e, &eid)
                let key = cat + "|" + name + "|" + bsd
                if !(cat == "Input" && seenUSB.contains(key)) && !(cat == "Storage" && bsd.isEmpty) {
                    seenUSB.insert(key)
                    var d = Dev(id: "\(eid)", name: name, cls: cat, parent: parent, bsd: bsd)
                    d.ejectable = cat == "Storage" && ((prop(e, "Ejectable") as? Bool) == true || (prop(e, "Removable") as? Bool) == true)
                    if cat == "Storage", (prop(e, "Internal") as? Bool) == false || d.ejectable { d.detail = "external / removable" }
                    devs.append(d); here = devs.count - 1
                }
            }
            var it: io_iterator_t = 0
            if IORegistryEntryGetChildIterator(e, kIOServicePlane, &it) == KERN_SUCCESS {
                while case let c = IOIteratorNext(it), c != 0 { visit(c, here, depth + 1); IOObjectRelease(c) }
                IOObjectRelease(it)
            }
        }
        visit(root, 0, 0); IOObjectRelease(root)
        // drop controller-only branches that ended up with nothing interesting under them
        var keep = [Bool](repeating: true, count: devs.count)
        for (i, d) in devs.enumerated() where (d.cls == "PCI" || d.cls == "Thunderbolt" || d.name.hasPrefix("USB controller")) {
            keep[i] = devs.contains { $0.parent == i } || d.cls == "PCI"
        }
        var remap: [Int] = Array(repeating: -1, count: devs.count); var out: [Dev] = []
        for (i, d) in devs.enumerated() where keep[i] { remap[i] = out.count; out.append(d) }
        for i in out.indices { var p = devs[devs.firstIndex { $0.id == out[i].id }!].parent; while p >= 0 && remap[p] < 0 { p = devs[p].parent }; out[i].parent = p >= 0 ? remap[p] : (i == 0 ? -1 : 0) }
        return out
    }
    private func diskStats() -> [String: (UInt64, UInt64)] {
        var out: [String: (UInt64, UInt64)] = [:]
        var it: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOBlockStorageDriver"), &it) == KERN_SUCCESS else { return out }
        while case let d = IOIteratorNext(it), d != 0 {
            if let st = prop(d, "Statistics") as? [String: Any] {
                let r = (st["Bytes (Read)"] as? NSNumber)?.uint64Value ?? 0, w = (st["Bytes (Write)"] as? NSNumber)?.uint64Value ?? 0
                var cit: io_iterator_t = 0
                if IORegistryEntryGetChildIterator(d, kIOServicePlane, &cit) == KERN_SUCCESS {
                    while case let m = IOIteratorNext(cit), m != 0 { if let b = prop(m, "BSD Name") as? String { out[b] = (r, w) }; IOObjectRelease(m) }
                    IOObjectRelease(cit)
                }
            }
            IOObjectRelease(d)
        }
        IOObjectRelease(it)
        return out
    }
    // ---- neighbours (ARP for IPv4, NDP for IPv6) from the routing table
    func neighbours() -> [(String, String, String)] {
        var out: [(String, String, String)] = []
        for fam in [AF_INET, AF_INET6] {
            var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, fam, NET_RT_FLAGS, RTF_LLINFO]
            var len = 0; if sysctl(&mib, 6, nil, &len, nil, 0) != 0 || len == 0 { continue }
            var buf = [UInt8](repeating: 0, count: len); if sysctl(&mib, 6, &buf, &len, nil, 0) != 0 { continue }
            buf.withUnsafeBytes { raw in
                var off = 0
                while off + MemoryLayout<rt_msghdr>.size <= len {
                    let h = raw.loadUnaligned(fromByteOffset: off, as: rt_msghdr.self); if h.rtm_msglen == 0 { break }
                    var sa = off + MemoryLayout<rt_msghdr>.size; var ip = "", mac = "", ifn = ""
                    for bit in 0..<8 where (h.rtm_addrs & (1 << bit)) != 0 {
                        guard sa + 2 <= off + Int(h.rtm_msglen) else { break }
                        let slen = Int(raw[sa]), fam2 = Int32(raw[sa + 1])
                        if bit == 0 {   // RTA_DST
                            if fam2 == AF_INET { ip = ipString(raw, sa + 4, v6: false) } else if fam2 == AF_INET6 { ip = ipString(raw, sa + 8, v6: true) }
                        } else if bit == 1 && fam2 == AF_LINK {   // RTA_GATEWAY: sockaddr_dl
                            let idx = Int(raw[sa + 2]) | Int(raw[sa + 3]) << 8, nlen = Int(raw[sa + 5]), alen = Int(raw[sa + 6])
                            var nm = [CChar](repeating: 0, count: Int(IFNAMSIZ) + 1); if_indextoname(UInt32(idx), &nm); ifn = String(cString: nm)
                            if alen == 6 { mac = (0..<6).map { String(format: "%02x", raw[sa + 8 + nlen + $0]) }.joined(separator: ":") }
                        }
                        sa += slen > 0 ? (1 + ((slen - 1) | 3)) : 4
                    }
                    if !ip.isEmpty && !mac.isEmpty && !ifn.isEmpty && !ip.hasPrefix("224.") && !ip.hasPrefix("ff") && mac != "ff:ff:ff:ff:ff:ff" { out.append((ip, mac, ifn)) }
                    off += Int(h.rtm_msglen)
                }
            }
        }
        return out
    }
    func gateways() -> [(String, String)] {
        var out: [(String, String)] = []
        for a in [["-n", "get", "default"], ["-n", "get", "-inet6", "default"]] {
            let (st, o) = run("/sbin/route", a, timeout: 3); if st != 0 { continue }
            var gw = "", ifn = ""
            for l in o.split(separator: "\n") { let t = l.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("gateway:") { gw = String(t.dropFirst(8)).trimmingCharacters(in: .whitespaces) }
                if t.hasPrefix("interface:") { ifn = String(t.dropFirst(10)).trimmingCharacters(in: .whitespaces) } }
            if let p = gw.firstIndex(of: "%") { gw = String(gw[..<p]) }
            if validIp(gw) && !ifn.isEmpty { out.append((gw, ifn)) }
        }
        return out
    }
}

// ---------------------------------------------------------------- layout (same cone tree with the spine rule as the process view)
func devColor(_ c: String) -> Col {
    switch c { case "Network", "Bluetooth": return C_CYAN; case "Storage": return C_BLUE; case "USB", "Input": return C_UDP; case "Display": return C_WHITE; case "Thunderbolt": return C_SAFE; default: return nameColor(c) }
}
func buildDevs() {
    let L = LY[5]; L.gen += 1; var lanes: [Lane] = []
    guard let DV = DV else { endNodes(L); setLanes(L, lanes); return }
    let nd = DV.devs.count, n = nd + DV.nbs.count
    var es: [(String, Int)] = []
    for d in DV.devs { es.append(("dev:" + d.id, d.parent)) }
    for b in DV.nbs { es.append(("nb:" + b.ip, b.dev)) }
    var sig: UInt64 = 1469598103934665603; L.kids = [:]
    for i in 0..<n { if es[i].1 >= 0 { L.kids[es[i].1, default: []].append(i) }; sig = (sig ^ UInt64(fnv(es[i].0)) ^ (UInt64(es[i].1 + 1) << 32)) &* 1099511628211 }
    if sig != L.sig {
        L.lay = [:]; let LEAF: Float = 1.9, LEVEL: Float = 9
        func measure(_ id: Int) -> Lay {
            var o = Lay(); o.r = LEAF; var mx: Float = 0
            if let ks = L.kids[id] {
                var big = -1; var second: Float = 0
                for k in ks { let ko = measure(k); o.sum += ko.r * 2; if ko.r > mx { second = mx; mx = ko.r; big = k } else { second = max(second, ko.r) } }
                // a child with a large subtree goes straight above its parent and its siblings ring around it
                if ks.count >= 2 && mx > LEAF * 2.5 { o.spine = true; o.big = big; o.sum -= mx * 2; o.R = max(o.sum / 6.2832 * 1.08, mx + second + 0.6); o.r = o.R + second }
                else { o.R = ks.count == 1 ? 0 : max(o.sum / 6.2832 * 1.08, mx * 1.2 + 0.6); o.r = max(LEAF, o.R + mx) }
            }
            L.lay[id] = o; return o
        }
        func place(_ id: Int, _ at: V3) {
            guard var o = L.lay[id] else { return }; o.pos = at; L.lay[id] = o
            var a = Float(fnv(es[id].0) % 628) / 100; let R = o.R, sum = o.sum
            guard let ks = L.kids[id] else { return }
            let big = o.spine ? o.big : -1; if big >= 0 { place(big, V3(at.x, at.y + LEVEL, at.z)) }
            for k in ks where k != big { let half = (L.lay[k]?.r ?? LEAF) * 2 / max(sum, 0.001) * .pi; a += half; place(k, V3(at.x + R * cos(a), at.y + LEVEL, at.z + R * sin(a))); a += half }
        }
        var x: Float = 0; L.ext = 60
        for i in 0..<n where es[i].1 < 0 { let o = measure(i); place(i, V3(x, -20, 0)); L.ext = max(L.ext, x + o.r); x += o.r * 2 + 6 }
        L.sig = sig
    }
    // traffic flows along the connection path: every hop carries what the devices behind it moved
    var inn = [Double](repeating: 0, count: n), out = [Double](repeating: 0, count: n)
    for i in 0..<nd where DV.devs[i].counters { var p = i, g = 0; while p >= 0 && g < 64 { inn[p] += DV.devs[i].rateIn; out[p] += DV.devs[i].rateOut; p = es[p].1; g += 1 } }
    if capOn() && n > nd {
        var byIp: [String: Int] = [:]; var gw = -1
        for i in nd..<n { byIp[DV.nbs[i - nd].ip] = i; if gw < 0 && DV.nbs[i - nd].gw { gw = i } }
        let t0 = nowSec() - 1
        for f in flowHist.reversed() { if f.t < t0 { break }; let e = byIp[f.rip] ?? (isPrivate(f.rip) || isLoop(f.rip) ? -1 : gw); if e >= 0 { if f.out { out[e] += Double(f.bytes) } else { inn[e] += Double(f.bytes) } } }
    }
    for i in 0..<n {
        guard let li = L.lay[i] else { continue }
        let par = es[i].1; let sp = par >= 0 ? L.lay[par]?.pos : nil; let nk = L.kids[i]?.count ?? 0
        if i < nd {
            let d = DV.devs[i]; let root = d.parent < 0, disk = d.cls == "Storage"
            let size: Float = root ? 5 : (0.55 + (d.counters ? 0.6 : 0) + min(0.7, Float(nk) * 0.08)) * (disk ? 1.7 : 1)
            let q = up(L, es[i].0, root ? .ico : disk ? .box : .octa, .dev, li.pos, S3(size), !d.up && d.cls == "Network" ? C_WARN : root ? C_CYAN : devColor(d.cls), sp)
            q.name = d.name; q.label = d.name; q.s1 = d.id; q.cnt = i; q.glow = 0.35 + min(1, Float((inn[i] + out[i]) / 200000))
            q.lp = root ? 9 : (d.counters ? 4 : 0) + (nk > 0 ? 1 + min(2, Float(nk) * 0.2) : 0.3)
        } else {
            let b = DV.nbs[i - nd]
            let q = up(L, es[i].0, .tetra, .nb, li.pos, S3(b.gw ? 1.3 : 0.9), b.gw ? C_WARN : C_SAFE, sp)
            q.label = b.ip + (b.gw ? " gateway" : ""); q.s1 = b.ip; q.name = b.ip; q.cnt = i - nd; q.glow = 0.6; q.lp = b.gw ? 3 : 0.8
        }
        if par >= 0 {
            let l = mkLane("dl:" + es[i].0, es[par].0, es[i].0, C_BLUE, w: 0.5); l.out = out[i]; l.inn = inn[i]; l.tree = inn[i] + out[i] <= 0
            l.proto = i < nd ? "device traffic (driver counters)" : "captured network traffic"
            l.from = par < nd ? DV.devs[par].name : es[par].0; l.to = i < nd ? DV.devs[i].name : DV.nbs[i - nd].ip
            lanes.append(l)
        }
    }
    endNodes(L); setLanes(L, lanes)
}
func devSpawnFlow(_ f: Flow) {}   // device lanes are paced from per-hop totals in buildDevs (captured flows included)

func devWin(_ id: String) -> (Double, Double) {
    guard let DV = DV else { return (0, 0) }
    var past: DevSnap? = nil; for h in devHist { if h.t <= DV.t - Double(winSec) + 0.5 { past = h } else { break } }
    if past == nil { past = devHist.first }
    guard let c = DV.devs.first(where: { $0.id == id }), let o = past?.devs.first(where: { $0.id == id }), c.counters, o.counters else { return (0, 0) }
    return (Double(c.cumIn >= o.cumIn ? c.cumIn - o.cumIn : 0), Double(c.cumOut >= o.cumOut ? c.cumOut - o.cumOut : 0))
}
func devTip(_ n: Node) -> [TL] {
    guard let DV = DV else { return [] }
    if n.kind == .dev, n.cnt < DV.devs.count {
        let d = DV.devs[n.cnt]; var t = [TL(s: d.name, c: .cyan), TL(s: d.cls + (d.detail.isEmpty ? "" : " · " + d.detail), c: .text)]
        if d.counters { t.append(TL(s: "▼ \(fmtR(d.rateIn))   ▲ \(fmtR(d.rateOut))", c: .dim)) }
        if d.cls == "Network" && !d.up { t.append(TL(s: "interface is down", c: .warn)) }
        return t
    }
    if n.kind == .nb, n.cnt < DV.nbs.count { let b = DV.nbs[n.cnt]; return [TL(s: b.ip + (b.gw ? " · gateway" : ""), c: .cyan), TL(s: "MAC " + b.mac, c: .text)] + dnsTip(b.ip) }
    return []
}
func devPanel() {
    guard let DV = DV else { P(0, "Devices"); P(1, "Reading the device tree…"); return }
    if sel.hasPrefix("dev:") {
        let id = String(sel.dropFirst(4)); guard let idx = DV.devs.firstIndex(where: { $0.id == id }) else { sel = ""; computeFocus(); return }
        let d = DV.devs[idx]
        P(0, d.name); P(1, d.cls + (d.bsd.isEmpty ? "" : " · " + d.bsd) + (d.detail.isEmpty ? "" : " · " + d.detail)); P(1, "IORegistry entry \(d.id)")
        var acts = "SYSTEM INFORMATION|act:sysinfo:"
        if d.parent < 0 { acts += ";FLUSH DNS CACHE|act:flushdns:" }
        P(7, acts)
        if d.cls == "Storage" && d.ejectable { P(5, "EJECT", "", .warn, "act:eject:/dev/" + d.bsd) }
        if d.cls == "Network" && !d.bsd.hasPrefix("lo") { P(5, d.up ? "INTERFACE DOWN" : "INTERFACE UP", "", d.up ? .red : .cyan, (d.up ? "act:ifdown:" : "act:ifup:") + d.bsd) }
        if d.counters {
            winButtons("TRAFFIC"); let w = devWin(d.id)
            P(3, d.cls == "Storage" ? "read" : "received", "▼ " + fmtB(w.0), .inn); P(3, d.cls == "Storage" ? "written" : "sent", "▲ " + fmtB(w.1), .out)
            P(3, "rate now", "▼" + fmtR(d.rateIn) + " ▲" + fmtR(d.rateOut), .text); P(3, "since boot", "▼" + fmtB(Double(d.cumIn)) + " ▲" + fmtB(Double(d.cumOut)), .text)
        } else if d.parent >= 0 { P(1, "macOS keeps no traffic counters for this kind of device.") }
        if d.parent >= 0 { P(2, "CONNECTED THROUGH"); var p = d.parent, g = 0; while p >= 0 && g < 32 { P(4, DV.devs[p].name, "", .dim, "dev:" + DV.devs[p].id); p = DV.devs[p].parent; g += 1 } }
        let kids = DV.devs.filter { $0.parent == idx }, nbs = DV.nbs.filter { $0.dev == idx }
        if !kids.isEmpty || !nbs.isEmpty {
            P(2, "CONNECTED DEVICES (\(kids.count + nbs.count))")
            for k in kids { P(4, k.name, "", .dim, "dev:" + k.id) }
            for b in nbs { P(4, b.ip + "  " + b.mac + (b.gw ? "  gateway" : ""), "", .dim, "nb:" + b.ip) }
        }
        return
    }
    if sel.hasPrefix("nb:") {
        guard let b = DV.nbs.first(where: { "nb:" + $0.ip == sel }) else { sel = ""; computeFocus(); return }
        P(0, b.ip); dnsRow(b.ip); if let w = Whois.shared.result(b.ip) { P(1, "owner: " + w) }
        P(7, "PING|act:ping:\(b.ip);COPY ADDRESS|act:copy:\(b.ip);WHO OWNS IT|act:whois:\(b.ip)")
        P(1, (b.gw ? "default gateway" : "machine on the local network") + " · MAC " + b.mac)
        P(2, "SEEN BY"); if b.dev < DV.devs.count { P(4, DV.devs[b.dev].name, "", .dim, "dev:" + DV.devs[b.dev].id) }
        netSection(-1, b.ip)
        if b.gw { P(1, "Internet traffic also passes through the gateway; the list above is traffic addressed to it directly.") }
        return
    }
    P(0, "Devices"); P(1, "\(DV.devs.count) devices · \(DV.nbs.count) machines on the local network"); winButtons("DEVICE TRAFFIC")
    var rows: [(Double, Double, Dev)] = []; for d in DV.devs where d.counters { let w = devWin(d.id); rows.append((w.0, w.1, d)) }
    rows.sort { $0.0 + $0.1 > $1.0 + $1.1 }
    for r in rows.prefix(14) { P(4, r.2.name + "  ▼" + fmtB(r.0) + " ▲" + fmtB(r.1), "", .dim, "dev:" + r.2.id) }
    P(7, "SYSTEM INFORMATION|act:sysinfo:;FLUSH DNS CACHE|act:flushdns:")
    P(1, "Counters exist for disks and network interfaces only. Generic device disable has no macOS equivalent and is not offered.")
}
