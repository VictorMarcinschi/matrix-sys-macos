// Packet viewer (contents read by the app itself from a pktap descriptor the helper opens, only while the viewer is open)
// and the process memory viewer.
import AppKit
import Darwin

let BIOCGBLEN_: UInt = 0x40044266   // _IOR('B', 102, u_int); the macro itself does not import into Swift

final class Packets {
    static let shared = Packets()
    var demo = false
    let lock = NSLock(); var pkts: [Pkt] = []
    var session: (bpf: Int32, ctl: Int32)? = nil
    var status = "", reading = false, gen = 0
    // filters and list state
    var fPid: Int32 = -1, fPort = -1, fProto = 0, fIp = "", dir = 0
    var list: [Pkt] = [], procs: [(Int32, Int, Int)] = []
    var frozen = false, hasSel = false, selP = Pkt(), scroll: Float = 0, hexScroll: Float = 0, procScroll: Float = 0, last = 0.0
    var lastDemo = 0.0
    var comm: [Int32: String] = [:]   // names from the pktap header, for processes that have already exited
    let tf: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm:ss.SSS"; return f }()

    func open(pid: Int32, ip: String, port: Int, proto: Int) {
        fPid = pid; fIp = ip; fPort = port; fProto = proto; list = []; hasSel = false; frozen = false; scroll = 0; hexScroll = 0; last = 0
        if demo { status = "demo"; return }
        guard Model.shared.helperConnected else { status = "nohelper"; return }
        status = "opening"; gen += 1; let g = gen
        async {
            guard let r = Model.shared.helperPacketFd() else { self.status = "The helper did not answer."; return }
            if r.0 < 0 { self.status = r.2.replacingOccurrences(of: "ERR ", with: ""); return }
            if g != self.gen || hexMode != 2 { Darwin.close(r.0); Darwin.close(r.1); return }
            self.lock.lock(); self.session = (r.0, r.1); self.pkts = []; self.lock.unlock()
            self.status = "live"; self.readLoop(r.0, g)
        }
    }
    func close() {
        gen += 1
        lock.lock(); if let s = session { Darwin.close(s.bpf); Darwin.close(s.ctl) }; session = nil; pkts = []; lock.unlock()
    }
    private func readLoop(_ fd: Int32, _ g: Int) {
        var blen: UInt32 = 0
        if ioctl(fd, BIOCGBLEN_, &blen) != 0 || blen == 0 { blen = 1 << 20 }
        var buf = [UInt8](repeating: 0, count: Int(blen))
        while g == gen {
            let n = read(fd, &buf, buf.count)
            if n < 0 { if errno == EINTR || errno == EAGAIN { continue }; break }
            if n == 0 { continue }
            var got: [Pkt] = []
            buf.withUnsafeBytes { raw in
                var off = 0
                while off + 18 <= n {
                    let sec = raw.loadUnaligned(fromByteOffset: off, as: Int32.self), usec = raw.loadUnaligned(fromByteOffset: off + 4, as: Int32.self)
                    let cap = Int(raw.loadUnaligned(fromByteOffset: off + 8, as: UInt32.self)), hl = Int(raw.loadUnaligned(fromByteOffset: off + 16, as: UInt16.self))
                    if hl == 0 || off + hl + cap > n { break }
                    if var p = parsePktap(UnsafeRawBufferPointer(rebasing: raw[(off + hl)..<(off + hl + cap)]), keep: 512) {
                        p.t = Double(sec) + Double(usec) / 1e6
                        got.append(p)
                    }
                    off += (hl + cap + 3) & ~3
                }
            }
            if got.isEmpty { continue }
            lock.lock(); pkts += got; if pkts.count > 3000 { pkts.removeFirst(pkts.count - 3000) }; lock.unlock()
        }
    }
    /// --demo-packets: made-up packets shaped like this Mac's real connections, labelled DEMO everywhere they appear.
    func demoTick() {
        guard demo, hexMode == 2, let S = S, nowSec() - lastDemo > 0.05 else { return }
        lastDemo = nowSec()
        let cs = S.conns.filter { $0.proto == "TCP" && $0.state == "Established" && !isLoop($0.ra) && !$0.ra.contains(":") }
        guard let c = cs.randomElement() else { return }
        var p = Pkt(); p.t = wallSec(); p.pid = c.pid; p.comm = S.get(c.pid)?.name ?? ""; p.proto = 6; p.out = Bool.random()
        p.lip = c.la; p.rip = c.ra; p.lp = UInt16(c.lp); p.rp = UInt16(c.rp); p.len = 60 + Int.random(in: 0..<1400); p.ifname = c.iface
        var d = [UInt8](repeating: 0, count: min(p.len, 512)); d[0] = 0x45; d[2] = UInt8(p.len >> 8); d[3] = UInt8(p.len & 255); d[8] = 64; d[9] = 6
        var a4 = in_addr(), b4 = in_addr(); inet_pton(AF_INET, c.la, &a4); inet_pton(AF_INET, c.ra, &b4)
        withUnsafeBytes(of: &a4) { for i in 0..<4 { d[(p.out ? 12 : 16) + i] = $0[i] } }; withUnsafeBytes(of: &b4) { for i in 0..<4 { d[(p.out ? 16 : 12) + i] = $0[i] } }
        let sp = p.out ? p.lp : p.rp, dp = p.out ? p.rp : p.lp
        d[20] = UInt8(sp >> 8); d[21] = UInt8(sp & 255); d[22] = UInt8(dp >> 8); d[23] = UInt8(dp & 255); d[32] = 0x50; d[33] = 0x18
        let tag = Array("DEMO PACKET - SYNTHETIC - ".utf8)
        for i in 40..<d.count { d[i] = tag[(i - 40) % tag.count] }
        p.data = d
        lock.lock(); pkts.append(p); if pkts.count > 3000 { pkts.removeFirst() }; lock.unlock()
    }

    func draw(X0: Float, Y0: Float, Wd: Float, Ht: Float, LWd: Float, top: Float, hx: Float, rows: Int, inList: Bool, wheel: Float) {
        let click = UIS.clickNow
        let fp = fPid >= 0 ? S?.get(fPid) : nil
        let what = fPid >= 0 ? (fp.map { $0.name + " " } ?? "") + "\(fPid)" : !fIp.isEmpty ? fIp : fPort >= 0 ? (fProto == 17 ? "UDP" : "TCP") + " port \(fPort) " + svcName(fPort) : "all traffic"
        g.text(X0 + 12, Y0 + 9, (demo ? "DEMO " : "") + "PACKETS · " + what + (demo ? "  (synthetic packets shaped like your real connections — not captured)" : ""), uiCol(demo ? .warn : .cyan), bold: true)
        if !demo && status != "live" {
            if status == "nohelper" {
                g.text(X0 + 12, top, "Packet contents need root. MatrixSys reads them itself through a capture descriptor the helper opens,", .warn)
                g.text(X0 + 12, top + 18, "only while this window is open. The helper itself only ever counts packets; it never reads their contents.", .dim)
                var b2 = X0 + 12; if button(&b2, top + 44, "FULL ACCESS (INSTALL HELPER)…", false, .warn) { Helper.offerInstall() }
            } else { g.text(X0 + 12, top, status == "opening" ? "Opening a packet session through the helper…" : "Capture could not start: " + status, status == "opening" ? .dim : .red) }
            return
        }
        do { var rx = X0 + Wd - 150; if button(&rx, Y0 + 8, frozen ? "RESUME" : "FREEZE", frozen) { frozen.toggle() } }
        if fPort >= 0 { var px = X0 + Wd - 250; if button(&px, Y0 + 8, "ALL PORTS", false) { hexClose(); hexMode = 3; return } }
        do { var dx = X0 + Wd - 430; for (m, n) in ["IN + OUT", "IN", "OUT"].enumerated() { if button(&dx, Y0 + 8, n, dir == m) && dir != m { dir = m; scroll = 0; last = 0; frozen = false }; dx += 4 } }
        if !frozen && nowSec() - last > 0.3 {
            last = nowSec(); list = []
            var agg: [Int32: (Int, Int)] = [:]
            lock.lock(); let all = pkts; lock.unlock()
            for p in all.reversed() {
                if !fIp.isEmpty && p.rip != fIp { continue }
                if fPort >= 0 && (Int(p.lp) != fPort || Int(p.proto) != fProto) { continue }
                let key = p.pid > 0 ? p.pid : -2
                var e = agg[key] ?? (0, 0); if p.out { e.1 += 1 } else { e.0 += 1 }; agg[key] = e
                if p.pid > 0 && !p.comm.isEmpty { comm[p.pid] = p.comm }   // counts everything the host / port filter lets through
                if (fPid >= 0 && p.pid != fPid) || (fPid == -2 && p.pid > 0) { continue }
                if (dir == 1 && p.out) || (dir == 2 && !p.out) { continue }
                if list.count < 500 { list.append(p) }
            }
            procs = agg.map { ($0.key, $0.value.0, $0.value.1) }.sorted { $0.1 + $0.2 != $1.1 + $1.2 ? $0.1 + $0.2 > $1.1 + $1.2 : $0.0 < $1.0 }
        }
        // top of the left column: processes seen in the capture; below it: the packets
        let PR = min(9, max(3, rows / 4)); let ptop = top + Float(PR + 2) * 15; let prow = max(3, rows - PR - 2); let inProc = inR(X0, top, LWd, Float(PR + 1) * 15)
        g.text(X0 + 10, top, "PROCESS (click to filter)            IN    OUT", hexFocus == 0 ? .cyan : .dim)
        var plist: [(Int32, Int, Int)] = [(-1, procs.reduce(0) { $0 + $1.1 }, procs.reduce(0) { $0 + $1.2 })] + procs
        if navKey == NK.left { hexFocus = 0 } else if navKey == NK.right { hexFocus = 1 }
        if hexFocus == 0 && navKey != 0 {
            var ci = plist.firstIndex { $0.0 == fPid } ?? 0; let old = ci
            navList(&ci, &procScroll, plist.count, PR)
            if ci != old { fPid = plist[ci].0; scroll = 0; last = 0; frozen = false; hasSel = false }
        }
        if inProc { procScroll = max(0, min(procScroll - wheel * 3, max(0, Float(plist.count - PR)))) }
        let pf = Int(procScroll)
        for i in 0..<PR where pf + i < plist.count {
            let p = plist[pf + i]; let y = top + 15 + Float(i) * 15; let hot = inR(X0 + 6, y, LWd - 8, 15), cur = fPid == p.0
            if hot || cur { g.fill(X0 + 6, y, LWd - 8, 15, rgba(0x4fe3ff, cur ? 0.22 : 0.1)) }
            let nm = ellipsize(p.0 == -1 ? "all processes" : p.0 == -2 ? "unknown process" : "\(S?.get(p.0)?.name ?? (comm[p.0].map { $0 + " (exited)" } ?? "(exited)")) \(p.0)", 33)
            g.text(X0 + 10, y, nm.padding(toLength: 33, withPad: " ", startingAt: 0) + String(format: " %5d %5d", p.1, p.2), cur ? .white : .text)
            if hot && click && !cur { fPid = p.0; scroll = 0; last = 0; frozen = false; hasSel = false }
        }
        plist = []
        g.fill(X0 + 8, ptop - 9, LWd - 12, 1, rgba(0x4fe3ff, hexFocus == 1 ? 0.8 : 0.25))
        if hexFocus == 1 && navKey != 0 && !list.isEmpty {   // moving through packets freezes the list so it does not slide away under the cursor
            var ci = hasSel ? (list.firstIndex { $0.t == selP.t && $0.len == selP.len } ?? -1) : -1
            if ci < 0 { ci = Int(scroll); if navKey != NK.up && navKey != NK.down { navList(&ci, &scroll, list.count, prow) } } else { navList(&ci, &scroll, list.count, prow) }
            if navKey != NK.left && navKey != NK.right && navKey != NK.enter { selP = list[ci]; hasSel = true; hexScroll = 0; frozen = true }
        }
        if inList && !inProc { scroll = max(0, min(scroll - wheel * 3, max(0, Float(list.count - prow)))) }
        if list.isEmpty { g.text(X0 + 12, ptop, "Waiting for packets…", .dim) }
        let first = Int(scroll)
        for i in 0..<prow where first + i < list.count {
            let k = list[first + i]; let y = ptop + Float(i) * 15; let hot = inR(X0 + 6, y, LWd - 8, 15), cur = hasSel && k.t == selP.t && k.len == selP.len
            if hot || cur { g.fill(X0 + 6, y, LWd - 8, 15, rgba(0x4fe3ff, cur ? 0.22 : 0.1)) }
            let tm = tf.string(from: Date(timeIntervalSince1970: k.t))
            let rem = ellipsize(k.rip + (k.v6 ? "." : ":") + "\(k.rp)", 23)
            g.text(X0 + 10, y, "\(tm) \(k.out ? "▲" : "▼") " + protoName(Int(k.proto)).padding(toLength: 4, withPad: " ", startingAt: 0) + " " + ellipsize(rem, 21).padding(toLength: 21, withPad: " ", startingAt: 0) + String(format: "%5d", k.len), k.out ? .out : .inn)
            if hot && click { selP = k; hasSel = true; hexScroll = 0 }
        }
        if !hasSel {
            g.text(hx, top, "Select a packet on the left. Only the first 512 bytes of each packet are kept, at most 3000 packets.", .dim)
            g.text(hx, top + 18, "Encrypted (TLS, QUIC) payloads are ciphertext; this view cannot decrypt them.", .dim)
            g.text(hx, top + 44, "Keys: ← → choose the process or packet list · ↑ ↓ PgUp PgDn Home End move · Esc closes", .dim)
            return
        }
        let k = selP; let d = k.data
        var ihl = 20, l4 = 0, fl = ""
        if !d.isEmpty && d[0] >> 4 == 4 { ihl = Int(d[0] & 15) * 4 } else if !d.isEmpty && d[0] >> 4 == 6 { ihl = 40 }
        if k.proto == 6 && d.count >= ihl + 14 {
            l4 = Int(d[ihl + 12] >> 4) * 4; let f = d[ihl + 13]
            for (i, n) in ["FIN", "SYN", "RST", "PSH", "ACK", "URG"].enumerated() where f & (1 << i) != 0 { fl += (fl.isEmpty ? "" : " ") + n }
        } else if k.proto == 17 || k.proto == 1 || k.proto == 58 { l4 = 8 }
        let payOff = min(d.count, ihl + l4), payLen = max(0, k.len - ihl - l4)
        let a = k.lip + ":\(k.lp)", b2 = k.rip + ":\(k.rp)"; let sv = svcName(Int(k.rp)).isEmpty ? svcName(Int(k.lp)) : svcName(Int(k.rp))
        let owner = k.pid > 0 ? "\(S?.get(k.pid)?.name ?? (k.comm.isEmpty ? "(exited)" : k.comm)) \(k.pid)" : "process unknown"
        g.text(hx, top, protoName(Int(k.proto)) + (sv.isEmpty ? "" : " · " + sv) + "   " + (k.out ? a + " → " + b2 : b2 + " → " + a) + "   " + owner + (k.ifname.isEmpty ? "" : " · " + k.ifname), k.out ? .out : .inn)
        g.text(hx, top + 16, "IP header \(ihl) B · \(protoName(Int(k.proto))) header \(l4) B" + (fl.isEmpty ? "" : " [" + fl + "]") + " · payload \(payLen) B · \(d.count) of \(k.len) B kept", .text)
        do {   // who is on the other end: host name is looked up when the packet is selected, the owner when asked
            let nm = DNS.shared.lookup(k.rip); let own = Whois.shared.result(k.rip) ?? ""
            g.text(hx, top + 32, "remote \(k.rip) · host name: " + (nm.isEmpty ? "resolving…" : nm == "-" ? "none" : nm), .text)
            var bx = hx
            if own.isEmpty { if button(&bx, top + 50, "WHO OWNS IT", false) { requestAction("act:whois:" + k.rip) }; bx += 4 }
            else { g.text(hx, top + 53, "owner: " + own, .safe); bx = hx + Float(own.unicodeScalars.count + 9) * CW }
            if bx + 110 < X0 + Wd && button(&bx, top + 50, "COPY ADDRESS", false) { requestAction("act:copy:" + k.rip) }
        }
        g.text(hx, top + 78, HEX_HDR, .dim)
        let hr = max(1, rows - 7), total = (d.count + 15) / 16
        if !inList { hexScroll = max(0, min(hexScroll - wheel * 3, Float(max(0, total - hr)))) }
        let start = Int(hexScroll) * 16, n = min(hr * 16, d.count - min(d.count, start))
        hexDump(hx, top + 93, UInt64(start), d, nil, nil, n, payOff, start)
    }
}

// ---------------------------------------------------------------- process memory
final class MemViewer {
    static let shared = MemViewer()
    struct Region { var base: UInt64; var size: UInt64; var prot: String; var type: String; var name: String }
    var pid: Int32 = -1, regions: [Region] = [], region = -1, regScroll: Float = 0, addr: UInt64 = 0, rows = 24
    var cur: [UInt8] = [], prev: [UInt8] = [], ok: [Bool] = [], err = "", loading = false, lastRead = 0.0, reading = false, gen = 0
    func open(_ p: Int32) {
        pid = p; regions = []; region = -1; regScroll = 0; cur = []; prev = []; ok = []; err = ""; loading = true; gen += 1; let g0 = gen
        async {
            var lines: [String]? = nil
            if Model.shared.helperConnected { lines = Model.shared.helperRequest("MEMREGIONS\t\(p)", timeout: 15) }
            DispatchQueue.main.async {
                guard g0 == self.gen else { return }
                self.loading = false
                guard let l = lines else {
                    self.err = Model.shared.helperConnected ? "The helper did not answer." : "Reading another process's memory needs task_for_pid, which macOS grants only to root. Install the helper (FULL ACCESS) to use this viewer."
                    return
                }
                if let f = l.first, f.hasPrefix("ERR") { self.err = String(f.dropFirst(4)); return }
                for line in l.dropFirst() {
                    let f = line.split(separator: "\t", omittingEmptySubsequences: false)
                    if f.count >= 6, let b = UInt64(f[0]), let s = UInt64(f[1]) { self.regions.append(Region(base: b, size: s, prot: String(f[2]), type: String(f[3]), name: String(f[5]))) }
                }
                if let i = self.regions.firstIndex(where: { $0.type == "MAP" && $0.prot.hasPrefix("r-x") }) ?? (self.regions.isEmpty ? nil : 0) { self.region = i; self.addr = self.regions[i].base; self.regScroll = Float(max(0, i - 3)) }
            }
        }
    }
    func close() { gen += 1; pid = -1 }
    func read() {
        guard !reading, region >= 0 else { return }
        reading = true; let p = pid, a = addr, n = rows * 16, g0 = gen
        async {
            let r = Model.shared.helperRequest("MEMREAD\t\(p)\t\(a)\t\(n)")
            DispatchQueue.main.async {
                self.reading = false; self.lastRead = nowSec()
                guard g0 == self.gen, let r = r, r.count >= 3, r[0] == "OK" else { return }
                var bytes = [UInt8](); var i = r[1].startIndex
                while i < r[1].endIndex { let j = r[1].index(i, offsetBy: 2); bytes.append(UInt8(r[1][i..<j], radix: 16) ?? 0); i = j }
                self.prev = self.cur.count == bytes.count && a == self.addr ? self.cur : []
                self.cur = bytes; self.ok = r[2].map { $0 == "1" }
            }
        }
    }
    func draw(X0: Float, Y0: Float, Wd: Float, Ht: Float, LWd: Float, top: Float, hx: Float, rows: Int, inList: Bool, wheel: Float) {
        let p = S?.get(pid); let tot = regions.reduce(UInt64(0)) { $0 + $1.size }
        g.text(X0 + 12, Y0 + 9, "MEMORY · \(p?.name ?? "?") \(pid) · \(regions.count) readable regions · \(fmtB(Double(tot)))", uiCol(.cyan), bold: true)
        if loading { g.text(X0 + 12, top, "Reading the memory map…", .dim); return }
        if !err.isEmpty || p == nil {
            for (i, l) in wrapText(err.isEmpty ? "The process has exited." : err, Int((Wd - 40) / CW)).enumerated() { g.text(X0 + 12, top + Float(i) * 16, l, .warn) }
            g.text(X0 + 12, top + 60, "Realistic coverage with the helper: your own and third-party apps without the hardened runtime. Apple's programs and", .dim)
            g.text(X0 + 12, top + 76, "hardened (notarized) apps are refused by macOS while System Integrity Protection is on.", .dim)
            if !Model.shared.helperConnected { var b2 = X0 + 12; if button(&b2, top + 104, "FULL ACCESS (INSTALL HELPER)…", false, .warn) { Helper.offerInstall() } }
            return
        }
        do { var rx = X0 + Wd - 150; if button(&rx, Y0 + 8, "REFRESH", false) { open(pid) } }
        if navKey == NK.left { hexFocus = 0 } else if navKey == NK.right { hexFocus = 1 }
        if hexFocus == 0 && navKey != 0 { let old = region; navList(&region, &regScroll, regions.count, rows); if region != old && region < regions.count { addr = regions[region].base; lastRead = 0 } }
        g.fill(hexFocus == 1 ? hx : X0 + 6, top - 4, hexFocus == 1 ? 560 : LWd - 8, 1, rgba(0x4fe3ff, 0.7))   // marks the column the keys act on
        if inList { regScroll = max(0, min(regScroll - wheel * 3, max(0, Float(regions.count - rows)))) }
        let first = Int(regScroll)
        for i in 0..<rows where first + i < regions.count {
            let r = regions[first + i]; let y = top + Float(i) * 15; let hot = inR(X0 + 6, y, LWd - 8, 15), c = first + i == region
            if hot || c { g.fill(X0 + 6, y, LWd - 8, 15, rgba(0x4fe3ff, c ? 0.22 : 0.1)) }
            g.text(X0 + 10, y, ellipsize(String(format: "%012llX %8@ %@ %@ %@", r.base, fmtB(Double(r.size)) as NSString, r.prot as NSString, r.type as NSString, r.name as NSString), 48), c ? .white : .text)
            if hot && UIS.clickNow { region = first + i; addr = r.base; lastRead = 0 }
        }
        self.rows = rows - 1
        guard region >= 0 && region < regions.count else { g.text(hx, top, "Select a region on the left.", .dim); return }
        let r = regions[region]; let span = UInt64(self.rows * 16), maxA = (r.base + (r.size > span ? r.size - span : 0)) & ~15
        if hexFocus == 1 && navKey != 0 {
            var a = Int64(addr)
            switch navKey { case NK.up: a -= 16; case NK.down: a += 16; case NK.pgUp: a -= Int64(span); case NK.pgDn: a += Int64(span); case NK.home: a = Int64(r.base); case NK.end: a = Int64(maxA); default: break }
            addr = UInt64(max(Int64(r.base), min(Int64(maxA), a))) & ~15; lastRead = 0
        }
        if !inList && wheel != 0 { let a = Int64(addr) - Int64(wheel * 64); addr = UInt64(max(Int64(r.base), min(Int64(maxA), a))) & ~15; lastRead = 0 }
        addr = max(r.base, min(maxA, addr))
        if nowSec() - lastRead > 0.35 { read() }
        g.text(hx, top, HEX_HDR, .dim)
        let n = Int(min(min(span, UInt64(cur.count)), r.base + r.size - addr))
        if cur.isEmpty { g.text(hx, top + 15, "reading…", .dim) } else { hexDump(hx, top + 15, addr, cur, ok, prev.count == cur.count ? prev : nil, n, 0) }
    }
}
