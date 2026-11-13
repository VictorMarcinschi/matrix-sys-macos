// Immediate-mode overlay: top bar, selection panel, legend, tooltips, toasts, confirmation, list and hex windows.
import AppKit

final class UIState {
    var mouseX: Float = 0, mouseY: Float = 0
    var clickNow = false, mouseOverUi = false
    var wheelUi: Float = 0, panelScroll: Float = 0
    var uiRects: [(Float, Float, Float, Float)] = []    // last frame's panels, for hit-testing mouse-down and scroll
    var prevRects: [(Float, Float, Float, Float)] = []
    func overUi(_ x: Float, _ y: Float) -> Bool { prevRects.contains { x >= $0.0 && x < $0.0 + $0.2 && y >= $0.1 && y < $0.1 + $0.3 } }
}
let UIS = UIState()
var legendTop: Float = 600
var g: Gfx { G.gfx! }
var CW: Float { G.gfx!.CW }

func inR(_ x: Float, _ y: Float, _ w: Float, _ h: Float) -> Bool { UIS.mouseX >= x && UIS.mouseX < x + w && UIS.mouseY >= y && UIS.mouseY < y + h }
func panelBg(_ x: Float, _ y: Float, _ w: Float, _ h: Float) {
    g.fill(x, y, w, h, rgba(0x020e1c, 0.86)); g.stroke(x, y, w, h, rgba(0x4fe3ff, 0.28))
    UIS.uiRects.append((x, y, w, h)); if inR(x, y, w, h) { UIS.mouseOverUi = true }
}
@discardableResult func button(_ x: inout Float, _ y: Float, _ t: String, _ on: Bool, _ col: T = .cyan) -> Bool {
    let w = Float(t.unicodeScalars.count) * CW + 18, h: Float = 22; let hot = inR(x, y, w, h)
    if on || hot { g.fill(x, y, w, h, rgba(0x4fe3ff, on ? 0.22 : 0.12)) }
    g.stroke(x, y, w, h, rgba(0x4fe3ff, on ? 0.9 : 0.3))
    g.text(x + 9, y + 3, t, uiCol(col)); x += w
    return hot && UIS.clickNow
}
struct TL { var s: String; var c: T }
func procTip(_ p: ProcInfo) -> [TL] {
    var t = [TL(s: "\(p.name) · pid \(p.pid)", c: .cyan)]
    t.append(TL(s: "mem \(fmtB(Double(p.rss))) · cpu \(String(format: "%.1f", p.cpu))%" + (p.threads > 0 ? " · \(p.threads) threads" : ""), c: .text))
    let r = procRate(p.pid)
    t.append(TL(s: "disk ▼ \(fmtR(r.rd))   ▲ \(fmtR(r.wr))" + (p.hasIO ? "" : " (not readable)"), c: .dim))
    if r.nin + r.nout > 0 { t.append(TL(s: "net  ▼ \(fmtR(r.nin))   ▲ \(fmtR(r.nout))", c: .dim)) }
    return t
}
func nodeTip(_ n: Node) -> [TL] {
    guard let S = S else { return [] }
    let p = n.pid >= 0 ? S.get(n.pid) : nil
    switch n.kind {
    case .proc:
        guard let p = p else { return [] }
        var t = procTip(p)
        if view == 3 { t.append(TL(s: "\(n.cnt) open files", c: .text)) }
        if view == 1 { t.append(TL(s: "\(SM_listen[n.pid]?.count ?? 0) open ports · \(SM_remote[n.pid]?.count ?? 0) remote connections", c: .text)) }
        return t
    case .hubnet: return [TL(s: "Network", c: .cyan), TL(s: "▼ \(fmtR(S.rx))   ▲ \(fmtR(S.tx))  (all interfaces)", c: .text)]
    case .hubio: return [TL(s: "Local I/O", c: .cyan), TL(s: "disk traffic; pipe and socket links between processes", c: .text)]
    case .pc: return [TL(s: S.host + " — this Mac", c: .cyan), TL(s: "▼ \(fmtR(S.rx))   ▲ \(fmtR(S.tx))", c: .text), TL(s: "\(n.cnt) processes with sockets", c: .text)]
    case .port:
        if n.more > 0 { return [TL(s: "\(n.more) more open ports on \(n.name)", c: .cyan)] }
        return [TL(s: (n.proto == 1 ? "UDP " : "TCP ") + "\(n.port) " + svcName(n.port), c: .cyan),
                TL(s: "bound to \(n.s1)" + (isLoop(n.s1) ? " — local only" : isAny(n.s1) ? " — all interfaces" : " — one interface"), c: isLoop(n.s1) ? .text : .warn),
                TL(s: "owner \(n.name) (\(n.pid))", c: .text)]
    case .host: return [TL(s: n.s1 + (isPrivate(n.s1) ? " · LAN" : " · internet"), c: .cyan), TL(s: "\(n.cnt) connection(s) from \(n.more) process(es)", c: .text)] + dnsTip(n.s1)
    case .dir, .vol: return diskTip(n)
    case .dev, .nb: return devTip(n)
    case .file: return [TL(s: (n.s1 as NSString).lastPathComponent, c: .cyan), TL(s: n.s1, c: .text), TL(s: "open in \(n.cnt) process(es)", c: .dim)]
    case .disk: return [TL(s: "Disk", c: .cyan), TL(s: "\(n.cnt) open files visible", c: .text)]
    case .group: return [TL(s: n.name, c: .cyan), TL(s: "\(fmtB(n.v)) resident · \(n.cnt) process(es)", c: .text), TL(s: String(format: "%.1f%% of RAM", n.v / Double(S.memTotal) * 100), c: .text)]
    case .free: return [TL(s: "Free physical memory", c: .cyan), TL(s: "\(fmtB(n.v)) of \(fmtB(Double(S.memTotal)))", c: .text)]
    case .other: return [TL(s: "Kernel, wired, compressed, file cache", c: .cyan), TL(s: "\(fmtB(n.v)) in use outside process resident sets", c: .text),
                         TL(s: "wired \(fmtB(Double(S.memWired))) · compressed \(fmtB(Double(S.memCompressed))) · cache \(fmtB(Double(S.memCache)))", c: .dim)]
    }
}
func dnsTip(_ ip: String) -> [TL] { let nm = DNS.shared.lookup(ip); return [TL(s: nm.isEmpty ? "host name: resolving…" : nm == "-" ? "host name: none" : nm, c: .dim)] }
func drawTip(_ t: [TL]) {
    if t.isEmpty { return }
    let mx = t.map { $0.s.unicodeScalars.count }.max() ?? 0
    let w = Float(mx) * CW + 18, h = Float(t.count) * 16 + 10, x = min(UIS.mouseX + 16, G.LW - w - 6), y = min(UIS.mouseY + 16, G.LH - h - 6)
    g.fill(x, y, w, h, rgba(0x020e1c, 0.94)); g.stroke(x, y, w, h, rgba(0x4fe3ff, 0.4))
    for (i, l) in t.enumerated() { g.text(x + 9, y + 5 + Float(i) * 16, l.s, l.c) }
}

// ---- selection panel
struct PItem { var type: Int; var a: String; var b = ""; var cb: T = .dim; var sel = ""; var view = -1 }   // 0 title, 1 sub, 2 header, 3 row, 4 link, 5 button, 6 window buttons, 7 button row
var pitems: [PItem] = []
func P(_ type: Int, _ a: String, _ b: String = "", _ cb: T = .dim, _ s: String = "", _ v: Int = -1) { pitems.append(PItem(type: type, a: a, b: b, cb: cb, sel: s, view: v)) }
func dnsRow(_ ip: String) { let nm = DNS.shared.lookup(ip); P(1, nm.isEmpty ? "host name: resolving…" : nm == "-" ? "host name: none (no reverse DNS record)" : "host name: " + nm) }
func winButtons(_ title: String) { P(2, title + " · LAST \(winSec)s"); P(6, "") }
func perRows(_ w: NetWin) {
    let v = w.per.sorted { $0.value.0 + $0.value.1 > $1.value.0 + $1.value.1 }
    for e in v.prefix(14) { P(3, e.key, "▼" + fmtB(e.value.0) + " ▲" + fmtB(e.value.1), .text) }
    if v.isEmpty { P(1, "nothing in this window") }
}
func netSection(_ pid: Int32, _ host: String) {
    winButtons("TRAFFIC")
    if capOn() { let w = netWin(pid, host); P(3, "received", "▼ " + fmtB(w.inn), .inn); P(3, "sent", "▲ " + fmtB(w.out), .out); P(3, "packets", "\(w.ev)", .text); perRows(w); return }
    let w = nettopWin(pid, host)
    P(3, "received", "▼ " + fmtB(w.inn), .inn); P(3, "sent", "▲ " + fmtB(w.out), .out)
    perRows(w)
    P(1, "Byte counts from nettop (exact). Packet counts and contents need the helper.")
}
func diskSection(_ pid: Int32, _ path: String) {
    winButtons("DISK I/O")
    if !diskLive() {
        if pid >= 0 { let w = ioWin(pid, pastSnap()); if let p = S?.get(pid), !p.hasIO { P(1, "Disk counters of other users' processes need the helper.") } else { P(3, "read (process total)", "▼ " + fmtB(w.rd), .inn); P(3, "written (process total)", "▲ " + fmtB(w.wr), .out) } }
        P(1, "Per-file amounts need the helper (fs_usage tracing)."); return
    }
    let w = diskWin(pid, path); P(3, "read", "▼ " + fmtB(w.inn), .inn); P(3, "written", "▲ " + fmtB(w.out), .out); perRows(w)
}
func memSection(_ pids: [Int32]) {
    winButtons("MEMORY CHANGE"); let past = pastSnap(); var dws = 0.0, dfp = 0.0; var ok = false
    for pid in pids { let w = ioWin(pid, past); if w.ok { ok = true; dws += w.dws; dfp += w.dfp } }
    if !ok { P(1, "no earlier sample yet"); return }
    P(3, "resident", sgnB(dws), dws > 0 ? .out : dws < 0 ? .inn : .text)
    if dfp != 0 { P(3, "footprint", sgnB(dfp), dfp > 0 ? .out : .inn) }
}
func winSection(_ p: ProcInfo) {
    if view == 1 { netSection(p.pid, "") } else if view == 3 { diskSection(p.pid, "") } else if view == 2 { memSection([p.pid]) }
    else { winButtons("ACTIVITY"); let w = ioWin(p.pid, pastSnap())
        P(3, "disk read", p.hasIO ? "▼ " + fmtB(w.rd) : "-", .inn); P(3, "disk written", p.hasIO ? "▲ " + fmtB(w.wr) : "-", .out)
        if w.netOk { P(3, "network in / out", "▼" + fmtB(w.nin) + " ▲" + fmtB(w.nout), .text) }
        P(3, "resident memory", w.ok ? sgnB(w.dws) : "-", .text) }
}
/// With nothing selected, each view lists who was most active in the window.
func summaryPanel() {
    guard let S = S else { return }
    let past = pastSnap(); struct R { var a: Double; var b: Double; var p: ProcInfo }; var rows: [R] = []
    if view == 0 {
        P(0, "Processes"); P(1, "\(S.procs.count) running. Click a process to spread out the cluster it sits in."); P(5, "LIST ALL BY LANE TRAFFIC", "", .dim, "hexlanes"); winButtons("DISK TRAFFIC")
        for p in S.procs { let w = ioWin(p.pid, past); if w.rd + w.wr > 0 { rows.append(R(a: w.rd, b: w.wr, p: p)) } }
        rows.sort { $0.a + $0.b > $1.a + $1.b }
        for r in rows.prefix(16) { P(4, "\(r.p.name) \(r.p.pid)  ▼\(fmtB(r.a)) ▲\(fmtB(r.b))", "", .dim, "p:\(r.p.pid)") }
        if rows.isEmpty { P(1, "nothing in this window") }
        if !S.helperData { P(1, "Disk counters cover your own processes; the helper adds everyone else's.") }
        return
    }
    if view == 1 {
        P(0, "Top talkers"); P(5, "OPEN PORTS LIST", "", .dim, "hexports")
        let fl = Firewall.shared.list()
        if !fl.isEmpty { P(2, "BLOCKED BY MATRIXSYS (\(fl.count))"); for r in fl { P(4, "unblock: " + r, "", .dim, "act:fwunblock:" + r) }; P(5, "REMOVE ALL MATRIXSYS RULES", "", .red, "act:fwflush:all") }
        P(5, "VIEW ALL PACKETS (HEX)", "", .dim, "hexpkt:all"); winButtons("TRAFFIC")
        if capOn() {
            var m: [Int32: (Double, Double)] = [:]; let t0 = nowSec() - Double(winSec)
            for f in flowHist.reversed() { if f.t < t0 { break }; var e = m[f.pid] ?? (0, 0); if f.out { e.1 += Double(f.bytes) } else { e.0 += Double(f.bytes) }; m[f.pid] = e }
            for (pid, v) in m { if let p = S.get(pid) { rows.append(R(a: v.0, b: v.1, p: p)) } }
        } else {
            P(1, "Exact byte counts from nettop; dots are paced from them (packet timing estimated).")
            for p in S.procs { let w = ioWin(p.pid, past); if w.nin + w.nout > 0 { rows.append(R(a: w.nin, b: w.nout, p: p)) } }
        }
        rows.sort { $0.a + $0.b > $1.a + $1.b }
        for r in rows.prefix(14) { P(4, "\(r.p.name) \(r.p.pid)  ▼\(fmtB(r.a)) ▲\(fmtB(r.b))", "", .dim, "n:\(r.p.pid)") }
    } else if view == 3 {
        P(0, "Top disk I/O"); P(1, "\(FH?.count ?? 0) open files in \(filesByPid.count) processes" + (S.fdDenied > 0 ? " · \(S.fdDenied) processes not readable without the helper" : "")); winButtons("DISK I/O")
        if diskLive() {
            var m: [Int32: (Double, Double)] = [:]; let t0 = nowSec() - Double(winSec)
            for d in diskHist.reversed() { if d.t < t0 { break }; var e = m[d.pid] ?? (0, 0); e.0 += Double(d.rd); e.1 += Double(d.wr); m[d.pid] = e }
            for (pid, v) in m { if let p = S.get(pid) { rows.append(R(a: v.0, b: v.1, p: p)) } }
        } else {
            P(1, "Process totals from rusage counters.")
            for p in S.procs { let w = ioWin(p.pid, past); if w.rd + w.wr > 0 { rows.append(R(a: w.rd, b: w.wr, p: p)) } }
        }
        rows.sort { $0.a + $0.b > $1.a + $1.b }
        for r in rows.prefix(14) { P(4, "\(r.p.name) \(r.p.pid)  ▼\(fmtB(r.a)) ▲\(fmtB(r.b))", "", .dim, "f:\(r.p.pid)") }
    } else {
        P(0, "Top memory movers")
        P(3, "physical memory", fmtB(Double(S.memTotal)), .text); P(3, "app memory", fmtB(Double(S.memApp)), .text); P(3, "wired", fmtB(Double(S.memWired)), .text)
        P(3, "compressed", fmtB(Double(S.memCompressed)), .text); P(3, "cached files", fmtB(Double(S.memCache)), .text); P(3, "free", fmtB(Double(S.memFree)), .safe)
        winButtons("MEMORY CHANGE")
        for p in S.procs { let w = ioWin(p.pid, past); if w.ok && w.dws != 0 { rows.append(R(a: w.dws, b: w.dfp, p: p)) } }
        rows.sort { abs($0.a) > abs($1.a) }
        for r in rows.prefix(14) { P(4, "\(r.p.name) \(r.p.pid)  " + sgnB(r.a), "", .dim, "g:" + r.p.name) }
    }
    if rows.isEmpty { P(1, "nothing in this window") }
}
func procPanel(_ p: ProcInfo) {
    guard let S = S else { return }
    let pre = view == 0 ? "p:" : view == 1 ? "n:" : view == 3 ? "f:" : "rp:"; let ps = "\(p.pid)"
    P(0, p.name); P(1, "pid \(p.pid) · user \(userName(p.uid))" + (p.nice != 0 ? " · nice \(p.nice)" : ""))
    if !p.path.isEmpty { P(1, p.path) }
    let kids = S.procs.contains { $0.ppid == p.pid }
    let app = NSRunningApplication(processIdentifier: p.pid)
    P(2, "CONTROL")
    P(7, "SUSPEND|act:suspend:\(ps);RESUME|act:resume:\(ps)" + (app != nil ? ";TO FRONT|act:front:\(ps);QUIT|act:quit:\(ps)" : ""))
    P(7, "TERMINATE|act:term:\(ps);KILL|act:kill:\(ps)" + (kids ? ";KILL TREE|act:killtree:\(ps)" : ""), "", .red)
    P(3, "priority", prioOf(p), .text)
    P(7, "LOWEST|act:prio:\(ps):0;LOW|act:prio:\(ps):1;NORMAL|act:prio:\(ps):2;ABOVE|act:prio:\(ps):3;HIGH|act:prio:\(ps):4")
    P(7, "BACKGROUND (E-CORES)|act:bg:\(ps):1;FOREGROUND|act:bg:\(ps):0")
    P(7, "SAMPLE 3 s|act:sample:\(ps);REVEAL|act:reveal:\(p.path);COPY PATH|act:copy:\(p.path)")
    if let job = LaunchJobs.shared.label(for: p.pid) {
        P(2, "LAUNCHD JOB"); P(3, job.label, job.domain, .dim)
        P(7, "STOP|act:svcstop:\(job.domain)/\(job.label);RESTART|act:svcrestart:\(job.domain)/\(job.label)", "", .red)
    }
    winSection(p)
    P(2, "RESOURCES"); P(3, "resident memory", p.rss > 0 ? fmtB(Double(p.rss)) : "-", .text)
    if p.footprint > 0 { P(3, "memory footprint", fmtB(Double(p.footprint)), .text) }
    P(3, "cpu", String(format: "%.1f%%", p.cpu), .text)
    if p.threads > 0 { P(3, "threads", "\(p.threads)", .text) }
    let r = procRate(p.pid)
    P(3, "disk read", p.hasIO ? "▼ " + fmtR(r.rd) : "needs the helper", .inn); P(3, "disk write", p.hasIO ? "▲ " + fmtR(r.wr) : "needs the helper", .out)
    P(3, "network in", "▼ " + fmtR(capOn() ? (capRate[p.pid]?.0 ?? 0) : r.nin), .inn); P(3, "network out", "▲ " + fmtR(capOn() ? (capRate[p.pid]?.1 ?? 0) : r.nout), .out)
    P(2, "HIERARCHY")
    if let par = S.get(p.ppid), p.ppid > 0 { P(4, "parent: \(par.name) \(par.pid)", "", .dim, (view >= 2 ? "p:" : pre) + "\(par.pid)", view >= 2 ? 0 : -1) } else { P(1, "root process") }
    var nk = 0; for k in S.procs where k.ppid == p.pid { if nk < 40 { P(4, "child: \(k.name) \(k.pid)", "", .dim, "p:\(k.pid)", 0) }; nk += 1 }
    if nk > 40 { P(1, "+\(nk - 40) more children") }
    let ls = SM_listen[p.pid] ?? []
    P(2, "OPEN PORTS (\(ls.count))"); if ls.isEmpty { P(1, "none") }
    for x in ls.prefix(40) { P(3, (x.proto == 1 ? "UDP " : "TCP ") + "\(x.port) " + svcName(x.port), isLoop(x.addr) ? "local only" : x.addr, isLoop(x.addr) ? .dim : .warn) }
    let rs = SM_remote[p.pid] ?? []
    P(2, "REMOTE CONNECTIONS (\(rs.count))"); if rs.isEmpty { P(1, "none") }
    if !rs.isEmpty { P(1, "Click a TCP connection to close it (needs the helper: a pf rule resets it)."); P(5, "CLOSE ALL CONNECTIONS", "", .red, "act:closeproc:\(ps)") }
    for c in rs.prefix(40) {
        let t = "\(c.ra):\(c.rp) \(svcName(c.rp))  :\(c.lp) \(c.st)"
        if c.proto == "TCP" && c.st != "recent" { P(4, t, "", .dim, "act:closeconn:\(c.la)|\(c.lp)|\(c.ra)|\(c.rp)") } else { P(3, t, "", .dim) }
    }
    var hdr = false
    for x in SM_loop.values where x.a == p.pid || x.b == p.pid {
        guard let o = S.get(x.a == p.pid ? x.b : x.a) else { continue }
        if !hdr { P(2, "LOCAL LANES (PIPES · UNIX SOCKETS · LOOPBACK)"); hdr = true }
        P(4, "\(o.name) \(o.pid)  \(x.kind) x\(x.n)", "", .dim, (view >= 2 ? "p:" : pre) + "\(o.pid)", view >= 2 ? 0 : -1)
    }
    if view == 3 {
        let fs = filesByPid[p.pid] ?? []; P(2, "OPEN FILES (\(fs.count))"); if fs.isEmpty { P(1, "none visible") }
        for f in fs.prefix(200) { P(4, f, "", .dim, "pf:\(p.pid):" + f) }
    }
    P(2, "INSPECT"); P(5, "VIEW MEMORY (HEX)", "", .dim, "hexmem:\(ps)"); P(5, "VIEW PACKETS (HEX)", "", .dim, "hexpkt:pid:\(ps)")
    P(2, "OPEN IN")
    if view != 0 { P(5, "PROCESS TREE", "", .dim, "p:\(ps)", 0) }
    if view != 1 && (!ls.isEmpty || !rs.isEmpty) { P(5, "NETWORK VIEW", "", .dim, "n:\(ps)", 1) }
    if view != 2 { P(5, "MEMORY VIEW", "", .dim, "g:" + p.name, 2) }
    if view != 3 { P(5, "FILES VIEW", "", .dim, "f:\(ps)", 3) }
}
func userName(_ uid: UInt32) -> String { if let pw = getpwuid(uid) { return String(cString: pw.pointee.pw_name) }; return "\(uid)" }

func buildPanel() {
    pitems = []; guard let S = S else { return }
    if view == 4 { diskPanel(); return }; if view == 5 { devPanel(); return }
    if sel.isEmpty { summaryPanel(); return }
    let L = LY[view]; let ni = L.nodes[sel]
    let isProc = sel.hasPrefix("p:") || sel.hasPrefix("n:") || sel.hasPrefix("rp:") || sel.hasPrefix("f:")
    if isProc {
        guard let pid = Int32(sel.split(separator: ":")[1]), let p = S.get(pid) else { sel = ""; computeFocus(); return }
        procPanel(p)
    } else if sel.hasPrefix("g:") {
        guard let gr = ramGroups[String(sel.dropFirst(2))] else { sel = ""; return }
        P(0, gr.name); P(1, fmtB(gr.v) + " resident" + String(format: " · %.1f%% of RAM", gr.v / Double(S.memTotal) * 100)); memSection(gr.pids)
        P(2, "PROCESSES (\(gr.pids.count))")
        let ps = gr.pids.compactMap { S.get($0) }.sorted { $0.rss > $1.rss }
        for p in ps.prefix(80) { P(4, (gr.misc ? p.name + " " : "") + "\(p.pid)   " + fmtB(Double(p.rss)) + (p.footprint > 0 ? "  footprint " + fmtB(Double(p.footprint)) : ""), "", .dim, "rp:\(p.pid)") }
    } else if let n = ni {
        if n.kind == .file {
            P(0, (n.s1 as NSString).lastPathComponent); P(1, n.s1)
            P(7, "REVEAL IN FINDER|act:reveal:\(n.s1);COPY PATH|act:copy:\(n.s1)")
            P(1, "Force-closing another process's file is not possible on macOS.")
            if diskLive() { diskSection(-1, n.s1) }
            P(2, "OPENED BY"); for pid in fileOwners[n.s1] ?? [] { P(4, "\(S.get(pid)?.name ?? "?") \(pid)", "", .dim, "f:\(pid)") }
        } else if n.kind == .host {
            P(0, n.s1); P(1, (isPrivate(n.s1) ? "local network" : "internet host") + " · \(n.cnt) connection(s)"); dnsRow(n.s1)
            if let w = Whois.shared.result(n.s1) { P(1, "owner: " + w) }
            P(7, "COPY ADDRESS|act:copy:\(n.s1);WHO OWNS IT|act:whois:\(n.s1);PING|act:ping:\(n.s1)")
            P(5, "CLOSE CONNECTIONS TO THIS HOST", "", .red, "act:closehost:" + n.s1); P(5, "BLOCK THIS HOST (PF FIREWALL)", "", .red, "act:fwblock:" + n.s1)
            netSection(-1, n.s1); P(5, "VIEW PACKETS (HEX)", "", .dim, "hexpkt:ip:" + n.s1); P(2, "CONNECTIONS")
            for (pid, rs) in SM_remote { for c in rs where c.ra == n.s1 { P(4, "\(S.get(pid)?.name ?? "?") \(pid)  :\(c.lp) → :\(c.rp) \(svcName(c.rp)) \(c.proto)", "", .dim, "n:\(pid)") } }
        } else if n.kind == .port && n.more == 0 {
            P(0, (n.proto == 1 ? "UDP " : "TCP ") + "\(n.port) " + svcName(n.port))
            P(1, "bound to \(n.s1)" + (isLoop(n.s1) ? " — reachable from this Mac only" : " — reachable from the network (firewall permitting)"))
            P(2, "OWNER"); P(4, "\(n.name) \(n.pid)", "", .dim, "n:\(n.pid)")
            P(5, "VIEW PACKETS (HEX)", "", .dim, "hexpkt:port:" + (n.proto == 1 ? "UDP:" : "TCP:") + "\(n.port)"); P(5, "ALL OPEN PORTS", "", .dim, "hexports")
            P(5, "BLOCK INBOUND TO THIS PORT (PF FIREWALL)", "", .red, "act:fwblockport:" + (n.proto == 1 ? "UDP:" : "TCP:") + "\(n.port)")
            if n.proto == 0 { P(2, "ACCEPTED CONNECTIONS"); var c = 0; for x in SM_est[n.pid] ?? [] where x.lp == n.port { P(3, "\(x.ra):\(x.rp)", x.st); c += 1 }; if c == 0 { P(1, "none right now") } }
        } else { for (i, l) in nodeTip(n).enumerated() { P(i == 0 ? 0 : 1, l.s) } }
    }
}
func wrapText(_ s: String, _ w: Int) -> [String] {
    let u = Array(s.unicodeScalars); var out: [String] = []; var o = 0
    while o < u.count {
        var n = min(w, u.count - o)
        if o + n < u.count, let sp = u[o..<(o + n)].lastIndex(of: " "), sp > o + w / 2 { n = sp - o + 1 }
        var str = ""; str.unicodeScalars.append(contentsOf: u[o..<(o + n)]); out.append(str); o += n
    }
    return out.isEmpty ? [""] : out
}
func ellipsizeLeft(_ s: String, _ room: Int) -> String { let u = Array(s.unicodeScalars); if u.count <= room { return s }; var r = "…"; r.unicodeScalars.append(contentsOf: u[(u.count - room + 1)...]); return r }
func ellipsize(_ s: String, _ room: Int) -> String { let u = Array(s.unicodeScalars); if u.count <= room { return s }; var r = ""; r.unicodeScalars.append(contentsOf: u[0..<(room - 1)]); return r + "~" }

func drawPanel() {
    buildPanel(); if pitems.isEmpty { return }
    let w: Float = 380, x = G.LW - w - 12, y0: Float = 58, maxH = max(120, legendTop - y0 - 8); let wrap = Int((w - 24) / CW)
    func height(_ i: PItem) -> Float { switch i.type { case 0: return 22; case 1: return 15 * Float(wrapText(i.a, wrap).count) + 2; case 2: return 28; case 5, 6, 7: return 26; default: return 16 } }
    var total: Float = 20; for i in pitems { total += height(i) }; let h = min(total, maxH)
    panelBg(x, y0, w, h)
    if inR(x, y0, w, h) { UIS.panelScroll -= UIS.wheelUi * 40; UIS.wheelUi = 0 }
    UIS.panelScroll = max(0, min(UIS.panelScroll, total - h))
    g.clip = (x, y0 + 1, x + w, y0 + h - 1)
    var y = y0 + 10 - UIS.panelScroll; var act = ""; var actView = -1; var doAct = false
    let inside = UIS.mouseY > y0 && UIS.mouseY < y0 + h
    for i in pitems {
        let ih = height(i)
        if y + ih > y0 && y < y0 + h {
            switch i.type {
            case 0: g.text(x + 12, y, i.a, uiCol(.cyan), bold: true)
            case 1: for (ln, l) in wrapText(i.a, wrap).enumerated() { g.text(x + 12, y + Float(ln) * 15, l, .dim) }
            case 2: g.text(x + 12, y + 10, i.a, .dim); g.fill(x + 12, y + 26, w - 24, 1, rgba(0x4fe3ff, 0.25))
            case 3:
                let room = wrap > i.b.unicodeScalars.count + 2 ? wrap - i.b.unicodeScalars.count - 2 : 4
                g.text(x + 12, y, ellipsizeLeft(i.a, room), .text); g.text(x + w - 12 - Float(i.b.unicodeScalars.count) * CW, y, i.b, i.cb)
            case 4:
                let hot = inR(x + 8, y, w - 16, 16) && inside
                if hot { g.fill(x + 8, y, w - 16, 16, rgba(0x4fe3ff, 0.14)) }
                g.text(x + 12, y, "› " + ellipsizeLeft(i.a, wrap - 2), hot ? .white : .text)
                if hot && UIS.clickNow { act = i.sel; actView = i.view; doAct = true }
            case 5: var bx = x + 12; if button(&bx, y + 2, i.a, false, i.cb == .dim ? .cyan : i.cb) && inside { act = i.sel; actView = i.view; doAct = true }
            case 7:
                var bx = x + 12
                for part in i.a.split(separator: ";") {
                    let kv = part.split(separator: "|", maxSplits: 1); guard kv.count == 2 else { continue }
                    let lbl = String(kv[0]); let bw = Float(lbl.unicodeScalars.count) * CW + 18
                    if bx + bw > x + w - 8 { continue }   // too many for one row: dropped rather than overflowing
                    if button(&bx, y + 1, lbl, false, i.cb == .dim ? .cyan : i.cb) && inside { act = String(kv[1]); actView = -1; doAct = true }
                    bx += 4
                }
            case 6:
                var bx = x + 12
                for s in [1, 5, 10, 30, 60] { if button(&bx, y + 1, "\(s)s", winSec == s) && inside { winSec = s }; bx += 4 }
            default: break
            }
        }
        y += ih
    }
    g.clip = nil
    if !sel.isEmpty { let bx = x + w - 26; let hot = inR(bx, y0 + 6, 18, 18); if hot && UIS.clickNow { doAct = true; act = ""; actView = -1 }; g.text(bx + 4, y0 + 6, "×", hot ? .white : .dim) }
    if doAct { UIS.panelScroll = 0; UIS.clickNow = false; if actView >= 0 && actView != view { setView(actView, act) } else { selectKey(act) } }
}

func drawLabels() {
    let L = LY[view]; var c: [(Float, Node)] = []
    for (k, n) in L.nodes where !n.dead && !n.label.isEmpty {
        var pr = n.lp
        if hasFocus { if focus.contains(k) { pr += 50 } else { continue } }
        if k == sel { pr += 200 }; if k == hov { pr += 300 }
        c.append((pr, n))
    }
    c.sort { $0.0 > $1.0 }
    var taken: [(Float, Float, Float)] = []; var used = 0
    for (_, n) in c {
        if used >= 80 { break }
        var p = n.pos; p.y += n.scale.y * (n.shape == .box ? 0.5 : 1)
        guard let (sx, sy) = project(p), sx > -40, sx < G.LW + 40, sy > 0, sy < G.LH else { continue }
        let lw = Float(n.label.unicodeScalars.count) * CW
        if taken.contains(where: { abs($0.0 - sx) < ($0.2 + lw) / 2 + 6 && abs($0.1 - sy) < 14 }) { continue }
        taken.append((sx, sy, lw)); used += 1
        let x = sx - Float(n.label.unicodeScalars.count) * CW / 2, y = sy - 20
        g.text(x + 1, y + 1, n.label, rgba(0x000814, 0.9)); g.text(x, y, n.label, n.key == sel ? uiCol(.white) : rgba(0x9fe9ff, min(1, 0.55 + n.op * 0.45)))
    }
}

// ---- toasts and confirmation
let toastLock = NSLock()
var toastMsg = "", toastCol = T.text, toastT = -10.0
func toast(_ m: String, _ c: T) { toastLock.lock(); toastMsg = m; toastCol = c; toastT = nowSec(); toastLock.unlock() }
struct Confirm { var open = false, needHelper = false; var title = "", warn = "", detail = "", key = "", yes = ""; var red = true; var extra: [(String, String)] = [] }
var cf = Confirm()
var statsLine = ""

func captureStatus() -> (String, T) {
    let m = Model.shared
    if m.captureLive { return ("● CAPTURE LIVE (helper) \(capPps) pk/s", .safe) }
    if m.helperConnected {
        var why = m.helperStatus.isEmpty ? "capture starting…" : m.helperStatus
        if why.contains("not permitted") { why = "capture needs root — the helper is not running as a LaunchDaemon" }
        return ("helper connected · " + why, .warn)
    }
    return ("", .warn)
}

func drawUi() {
    UIS.prevRects = UIS.uiRects; UIS.uiRects = []
    UIS.mouseOverUi = false; let savedClick = UIS.clickNow; if cf.open { UIS.clickNow = false }
    drawLabels()
    // top bar
    panelBg(12, 12, G.LW - 24, 36); var x: Float = 24; let y: Float = 19
    g.text(x, y + 1, "MATRIX//SYS", uiCol(.cyan), bold: true); x += 112
    let tabs = ["PROCESSES", "NETWORK", "FILES", "DISKS", "DEVICES", "MEMORY"], tv = [0, 1, 3, 4, 5, 2]
    for i in 0..<6 { if button(&x, y, tabs[i], view == tv[i]) && view != tv[i] { setView(tv[i]) } }
    x += 10
    do { let w: Float = 120; g.stroke(x, y, w, 22, rgba(0x4fe3ff, query.isEmpty ? 0.28 : 0.8))
        if query.isEmpty { g.text(x + 8, y + 3, "type to filter", .dim) } else { g.text(x + 8, y + 3, query + "_", .white) }; x += w + 10 }
    if button(&x, y, paused ? "RESUME" : "PAUSE", paused) { paused.toggle() }
    x += 10
    let (st, sc) = captureStatus()
    if st.isEmpty {
        if button(&x, y, "FULL ACCESS (HELPER)", false, .warn) { Helper.offerInstall() }
        if inR(x - 180, y, 180, 22) { pendingTip = [TL(s: "Installs a root LaunchDaemon (asks for your password) for capture, all processes' files and counters.", c: .text)] }
    } else { g.text(x, y + 3, st, st.hasPrefix("●") ? uiCol(sc) : uiCol(sc)); x += Float(st.unicodeScalars.count) * CW }
    if let S = S {
        statsLine = "\(S.procs.count) procs · \(S.conns.count) sockets · RAM used \(fmtB(Double(S.memApp + S.memWired + S.memCompressed)))/\(fmtB(Double(S.memTotal))) · ▼ \(fmtR(S.rx)) ▲ \(fmtR(S.tx))" + (S.nettopOK ? "" : " · nettop unavailable")
    } else { g.text(G.LW / 2 - 50, G.LH / 2, "JACKING IN...", uiCol(.cyan), bold: true) }
    // legend
    do {
        var lg: [TL]
        switch view {
        case 0: lg = [TL(s: "PROCESS TREE — children rise above their parent; size = memory, glow = CPU. launchd's children are separate trees.", c: .text), TL(s: "Violet lanes = pipes, unix sockets and loopback TCP between processes.", c: .dim)]
        case 1: lg = [TL(s: "NETWORK — inner ring: processes with sockets; stacks: open ports; outer ring: remote hosts.", c: .text), TL(s: "Ports: green = local only, amber = network-reachable, violet = UDP.", c: .dim)]
        case 4: lg = [TL(s: "DISKS — floor area and height = allocated size on each volume, by folder.", c: .text), TL(s: "Select a folder to open it in place; the panel can zoom the whole floor into it. Backspace goes up.", c: .dim)]
        case 5: lg = [TL(s: "DEVICES — the IOKit tree by connection, rising from this Mac; network neighbours hang off their interface.", c: .text), TL(s: "Dots follow the connection path for disks and network interfaces (driver counters).", c: .dim)]
        case 3: lg = [TL(s: "FILES — ring: processes holding files open; outer boxes: files shared by several processes.", c: .text), TL(s: "Select a process to fan out its open files. Without the helper only your own processes are readable.", c: .dim)]
        default: lg = [TL(s: "MEMORY — floor area and height = resident memory per application.", c: .text), TL(s: "Select a tower to split it into its processes. Shared pages count in each process.", c: .dim)]
        }
        if view < 2 || view == 3 { lg.append(TL(s: capOn() ? "Network dots are captured packets (250 ms bundles per flow)." : "Dots are paced from exact byte counters (nettop, rusage); packet timing is estimated.", c: .dim)) }
        lg.append(TL(s: "Drag orbit · right/shift-drag or option-scroll pan · scroll/pinch zoom · click select · Esc clear · Home reset · [ ] time window", c: .dim))
        if !statsLine.isEmpty { lg.insert(TL(s: statsLine, c: .cyan), at: 0) }
        let mx = lg.map { $0.s.unicodeScalars.count }.max() ?? 0; let w = Float(mx) * CW + 24, h = Float(lg.count) * 16 + 14
        legendTop = G.LH - h - 12; panelBg(12, G.LH - h - 12, w, h)
        for (i, l) in lg.enumerated() { g.text(24, G.LH - h - 12 + 7 + Float(i) * 16, l.s, l.c) }
    }
    if hexMode != 0 { drawHex() } else { drawPanel() }
    // tooltip
    if let t = pendingTip { drawTip(t); pendingTip = nil }
    else if !UIS.mouseOverUi {
        if hovPart >= 0 && hovPart < parts.count {
            let p = parts[hovPart]; let o = p.dir > 0; var t: [TL] = []
            if p.disk, let f = p.flow { t = [TL(s: fmtB(p.bytes) + (o ? " written" : " read"), c: o ? .out : .inn), TL(s: "\(S?.get(f.pid)?.name ?? "?") \(f.pid)", c: .text), TL(s: p.dpath.isEmpty ? "(no path)" : p.dpath, c: .text), TL(s: "traced live (fs_usage)", c: .safe)] }
            else if p.real, let f = p.flow {
                let a = "\(S?.get(f.pid)?.name ?? "?") \(f.lip):\(f.lp)", b = "\(f.rip):\(f.rp)"; let sv = svcName(f.rp).isEmpty ? svcName(f.lp) : svcName(f.rp)
                t = [TL(s: fmtB(Double(f.bytes)) + " in \(f.n) packet" + (f.n > 1 ? "s" : "") + (o ? "  ▲ outbound" : "  ▼ inbound"), c: o ? .out : .inn), TL(s: protoName(f.proto) + (sv.isEmpty ? "" : " · " + sv), c: .text),
                     TL(s: (o ? a : b) + " → " + (o ? b : a), c: .text), TL(s: "captured live", c: .safe)]
            } else if let l = LY[view].lanes[p.lane] {
                t = [TL(s: "≈ " + fmtB(p.bytes) + " bundle" + (o ? "  ▲ outbound" : "  ▼ inbound"), c: o ? .out : .inn), TL(s: l.proto, c: .text), TL(s: (o ? l.from : l.to) + " → " + (o ? l.to : l.from), c: .text),
                     TL(s: "lane rate " + fmtR(o ? l.out : l.inn) + " (exact counter, dot timing estimated)", c: .dim)]
            }
            drawTip(t)
        } else if !hov.isEmpty, let n = LY[view].nodes[hov] { drawTip(nodeTip(n)) }
    }
    do {
        toastLock.lock(); let tm = toastMsg, tc = toastCol, tt = toastT; toastLock.unlock()
        if nowSec() - tt < 7 && !tm.isEmpty {
            let tw = min(G.LW - 40, Float(tm.unicodeScalars.count) * CW + 28), tx = G.LW / 2 - tw / 2
            g.fill(tx, 62, tw, 26, rgba(0x020a16, 0.96)); g.stroke(tx, 62, tw, 26, uiCol(tc, 0.9)); g.text(tx + 14, 67, ellipsize(tm, Int((tw - 28) / CW)), tc)
        }
    }
    if cf.open {   // modal: nothing else reacts to the click
        UIS.clickNow = savedClick; UIS.mouseOverUi = true; g.fill(0, 0, G.LW, G.LH, rgba(0x000408, 0.62)); UIS.uiRects.append((0, 0, G.LW, G.LH))
        let w: Float = 600, x = G.LW / 2 - w / 2; let wr = Int((w - 40) / CW)
        let wl = wrapText(cf.warn, wr), dl = cf.detail.isEmpty ? [] : wrapText(cf.detail, wr)
        let h: Float = 60 + Float(wl.count + dl.count) * 16 + 60 + (cf.needHelper ? 24 : 0); let y = G.LH / 2 - h / 2; var yy = y + 48
        let edge: T = cf.red ? .red : .warn
        g.fill(x, y, w, h, cf.red ? rgba(0x12060a, 0.98) : rgba(0x020a16, 0.98)); g.stroke(x, y, w, h, uiCol(edge)); g.stroke(x + 2, y + 2, w - 4, h - 4, uiCol(edge, 0.35))
        g.text(x + 20, y + 16, cf.title, uiCol(.white), bold: true)
        for l in wl { g.text(x + 20, yy, l, edge); yy += 16 }; yy += 6; for l in dl { g.text(x + 20, yy, l, .text); yy += 16 }
        if cf.needHelper { g.text(x + 20, yy + 4, "This needs the privileged helper (FULL ACCESS).", .warn) }
        var bx = x + 20; let by = y + h - 40
        if cf.needHelper { if button(&bx, by, "INSTALL HELPER…", false, .warn) { cf.open = false; Helper.offerInstall() } }
        else {
            if button(&bx, by, cf.yes, false, edge) { cf.open = false; performAction(cf.key) }
            for e in cf.extra { bx += 12; if button(&bx, by, e.0, false, edge) { cf.open = false; performAction(e.1) } }
        }
        bx += 12; if button(&bx, by, "CANCEL", false) { cf.open = false }
    }
}
var pendingTip: [TL]? = nil

// ================================================================ list and hex windows
var hexMode = 0   // 1 memory, 2 packets, 3 open ports, 4 processes by lane traffic
var navKey = 0, listCur = 0, hexFocus = 1
var portScroll: Float = 0, laneSort = 0
enum NK { static let up = 1, down = 2, left = 3, right = 4, pgUp = 5, pgDn = 6, home = 7, end = 8, enter = 9 }
@discardableResult func navList(_ cur: inout Int, _ scroll: inout Float, _ n: Int, _ page: Int) -> Bool {
    if n <= 0 { cur = 0; return false }; let k = navKey; var moved = true; let page = max(1, page)
    switch k { case NK.up: cur -= 1; case NK.down: cur += 1; case NK.pgUp: cur -= page; case NK.pgDn: cur += page; case NK.home: cur = 0; case NK.end: cur = n - 1; default: moved = false }
    cur = max(0, min(n - 1, cur))
    if moved { if cur < Int(scroll) { scroll = Float(cur) }; if cur >= Int(scroll) + page { scroll = Float(cur - page + 1) } }
    return k == NK.enter
}
func hexClose() { if hexMode == 2 { Packets.shared.close() }; MemViewer.shared.close(); hexMode = 0 }
func hexOpenMem(_ pid: Int32) { hexClose(); hexMode = 1; hexFocus = 1; MemViewer.shared.open(pid) }
func hexOpenPkts(_ pid: Int32, _ ip: String, port: Int = -1, proto: Int = 0) {
    hexClose(); hexMode = 2; hexFocus = 1; Packets.shared.open(pid: pid, ip: ip, port: port, proto: proto)
}
let HEX_HDR = "OFFSET        00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII"
/// 16 bytes per row. Leading bytes up to dimUntil are drawn dim (packet headers); bytes that changed since prev are magenta.
func hexDump(_ x: Float, _ y: Float, _ addr: UInt64, _ d: [UInt8], _ ok: [Bool]?, _ prev: [UInt8]?, _ n: Int, _ dimUntil: Int, _ start: Int = 0) {
    var r = 0
    while r * 16 < n {
        let yy = y + Float(r) * 15; g.text(x, yy, String(format: "%012llX", addr + UInt64(r * 16)), .dim)
        var h0 = [Character](repeating: " ", count: 50), h1 = h0, h2 = h0, s1 = [Character](repeating: " ", count: 16), s2 = s1; var any2 = false
        for i in 0..<16 where r * 16 + i < n {
            let k = start + r * 16 + i; let c = i * 3 + (i >= 8 ? 1 : 0)
            let good = ok == nil || ok![k], chg = good && prev != nil && prev![k] != d[k]
            let bb = good ? Array(String(format: "%02X", d[k])) : ["?", "?"]
            if chg { h2[c] = bb[0]; h2[c + 1] = bb[1] } else if k < dimUntil || !good { h0[c] = bb[0]; h0[c + 1] = bb[1] } else { h1[c] = bb[0]; h1[c + 1] = bb[1] }
            let ch: Character = good && d[k] >= 32 && d[k] < 127 ? Character(UnicodeScalar(d[k])) : "."
            if chg { s2[i] = ch } else { s1[i] = ch }; any2 = any2 || chg
        }
        let hx = x + 14 * CW, ax = hx + 52 * CW
        g.text(hx, yy, String(h0), .dim); g.text(hx, yy, String(h1), .text); g.text(ax, yy, String(s1), .cyan)
        if any2 { g.text(hx, yy, String(h2), .out); g.text(ax, yy, String(s2), .out) }
        r += 1
    }
}

func drawHex() {
    let X0: Float = 12, Y0: Float = 58, Wd = G.LW - 24, Ht = max(200, legendTop - 8 - Y0), LWd: Float = 360
    panelBg(X0, Y0, Wd, Ht); g.fill(X0 + 1, Y0 + 1, Wd - 2, Ht - 2, rgba(0x020a16, 0.93))
    let inside = inR(X0, Y0, Wd, Ht); let wheel = inside ? UIS.wheelUi : 0; if inside { UIS.wheelUi = 0 }
    do { var bx = X0 + Wd - 66; if button(&bx, Y0 + 8, "CLOSE", false) { hexClose(); return } }
    let top = Y0 + 42, listH = Ht - 52, hx = X0 + LWd + 14; let rows = max(4, Int(listH / 15)); let inList = inR(X0, top, LWd, listH)
    guard let S = S else { return }
    let click = UIS.clickNow
    if hexMode == 4 {   // every process, ordered by the traffic on its lanes in the time window
        struct LR { var p: ProcInfo; var rd: Double; var wr: Double; var nin: Double; var nout: Double; var socks: Int }
        var rs: [LR] = []; let past = pastSnap(); let cap = capOn()
        var net: [Int32: (Double, Double)] = [:]
        if cap { let t0 = nowSec() - Double(winSec); for f in flowHist.reversed() { if f.t < t0 { break }; var e = net[f.pid] ?? (0, 0); if f.out { e.1 += Double(f.bytes) } else { e.0 += Double(f.bytes) }; net[f.pid] = e } }
        var socks: [Int32: Int] = [:]; for x in SM_loop.values { socks[x.a, default: 0] += x.n; socks[x.b, default: 0] += x.n }
        for p in S.procs { let w = ioWin(p.pid, past); let n = cap ? net[p.pid] ?? (0, 0) : (w.nin, w.nout); rs.append(LR(p: p, rd: w.rd, wr: w.wr, nin: n.0, nout: n.1, socks: socks[p.pid] ?? 0)) }
        func key(_ a: LR) -> Double { laneSort == 1 ? a.nin + a.nout : laneSort == 2 ? a.rd : laneSort == 3 ? a.wr : a.rd + a.wr + a.nin + a.nout }
        rs.sort { let x = key($0), y = key($1); return x != y ? x > y : $0.p.pid < $1.p.pid }
        g.text(X0 + 12, Y0 + 9, "PROCESSES BY LANE TRAFFIC · \(rs.count) processes · last \(winSec)s ( [ ] changes it )", uiCol(.cyan), bold: true)
        do { var bx = X0 + 12; g.text(bx, top + 3, "SORT BY", .dim); bx += 62
            for (m, nm) in ["ALL LANES", "NETWORK", "DISK READS", "DISK WRITES"].enumerated() { if button(&bx, top, nm, laneSort == m) { laneSort = m; portScroll = 0 }; bx += 4 } }
        g.text(X0 + 12, top + 26, "PROCESS                           PID   ALL LANES  in / out       NETWORK  in / out       DISK  read / write     LOCAL LANES", .dim)
        if inside { portScroll = max(0, min(portScroll - wheel * 3, max(0, Float(rs.count - (rows - 3))))) }
        let enter = navList(&listCur, &portScroll, rs.count, rows - 3)
        let first = Int(portScroll)
        for i in 0..<(rows - 3) where first + i < rs.count {
            let r = rs[first + i]; let y = top + 41 + Float(i) * 15; let hot = inR(X0 + 6, y, Wd - 12, 15), cur = first + i == listCur
            if hot || cur { g.fill(X0 + 6, y, Wd - 12, 15, rgba(0x4fe3ff, cur ? 0.22 : 0.12)) }
            let nm = ellipsize(r.p.name, 28)
            let line = nm.padding(toLength: 28, withPad: " ", startingAt: 0) + String(format: " %8d   %9@ %9@     %9@ %9@     %9@ %9@     %@", r.p.pid,
                fmtB(r.rd + r.nin) as NSString, fmtB(r.wr + r.nout) as NSString, fmtB(r.nin) as NSString, fmtB(r.nout) as NSString,
                (r.p.hasIO ? fmtB(r.rd) : "-") as NSString, (r.p.hasIO ? fmtB(r.wr) : "-") as NSString, (r.socks > 0 ? "\(r.socks)" : "") as NSString)
            g.text(X0 + 12, y, line, hot || cur ? .white : r.rd + r.wr + r.nin + r.nout > 0 ? .text : .dim)
            if (hot && click) || (cur && enter) { let k = "p:\(r.p.pid)"; hexClose(); UIS.clickNow = false; if view != 0 { setView(0, k) } else { selectKey(k) }; return }
        }
        return
    }
    if hexMode == 3 {   // every listening port on this Mac; open one for its packets
        struct PR { var proto: Int; var port: Int; var pid: Int32; var addr: String; var inn = 0.0, out = 0.0 }
        var ps: [PR] = []
        for (pid, ls) in SM_listen { for x in ls { ps.append(PR(proto: x.proto, port: x.port, pid: pid, addr: x.addr)) } }
        ps.sort { ($0.proto, $0.port, $0.pid) < ($1.proto, $1.port, $1.pid) }
        let t0 = nowSec() - Double(winSec)
        if capOn() {
            var m: [String: (Double, Double, Int, Int)] = [:]
            for f in flowHist.reversed() { if f.t < t0 { break }; let k = "\(f.proto == 17 ? 1 : 0):\(f.lp)"; var e = m[k] ?? (0, 0, 0, 0); if f.out { e.1 += Double(f.bytes); e.3 += f.n } else { e.0 += Double(f.bytes); e.2 += f.n }; m[k] = e }
            for i in ps.indices { if let e = m["\(ps[i].proto):\(ps[i].port)"] { ps[i].inn = e.0; ps[i].out = e.1 } }
        } else if let past = pastSnap() {
            var old: [String: (UInt64, UInt64)] = [:]; for c in past.conns { old[c.key] = (c.bin, c.bout) }
            var m: [String: (Double, Double)] = [:]
            for c in S.conns { let o = old[c.key] ?? (c.bin, c.bout); let k = "\(c.proto == "UDP" ? 1 : 0):\(c.lp)"; var e = m[k] ?? (0, 0)
                e.0 += Double(c.bin >= o.0 ? c.bin - o.0 : 0); e.1 += Double(c.bout >= o.1 ? c.bout - o.1 : 0); m[k] = e }
            for i in ps.indices { if let e = m["\(ps[i].proto):\(ps[i].port)"] { ps[i].inn = e.0; ps[i].out = e.1 } }
        }
        g.text(X0 + 12, Y0 + 9, "OPEN PORTS · \(ps.count) listening · traffic in the last \(winSec)s ( [ ] changes it )" + (capOn() ? "" : " · bytes from nettop, packets need the helper"), uiCol(.cyan), bold: true)
        g.text(X0 + 12, top, "PROTO PORT  SERVICE        REACHABLE FROM           PROCESS                        IN / OUT", .dim)
        if inside { portScroll = max(0, min(portScroll - wheel * 3, max(0, Float(ps.count - (rows - 1))))) }
        let enter = navList(&listCur, &portScroll, ps.count, rows - 1)
        let first = Int(portScroll)
        for i in 0..<(rows - 1) where first + i < ps.count {
            let p = ps[first + i]; let y = top + 15 + Float(i) * 15; let hot = inR(X0 + 6, y, Wd - 12, 15), cur = first + i == listCur
            if hot || cur { g.fill(X0 + 6, y, Wd - 12, 15, rgba(0x4fe3ff, cur ? 0.22 : 0.12)) }
            let who = ellipsize("\(S.get(p.pid)?.name ?? "?") \(p.pid)", 30)
            let from = ellipsize(isLoop(p.addr) ? "this Mac only" : isAny(p.addr) ? "network (all interfaces)" : p.addr, 24)
            var line = (p.proto == 1 ? "UDP" : "TCP").padding(toLength: 6, withPad: " ", startingAt: 0) + String(format: "%5d ", p.port)
                + svcName(p.port).padding(toLength: 15, withPad: " ", startingAt: 0) + from.padding(toLength: 25, withPad: " ", startingAt: 0) + who.padding(toLength: 31, withPad: " ", startingAt: 0)
            if p.inn + p.out > 0 { line += "▼" + fmtB(p.inn) + " ▲" + fmtB(p.out) }
            g.text(X0 + 12, y, line, hot || cur ? .white : isLoop(p.addr) ? .text : .warn)
            if (hot && click) || (cur && enter) { UIS.clickNow = false; hexOpenPkts(-1, "", port: p.port, proto: p.proto == 1 ? 17 : 6); return }
        }
        return
    }
    if hexMode == 1 { MemViewer.shared.draw(X0: X0, Y0: Y0, Wd: Wd, Ht: Ht, LWd: LWd, top: top, hx: hx, rows: rows, inList: inList, wheel: wheel); return }
    Packets.shared.draw(X0: X0, Y0: Y0, Wd: Wd, Ht: Ht, LWd: LWd, top: top, hx: hx, rows: rows, inList: inList, wheel: wheel)
}
