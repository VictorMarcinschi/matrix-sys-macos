// Disks view: every volume with used and free space, broken down by folder as a treemap.
// APFS: volumes in one container share its free space, so free is shown once per container; the read-only System volume
// and the Data volume are joined by firmlinks, and scanning never crosses devices, so nothing is counted twice; sizes are
// allocated sizes (st_blocks), so sparse files do not inflate totals. Space no folder accounts for (local Time Machine
// snapshots, purgeable, metadata, unreadable folders) is shown as its own block.
import Foundation
import Darwin

final class DNode {
    let name: String; weak var parent: DNode?
    var size: UInt64 = 0, own: UInt64 = 0, files: UInt64 = 0
    var kids: [String: DNode] = [:]
    var denied = false
    init(_ n: String, _ p: DNode?) { name = n; parent = p }
}
struct Vol {
    var mount: String, dev: String, fs: String, name: String
    var total: UInt64, free: UInt64, used: UInt64
    var container: String = "", roles: [String] = [], scannable = true, removable = false, readOnly = false
}
struct Container { var ref: String; var ceiling: UInt64; var free: UInt64; var vols: [(String, String, [String], UInt64, String?)] }   // dev, name, roles, inUse, mount

var diskRoot = ""
func diskParent(_ p: String) -> String { let v = Disks.shared.volume(for: p); if let v = v, p == v.mount { return "" }; let q = (p as NSString).deletingLastPathComponent; if let v = v, q.count < v.mount.count { return v.mount }; return q }

final class Disks {
    static let shared = Disks()
    let lock = NSLock()
    var wanted = false { didSet { if wanted && !started { started = true; Thread { self.loop() }.start() } } }
    private var started = false
    var vols: [Vol] = [], containers: [Container] = []
    var roots: [String: DNode] = [:]           // mount -> tree
    var scanning: [String: String] = [:]       // mount -> current folder
    var done = Set<String>(), filesSeen: UInt64 = 0
    var snapshots = 0, fda = true
    private var dirty = false, lastChange = 0.0
    private var rescanQ: [String] = []
    static let MAXDEPTH = 8
    static let nameOff = MemoryLayout<FTSENT>.offset(of: \FTSENT.fts_name)!

    func changed() -> Bool { lock.lock(); defer { lock.unlock() }; if dirty && nowSec() - lastChange > 0.9 { dirty = false; lastChange = nowSec(); return true }; return false }
    func markDirty() { lock.lock(); dirty = true; lock.unlock() }
    func rescanAll() { fda = checkFDA(); lock.lock(); roots = [:]; done = []; filesSeen = 0; lock.unlock(); refreshVolumes(); startScans() }
    func rescan(_ path: String) { lock.lock(); rescanQ.append(path); lock.unlock() }
    func isMountPoint(_ p: String) -> Bool { lock.lock(); defer { lock.unlock() }; return vols.contains { $0.mount == p } }
    func volume(for path: String) -> Vol? {
        lock.lock(); defer { lock.unlock() }
        return vols.filter { path == $0.mount || path.hasPrefix($0.mount == "/" ? "/" : $0.mount + "/") }.max { $0.mount.count < $1.mount.count }
    }

    private func loop() {
        fda = checkFDA()
        refreshVolumes(); startScans()
        while true {
            sleep(1)
            lock.lock(); let q = rescanQ; rescanQ = []; lock.unlock()
            for p in q { Thread { self.scanSubtree(p) }.start() }
        }
    }
    /// Full Disk Access is needed to read Mail, Messages, Safari data and other protected folders.
    /// Probing TCC.db is unreliable (the verdict differs per binary), so this opens the folders the scan actually wants.
    func checkFDA() -> Bool {
        let home = NSHomeDirectory()
        var sawProtected = false
        for c in ["/Library/Messages", "/Library/Mail", "/Library/Safari", "/Library/Cookies", "/Library/Suggestions"].map({ home + $0 }) {
            var st = stat(); if stat(c, &st) != 0 { continue }
            sawProtected = true
            if let d = opendir(c) { closedir(d); return true }     // one readable protected folder is enough
            if errno != EPERM && errno != EACCES { return true }   // refused for some other reason: do not cry wolf
        }
        return !sawProtected                                       // none of them exist: nothing to warn about
    }
    func refreshVolumes() {
        // APFS layout from diskutil (containers, roles, per-volume space in use)
        var cs: [Container] = []
        let (st, out) = run("/usr/sbin/diskutil", ["apfs", "list", "-plist"], timeout: 15)
        if st == 0, let d = try? PropertyListSerialization.propertyList(from: Data(out.utf8), format: nil) as? [String: Any], let arr = d["Containers"] as? [[String: Any]] {
            for c in arr {
                var vs: [(String, String, [String], UInt64, String?)] = []
                for v in c["Volumes"] as? [[String: Any]] ?? [] {
                    vs.append((v["DeviceIdentifier"] as? String ?? "", v["Name"] as? String ?? "", v["Roles"] as? [String] ?? [], (v["CapacityInUse"] as? NSNumber)?.uint64Value ?? 0, nil))
                }
                cs.append(Container(ref: c["ContainerReference"] as? String ?? "", ceiling: (c["CapacityCeiling"] as? NSNumber)?.uint64Value ?? 0, free: (c["CapacityFree"] as? NSNumber)?.uint64Value ?? 0, vols: vs))
            }
        }
        // mounted local volumes
        var mnt: UnsafeMutablePointer<statfs>? = nil
        let n = getmntinfo(&mnt, MNT_NOWAIT)
        var vs: [Vol] = []
        for i in 0..<Int(n) {
            var s = mnt![i]
            let fs = cString(s.f_fstypename), mount = cString(s.f_mntonname), from = cString(s.f_mntfromname)
            if (Int32(s.f_flags) & MNT_LOCAL) == 0 || ["devfs", "autofs", "nullfs", "lifs"].contains(fs) { continue }   // network mounts and pseudo file systems are skipped
            if mount.hasPrefix("/Library/Developer/CoreSimulator") || mount.hasPrefix("/private/var/folders") { continue }
            let total = UInt64(s.f_blocks) * UInt64(s.f_bsize), free = UInt64(s.f_bavail) * UInt64(s.f_bsize)
            let dev = from.hasPrefix("/dev/") ? String(from.dropFirst(5)) : from
            let name = (try? URL(fileURLWithPath: mount).resourceValues(forKeys: [.volumeNameKey]).volumeName).flatMap { $0 } ?? (mount as NSString).lastPathComponent
            var v = Vol(mount: mount, dev: dev, fs: fs, name: name, total: total, free: free, used: total >= free ? total - free : 0)
            v.readOnly = (Int32(s.f_flags) & MNT_RDONLY) != 0
            v.removable = (try? URL(fileURLWithPath: mount).resourceValues(forKeys: [.volumeIsRemovableKey]).volumeIsRemovable) ?? false
            for (ci, c) in cs.enumerated() {
                if let k = c.vols.indices.filter({ dev == c.vols[$0].0 || dev.hasPrefix(c.vols[$0].0 + "s") }).max(by: { c.vols[$0].0.count < c.vols[$1].0.count }) {
                    v.container = c.ref; v.roles = c.vols[k].2; v.used = c.vols[k].3; v.name = c.vols[k].1; cs[ci].vols[k].4 = mount
                }
            }
            // system-managed APFS volumes (Preboot, VM, Update, xART, Hardware…) are shown as blocks but not walked
            if !v.roles.isEmpty && !v.roles.contains("System") && !v.roles.contains("Data") { v.scannable = false }
            _ = withUnsafeMutablePointer(to: &s) { $0 }
            vs.append(v)
        }
        let (_, snaps) = run("/usr/bin/tmutil", ["listlocalsnapshots", "/"], timeout: 10)
        lock.lock(); vols = vs; containers = cs; snapshots = snaps.split(separator: "\n").filter { $0.contains("com.apple") }.count; dirty = true; lock.unlock()
    }
    private func startScans() {
        lock.lock(); let vs = vols.filter { $0.scannable && roots[$0.mount] == nil }; lock.unlock()
        for v in vs {   // one scan thread per volume
            let root = DNode(v.mount, nil)
            lock.lock(); roots[v.mount] = root; scanning[v.mount] = v.mount; lock.unlock()
            Thread { self.scan(v.mount, into: root); self.lock.lock(); self.done.insert(v.mount); self.scanning[v.mount] = nil; self.dirty = true; self.lock.unlock() }.start()
        }
    }
    /// fts walk: physical (never follows symlinks), XDEV (never enters another volume's mount point), allocated sizes.
    private func scan(_ path: String, into root: DNode) {
        let rootDepth = path == "/" ? 0 : path.split(separator: "/").count
        guard let fts = fts_open([strdup(path), nil], FTS_PHYSICAL | FTS_XDEV | FTS_NOCHDIR, nil) else { return }
        defer { fts_close(fts) }
        var stack: [DNode] = [root]   // stack[i] = node at fts_level i (capped at MAXDEPTH)
        var count = 0; var links = Set<UInt64>()
        while let e = fts_read(fts) {
            let lvl = Int(e.pointee.fts_level)
            switch Int32(e.pointee.fts_info) {
            case FTS_D:
                if lvl == 0 { continue }
                let name = String(cString: (UnsafeRawPointer(e) + Disks.nameOff).assumingMemoryBound(to: CChar.self))
                if lvl <= Disks.MAXDEPTH {
                    let parent = stack[min(lvl - 1, stack.count - 1)]
                    lock.lock(); let n = parent.kids[name] ?? DNode(name, parent); parent.kids[name] = n; lock.unlock()
                    if stack.count > lvl { stack[lvl] = n; stack.removeSubrange((lvl + 1)...) } else { stack.append(n) }
                    if lvl <= 3 { lock.lock(); scanning[root.name] = String(cString: e.pointee.fts_path); lock.unlock() }
                }
            case FTS_F, FTS_SL, FTS_DEFAULT, FTS_SLNONE:
                guard let st = e.pointee.fts_statp else { continue }
                if st.pointee.st_nlink > 1 && Int32(e.pointee.fts_info) == FTS_F {   // hard links: count the data once
                    if !links.insert(UInt64(st.pointee.st_ino)).inserted { continue }
                }
                let sz = UInt64(st.pointee.st_blocks) * 512
                let holder = stack[min(lvl - 1, stack.count - 1)]
                lock.lock()
                holder.own += sz; var n: DNode? = holder; while let x = n { x.size += sz; x.files += 1; n = x.parent }
                filesSeen += 1; lock.unlock()
                count += 1; if count % 5000 == 0 { lock.lock(); dirty = true; lock.unlock() }
            case FTS_DNR, FTS_ERR:
                if lvl > 0 && lvl <= Disks.MAXDEPTH { let parent = stack[min(lvl - 1, stack.count - 1)]; lock.lock(); parent.denied = true; lock.unlock() }
            default: break
            }
        }
        _ = rootDepth
    }
    /// Rescans one folder: its subtree is replaced, ancestors are corrected by the difference.
    private func scanSubtree(_ path: String) {
        guard let v = volume(for: path), v.scannable else { return }
        lock.lock(); guard let old = find(path) else { lock.unlock(); return }
        let fresh = DNode(old.name, nil); lock.unlock()
        scan(path, into: fresh)
        lock.lock()
        let dSize = Int64(fresh.size) - Int64(old.size), dFiles = Int64(fresh.files) - Int64(old.files)
        old.kids = fresh.kids; for k in old.kids.values { k.parent = old }; old.own = fresh.own; old.size = fresh.size; old.files = fresh.files
        var p = old.parent; while let x = p { x.size = UInt64(max(0, Int64(x.size) + dSize)); x.files = UInt64(max(0, Int64(x.files) + dFiles)); p = x.parent }
        dirty = true; lock.unlock()
        toast("Rescanned " + path, .safe)
    }
    /// caller holds lock
    func find(_ path: String) -> DNode? {
        guard let v = vols.filter({ path == $0.mount || path.hasPrefix($0.mount == "/" ? "/" : $0.mount + "/") }).max(by: { $0.mount.count < $1.mount.count }), var n = roots[v.mount] else { return nil }
        if path == v.mount { return n }
        let rest = path.dropFirst(v.mount == "/" ? 1 : v.mount.count + 1)
        for part in rest.split(separator: "/") { guard let k = n.kids[String(part)] else { return nil }; n = k }
        return n
    }
}

// ---------------------------------------------------------------- layout
private func dkExpand(_ L: Layer, _ n: DNode, _ vol: Vol?, _ path: String, _ x: Float, _ z: Float, _ w: Float, _ d: Float, _ tot: Double, _ depth: Int) {
    let D = Disks.shared
    let ks = n.kids.values.filter { $0.size > 0 }.sorted { $0.size > $1.size }
    var items: [TItem] = []; var rest = 0.0, nrest = 0
    for (i, k) in ks.enumerated() { if i < 40 { items.append(TItem(v: Double(k.size), kind: 0, g: k.name)) } else { rest += Double(k.size); nrest += 1 } }
    if rest > 0 { items.append(TItem(v: rest, kind: 4, pid: Int32(nrest))) }
    if n.own > 0 { items.append(TItem(v: Double(n.own), kind: 1)) }
    if let v = vol { let other = Double(v.used) - Double(n.size); if other > 0 { items.append(TItem(v: other, kind: 3)) } }
    if items.isEmpty { return }
    items.sort { $0.v > $1.v }
    var rects: [TRect] = []; treemap(items, 0, items.count, x, z, w, d, &rects)
    func H(_ v: Double) -> Float { 1.2 + 46 * Float((v / tot).squareRoot()) + Float(depth) * 0.8 }
    let c0 = V3(x + w / 2, -30, z + d / 2); let pad: Float = depth > 0 ? 0.25 : 0.5
    for r in rects {
        func box(_ key: String, _ h: Float, _ c: Col) -> Node {
            let q = up(L, key, .box, .dir, V3(r.x + r.w / 2, -30 + h / 2, r.z + r.d / 2), V3(max(0.2, r.w - pad), h, max(0.2, r.d - pad)), c, depth > 0 ? c0 : nil)
            q.v = r.it.v; q.s1 = path; q.more = r.it.kind; q.lp = Float(r.it.v / tot * 40) + Float(depth) * 1.5; q.glow = 0.45 + Float(depth) * 0.1; return q
        }
        switch r.it.kind {
        case 0:
            guard let k = n.kids[r.it.g] else { continue }
            let cp = (path == "/" ? "" : path) + "/" + k.name, key = "dk:" + cp
            let onPath = sel == key || sel.hasPrefix(key + "/")
            if onPath && !k.kids.isEmpty && r.w > 1.2 && r.d > 1.2 && depth < 12 { dkExpand(L, k, nil, cp, r.x + 0.3, r.z + 0.3, r.w - 0.6, r.d - 0.6, tot, depth + 1) }
            else { let q = box(key, H(r.it.v), k.denied ? C_WARN : nameColor(k.name)); q.s1 = cp; q.name = k.name; q.cnt = Int(k.files); q.label = k.name + " " + fmtB(r.it.v) }
        case 1: let q = box("dkf:" + path, H(r.it.v) * 0.6, mix(C_BLUE, C_WHITE, 0.3)); q.label = "files " + fmtB(r.it.v); q.glow = 0.35
        case 3:
            let q = box("dko:" + path, H(r.it.v) * 0.5, C_BLUE)
            let scanningNow = D.scanning[vol?.mount ?? ""] != nil
            q.label = (scanningNow ? "NOT SCANNED YET " : "NO FOLDER · SNAPSHOTS · PURGEABLE ") + fmtB(r.it.v); q.glow = 0.3; q.s1 = vol?.mount ?? path
        case 4: let q = box("dks:" + path, H(r.it.v) * 0.6, C_BLUE); q.label = "\(r.it.pid) smaller folders " + fmtB(r.it.v); q.cnt = Int(r.it.pid); q.glow = 0.3
        default: break
        }
    }
}
func buildDisks() {
    let L = LY[4]; L.gen += 1; L.ext = 125; let W: Float = 170
    let D = Disks.shared; D.lock.lock(); defer { D.lock.unlock() }
    if !diskRoot.isEmpty, let rn = D.find(diskRoot) {
        let v = D.vols.first { $0.mount == diskRoot }
        dkExpand(L, rn, v, diskRoot, -W / 2, -W / 2, W, W, max(1, Double(v?.used ?? rn.size)), 0)
    } else {
        diskRoot = ""
        // top level: APFS containers (their volumes share one free block) and other volumes
        struct Top { var key: String; var total: Double; var label: String; var vols: [Vol]; var free: Double; var container: Container? }
        var tops: [Top] = []
        for c in D.containers {
            let vs = D.vols.filter { $0.container == c.ref }
            if vs.isEmpty { continue }
            let nm = vs.first { $0.roles.contains("Data") }?.name ?? vs.first?.name ?? c.ref
            tops.append(Top(key: c.ref, total: Double(c.ceiling), label: "\(c.ref) · \(nm)", vols: vs, free: Double(c.free), container: c))
        }
        for v in D.vols where v.container.isEmpty { tops.append(Top(key: v.dev, total: Double(v.total), label: v.name, vols: [v], free: Double(v.free), container: nil)) }
        let tot = tops.reduce(0) { $0 + $1.total }
        var items = tops.enumerated().map { TItem(v: $0.element.total, kind: 0, pid: Int32($0.offset)) }; items.sort { $0.v > $1.v }
        var rects: [TRect] = []; treemap(items, 0, items.count, -W / 2, -W / 2, W, W, &rects)
        for r in rects {
            let t = tops[Int(r.it.pid)]
            let pl = up(L, "dkc:" + t.key, .box, .vol, V3(r.x + r.w / 2, -30.4, r.z + r.d / 2), V3(max(0.2, r.w - 0.4), 0.3, max(0.2, r.d - 0.4)), C_CYAN)
            let used = t.container.map { Double($0.ceiling - $0.free) } ?? Double(t.vols[0].used)
            pl.more = 5; pl.s1 = t.key; pl.v = t.total; pl.label = t.label + "  " + fmtB(used) + " / " + fmtB(t.total); pl.lp = 30; pl.glow = 0.6; pl.name = t.key
            // inside: one block per volume (sized by its own use) plus the container's shared free space
            var sub: [TItem] = []
            for (i, v) in t.vols.enumerated() where v.used > 0 { sub.append(TItem(v: Double(v.used), kind: 0, pid: Int32(i))) }
            if let c = t.container { let mounted = Set(t.vols.map { $0.dev }); for cv in c.vols where !mounted.contains(where: { $0 == cv.0 || $0.hasPrefix(cv.0 + "s") }) && cv.3 > 0 { sub.append(TItem(v: Double(cv.3), kind: 6, g: cv.1)) } }
            sub.append(TItem(v: max(1, t.free), kind: 2)); sub.sort { $0.v > $1.v }
            var sr: [TRect] = []; treemap(sub, 0, sub.count, r.x + 1.2, r.z + 1.2, max(1, r.w - 2.4), max(1, r.d - 2.4), &sr)
            for q in sr {
                switch q.it.kind {
                case 2: let n = up(L, "dkfree:" + t.key, .box, .dir, V3(q.x + q.w / 2, -29.7, q.z + q.d / 2), V3(max(0.2, q.w - 0.5), 0.6, max(0.2, q.d - 0.5)), C_DEEP)
                    n.more = 2; n.v = q.it.v; n.s1 = t.label; n.label = "FREE " + fmtB(q.it.v) + (t.container != nil && t.vols.count > 1 ? " (shared by \(t.vols.count) volumes)" : ""); n.glow = 0.25; n.lp = 3
                case 6: let h: Float = 1.2 + 46 * Float((q.it.v / tot).squareRoot()) * 0.4
                    let n = up(L, "dku:" + t.key + ":" + q.it.g, .box, .dir, V3(q.x + q.w / 2, -30 + h / 2, q.z + q.d / 2), V3(max(0.2, q.w - 0.5), h, max(0.2, q.d - 0.5)), C_BLUE)
                    n.more = 7; n.v = q.it.v; n.label = q.it.g + " (not mounted) " + fmtB(q.it.v); n.name = q.it.g; n.glow = 0.3
                default:
                    let v = t.vols[Int(q.it.pid)]
                    if let root = D.roots[v.mount] {
                        let vp = up(L, "dkv:" + v.mount, .box, .vol, V3(q.x + q.w / 2, -30.1, q.z + q.d / 2), V3(max(0.2, q.w - 0.3), 0.2, max(0.2, q.d - 0.3)), C_CYAN)
                        vp.more = 6; vp.s1 = v.mount; vp.v = Double(v.used); vp.name = v.name; vp.label = v.name + " " + fmtB(Double(v.used)); vp.lp = 20; vp.glow = 0.5
                        dkExpand(L, root, v, v.mount, q.x + 0.8, q.z + 0.8, max(0.5, q.w - 1.6), max(0.5, q.d - 1.6), max(1, tot), 0)
                    } else {
                        let h: Float = 1.2 + 46 * Float((Double(v.used) / max(1, tot)).squareRoot()) * 0.5
                        let n = up(L, "dkv:" + v.mount, .box, .vol, V3(q.x + q.w / 2, -30 + h / 2, q.z + q.d / 2), V3(max(0.2, q.w - 0.5), h, max(0.2, q.d - 0.5)), C_BLUE)
                        n.more = 6; n.s1 = v.mount; n.v = Double(v.used); n.name = v.name; n.label = v.name + " " + fmtB(Double(v.used)) + (v.roles.isEmpty ? "" : " · " + v.roles.joined(separator: ",")); n.glow = 0.35
                    }
                }
            }
        }
    }
    endNodes(L); setLanes(L, [])
}

func diskTip(_ n: Node) -> [TL] {
    switch n.more {
    case 0: return [TL(s: n.name, c: .cyan), TL(s: n.s1, c: .text), TL(s: fmtB(n.v) + " allocated · \(n.cnt) files", c: .text)]
    case 1: return [TL(s: "Files directly in this folder", c: .cyan), TL(s: n.s1, c: .text), TL(s: fmtB(n.v), c: .text)]
    case 2: return [TL(s: "Free space", c: .cyan), TL(s: fmtB(n.v) + " on " + n.s1, c: .text)]
    case 3: return [TL(s: "Space no folder accounts for", c: .cyan), TL(s: fmtB(n.v) + " in use on this volume beyond the scanned folders:", c: .text),
                    TL(s: "local Time Machine snapshots (\(Disks.shared.snapshots)), purgeable space, file system metadata, unreadable folders", c: .dim)]
    case 4: return [TL(s: "\(n.cnt) smaller folders", c: .cyan), TL(s: fmtB(n.v) + " in " + n.s1, c: .text)]
    case 5: return [TL(s: n.label, c: .cyan), TL(s: "APFS container or volume", c: .text)]
    case 6: return [TL(s: n.name, c: .cyan), TL(s: n.s1, c: .text), TL(s: fmtB(n.v) + " in use", c: .text)]
    case 7: return [TL(s: n.name + " (not mounted)", c: .cyan), TL(s: fmtB(n.v) + " in use in the same container", c: .text)]
    default: return [TL(s: n.label, c: .cyan)]
    }
}

func diskPanel() {
    let D = Disks.shared
    D.lock.lock(); defer { D.lock.unlock() }
    var path = ""; if sel.hasPrefix("dk:") { path = String(sel.dropFirst(3)) } else if sel.hasPrefix("dkv:") { path = String(sel.dropFirst(4)) }
    let n = path.isEmpty ? nil : D.find(path)
    let scanning = D.scanning.values.sorted().first
    let status = scanning != nil ? "Scanning \(scanning!) — \(D.filesSeen) files so far" : D.roots.isEmpty ? "Starting scan…" : "Scan complete — \(D.filesSeen) files"
    if !D.fda {
        P(1, "Full Disk Access is off: Mail, Messages, Safari and other protected folders count as unreadable.")
        P(1, "Grant it to this exact app: " + Bundle.main.bundlePath)
        P(7, "OPEN SETTINGS|act:fda:;RESCAN AFTER GRANTING|dkrescan", "", .warn)
    }
    guard let node = n else {
        P(0, diskRoot.isEmpty ? "Disks" : (diskRoot as NSString).lastPathComponent); if !diskRoot.isEmpty { P(1, diskRoot) }; P(1, status)
        if !sel.isEmpty, let ni = LY[4].nodes[sel] {
            P(2, "SELECTED"); for l in diskTip(ni) { P(1, l.s) }
            if ni.more == 3 { P(1, "Free part of it with: tmutil thinlocalsnapshots / 9999999999999 4 (removes local snapshots).") }
        }
        if !diskRoot.isEmpty { P(5, "UP ONE LEVEL", "", .dim, "dkroot:" + diskParentLocked(diskRoot)); P(5, "ALL DISKS", "", .dim, "dkroot:") }
        P(2, "APFS CONTAINERS AND VOLUMES")
        for c in D.containers { let vs = D.vols.filter { $0.container == c.ref }; if vs.isEmpty { continue }
            P(3, c.ref + " container", fmtB(Double(c.ceiling - c.free)) + " / " + fmtB(Double(c.ceiling)), .text); P(3, "  free (shared)", fmtB(Double(c.free)), .safe)
            for v in vs { P(4, "  \(v.name) — \(v.mount)  " + fmtB(Double(v.used)) + (v.roles.isEmpty ? "" : " · " + v.roles.joined(separator: ",")), "", .dim, "dkv:" + v.mount) } }
        for v in D.vols where v.container.isEmpty { P(4, "\(v.name) (\(v.fs)) — \(v.mount)", "", .dim, "dkv:" + v.mount); P(3, "  used / total", fmtB(Double(v.used)) + " / " + fmtB(Double(v.total)), .text); P(3, "  free", fmtB(Double(v.free)), .safe) }
        P(5, "RESCAN", "", .dim, "dkrescan"); P(5, "EMPTY TRASH", "", .red, "act:emptytrash:")
        P(1, "Sizes are allocated sizes. Network volumes and system-managed APFS volumes (Preboot, VM, Update) are not walked.")
        return
    }
    let vol = D.vols.first { $0.mount == path }
    P(0, vol?.name ?? (path as NSString).lastPathComponent); P(1, path); if scanning != nil { P(1, status) }
    if let v = vol {
        P(1, "\(v.fs) · /dev/\(v.dev)" + (v.container.isEmpty ? "" : " · container \(v.container)") + (v.roles.isEmpty ? "" : " · role " + v.roles.joined(separator: ",")) + (v.readOnly ? " · read-only" : ""))
        if v.roles.contains("System") { P(1, "The sealed, read-only system volume. Its firmlinked folders (Users, Applications…) live on the Data volume and are counted there.") }
    }
    P(2, "SIZE"); P(3, "allocated", fmtB(Double(node.size)), .text); P(3, "files", "\(node.files)", .text); P(3, "files directly here", fmtB(Double(node.own)), .text)
    if node.denied { P(3, "some folders", "not readable", .warn) }
    if let p = node.parent, p.size > 0 { P(3, "share of parent folder", String(format: "%.1f%%", Double(node.size) * 100 / Double(p.size)), .text) }
    if let v = vol { P(3, "in use on the volume", fmtB(Double(v.used)), .text); P(3, "free", fmtB(Double(v.free)), .safe) }
    P(5, "ZOOM INTO THIS FOLDER", "", .dim, "dkroot:" + path)
    P(7, "SHOW IN FINDER|act:reveal:\(path);TERMINAL HERE|act:terminal:\(path);RESCAN|act:dkrescan1:\(path)")
    P(5, "COPY PATH", "", .dim, "act:copy:" + path)
    if vol == nil { P(5, "MOVE TO TRASH", "", .red, "act:trash:" + path); P(5, "SELECT PARENT", "", .dim, "dk:" + (path as NSString).deletingLastPathComponent) }
    if let v = vol, v.removable || v.mount.hasPrefix("/Volumes/") { P(5, "EJECT", "", .warn, "act:eject:" + v.mount) }
    if !diskRoot.isEmpty { P(5, "ALL DISKS", "", .dim, "dkroot:") }
    let ks = node.kids.values.sorted { $0.size > $1.size }
    P(2, "SUBFOLDERS (\(ks.count))"); if ks.isEmpty { P(1, "none") }
    for k in ks.prefix(40) { P(4, k.name + "  " + fmtB(Double(k.size)), "", .dim, "dk:" + (path == "/" ? "" : path) + "/" + k.name) }
}
/// diskParent without taking the lock (callers inside diskPanel already hold it)
private func diskParentLocked(_ p: String) -> String {
    let v = Disks.shared.vols.filter { p == $0.mount || p.hasPrefix($0.mount == "/" ? "/" : $0.mount + "/") }.max { $0.mount.count < $1.mount.count }
    if let v = v, p == v.mount { return "" }
    let q = (p as NSString).deletingLastPathComponent; if let v = v, q.count < v.mount.count { return v.mount }; return q
}
