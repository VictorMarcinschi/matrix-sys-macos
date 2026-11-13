// com.matrixsys.helper — the privileged half of MatrixSys, run by launchd as root (LaunchDaemon).
// It serves a Unix domain socket that only root, the console user and admin-group members may use, and provides:
//   - counters and file descriptors of every process (libproc as root)
//   - packet ACCOUNTING from pktap (addresses, ports, lengths, owning pid) in 250 ms bundles — never packet contents
//   - per-file disk I/O from fs_usage (kdebug)
//   - on request: a BPF/pktap descriptor handed to the app (SCM_RIGHTS) so the APP reads packet contents itself,
//     process memory regions/bytes (task_for_pid), signals, priorities, pf rules in its own anchor, launchctl, ifconfig.
import Foundation
import Darwin

// ---------------------------------------------------------------- private libpcap extensions (Apple), looked up at run time
typealias PcapSetInt = @convention(c) (OpaquePointer?, Int32) -> Int32
let libpcap = dlopen("/usr/lib/libpcap.A.dylib", RTLD_NOW)
let pcap_set_want_pktap_p: PcapSetInt? = libpcap.flatMap { dlsym($0, "pcap_set_want_pktap") }.map { unsafeBitCast($0, to: PcapSetInt.self) }

func log(_ s: String) { FileHandle.standardError.write((ISO8601DateFormatter().string(from: Date()) + " " + s + "\n").data(using: .utf8)!) }

// ---------------------------------------------------------------- clients
final class Client {
    let fd: Int32; let uid: uid_t; let wlock = NSLock(); var subscribed = false; var alive = true
    init(fd: Int32, uid: uid_t) { self.fd = fd; self.uid = uid }
    func send(_ s: String) { wlock.lock(); if alive && !writeAll(fd, s) { alive = false }; wlock.unlock() }
}
let clientsLock = NSLock(); var clients: [Client] = []
func broadcast(_ s: String) {
    clientsLock.lock(); let cs = clients.filter { $0.subscribed && $0.alive }; clientsLock.unlock()
    for c in cs { c.send(s) }
}
func subscribers() -> Int { clientsLock.lock(); defer { clientsLock.unlock() }; return clients.filter { $0.subscribed && $0.alive }.count }

func consoleUid() -> uid_t { var st = stat(); return stat("/dev/console", &st) == 0 ? st.st_uid : 0 }
func isAdmin(_ uid: uid_t) -> Bool {
    guard let pw = getpwuid(uid) else { return false }
    var groups = [Int32](repeating: 0, count: 64); var n: Int32 = 64
    getgrouplist(pw.pointee.pw_name, Int32(bitPattern: pw.pointee.pw_gid), &groups, &n)
    return groups.prefix(Int(max(0, n))).contains(80)   // gid 80 = admin
}

// ---------------------------------------------------------------- snapshot of processes and descriptors
var socketOwner: [String: Int32] = [:]   // "proto|lport" -> pid, for packets pktap could not attribute
let ownerLock = NSLock()
func snapshotLoop() {
    var lastFds = -100.0, prevCpu: [Int32: (UInt64, Double)] = [:]
    while true {
        if subscribers() == 0 { usleep(500000); continue }
        var out = ""
        let procs = listProcesses(); let now = nowSec()
        var cpuNow: [Int32: (UInt64, Double)] = [:]
        for var p in procs {
            fillTaskInfo(&p)
            var cpu = 0.0
            if let o = prevCpu[p.pid], now > o.1, p.cpuNs >= o.0 { cpu = Double(p.cpuNs - o.0) * machToNs / 1e9 / (now - o.1) * 100 }
            cpuNow[p.pid] = (p.cpuNs, now)
            out += joinRec(["P", "\(p.pid)", "\(p.ppid)", "\(p.uid)", "\(p.rss)", "\(p.footprint)", "\(p.cpuNs)", "\(p.diskR)", "\(p.diskW)", "\(p.threads)", p.hasTask ? "1" : "0", p.hasIO ? "1" : "0", String(format: "%.1f", cpu)])
        }
        prevCpu = cpuNow
        var withFds = false
        if now - lastFds > 3 {
            lastFds = now; withFds = true
            var owners: [String: Int32] = [:]
            for p in procs where p.pid > 0 {
                guard let fds = listFds(pid: p.pid) else { continue }
                var files = 0
                for f in fds {
                    switch f.kind {
                    case .file: if files < 400 { out += joinRec(["F", "\(f.pid)", f.path]) }; files += 1
                    default:
                        out += joinRec(["S", "\(f.pid)", "\(f.kind.rawValue)", f.laddr, "\(f.lport)", f.raddr, "\(f.rport)", "\(f.state)", "\(f.handle)", "\(f.peer)", f.path])
                        if f.kind == .tcp || f.kind == .udp { owners["\(f.kind == .tcp ? 6 : 17)|\(f.lport)"] = f.pid }
                    }
                }
            }
            ownerLock.lock(); socketOwner = owners; ownerLock.unlock()
        }
        out += joinRec(["E", withFds ? "1" : "0"])   // fds are rescanned every 3 s; in between the app keeps the set it has
        broadcast(out)
        usleep(1_000_000)
    }
}

// ---------------------------------------------------------------- packet accounting (headers only)
var captureState = ("off", "starting")
func openPktap(snaplen: Int32, immediate: Bool) -> (OpaquePointer?, String) {
    var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
    guard let p = pcap_create("pktap", &err) else { return (nil, String(cString: err)) }
    _ = pcap_set_want_pktap_p?(p, 1)
    pcap_set_snaplen(p, snaplen); pcap_set_promisc(p, 0); pcap_set_timeout(p, 100)
    pcap_set_buffer_size(p, 4 << 20)
    if immediate { pcap_set_immediate_mode(p, 1) }
    let r = pcap_activate(p)
    if r < 0 { let e = String(cString: pcap_geterr(p)); pcap_close(p); return (nil, "pcap_activate: \(e)") }
    let dlt = UInt32(pcap_datalink(p))
    if dlt != PKTAP.DLT_PKTAP && dlt != PKTAP.DLT_USER2 { pcap_close(p); return (nil, "pktap gave datalink \(dlt)") }
    return (p, "")
}
struct AccKey: Hashable { var pid: Int32; var proto: UInt8; var lip: String; var lp: UInt16; var rip: String; var rp: UInt16; var ifn: String }
var acc: [AccKey: (Int, UInt64, Int, UInt64)] = [:]; let accLock = NSLock()
func captureLoop() {
    while true {
        if subscribers() == 0 { captureState = ("off", "no clients"); usleep(500000); continue }
        // 218 bytes per packet = pktap header + link + IP + the first 8 bytes of TCP/UDP: enough for ports, not for contents
        let (pc, err) = openPktap(snaplen: 218, immediate: false)
        guard let p = pc else { captureState = ("failed", err); broadcast(joinRec(["C", "failed", err])); log("capture: " + err); sleep(getuid() == 0 ? 5 : 60); continue }
        captureState = ("live", "pktap"); broadcast(joinRec(["C", "live", "pktap"]))
        log("capture live")
        let flusher = Thread {
            while true {
                usleep(250_000)
                accLock.lock(); let a = acc; acc = [:]; accLock.unlock()
                var out = ""
                for (k, v) in a { out += joinRec(["W", "0", "\(k.pid)", "\(k.proto)", k.lip, "\(k.lp)", k.rip, "\(k.rp)", "\(v.0)", "\(v.1)", "\(v.2)", "\(v.3)", k.ifn]) }
                if !out.isEmpty { broadcast(out) }
                if subscribers() == 0 { break }
            }
        }
        flusher.start()
        while subscribers() > 0 {
            let n = pcap_dispatch(p, 512, { _, hdr, bytes in
                guard let hdr = hdr, let bytes = bytes else { return }
                let rec = UnsafeRawBufferPointer(start: bytes, count: Int(hdr.pointee.caplen))
                guard var k = parsePktap(rec, keep: 0) else { return }
                if k.pid <= 0 { ownerLock.lock(); k.pid = socketOwner["\(k.proto)|\(k.lp)"] ?? -1; ownerLock.unlock() }
                let key = AccKey(pid: k.pid, proto: k.proto, lip: k.lip, lp: k.lp, rip: k.rip, rp: k.rp, ifn: k.ifname)
                accLock.lock(); var v = acc[key] ?? (0, 0, 0, 0)
                if k.out { v.2 += 1; v.3 += UInt64(k.len) } else { v.0 += 1; v.1 += UInt64(k.len) }
                acc[key] = v; accLock.unlock()
            }, nil)
            if n < 0 { log("pcap_dispatch failed: " + String(cString: pcap_geterr(p))); break }
        }
        pcap_close(p); captureState = ("off", "stopped")
    }
}

// ---------------------------------------------------------------- per-file disk I/O from fs_usage (kdebug)
var tidPid: [UInt64: Int32] = [:], lastTidScan = -100.0
func refreshTids() {
    // PROC_PIDLISTTHREADIDS (28) is not in the public header; without it, attribution falls back to the process name
    var m: [UInt64: Int32] = [:]
    for p in listProcesses() where p.pid > 0 {
        var buf = [UInt64](repeating: 0, count: 2048)
        let n = proc_pidinfo(p.pid, 28, 0, &buf, Int32(buf.count * 8))
        if n > 0 { for i in 0..<Int(n) / 8 { m[buf[i]] = p.pid } }
    }
    tidPid = m; lastTidScan = nowSec()
}
func fsUsageLoop() {
    while true {
        if subscribers() == 0 { usleep(500000); continue }
        let proc = Process(); proc.executableURL = URL(fileURLWithPath: "/usr/bin/fs_usage"); proc.arguments = ["-w", "-f", "diskio"]
        let pipe = Pipe(); proc.standardOutput = pipe; proc.standardError = FileHandle.nullDevice
        if getuid() != 0 { sleep(60); continue }
        do { try proc.run() } catch { log("fs_usage: \(error)"); sleep(10); continue }
        let rd = LineReader(fd: pipe.fileHandleForReading.fileDescriptor)
        var agg: [String: (Int32, UInt64, UInt64, String)] = [:]; var lastFlush = nowSec()
        var byName: [String: Int32] = [:], lastNames = -100.0
        while let line = rd.next() {
            if subscribers() == 0 { proc.terminate(); break }
            let t = line.split(separator: " ", omittingEmptySubsequences: true)
            guard t.count >= 6, let bi = t.firstIndex(where: { $0.hasPrefix("B=0x") }), let size = UInt64(t[bi].dropFirst(4), radix: 16) else { continue }
            let call = t[1]; let isRead = call.hasPrefix("Rd") || call.hasPrefix("PgIn"); let isWrite = call.hasPrefix("Wr") || call.hasPrefix("PgOut")
            if !isRead && !isWrite { continue }
            var end = t.count - 1                 // t[end] is "process.threadid"
            let procTok = t[end]
            while end > bi + 1 {                  // elapsed time, the W (wait) flag and bracketed flags trail the path
                let tok = t[end - 1]
                if tok == "W" || tok.hasPrefix("[") || tok.range(of: "^[0-9]+\\.[0-9]+$", options: .regularExpression) != nil { end -= 1 } else { break }
            }
            var s0 = bi + 1
            var dev = ""
            if s0 < end, t[s0].hasPrefix("/dev/") { dev = String(t[s0]); s0 += 1 }
            var path = s0 < end ? t[s0..<end].joined(separator: " ") : ""
            if path.isEmpty { path = dev }        // raw device I/O with no file behind it
            // fs_usage names the caller as "process.threadid": map the thread back to its process,
            // falling back to the (truncated) process name for a thread that has already gone.
            var pid: Int32 = -1
            if let dot = procTok.lastIndex(of: "."), let tid = UInt64(procTok[procTok.index(after: dot)...]) {
                if let p = tidPid[tid] { pid = p } else if nowSec() - lastTidScan > 2 { refreshTids(); pid = tidPid[tid] ?? -1 }
                if pid < 0 {
                    if nowSec() - lastNames > 5 { byName = [:]; for p in listProcesses() { byName[String(p.name.prefix(16))] = p.pid }; lastNames = nowSec() }
                    pid = byName[String(procTok[..<dot])] ?? -1
                }
            }
            let k = "\(pid)|\(path)"; var v = agg[k] ?? (pid, 0, 0, path)
            if isRead { v.1 += size } else { v.2 += size }; agg[k] = v
            if nowSec() - lastFlush > 0.25 {
                var out = ""; for v in agg.values { out += joinRec(["D", "\(v.0)", "\(v.1)", "\(v.2)", v.3]) }
                agg = [:]; lastFlush = nowSec(); if !out.isEmpty { broadcast(out) }
            }
        }
        proc.waitUntilExit()
        if subscribers() > 0 { sleep(3) }
    }
}

// ---------------------------------------------------------------- pf rules in the MatrixSys anchor
let pfLock = NSLock(); var pfRules: [String] = []; var pfTransient: [(String, Double)] = []; var pfToken = ""
let pfFile = "/Library/Application Support/MatrixSys/pf.rules"
func pfLoad() {
    if let s = try? String(contentsOfFile: pfFile, encoding: .utf8) { pfRules = s.split(separator: "\n").map(String.init).filter { $0.hasPrefix("block ") } }
    if !pfRules.isEmpty { _ = pfApply() }
}
func pfApply() -> (Bool, String) {
    try? FileManager.default.createDirectory(atPath: (pfFile as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    try? (pfRules.joined(separator: "\n") + "\n").write(toFile: pfFile, atomically: true, encoding: .utf8)
    let all = pfRules + pfTransient.map { $0.0 }
    if !all.isEmpty && pfToken.isEmpty {
        let (_, out) = run("/sbin/pfctl", ["-E"])   // reference-counted enable; released with pfctl -X on flush/uninstall
        if let r = out.range(of: "Token : ") { pfToken = String(out[r.upperBound...].prefix { $0.isNumber }) }
    }
    let tmp = "/var/run/com.matrixsys.pf.\(getpid())"
    try? (all.joined(separator: "\n") + "\n").write(toFile: tmp, atomically: true, encoding: .utf8)
    defer { unlink(tmp) }
    let (st, out) = run("/sbin/pfctl", ["-a", PF_ANCHOR, "-f", tmp])
    if all.isEmpty && !pfToken.isEmpty { run("/sbin/pfctl", ["-X", pfToken]); pfToken = "" }
    return (st == 0, out.split(separator: "\n").filter { !$0.contains("ALTQ") && !$0.contains("pf.conf") }.joined(separator: " "))
}
func pfCommand(_ f: [Substring]) -> [String] {
    pfLock.lock(); defer { pfLock.unlock() }
    guard f.count >= 2 else { return ["ERR bad request"] }
    switch f[1] {
    case "list": return ["OK"] + pfRules
    case "block":
        let ip = String(f.count > 2 ? f[2] : ""); guard validIp(ip) else { return ["ERR not an address"] }
        for r in ["block drop out quick from any to \(ip)", "block drop in quick from \(ip) to any"] where !pfRules.contains(r) { pfRules.append(r) }
        let (ok, e) = pfApply(); run("/sbin/pfctl", ["-k", "0.0.0.0/0", "-k", ip]); run("/sbin/pfctl", ["-k", ip])
        return [ok ? "OK" : "ERR " + e]
    case "blockport":
        let spec = f.count > 2 ? f[2] : ""; let parts = spec.split(separator: ":")
        guard parts.count == 2, let port = Int(parts[1]), port > 0, port < 65536 else { return ["ERR bad port"] }
        let r = "block drop in quick proto \(parts[0] == "UDP" ? "udp" : "tcp") from any to any port \(port)"
        if !pfRules.contains(r) { pfRules.append(r) }
        let (ok, e) = pfApply(); return [ok ? "OK" : "ERR " + e]
    case "unblock":
        let r = f.count > 2 ? String(f[2]) : ""
        guard pfRules.contains(r) else { return ["ERR no such MatrixSys rule"] }
        // a host block is two rules; removing either removes both
        let ip = r.components(separatedBy: " ").last { validIp($0) } ?? ""
        pfRules.removeAll { $0 == r || (!ip.isEmpty && $0.hasSuffix(" \(ip)") || (!ip.isEmpty && $0.contains(" from \(ip) "))) }
        let (ok, e) = pfApply(); return [ok ? "OK" : "ERR " + e]
    case "flush":
        pfRules = []; pfTransient = []; let (ok, e) = pfApply()
        run("/sbin/pfctl", ["-a", PF_ANCHOR, "-F", "all"]); if !pfToken.isEmpty { run("/sbin/pfctl", ["-X", pfToken]); pfToken = "" }
        try? FileManager.default.removeItem(atPath: pfFile)
        return [ok ? "OK" : "ERR " + e]
    case "kill":
        // Each connection gets a valid RST in both directions (see TcpReset.swift). IPv6 connections fall back to a short pf
        // "block return" rule, which stops the traffic but leaves the socket to time out.
        let specs = (f.count > 2 ? f[2] : "").split(separator: ","); var done = 0, v6 = 0, fail: [String] = []
        for s in specs {
            let a = s.split(separator: "|").map(String.init); guard a.count == 4, validIp(a[0]), validIp(a[2]), let lp = Int(a[1]), let rp = Int(a[3]) else { continue }
            if let err = resetConnection(a[0], lp, a[2], rp) {
                if err == "IPv6" {
                    let t = nowSec() + 8; v6 += 1
                    pfTransient.append(("block return out quick proto tcp from \(a[0]) port \(lp) to \(a[2]) port \(rp)", t))
                    pfTransient.append(("block return in quick proto tcp from \(a[2]) port \(rp) to \(a[0]) port \(lp)", t))
                } else { fail.append(err) }
            } else { done += 1 }
        }
        if v6 > 0 { _ = pfApply() }
        log("reset \(done) connection(s), \(v6) IPv6 blocked, \(fail.count) failed")
        if done + v6 == 0 { return ["ERR " + (fail.first ?? "no valid connection")] }
        return ["OK \(done) \(v6) \(fail.count)"]
    default: return ["ERR unknown pf verb"]
    }
}
func pfJanitor() {
    while true {
        sleep(1)
        pfLock.lock()
        let before = pfTransient.count; pfTransient.removeAll { $0.1 < nowSec() }
        if pfTransient.count != before { _ = pfApply() }
        pfLock.unlock()
    }
}

// ---------------------------------------------------------------- process memory (task_for_pid as root)
func protStr(_ p: vm_prot_t) -> String { ((p & VM_PROT_READ) != 0 ? "r" : "-") + ((p & VM_PROT_WRITE) != 0 ? "w" : "-") + ((p & VM_PROT_EXECUTE) != 0 ? "x" : "-") }
func taskFor(_ pid: Int32) -> (mach_port_t, String) {
    // task_for_pid can block (AMFI / taskgated checks); never let it hang a request
    var task: mach_port_t = 0; var kr: kern_return_t = KERN_FAILURE
    let done = DispatchSemaphore(value: 0); let t0 = nowSec()
    Thread { var t: mach_port_t = 0; kr = task_for_pid(mach_task_self_, pid, &t); task = t; done.signal() }.start()
    if done.wait(timeout: .now() + 4) == .timedOut { log("task_for_pid(\(pid)) did not return within 4 s"); return (0, "macOS did not answer the request for this process's task port within 4 s.") }
    log("task_for_pid(\(pid)) = \(kr) in \(Int((nowSec() - t0) * 1000)) ms")
    if kr != KERN_SUCCESS {
        return (0, "task_for_pid refused (\(kr)): with SIP on, macOS does not hand out the task port of platform binaries (Apple's own programs) or of apps built with the hardened runtime.")
    }
    return (task, "")
}
func memRegions(_ pid: Int32) -> [String] {
    let (task, err) = taskFor(pid); if task == 0 { return ["ERR " + err] }
    defer { mach_port_deallocate(mach_task_self_, task) }
    var out = ["OK"]; var addr: mach_vm_address_t = 0
    var pathBuf = [CChar](repeating: 0, count: 1024)
    var depth: natural_t = 0; var iter = 0; let deadline = nowSec() + 5
    while out.count < 20000 && iter < 200000 && nowSec() < deadline {
        iter += 1
        var size: mach_vm_size_t = 0
        var info = vm_region_submap_info_data_64_t(); var cnt = mach_msg_type_number_t(MemoryLayout<vm_region_submap_info_data_64_t>.size / 4)
        let kr = withUnsafeMutablePointer(to: &info) { $0.withMemoryRebound(to: Int32.self, capacity: Int(cnt)) { mach_vm_region_recurse(task, &addr, &size, &depth, $0, &cnt) } }
        if kr != KERN_SUCCESS { break }
        if info.is_submap != 0 { depth += 1; continue }
        if (info.protection & VM_PROT_READ) != 0 {
            let n = proc_regionfilename(pid, addr, &pathBuf, UInt32(pathBuf.count))
            let name = n > 0 ? (String(cString: pathBuf) as NSString).lastPathComponent : ""
            let type = info.share_mode == SM_PRIVATE ? "PRV" : name.isEmpty ? "SHM" : "MAP"
            out.append("\(addr)\t\(size)\t\(protStr(info.protection))\t\(type)\t\(info.user_tag)\t\(name)")
        }
        addr += size
    }
    return out
}
func memRead(_ pid: Int32, _ addr: UInt64, _ len: Int) -> [String] {
    let (task, err) = taskFor(pid); if task == 0 { return ["ERR " + err] }
    defer { mach_port_deallocate(mach_task_self_, task) }
    let n = min(len, 65536); var hexs = ""; var okMask = ""
    var page = addr; let end = addr + UInt64(n)
    while page < end {
        let chunk = min(end - page, 4096 - (page & 4095))
        var buf = [UInt8](repeating: 0, count: Int(chunk)); var got: mach_vm_size_t = 0
        let kr = buf.withUnsafeMutableBytes { mach_vm_read_overwrite(task, page, chunk, mach_vm_address_t(UInt(bitPattern: $0.baseAddress!)), &got) }
        let ok = kr == KERN_SUCCESS && got == chunk
        for b in buf { hexs += String(format: "%02x", ok ? b : 0) }
        okMask += String(repeating: ok ? "1" : "0", count: Int(chunk))
        page += chunk
    }
    return ["OK", hexs, okMask]
}

// ---------------------------------------------------------------- requests
func handle(_ c: Client) {
    let rd = LineReader(fd: c.fd)
    while let line = rd.next() {
        let f = splitRec(Substring(line)); guard let cmd = f.first else { continue }
        // lines are already tab-separated records: strip newlines only, never the separators
        func reply(_ lines: [String]) { c.send(lines.map { $0.replacingOccurrences(of: "\n", with: " ") }.joined(separator: "\n") + "\nEND\n") }
        switch cmd {
        case "HELLO": continue
        case "SUB":
            c.subscribed = true
            c.send(joinRec(["C", captureState.0, captureState.1]))
        case "PCAPFD":
            // contents are read by the app itself, only while its packet viewer is open; this process never looks at them
            let (pc, err) = openPktap(snaplen: 156 + 14 + 512, immediate: true)
            guard let p = pc else { _ = sendFd(c.fd, -1, "ERR " + err); continue }
            let bfd = pcap_get_selectable_fd(p)
            if !sendFd(c.fd, bfd, "OK\t\(pcap_datalink(p))") { pcap_close(p); continue }
            log("packet session opened for uid \(c.uid)")
            var b = [UInt8](repeating: 0, count: 64)
            while read(c.fd, &b, 64) > 0 {}    // wait for the app to close the session
            pcap_close(p); log("packet session closed"); c.alive = false; return
        case "MEMREGIONS": reply(memRegions(Int32(f.count > 1 ? f[1] : "") ?? -1))
        case "MEMREAD": reply(memRead(Int32(f.count > 1 ? f[1] : "") ?? -1, UInt64(f.count > 2 ? f[2] : "") ?? 0, Int(f.count > 3 ? f[3] : "") ?? 0))
        case "SIG":
            let pid = Int32(f.count > 1 ? f[1] : "") ?? -1, sig = Int32(f.count > 2 ? f[2] : "") ?? 0
            let name = listProcesses().first { $0.pid == pid }?.name ?? ""
            if pid <= 1 || criticalNames.contains(name) || ![SIGTERM, SIGKILL, SIGSTOP, SIGCONT].contains(sig) { reply(["ERR refused: protected process"]); continue }
            reply([kill(pid, sig) == 0 ? "OK" : "ERR " + String(cString: strerror(errno))])
        case "PRIO":
            let pid = Int32(f.count > 1 ? f[1] : "") ?? -1, n = Int32(f.count > 2 ? f[2] : "") ?? 0
            reply([pid > 1 && setpriority(PRIO_PROCESS, id_t(pid), max(-10, min(19, n))) == 0 ? "OK" : "ERR " + String(cString: strerror(errno))])
        case "BG":
            let pid = Int32(f.count > 1 ? f[1] : "") ?? -1
            reply([pid > 1 && setpriority(PRIO_DARWIN_PROCESS, id_t(pid), f.count > 2 && f[2] == "1" ? PRIO_DARWIN_BG : 0) == 0 ? "OK" : "ERR " + String(cString: strerror(errno))])
        case "PF": reply(pfCommand(f))
        case "LAUNCHCTL":
            let a = f.dropFirst().map(String.init)
            guard let v = a.first, ["list", "kill", "kickstart"].contains(v) else { reply(["ERR refused"]); continue }
            if v != "list", let target = a.last, target.contains(HELPER_LABEL) { reply(["ERR refused: that is this helper"]); continue }
            let (st, out) = run("/bin/launchctl", a)
            reply([st == 0 ? "OK" : "ERR exit \(st)"] + out.split(separator: "\n").map(String.init))
        case "IFACE":
            let name = String(f.count > 1 ? f[1] : ""), up = f.count > 2 && f[2] == "up"
            guard name.range(of: "^[a-z]+[0-9]+$", options: .regularExpression) != nil, !name.hasPrefix("lo") else { reply(["ERR bad interface"]); continue }
            let (st, out) = run("/sbin/ifconfig", [name, up ? "up" : "down"]); reply([st == 0 ? "OK" : "ERR " + out])
        case "FLUSHDNS":
            run("/usr/bin/dscacheutil", ["-flushcache"]); let (st, _) = run("/usr/bin/killall", ["-HUP", "mDNSResponder"]); reply([st == 0 ? "OK" : "ERR mDNSResponder not signalled"])
        case "STATUS": reply(["OK", "capture \(captureState.0) \(captureState.1)", "subscribers \(subscribers())", "pf rules \(pfRules.count)"])
        default: reply(["ERR unknown command"])
        }
    }
    c.alive = false; close(c.fd)
    clientsLock.lock(); clients.removeAll { $0 === c }; clientsLock.unlock()
}

func serve() {
    signal(SIGPIPE, SIG_IGN)
    var ownSocket = false
    let argv = CommandLine.arguments
    if let i = argv.firstIndex(of: "--socket"), i + 1 < argv.count { HELPER_SOCKET = argv[i + 1]; ownSocket = true }
    // on stop (launchctl bootout / uninstall) give back the pf enable reference; saved block rules return at the next start
    let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
    signal(SIGTERM, SIG_IGN)
    term.setEventHandler { pfLock.lock(); if !pfToken.isEmpty { run("/sbin/pfctl", ["-X", pfToken]) }; run("/sbin/pfctl", ["-a", PF_ANCHOR, "-F", "rules"]); unlink(HELPER_SOCKET); exit(0) }
    term.resume()
    guard getuid() == 0 || ownSocket else { log("must run as root (launchd starts it from \(HELPER_PLIST))"); exit(1) }
    if getuid() != 0 { log("running without root: only this user's processes are visible; capture, memory reading, pf and launchctl are unavailable") }
    unlink(HELPER_SOCKET)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    var a = sockaddr_un(); a.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &a.sun_path) { p in _ = HELPER_SOCKET.utf8CString.withUnsafeBytes { memcpy(p.baseAddress!, $0.baseAddress!, min(p.count - 1, $0.count)) } }
    guard withUnsafePointer(to: &a, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }) == 0 else { log("bind failed: \(String(cString: strerror(errno)))"); exit(1) }
    chmod(HELPER_SOCKET, getuid() == 0 ? 0o666 : 0o600)   // reachable by every local user; each connection is checked below
    listen(fd, 16)
    pfLoad()
    for f in [snapshotLoop, captureLoop, fsUsageLoop, pfJanitor] { Thread { f() }.start() }
    log("listening on \(HELPER_SOCKET)")
    while true {
        let c = accept(fd, nil, nil); if c < 0 { continue }
        var cred = xucred(); var len = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(c, SOL_LOCAL, LOCAL_PEERCRED, &cred, &len) == 0 else { close(c); continue }
        let uid = cred.cr_uid
        guard uid == 0 || uid == getuid() || uid == consoleUid() || isAdmin(uid) else { _ = writeAll(c, "ERR not allowed\nEND\n"); close(c); log("refused uid \(uid)"); continue }
        var one: Int32 = 1; setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)
        let cl = Client(fd: c, uid: uid)
        clientsLock.lock(); clients.append(cl); clientsLock.unlock()
        Thread { handle(cl) }.start()
    }
}

serve()
