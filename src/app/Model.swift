// Data collection. Background threads build immutable snapshots; the render loop swaps a reference.
// Sources without privileges: sysctl(KERN_PROC_ALL) + libproc (own processes), /bin/ps (setuid: RSS and CPU of every process),
// /usr/bin/nettop (per-process and per-connection byte counters for every process), host_statistics64, interface counters.
// With the helper: task/disk counters and file descriptors of every process, captured packet accounting, per-file disk I/O.
import Foundation
import Darwin

struct Conn { var pid: Int32; var proto: String; var la: String; var lp: Int; var ra: String; var rp: Int; var state: String; var iface: String; var bin: UInt64; var bout: UInt64
    var key: String { "\(pid)|\(proto)|\(la)|\(lp)|\(ra)|\(rp)" } }
struct Listen { var proto: Int; var addr: String; var port: Int }   // proto 0 TCP, 1 UDP
struct LoopPair { var a: Int32; var b: Int32; var n: Int; var kind: String; var bytes: Double }
struct Flow { var t: Double; var pid: Int32; var proto: Int; var lip: String; var lp: Int; var rip: String; var rp: Int; var out: Bool; var n: Int; var bytes: UInt64; var iface: String }
struct DiskIo { var t: Double; var pid: Int32; var path: String; var rd: UInt64; var wr: UInt64 }
struct FileH { var pid: Int32; var path: String }

final class Snapshot {
    var t = 0.0
    var procs: [ProcInfo] = []
    var idx: [Int32: Int] = [:]
    var conns: [Conn] = []                 // every TCP/UDP socket nettop reports, listeners included
    var procNet: [Int32: (UInt64, UInt64)] = [:]   // cumulative bytes in/out per process (nettop)
    var memTotal: UInt64 = 0, memFree: UInt64 = 0, memWired: UInt64 = 0, memCompressed: UInt64 = 0, memApp: UInt64 = 0, memCache: UInt64 = 0
    var rx = 0.0, tx = 0.0                 // all interfaces, bytes/s
    var host = Host.current().localizedName ?? "this Mac"
    var ipc: [LoopPair] = []               // pipes and unix sockets between processes (fd tables)
    var fdVisible = 0, fdDenied = 0
    var nettopOK = false, helperData = false
    // per-second rates, computed against the previous snapshot
    var rate: [Int32: (rd: Double, wr: Double, nin: Double, nout: Double)] = [:]
    func get(_ pid: Int32) -> ProcInfo? { if let i = idx[pid] { return procs[i] }; return nil }
}

final class Model {
    static let shared = Model()
    let lock = NSLock()
    private(set) var snap: Snapshot? = nil
    private(set) var files: [FileH]? = nil
    private(set) var filesGen = 0
    private var flows: [Flow] = [], disk: [DiskIo] = []
    var wantFiles = false
    let myUid = getuid()

    // helper state
    var helperConnected = false, helperStatus = "", captureLive = false
    private var helperProcs: [Int32: ProcInfo] = [:], helperFds: [FdRec] = [], helperT = -100.0
    private var helperSock: Int32 = -1
    let reqLock = NSLock()

    func latest() -> Snapshot? { lock.lock(); defer { lock.unlock() }; return snap }
    func latestFiles() -> ([FileH], Int)? { lock.lock(); defer { lock.unlock() }; guard let f = files else { return nil }; return (f, filesGen) }
    func takeFlows() -> ([Flow], [DiskIo]) { lock.lock(); defer { lock.unlock() }; let f = flows, d = disk; flows.removeAll(); disk.removeAll(); return (f, d) }

    func start() {
        Thread { self.collectLoop() }.start()
        Thread { self.helperLoop() }.start()
    }

    // ------------------------------------------------------------ main collector
    private var prevNet: [Int32: (UInt64, UInt64)] = [:], prevIO: [Int32: (UInt64, UInt64, Double)] = [:], prevIf: (UInt64, UInt64, Double) = (0, 0, 0)
    private var lastFdScan = -100.0, fdCache: [FdRec] = [], fdDenied = 0
    private func collectLoop() {
        while true {
            let t0 = nowSec()
            let s = Snapshot(); s.t = t0
            var procs = listProcesses()
            let useHelper = helperConnected && nowSec() - helperT < 5
            var psInfo: [Int32: (UInt64, Double)] = [:]
            if !useHelper {
                let (_, out) = run("/bin/ps", ["-axo", "pid=,rss=,%cpu="], timeout: 5)
                for line in out.split(separator: "\n") {
                    let f = line.split(separator: " ", omittingEmptySubsequences: true)
                    if f.count >= 3, let pid = Int32(f[0]), let rss = UInt64(f[1]), let cpu = Double(f[2]) { psInfo[pid] = (rss * 1024, cpu) }
                }
            }
            var hp: [Int32: ProcInfo] = [:]
            if useHelper { lock.lock(); hp = helperProcs; lock.unlock() }
            for i in procs.indices {
                let pid = procs[i].pid
                if useHelper, let h = hp[pid] {
                    procs[i].rss = h.rss; procs[i].footprint = h.footprint; procs[i].cpuNs = h.cpuNs; procs[i].diskR = h.diskR; procs[i].diskW = h.diskW
                    procs[i].threads = h.threads; procs[i].hasTask = h.hasTask; procs[i].hasIO = h.hasIO; procs[i].cpu = h.cpu
                    continue
                }
                if procs[i].uid == myUid || myUid == 0 { fillTaskInfo(&procs[i]) }
                if let p = psInfo[pid] { if !procs[i].hasTask { procs[i].rss = p.0 }; procs[i].cpu = p.1 }
            }
            s.helperData = useHelper
            s.procs = procs
            for (i, p) in procs.enumerated() { s.idx[p.pid] = i }
            // network counters per process and per connection
            readNettop(into: s)
            // memory
            readMemory(into: s)
            // interfaces
            let (ib, ob) = interfaceTotals(); let now = nowSec()
            if prevIf.2 > 0 { let dt = max(0.2, now - prevIf.2); s.rx = Double(ib &- prevIf.0) / dt; s.tx = Double(ob &- prevIf.1) / dt
                if ib < prevIf.0 || ob < prevIf.1 { s.rx = 0; s.tx = 0 } }
            prevIf = (ib, ob, now)
            // rates
            for p in procs {
                var r = (rd: 0.0, wr: 0.0, nin: 0.0, nout: 0.0)
                if p.hasIO, let o = prevIO[p.pid], now > o.2 { let dt = now - o.2; r.rd = Double(p.diskR >= o.0 ? p.diskR - o.0 : 0) / dt; r.wr = Double(p.diskW >= o.1 ? p.diskW - o.1 : 0) / dt }
                if let n = s.procNet[p.pid], let o = prevNet[p.pid] { r.nin = Double(n.0 >= o.0 ? n.0 - o.0 : 0); r.nout = Double(n.1 >= o.1 ? n.1 - o.1 : 0) }
                s.rate[p.pid] = r
            }
            prevIO = [:]; for p in procs where p.hasIO { prevIO[p.pid] = (p.diskR, p.diskW, now) }
            prevNet = s.procNet
            // file descriptors: pipes / unix sockets between processes, and open files (every 3 s)
            if now - lastFdScan > 3 {
                lastFdScan = now
                if useHelper { lock.lock(); fdCache = helperFds; lock.unlock(); fdDenied = 0 }
                else {
                    var all: [FdRec] = []; var denied = 0
                    for p in procs where p.pid > 0 {
                        if p.uid != myUid && myUid != 0 { denied += 1; continue }
                        if let f = listFds(pid: p.pid) { all.append(contentsOf: f) } else { denied += 1 }
                    }
                    fdCache = all; fdDenied = denied
                }
                var fh: [FileH] = []
                for f in fdCache where f.kind == .file { fh.append(FileH(pid: f.pid, path: f.path)) }
                lock.lock(); files = fh; filesGen += 1; lock.unlock()
            }
            s.fdDenied = fdDenied; s.fdVisible = fdCache.count
            s.ipc = ipcPairs(fdCache)
            lock.lock(); snap = s; lock.unlock()
            let spent = nowSec() - t0
            usleep(useconds_t(max(0.2, 1.0 - spent) * 1e6))
        }
    }

    /// Pipes are matched by pipe_handle/pipe_peerhandle, unix sockets by socket pcb/unsi_conn_pcb.
    private func ipcPairs(_ fds: [FdRec]) -> [LoopPair] {
        var byHandle: [UInt64: Int32] = [:]
        for f in fds where (f.kind == .pipe || f.kind == .unix) && f.handle != 0 { byHandle[f.handle] = f.pid }
        var pairs: [String: LoopPair] = [:]
        for f in fds where (f.kind == .pipe || f.kind == .unix) && f.peer != 0 {
            guard let other = byHandle[f.peer], other != f.pid else { continue }
            let a = min(f.pid, other), b = max(f.pid, other)
            let kind = f.kind == .pipe ? "pipe" : "unix socket"
            let k = "\(a)-\(b)-\(kind)"
            if pairs[k] == nil { pairs[k] = LoopPair(a: a, b: b, n: 0, kind: kind, bytes: 0) }
            pairs[k]!.n += 1
        }
        // each connection is seen from both ends
        return pairs.values.map { var p = $0; p.n = max(1, p.n / 2); return p }
    }

    private func parseEndpoint(_ s: Substring, v6: Bool) -> (String, Int) {
        let str = String(s)
        let sep: Character = v6 ? "." : ":"
        guard let i = str.lastIndex(of: sep) else { return (str, 0) }
        var addr = String(str[..<i]); let port = Int(str[str.index(after: i)...]) ?? 0
        if let pct = addr.firstIndex(of: "%") { addr = String(addr[..<pct]) }
        if addr == "*" { addr = v6 ? "::" : "0.0.0.0" }
        return (addr, port)
    }

    private func readNettop(into s: Snapshot) {
        let (st, out) = run("/usr/bin/nettop", ["-L", "1", "-x", "-n", "-J", "interface,state,bytes_in,bytes_out"], timeout: 4)
        guard st == 0 else { return }
        var cols: [String: Int] = [:]
        var pid: Int32 = -1
        for line in out.split(separator: "\n") {
            let f = line.split(separator: ",", omittingEmptySubsequences: false)
            if f.contains("bytes_in") { cols = [:]; for (i, c) in f.enumerated() { cols[String(c)] = i }; continue }
            guard f.count >= 3, let ci = cols["interface"], let si = cols["state"], let bi = cols["bytes_in"], let bo = cols["bytes_out"], f.count > bo else { continue }
            let name = f[0]
            let bin = UInt64(f[bi]) ?? 0, bout = UInt64(f[bo]) ?? 0
            if name.hasPrefix("tcp4 ") || name.hasPrefix("tcp6 ") || name.hasPrefix("udp4 ") || name.hasPrefix("udp6 ") {
                guard pid >= 0 else { continue }
                let v6 = name.hasPrefix("tcp6") || name.hasPrefix("udp6")
                let body = name.dropFirst(5)
                let ends = body.components(separatedBy: "<->"); guard ends.count == 2 else { continue }
                let (la, lp) = parseEndpoint(Substring(ends[0]), v6: v6), (ra, rp) = parseEndpoint(Substring(ends[1]), v6: v6)
                let proto = name.hasPrefix("tcp") ? "TCP" : "UDP"
                if proto == "UDP" && lp == 0 { continue }
                s.conns.append(Conn(pid: pid, proto: proto, la: la, lp: lp, ra: ra, rp: rp, state: String(f[si]), iface: String(f[ci]), bin: bin, bout: bout))
            } else {
                guard let dot = name.lastIndex(of: "."), let p = Int32(name[name.index(after: dot)...]) else { pid = -1; continue }
                pid = p
                s.procNet[p] = (bin, bout)
            }
        }
        s.nettopOK = true
    }

    private func readMemory(into s: Snapshot) {
        var size: UInt64 = 0; var len = MemoryLayout<UInt64>.size
        sysctlbyname("hw.memsize", &size, &len, nil, 0); s.memTotal = size
        var vm = vm_statistics64(); var cnt = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
        let r = withUnsafeMutablePointer(to: &vm) { $0.withMemoryRebound(to: integer_t.self, capacity: Int(cnt)) { host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &cnt) } }
        if r == KERN_SUCCESS {
            let pg = UInt64(vm_kernel_page_size)
            s.memFree = UInt64(vm.free_count + vm.speculative_count) * pg
            s.memWired = UInt64(vm.wire_count) * pg
            s.memCompressed = UInt64(vm.compressor_page_count) * pg
            s.memApp = UInt64(vm.internal_page_count &- vm.purgeable_count) * pg
            s.memCache = UInt64(vm.external_page_count + vm.purgeable_count) * pg
        }
    }

    // ------------------------------------------------------------ helper client
    func helperRequest(_ line: String, timeout: Double = 8) -> [String]? {
        // a separate short-lived connection per request, so the streaming connection is never blocked
        reqLock.lock(); defer { reqLock.unlock() }
        let fd = connectHelper(); if fd < 0 { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0); setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        guard writeAll(fd, "HELLO\t\(PROTO_VERSION)\n" + line + "\n") else { return nil }
        let rd = LineReader(fd: fd); var out: [String] = []
        while let l = rd.next() { if l == "END" { return out }; out.append(l); if out.count > 200000 { break } }
        return out.isEmpty ? nil : out
    }
    /// Opens a packet session: the helper hands over a BPF descriptor (pktap); the app reads the packets itself.
    func helperPacketFd() -> (Int32, Int32, String)? {
        let fd = connectHelper(); if fd < 0 { return nil }
        guard writeAll(fd, "HELLO\t\(PROTO_VERSION)\nPCAPFD\n") else { close(fd); return nil }
        guard let (bpf, text) = recvFd(fd) else { close(fd); return nil }
        if bpf < 0 { close(fd); return (-1, -1, text) }
        return (bpf, fd, text)       // keep fd open: closing it ends the session in the helper
    }
    func connectHelper() -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0); if fd < 0 { return -1 }
        var a = sockaddr_un(); a.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &a.sun_path) { p in _ = HELPER_SOCKET.utf8CString.withUnsafeBytes { memcpy(p.baseAddress!, $0.baseAddress!, min(p.count - 1, $0.count)) } }
        let ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        if ok != 0 { close(fd); return -1 }
        var one: Int32 = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)
        return fd
    }
    private func helperLoop() {
        while true {
            let fd = connectHelper()
            if fd < 0 { helperConnected = false; captureLive = false; sleep(2); continue }
            helperSock = fd
            _ = writeAll(fd, "HELLO\t\(PROTO_VERSION)\nSUB\n")
            let rd = LineReader(fd: fd)
            var procs: [Int32: ProcInfo] = [:], fds: [FdRec] = []
            helperConnected = true
            while let line = rd.next() {
                let f = splitRec(Substring(line)); guard let k = f.first else { continue }
                switch k {
                case "P" where f.count >= 12:
                    var p = ProcInfo(); p.pid = Int32(f[1]) ?? 0; p.ppid = Int32(f[2]) ?? 0; p.uid = UInt32(f[3]) ?? 0
                    p.rss = UInt64(f[4]) ?? 0; p.footprint = UInt64(f[5]) ?? 0; p.cpuNs = UInt64(f[6]) ?? 0
                    p.diskR = UInt64(f[7]) ?? 0; p.diskW = UInt64(f[8]) ?? 0; p.threads = Int32(f[9]) ?? 0
                    p.hasTask = f[10] == "1"; p.hasIO = f[11] == "1"; if f.count > 12 { p.cpu = Double(f[12]) ?? 0 }
                    procs[p.pid] = p
                case "S" where f.count >= 11:
                    var r = FdRec(pid: Int32(f[1]) ?? 0, kind: FdKind(rawValue: Int(f[2]) ?? 5) ?? .other)
                    r.laddr = String(f[3]); r.lport = Int(f[4]) ?? 0; r.raddr = String(f[5]); r.rport = Int(f[6]) ?? 0
                    r.state = Int(f[7]) ?? 0; r.handle = UInt64(f[8]) ?? 0; r.peer = UInt64(f[9]) ?? 0; r.path = String(f[10])
                    fds.append(r)
                case "F" where f.count >= 3:
                    fds.append(FdRec(pid: Int32(f[1]) ?? 0, kind: .file, path: String(f[2])))
                case "E":
                    let withFds = f.count > 1 && f[1] == "1"
                    lock.lock(); helperProcs = procs; if withFds { helperFds = fds }; helperT = nowSec(); lock.unlock()
                    procs = [:]; if withFds { fds = [] }
                case "W" where f.count >= 13:
                    let t = nowSec(); let pid = Int32(f[2]) ?? -1, proto = Int(f[3]) ?? 0
                    let lip = String(f[4]), lp = Int(f[5]) ?? 0, rip = String(f[6]), rp = Int(f[7]) ?? 0
                    let pin = Int(f[8]) ?? 0, bin = UInt64(f[9]) ?? 0, pout = Int(f[10]) ?? 0, bout = UInt64(f[11]) ?? 0
                    lock.lock()
                    if pin > 0 { flows.append(Flow(t: t, pid: pid, proto: proto, lip: lip, lp: lp, rip: rip, rp: rp, out: false, n: pin, bytes: bin, iface: String(f[12]))) }
                    if pout > 0 { flows.append(Flow(t: t, pid: pid, proto: proto, lip: lip, lp: lp, rip: rip, rp: rp, out: true, n: pout, bytes: bout, iface: String(f[12]))) }
                    if flows.count > 20000 { flows.removeFirst(flows.count - 20000) }
                    lock.unlock()
                case "D" where f.count >= 5:
                    lock.lock(); disk.append(DiskIo(t: nowSec(), pid: Int32(f[1]) ?? -1, path: String(f[4]), rd: UInt64(f[2]) ?? 0, wr: UInt64(f[3]) ?? 0))
                    if disk.count > 20000 { disk.removeFirst(disk.count - 20000) }; lock.unlock()
                case "C" where f.count >= 3:
                    captureLive = f[1] == "live"; helperStatus = String(f[2])
                default: break
                }
            }
            close(fd); helperSock = -1; helperConnected = false; captureLive = false
            sleep(1)
        }
    }
}

/// Bytes in/out over all physical and virtual interfaces (64-bit counters from NET_RT_IFLIST2).
func interfaceTotals() -> (UInt64, UInt64) {
    var tin: UInt64 = 0, tout: UInt64 = 0
    for i in interfaceCounters() where !i.name.hasPrefix("lo") { tin &+= i.ib; tout &+= i.ob }
    return (tin, tout)
}
struct IfCounter { var name: String; var ib: UInt64; var ob: UInt64; var up: Bool; var type: UInt8; var index: Int }
func interfaceCounters() -> [IfCounter] {
    var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
    var len = 0
    if sysctl(&mib, 6, nil, &len, nil, 0) != 0 { return [] }
    var buf = [UInt8](repeating: 0, count: len)
    if sysctl(&mib, 6, &buf, &len, nil, 0) != 0 { return [] }
    var out: [IfCounter] = []
    buf.withUnsafeBytes { raw in
        var off = 0
        while off + MemoryLayout<if_msghdr>.size <= len {
            let h = raw.loadUnaligned(fromByteOffset: off, as: if_msghdr.self)
            if h.ifm_msglen == 0 { break }
            if Int32(h.ifm_type) == RTM_IFINFO2 {
                let m = raw.loadUnaligned(fromByteOffset: off, as: if_msghdr2.self)
                var name = [CChar](repeating: 0, count: Int(IFNAMSIZ) + 1)
                if_indextoname(UInt32(m.ifm_index), &name)
                out.append(IfCounter(name: String(cString: name), ib: m.ifm_data.ifi_ibytes, ob: m.ifm_data.ifi_obytes,
                                     up: (m.ifm_flags & IFF_UP) != 0, type: m.ifm_data.ifi_type, index: Int(m.ifm_index)))
            }
            off += Int(h.ifm_msglen)
        }
    }
    return out
}
