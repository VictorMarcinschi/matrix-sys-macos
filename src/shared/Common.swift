// Shared by the app and the privileged helper: process / file-descriptor collection through libproc,
// the helper's line protocol, and small helpers. Everything here is public macOS API.
import Foundation
import Darwin

let HELPER_LABEL = "com.matrixsys.helper"
let HELPER_SOCKET_DEFAULT = "/var/run/com.matrixsys.helper.sock"
/// --socket / --helper-socket override it; only ever for testing, the installed daemon uses the default.
var HELPER_SOCKET = HELPER_SOCKET_DEFAULT
let HELPER_PATH = "/Library/PrivilegedHelperTools/com.matrixsys.helper"
let HELPER_PLIST = "/Library/LaunchDaemons/com.matrixsys.helper.plist"
let PF_ANCHOR = "com.apple/250.MatrixSys"     // evaluated by the stock pf.conf through its `anchor "com.apple/*"` line
let PROTO_VERSION = 1

private let t0 = Date().timeIntervalSince1970
func nowSec() -> Double { Date().timeIntervalSince1970 - t0 }
func wallSec() -> Double { Date().timeIntervalSince1970 }

func fmtB(_ v: Double) -> String {
    var b = v
    if b < 1024 { return String(format: "%.0f B", b) }
    let u = ["KB", "MB", "GB", "TB"]; var i = -1
    repeat { b /= 1024; i += 1 } while b >= 1024 && i < 3
    return String(format: b < 10 ? "%.1f %@" : "%.0f %@", b, u[i])
}
func fmtR(_ b: Double) -> String { fmtB(b) + "/s" }
/// Link rates only (SNMP ifSpeed, UPnP line rate), which are quoted in bits per second, not bytes.
func fmtBits(_ bitsPerSec: Double) -> String {
    let u = ["b", "Kb", "Mb", "Gb", "Tb"]
    var v = bitsPerSec, i = 0
    while v >= 1000 && i < u.count - 1 { v /= 1000; i += 1 }
    return String(format: v < 10 && i > 0 ? "%.1f %@/s" : "%.0f %@/s", v, u[i])
}
func sgnB(_ d: Double) -> String { (d >= 0 ? "+" : "-") + fmtB(abs(d)) }

func cString<T>(_ tuple: T) -> String {
    withUnsafeBytes(of: tuple) { raw in
        let p = raw.bindMemory(to: CChar.self)
        let n = p.firstIndex(of: 0) ?? p.count
        return String(decoding: raw.prefix(n), as: UTF8.self)
    }
}

// ---------------------------------------------------------------- processes
struct ProcInfo {
    var pid: Int32 = 0, ppid: Int32 = 0, uid: UInt32 = 0
    var name = "", path = ""
    var rss: UInt64 = 0, footprint: UInt64 = 0
    var cpuNs: UInt64 = 0, cpu: Double = 0          // cpu = percent of one core
    var diskR: UInt64 = 0, diskW: UInt64 = 0
    var hasTask = false, hasIO = false              // false = the numbers above were not readable
    var threads: Int32 = 0, fds: Int32 = 0
    var start: Double = 0                           // epoch seconds, distinguishes a reused pid
    var nice: Int32 = 0
}

/// Every process through sysctl(KERN_PROC_ALL): works for all users without privileges.
func listProcesses() -> [ProcInfo] {
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
    var size = 0
    if sysctl(&mib, 4, nil, &size, nil, 0) != 0 { return [] }
    size += size / 8
    let n = size / MemoryLayout<kinfo_proc>.stride
    var buf = [kinfo_proc](repeating: kinfo_proc(), count: n)
    if sysctl(&mib, 4, &buf, &size, nil, 0) != 0 { return [] }
    let count = size / MemoryLayout<kinfo_proc>.stride
    var out: [ProcInfo] = []; out.reserveCapacity(count)
    var pathBuf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    for i in 0..<count {
        let k = buf[i]
        var p = ProcInfo()
        p.pid = k.kp_proc.p_pid; p.ppid = k.kp_eproc.e_ppid; p.uid = k.kp_eproc.e_ucred.cr_uid
        p.start = Double(k.kp_proc.p_starttime.tv_sec) + Double(k.kp_proc.p_starttime.tv_usec) / 1e6
        p.nice = Int32(k.kp_proc.p_nice)
        let comm = cString(k.kp_proc.p_comm)
        if p.pid == 0 { p.name = "kernel_task"; out.append(p); continue }
        let r = proc_pidpath(p.pid, &pathBuf, UInt32(pathBuf.count))
        if r > 0 { p.path = String(cString: pathBuf); p.name = (p.path as NSString).lastPathComponent }
        if p.name.isEmpty { p.name = comm }
        out.append(p)
    }
    return out
}

/// Task and I/O counters; readable for the caller's own processes, or for all of them as root.
func fillTaskInfo(_ p: inout ProcInfo) {
    var ti = proc_taskinfo()
    if proc_pidinfo(p.pid, PROC_PIDTASKINFO, 0, &ti, Int32(MemoryLayout<proc_taskinfo>.size)) == Int32(MemoryLayout<proc_taskinfo>.size) {
        p.rss = ti.pti_resident_size; p.threads = ti.pti_threadnum
        p.cpuNs = ti.pti_total_user + ti.pti_total_system
        p.hasTask = true
    }
    var ru = rusage_info_v4()
    let ok = withUnsafeMutablePointer(to: &ru) { ptr in
        ptr.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(p.pid, RUSAGE_INFO_V4, $0) }
    }
    if ok == 0 {
        p.diskR = ru.ri_diskio_bytesread; p.diskW = ru.ri_diskio_byteswritten
        p.footprint = ru.ri_phys_footprint; p.hasIO = true
        if !p.hasTask { p.rss = ru.ri_resident_size; p.cpuNs = ru.ri_user_time + ru.ri_system_time }
    }
}

/// mach absolute time units -> ns (Apple silicon ticks are not nanoseconds)
let machToNs: Double = { var tb = mach_timebase_info_data_t(); mach_timebase_info(&tb); return Double(tb.numer) / Double(tb.denom) }()

// ---------------------------------------------------------------- file descriptors
enum FdKind: Int { case file = 0, tcp, udp, unix, pipe, other }
struct FdRec {
    var pid: Int32
    var kind: FdKind
    var path = ""                  // vnode path, or unix socket path
    var laddr = "", raddr = ""
    var lport: Int = 0, rport: Int = 0
    var state = 0                  // TCP state (TSI_S_*)
    var handle: UInt64 = 0         // pipe handle / unix socket pcb
    var peer: UInt64 = 0           // pipe peer handle / unix conn pcb
}

private func addrString(_ ini: in_sockinfo) -> (String, String) {
    var ini = ini
    let v4 = (ini.insi_vflag & UInt8(INI_IPV4)) != 0
    func s(_ a: inout in6_addr, _ v4a: in_addr) -> String {
        var buf = [CChar](repeating: 0, count: 64)
        if v4 { var x = v4a; inet_ntop(AF_INET, &x, &buf, 64) } else { inet_ntop(AF_INET6, &a, &buf, 64) }
        return String(cString: buf)
    }
    let l = s(&ini.insi_laddr.ina_6, ini.insi_laddr.ina_46.i46a_addr4)
    let f = s(&ini.insi_faddr.ina_6, ini.insi_faddr.ina_46.i46a_addr4)
    return (l, f)
}

/// Open files, sockets and pipes of one process (libproc). Returns nil when the process is not readable.
func listFds(pid: Int32, filesOnly: Bool = false) -> [FdRec]? {
    let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
    if bytes <= 0 { return nil }
    let n = Int(bytes) / MemoryLayout<proc_fdinfo>.stride + 16
    var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: n)
    let got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(n * MemoryLayout<proc_fdinfo>.stride))
    if got <= 0 { return nil }
    let cnt = Int(got) / MemoryLayout<proc_fdinfo>.stride
    var out: [FdRec] = []
    for i in 0..<cnt {
        let fd = fds[i]
        switch Int32(fd.proc_fdtype) {
        case PROX_FDTYPE_VNODE:
            var vi = vnode_fdinfowithpath()
            if proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, Int32(MemoryLayout<vnode_fdinfowithpath>.size)) > 0 {
                let path = cString(vi.pvip.vip_path)
                let mode = vi.pvip.vip_vi.vi_stat.vst_mode
                if !path.isEmpty && (mode & S_IFMT) == S_IFREG { out.append(FdRec(pid: pid, kind: .file, path: path)) }
            }
        case PROX_FDTYPE_SOCKET where !filesOnly:
            var si = socket_fdinfo()
            if proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &si, Int32(MemoryLayout<socket_fdinfo>.size)) <= 0 { continue }
            let s = si.psi
            switch Int32(s.soi_kind) {
            case Int32(SOCKINFO_TCP):
                let t = s.soi_proto.pri_tcp
                let (l, f) = addrString(t.tcpsi_ini)
                out.append(FdRec(pid: pid, kind: .tcp, laddr: l, raddr: f, lport: Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: t.tcpsi_ini.insi_lport))),
                                 rport: Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: t.tcpsi_ini.insi_fport))), state: Int(t.tcpsi_state)))
            case Int32(SOCKINFO_IN):
                let ini = s.soi_proto.pri_in
                let (l, f) = addrString(ini)
                out.append(FdRec(pid: pid, kind: Int32(s.soi_protocol) == IPPROTO_UDP ? .udp : .other, laddr: l, raddr: f,
                                 lport: Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_lport))), rport: Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport)))))
            case Int32(SOCKINFO_UN):
                let u = s.soi_proto.pri_un
                var r = FdRec(pid: pid, kind: .unix)
                r.handle = s.soi_pcb; r.peer = u.unsi_conn_pcb
                r.path = withUnsafeBytes(of: u.unsi_addr.ua_sun.sun_path) { raw in
                    let p = raw.bindMemory(to: CChar.self); let n = p.firstIndex(of: 0) ?? p.count
                    return String(decoding: raw.prefix(n), as: UTF8.self) }
                out.append(r)
            default: break
            }
        case PROX_FDTYPE_PIPE where !filesOnly:
            var pi = pipe_fdinfo()
            if proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDPIPEINFO, &pi, Int32(MemoryLayout<pipe_fdinfo>.size)) > 0 {
                var r = FdRec(pid: pid, kind: .pipe); r.handle = pi.pipeinfo.pipe_handle; r.peer = pi.pipeinfo.pipe_peerhandle
                out.append(r)
            }
        default: break
        }
    }
    return out
}

// ---------------------------------------------------------------- helper protocol
// Plain text, one record per line, fields separated by a TAB so paths with spaces survive.
//   helper -> app:  P pid ppid uid rss footprint cpuNs diskR diskW threads hasTask hasIO
//                   S pid kind laddr lport raddr rport state handle peer path      (sockets / pipes)
//                   F pid path                                                     (open regular files)
//                   E                                                             (end of one snapshot)
//                   W t pid proto lip lport rip rport pktsIn bytesIn pktsOut bytesOut iface   (captured accounting, 250 ms bundles)
//                   C status text                                                 (capture status)
//                   R ...                                                         (reply to a request)
//   app -> helper:  HELLO v, SUB (stream snapshots + accounting), PCAPFD (open a packet session; fd follows via SCM_RIGHTS),
//                   PCAPCLOSE, MEMREGIONS pid, MEMREAD pid addr len, PF verb args, SIG pid signo, PRIO pid nice, LAUNCHCTL verb label,
//                   IFACE name up|down, FLUSHDNS
func esc(_ s: String) -> String { s.replacingOccurrences(of: "\t", with: " ").replacingOccurrences(of: "\n", with: " ") }
func joinRec(_ f: [String]) -> String { f.map(esc).joined(separator: "\t") + "\n" }
func splitRec(_ line: Substring) -> [Substring] { line.split(separator: "\t", omittingEmptySubsequences: false) }

/// Send a buffer fully on a blocking socket.
@discardableResult func writeAll(_ fd: Int32, _ s: String) -> Bool {
    var data = Array(s.utf8); var off = 0
    while off < data.count {
        let n = data.withUnsafeMutableBytes { write(fd, $0.baseAddress! + off, $0.count - off) }
        if n <= 0 { if n < 0 && errno == EINTR { continue }; return false }
        off += n
    }
    return true
}

/// Buffered line reader on a file descriptor.
final class LineReader {
    let fd: Int32; var buf = [UInt8](); var tmp = [UInt8](repeating: 0, count: 65536)
    init(fd: Int32) { self.fd = fd }
    func next() -> String? {
        while true {
            if let i = buf.firstIndex(of: 10) {
                let line = String(decoding: buf[0..<i], as: UTF8.self); buf.removeSubrange(0...i); return line
            }
            let n = read(fd, &tmp, tmp.count)
            if n <= 0 { if n < 0 && errno == EINTR { continue }; return nil }
            buf.append(contentsOf: tmp[0..<n])
        }
    }
}

/// Receive one file descriptor sent with SCM_RIGHTS (plus the line that came with it).
func recvFd(_ sock: Int32) -> (Int32, String)? {
    var data = [UInt8](repeating: 0, count: 512)
    let ctlLen = Int(MemoryLayout<cmsghdr>.size + MemoryLayout<Int32>.size + 8)
    var ctl = [UInt8](repeating: 0, count: ctlLen)
    return data.withUnsafeMutableBytes { dp -> (Int32, String)? in
        ctl.withUnsafeMutableBytes { cp -> (Int32, String)? in
            var iov = iovec(iov_base: dp.baseAddress, iov_len: dp.count)
            var msg = msghdr(); msg.msg_iov = withUnsafeMutablePointer(to: &iov) { $0 }; msg.msg_iovlen = 1
            msg.msg_control = cp.baseAddress; msg.msg_controllen = socklen_t(cp.count)
            let n = withUnsafeMutablePointer(to: &iov) { iovp -> Int in msg.msg_iov = iovp; return recvmsg(sock, &msg, 0) }
            if n <= 0 { return nil }
            let text = String(decoding: dp.prefix(n), as: UTF8.self)
            guard msg.msg_controllen >= socklen_t(MemoryLayout<cmsghdr>.size) else { return (-1, text) }
            let h = cp.baseAddress!.assumingMemoryBound(to: cmsghdr.self).pointee
            if h.cmsg_level == SOL_SOCKET && h.cmsg_type == SCM_RIGHTS {
                let fdp = cp.baseAddress!.advanced(by: MemoryLayout<cmsghdr>.size).assumingMemoryBound(to: Int32.self)
                return (fdp.pointee, text)
            }
            return (-1, text)
        }
    }
}

func sendFd(_ sock: Int32, _ fd: Int32, _ text: String) -> Bool {
    var data = Array(text.utf8)
    let ctlLen = MemoryLayout<cmsghdr>.size + MemoryLayout<Int32>.size
    var ctl = [UInt8](repeating: 0, count: ctlLen + 8)
    return data.withUnsafeMutableBytes { dp in
        ctl.withUnsafeMutableBytes { cp in
            let h = cp.baseAddress!.assumingMemoryBound(to: cmsghdr.self)
            h.pointee.cmsg_len = socklen_t(ctlLen); h.pointee.cmsg_level = SOL_SOCKET; h.pointee.cmsg_type = SCM_RIGHTS
            cp.baseAddress!.advanced(by: MemoryLayout<cmsghdr>.size).assumingMemoryBound(to: Int32.self).pointee = fd
            var iov = iovec(iov_base: dp.baseAddress, iov_len: dp.count)
            var msg = msghdr()
            msg.msg_control = cp.baseAddress; msg.msg_controllen = socklen_t(ctlLen)
            return withUnsafeMutablePointer(to: &iov) { iovp -> Bool in
                msg.msg_iov = iovp; msg.msg_iovlen = 1
                return sendmsg(sock, &msg, 0) > 0
            }
        }
    }
}

// ---------------------------------------------------------------- packets (pktap / BPF)
// One captured packet, addresses as strings (v4 or v6), the first 512 bytes from the IP header on.
struct Pkt {
    var t: Double = 0
    var pid: Int32 = -1
    var comm = ""
    var proto: UInt8 = 0
    var out = false
    var lip = "", rip = ""
    var lp: UInt16 = 0, rp: UInt16 = 0
    var len: Int = 0
    var ifname = ""
    var data: [UInt8] = []          // capped at 512 bytes; empty in accounting-only mode
    var v6 = false
}

// Layout of struct pktap_header (xnu bsd/net/pktap.h, stable since 10.9). Not in the public SDK, so the offsets live here.
enum PKTAP {
    static let DLT_PKTAP: UInt32 = 258, DLT_USER2: UInt32 = 149
    static let offLength = 0, offDlt = 8, offIfname = 12, offFlags = 36, offPid = 52, offComm = 56, offEpid = 84, offEcomm = 88
    static let FLAG_DIR_IN: UInt32 = 0x1, FLAG_DIR_OUT: UInt32 = 0x2
}

@inline(__always) func rd32(_ p: UnsafeRawBufferPointer, _ o: Int) -> UInt32 { o + 4 <= p.count ? p.loadUnaligned(fromByteOffset: o, as: UInt32.self) : 0 }
@inline(__always) func be16(_ p: UnsafeRawBufferPointer, _ o: Int) -> UInt16 { o + 2 <= p.count ? (UInt16(p[o]) << 8 | UInt16(p[o + 1])) : 0 }

func ipString(_ p: UnsafeRawBufferPointer, _ o: Int, v6: Bool) -> String {
    var buf = [CChar](repeating: 0, count: 64)
    if v6 { guard o + 16 <= p.count else { return "?" }; inet_ntop(AF_INET6, p.baseAddress! + o, &buf, 64) }
    else { guard o + 4 <= p.count else { return "?" }; inet_ntop(AF_INET, p.baseAddress! + o, &buf, 64) }
    return String(cString: buf)
}

/// Parses one pktap record (pktap header + link-layer frame). keep = bytes of the IP packet to copy (0 for accounting).
func parsePktap(_ rec: UnsafeRawBufferPointer, keep: Int) -> Pkt? {
    let hl = Int(rd32(rec, PKTAP.offLength)); if hl < 108 || hl > rec.count { return nil }
    let dlt = rd32(rec, PKTAP.offDlt), flags = rd32(rec, PKTAP.offFlags)
    var p = Pkt()
    p.pid = Int32(bitPattern: rd32(rec, PKTAP.offPid))
    let epid = Int32(bitPattern: rd32(rec, PKTAP.offEpid))
    if p.pid <= 0 && epid > 0 { p.pid = epid }
    p.comm = String(decoding: UnsafeRawBufferPointer(rebasing: rec[PKTAP.offComm..<PKTAP.offComm + 17]).prefix { $0 != 0 }, as: UTF8.self)
    p.ifname = String(decoding: UnsafeRawBufferPointer(rebasing: rec[PKTAP.offIfname..<PKTAP.offIfname + 24]).prefix { $0 != 0 }, as: UTF8.self)
    p.out = (flags & PKTAP.FLAG_DIR_OUT) != 0
    var off = hl
    switch dlt {
    case 1:  // DLT_EN10MB
        guard rec.count >= off + 14 else { return nil }
        var et = be16(rec, off + 12); off += 14
        if et == 0x8100 { et = be16(rec, off + 2); off += 4 }
        if et != 0x0800 && et != 0x86DD { return nil }
    case 0:  // DLT_NULL: 4-byte host-order family
        guard rec.count >= off + 4 else { return nil }; off += 4
    case 12, 101: break  // DLT_RAW
    default:
        // utun & co: look at the version nibble
        break
    }
    return parseIP(UnsafeRawBufferPointer(rebasing: rec[off...]), into: &p, keep: keep) ? p : nil
}

/// Fills addresses/ports/proto from an IP packet. Without the pktap direction flag the caller decides direction.
func parseIP(_ ip: UnsafeRawBufferPointer, into p: inout Pkt, keep: Int) -> Bool {
    guard ip.count >= 20 else { return false }
    let ver = ip[0] >> 4
    var l4 = 0, src = "", dst = ""
    if ver == 4 {
        let ihl = Int(ip[0] & 15) * 4; guard ihl >= 20 else { return false }
        p.proto = ip[9]; p.len = Int(be16(ip, 2)); l4 = ihl
        src = ipString(ip, 12, v6: false); dst = ipString(ip, 16, v6: false)
    } else if ver == 6 {
        guard ip.count >= 40 else { return false }
        p.proto = ip[6]; p.len = Int(be16(ip, 4)) + 40; l4 = 40; p.v6 = true
        src = ipString(ip, 8, v6: true); dst = ipString(ip, 24, v6: true)
    } else { return false }
    var sp: UInt16 = 0, dp: UInt16 = 0
    if (p.proto == 6 || p.proto == 17) && ip.count >= l4 + 4 { sp = be16(ip, l4); dp = be16(ip, l4 + 2) }
    if p.out { p.lip = src; p.rip = dst; p.lp = sp; p.rp = dp } else { p.lip = dst; p.rip = src; p.lp = dp; p.rp = sp }
    if keep > 0 { p.data = Array(ip.prefix(keep)) }
    return true
}

// ---------------------------------------------------------------- misc
func isLoop(_ a: String) -> Bool { a.hasPrefix("127.") || a == "::1" }
func isAny(_ a: String) -> Bool { a == "0.0.0.0" || a == "::" || a == "*" || a.isEmpty }
func isPrivate(_ a: String) -> Bool {
    if a.hasPrefix("10.") || a.hasPrefix("192.168.") || a.hasPrefix("169.254.") { return true }
    if a.hasPrefix("172."), let o = Int(a.split(separator: ".").dropFirst().first ?? "") { return o >= 16 && o <= 31 }
    let l = a.lowercased(); return l.hasPrefix("fe80") || l.hasPrefix("fc") || l.hasPrefix("fd")
}
func validIp(_ s: String) -> Bool {
    var a4 = in_addr(), a6 = in6_addr()
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1
}

/// Runs a tool and returns (status, stdout+stderr). Used for system tools only (ps, nettop, diskutil, pfctl, launchctl ...).
@discardableResult func run(_ path: String, _ args: [String], timeout: Double = 20) -> (Int32, String) {
    let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
    p.standardInput = FileHandle.nullDevice
    do { try p.run() } catch { return (-1, "\(error.localizedDescription)") }
    var data = Data(); let lock = NSLock()
    let reader = Thread { let d = pipe.fileHandleForReading.readDataToEndOfFile(); lock.lock(); data = d; lock.unlock() }
    reader.start()
    let deadline = Date().addingTimeInterval(timeout)
    while p.isRunning && Date() < deadline { usleep(5000) }
    if p.isRunning { p.terminate(); usleep(100000); if p.isRunning { kill(p.processIdentifier, SIGKILL) } }
    p.waitUntilExit()
    var tries = 0; while reader.isExecuting && tries < 200 { usleep(5000); tries += 1 }
    lock.lock(); let s = String(decoding: data, as: UTF8.self); lock.unlock()
    return (p.terminationStatus, s)
}

/// Processes that must never be signalled: losing them logs the user out, hangs or panics the Mac.
let criticalNames: Set<String> = ["kernel_task", "launchd", "WindowServer", "loginwindow", "logd", "configd", "notifyd", "opendirectoryd",
    "securityd", "diskarbitrationd", "coreservicesd", "syslogd", "powerd", "fseventsd", "watchdogd", "kernelmanagerd", "runningboardd",
    "launchservicesd", "apfsd", "endpointsecurityd", "amfid", "com.matrixsys.helper", "MatrixSys"]
