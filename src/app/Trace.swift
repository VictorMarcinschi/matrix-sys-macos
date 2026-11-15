// Trace.swift — an active trace of the route and the conversation between this Mac and a target.
// Steps: name resolution (raw DNS over UDP to the configured servers), hop discovery (unprivileged ICMP echo with a
// rising TTL), then the chosen protocol: ICMP echo, TCP connect + greeting, HTTP, HTTPS, or DNS record queries.
// Every request and every answer is recorded as a message with decoded fields and the bytes that were on the wire.
//
// Nothing here needs the helper: macOS lets any process open SOCK_DGRAM/IPPROTO_ICMP and set IP_TTL on it.
import Foundation
import Network
import Security
import SystemConfiguration

enum TP { static let icmp = 0, tcp = 1, http = 2, https = 3, dns = 4 }
enum TK { static let dnsq = 0, dnsr = 1, probe = 2, ttlx = 3, echoq = 4, echor = 5, syn = 6, synack = 7,
                     refused = 8, tlsc = 9, tlss = 10, httpq = 11, httpr = 12, banner = 13, fin = 14, lost = 15, info = 16 }
enum TN { static let me = 0, dns = 1, hop = 2, silent = 3, target = 4 }

typealias TrFields = [(String, String)]
struct TrMsg {
    var t = 0.0, ms = -1.0
    var from = 0, to = 0, kind = 0, pair = -1, phase = 0
    var out = true
    var title = "", body = ""
    var url = "", page = "", ctype = "", csp = ""      // an HTML answer kept whole, for the rendered view
    var f: TrFields = []
    var raw: [UInt8] = []; var rawTotal = 0
}
struct TrNode { var kind = 0, ttl = 0; var ip = "", name = "", note = ""; var ms = -1.0 }
struct Trace {
    var ver = 0, proto = 0, port = 0
    var running = false, live = false
    var input = "", host = "", path = "", status = "", err = ""
    var took = 0.0
    var nodes: [TrNode] = [], msgs: [TrMsg] = [], chain: [Int] = []
    var links: [(Int, Int)] = []
}

/// What the trace thread publishes and the view reads, plus the gate a step-by-step run waits at.
final class TrShared {
    static let i = TrShared()
    private let lock = NSLock()
    private var t = Trace()
    private var gen = 0
    private var permits = 0
    private(set) var waiting = false      // the thread is at the gate, asking for a permit
    func snapshot() -> Trace { lock.lock(); defer { lock.unlock() }; return t }
    func version() -> Int { lock.lock(); defer { lock.unlock() }; return t.ver }
    func currentGen() -> Int { lock.lock(); defer { lock.unlock() }; return gen }
    func begin(_ input: String, _ live: Bool) -> Int {
        lock.lock(); defer { lock.unlock() }
        gen += 1; permits = 0
        let v = t.ver + 1; t = Trace(); t.ver = v; t.running = true; t.live = live; t.input = input; t.status = "starting"
        return gen
    }
    func stop() {
        lock.lock(); defer { lock.unlock() }
        gen += 1
        if t.running { t.running = false; t.status = "stopped"; t.err = "Stopped."; t.ver += 1 }
    }
    func alive(_ g: Int) -> Bool { lock.lock(); defer { lock.unlock() }; return gen == g && !quitting }
    func mutate(_ g: Int, _ fn: (inout Trace) -> Void) {
        lock.lock(); defer { lock.unlock() }
        if gen != g { return }
        fn(&t); t.ver += 1
    }
    func grant() { lock.lock(); if permits < 1 { permits = 1 }; lock.unlock() }
    func permitsPending() -> Bool { lock.lock(); defer { lock.unlock() }; return permits > 0 }
    /// Blocks until a permit is granted (step-by-step runs only). Returns the time it spent waiting.
    func gate(_ g: Int) -> Double {
        let t0 = nowSec()
        while true {
            lock.lock()
            if gen != g || quitting { lock.unlock(); break }
            if permits > 0 { permits -= 1; waiting = false; lock.unlock(); break }
            waiting = true
            lock.unlock()
            usleep(12000)
        }
        waiting = false
        return nowSec() - t0
    }
    var quitting = false
}

/// One run of the trace: its generation, its clock, and the time it spent waiting at the gate (kept out of every timing).
final class TrRun {
    let gen: Int, t0: Double, live: Bool
    var held = 0.0
    init(_ gen: Int, _ live: Bool) { self.gen = gen; self.t0 = nowSec(); self.live = live }
    var ok: Bool { TrShared.i.alive(gen) }
    func now() -> Double { nowSec() - t0 - held }
    func gate() { if live { held += TrShared.i.gate(gen) } }
    func set(_ fn: (inout Trace) -> Void) { TrShared.i.mutate(gen, fn) }
    @discardableResult func addNode(_ kind: Int, _ ip: String, _ name: String = "", _ ttl: Int = 0) -> Int {
        var idx = 0
        TrShared.i.mutate(gen) { t in
            if kind != TN.hop && kind != TN.silent && !ip.isEmpty {
                for (i, n) in t.nodes.enumerated() where n.ip == ip && (n.kind == TN.dns || n.kind == TN.target) { idx = i; return }
            }
            t.nodes.append(TrNode(kind: kind, ttl: ttl, ip: ip, name: name)); idx = t.nodes.count - 1
        }
        return idx
    }
    @discardableResult func add(_ m: TrMsg) -> Int {
        var idx = -1
        TrShared.i.mutate(gen) { t in
            var m = m; m.rawTotal = m.raw.count; if m.raw.count > 4096 { m.raw = Array(m.raw.prefix(4096)) }
            t.msgs.append(m); idx = t.msgs.count - 1
        }
        return idx
    }
    func link(_ a: Int, _ b: Int) {
        TrShared.i.mutate(gen) { t in
            if t.links.contains(where: { $0.0 == a && $0.1 == b }) { return }
            if b != 0 && t.chain.contains(b) { return }
            t.links.append((a, b))
        }
    }
}

func trMk(_ t: Double, _ from: Int, _ to: Int, _ kind: Int, _ phase: Int, _ out: Bool, _ title: String, _ pair: Int = -1, _ ms: Double = -1) -> TrMsg {
    var m = TrMsg(); m.t = t; m.from = from; m.to = to; m.kind = kind; m.phase = phase; m.out = out; m.title = title; m.pair = pair; m.ms = ms; return m
}
func trBytes(_ b: Double) -> String { b < 1024 ? String(format: "%.0f bytes", b) : b < 1048576 ? String(format: "%.1f KB", b / 1024) : String(format: "%.1f MB", b / 1048576) }
func trMs(_ ms: Double) -> String { ms < 1 ? "<1 ms" : String(format: ms < 10 ? "%.1f ms" : "%.0f ms", ms) }
func trHex(_ v: UInt32, _ w: Int = 4) -> String { String(format: "0x%0\(w)X", v) }
/// Printable rendering of bytes, for a preview.
func trText(_ d: ArraySlice<UInt8>) -> String {
    var o = ""; o.reserveCapacity(d.count)
    for c in d { if c == 13 { continue }; o.append(Character(UnicodeScalar((c == 10 || c == 9 || c >= 32) && c != 127 ? c : 46))) }
    return o
}
func trText(_ d: [UInt8], _ n: Int) -> String { trText(d.prefix(min(n, d.count))) }

// ---------------------------------------------------------------- what the user typed
struct TrTarget { var proto = TP.icmp, port = 0; var host = "", path = "/", server = "" }
private let trSchemes: [(String, Int, Int)] = [("http", TP.http, 80), ("ws", TP.http, 80), ("https", TP.https, 443), ("wss", TP.https, 443),
    ("tcp", TP.tcp, 0), ("icmp", TP.icmp, 0), ("ping", TP.icmp, 0), ("dns", TP.dns, 53),
    ("ssh", TP.tcp, 22), ("sftp", TP.tcp, 22), ("ftp", TP.tcp, 21), ("smtp", TP.tcp, 25), ("telnet", TP.tcp, 23), ("imap", TP.tcp, 143),
    ("pop3", TP.tcp, 110), ("rdp", TP.tcp, 3389), ("mysql", TP.tcp, 3306), ("redis", TP.tcp, 6379), ("vnc", TP.tcp, 5900)]
/// The protocol a scheme prefix such as "https://" implies, or nil.
func trSchemeProto(_ input: String) -> (proto: Int, port: Int)? {
    guard let r = input.range(of: "://"), r.lowerBound != input.startIndex else { return nil }
    let s = input[input.startIndex..<r.lowerBound].trimmingCharacters(in: .whitespaces).lowercased()
    for (n, p, port) in trSchemes where n == s { return (p, port) }
    return nil
}
func trParse(_ raw: String, _ protoSel: Int) -> (TrTarget, String?) {
    var o = TrTarget()
    var inp = raw.trimmingCharacters(in: .whitespaces)
    if inp.isEmpty { return (o, "Type a host name, an IPv4 address or a URL.") }
    var defPort = 0
    if let sp = trSchemeProto(inp) { o.proto = sp.proto; defPort = sp.port } else { o.proto = protoSel }
    if let r = inp.range(of: "://") {
        if trSchemeProto(inp) == nil { return (o, "Unknown scheme \"\(inp[inp.startIndex..<r.lowerBound])\". Known: http, https, tcp, icmp, dns, ssh, ftp, smtp.") }
        inp = String(inp[r.upperBound...])
    }
    if o.proto == TP.dns {   // name@server, or dns://server/name
        if let at = inp.lastIndex(of: "@") { o.server = inp[inp.index(after: at)...].lowercased(); inp = String(inp[..<at]) }
        else if let sl = inp.firstIndex(of: "/"), inp.index(after: sl) < inp.endIndex { o.server = inp[..<sl].lowercased(); inp = String(inp[inp.index(after: sl)...]) }
        while let l = inp.last, l == "/" || l == "." { inp.removeLast() }
    } else {
        if let sl = inp.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
            o.path = inp[sl] == "/" ? String(inp[sl...]) : "/" + String(inp[sl...])
            inp = String(inp[..<sl])
        }
        if let h = o.path.firstIndex(of: "#") { o.path = String(o.path[..<h]) }
        if let at = o.path.isEmpty ? nil : inp.lastIndex(of: "@") { inp = String(inp[inp.index(after: at)...]) }
        else if let at = inp.lastIndex(of: "@") { inp = String(inp[inp.index(after: at)...]) }
    }
    if inp.hasPrefix("[") { return (o, "IPv6 targets are not supported yet; use a name or an IPv4 address.") }
    if let col = inp.lastIndex(of: ":") {
        let tail = inp[inp.index(after: col)...]
        if !tail.isEmpty, tail.allSatisfy({ $0.isNumber }), inp.firstIndex(of: ":") == col { o.port = Int(tail) ?? 0; inp = String(inp[..<col]) }
        else { return (o, "IPv6 targets are not supported yet; use a name or an IPv4 address.") }
    }
    o.host = inp.lowercased()
    while o.host.hasSuffix(".") { o.host.removeLast() }
    if o.host.isEmpty { return (o, "Type a host name, an IPv4 address or a URL.") }
    for c in o.host.unicodeScalars where !(CharacterSet.alphanumerics.contains(c) || c == "." || c == "-" || c == "_" || c.value >= 128) {
        return (o, "The host name contains a character that is not allowed: '\(c)'.")
    }
    if o.port <= 0 || o.port > 65535 { o.port = defPort != 0 ? defPort : o.proto == TP.https ? 443 : o.proto == TP.dns ? 53 : 80 }
    return (o, nil)
}

// ---------------------------------------------------------------- DNS wire format
func dnsTypeName(_ t: Int) -> String {
    switch t { case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA"; case 12: return "PTR"
    case 15: return "MX"; case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV"; case 41: return "OPT"; case 65: return "HTTPS"
    default: return "TYPE\(t)" }
}
func dnsRcode(_ r: Int) -> String {
    switch r { case 0: return "NOERROR"; case 1: return "FORMERR (malformed query)"; case 2: return "SERVFAIL (server failure)"
    case 3: return "NXDOMAIN (no such name)"; case 4: return "NOTIMP (not implemented)"; case 5: return "REFUSED"; default: return "error" }
}
func dnsBuild(_ id: UInt16, _ name: String, _ type: UInt16) -> [UInt8] {
    var d: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
    for label in name.split(separator: ".") {
        let b = Array(label.utf8).prefix(63)
        if !b.isEmpty { d.append(UInt8(b.count)); d += b }
    }
    d.append(0); d.append(UInt8(type >> 8)); d.append(UInt8(type & 0xff)); d.append(0); d.append(1)
    return d
}
/// Reads a name, following compression pointers. Advances `off` past the name as it appears here.
func dnsReadName(_ d: [UInt8], _ off: inout Int) -> String? {
    var p = off, jumped = false, guardN = 0, out = ""
    while p < d.count && guardN < 128 {
        guardN += 1
        let l = d[p]
        if l == 0 { if !jumped { off = p + 1 }; return out.isEmpty ? "." : out }
        if l & 0xC0 == 0xC0 {
            if p + 1 >= d.count { return nil }
            if !jumped { off = p + 2 }
            jumped = true; p = (Int(l & 0x3F) << 8) | Int(d[p + 1]); continue
        }
        if p + 1 + Int(l) > d.count { return nil }
        if !out.isEmpty { out += "." }
        out += String(decoding: d[(p + 1)..<(p + 1 + Int(l))], as: UTF8.self)
        p += 1 + Int(l)
    }
    return nil
}
struct DnsRR { var name = "", val = ""; var type = 0, sec = 0; var ttl: UInt32 = 0 }
struct DnsMsg { var id = 0, rcode = 0, qtype = 0; var aa = false, tc = false, ra = false; var qname = ""; var rr: [DnsRR] = [] }
func dnsParse(_ d: [UInt8]) -> DnsMsg? {
    if d.count < 12 { return nil }
    func be(_ o: Int) -> Int { o + 1 < d.count ? (Int(d[o]) << 8) | Int(d[o + 1]) : 0 }
    var m = DnsMsg()
    m.id = be(0); m.aa = d[2] & 4 != 0; m.tc = d[2] & 2 != 0; m.ra = d[3] & 0x80 != 0; m.rcode = Int(d[3] & 15)
    let qd = be(4); let cnt = [be(6), be(8), be(10)]
    var o = 12
    for _ in 0..<qd { guard let n = dnsReadName(d, &o), o + 4 <= d.count else { return nil }; m.qname = n; m.qtype = be(o); o += 4 }
    for sec in 0..<3 { for _ in 0..<cnt[sec] {
        var r = DnsRR(); r.sec = sec
        guard let n = dnsReadName(d, &o), o + 10 <= d.count else { return nil }
        r.name = n; r.type = be(o); r.ttl = (UInt32(be(o + 4)) << 16) | UInt32(be(o + 6))
        let len = be(o + 8); o += 10
        if o + len > d.count { return nil }
        let ro = o
        switch r.type {
        case 1 where len == 4:
            r.val = "\(d[ro]).\(d[ro+1]).\(d[ro+2]).\(d[ro+3])"
        case 28 where len == 16:
            var a = in6_addr(); withUnsafeMutableBytes(of: &a) { b in for i in 0..<16 { b[i] = d[ro + i] } }
            var buf = [CChar](repeating: 0, count: 64)
            if inet_ntop(AF_INET6, &a, &buf, 64) != nil { r.val = String(cString: buf) }
        case 2, 5, 12:
            var p = ro; r.val = dnsReadName(d, &p) ?? ""
        case 15 where len > 2:
            var p = ro + 2; let n = dnsReadName(d, &p) ?? ""; r.val = "\(n) (preference \(be(ro)))"
        case 16:
            var p = ro
            while p < ro + len { let l = Int(d[p]); p += 1; if p + l > ro + len { break }
                if !r.val.isEmpty { r.val += " " }
                r.val += "\"" + trText(d[p..<(p + l)]) + "\""; p += l }
        case 6:
            var p = ro
            if let mn = dnsReadName(d, &p), let rn = dnsReadName(d, &p), p + 20 <= d.count {
                r.val = "primary \(mn), contact \(rn), serial \((UInt32(be(p)) << 16) | UInt32(be(p + 2)))"
            }
        default: break
        }
        if r.val.isEmpty { r.val = "\(len) bytes of data" }
        o = ro + len; m.rr.append(r)
    } }
    return m
}

// ---------------------------------------------------------------- the DNS servers this Mac is configured to use
/// From the system configuration (the same list `scutil --dns` shows), IPv4 first, deduplicated.
func trDnsServers() -> [String] {
    var v4: [String] = [], v6: [String] = []
    if let st = SCDynamicStoreCreate(nil, "MatrixSys" as CFString, nil, nil),
       let d = SCDynamicStoreCopyValue(st, "State:/Network/Global/DNS" as CFString) as? [String: Any],
       let list = d["ServerAddresses"] as? [String] {
        for s in list { if s.contains(":") { v6.append(s) } else { v4.append(s) } }
    }
    if v4.isEmpty && v6.isEmpty, let txt = try? String(contentsOfFile: "/etc/resolv.conf", encoding: .utf8) {
        for line in txt.split(separator: "\n") where line.hasPrefix("nameserver ") {
            let s = line.dropFirst(11).trimmingCharacters(in: .whitespaces)
            if s.contains(":") { v6.append(s) } else { v4.append(s) }
        }
    }
    var out: [String] = []
    for s in v4 + v6 where !out.contains(s) { out.append(s) }
    return out
}

// ---------------------------------------------------------------- small socket helpers
func sa4(_ ip: String, _ port: UInt16) -> sockaddr_in? {
    var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); a.sin_port = port.bigEndian
    return inet_pton(AF_INET, ip, &a.sin_addr) == 1 ? a : nil
}
func sa6(_ ip: String, _ port: UInt16) -> sockaddr_in6? {
    var a = sockaddr_in6(); a.sin6_family = sa_family_t(AF_INET6); a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); a.sin6_port = port.bigEndian
    return inet_pton(AF_INET6, ip, &a.sin6_addr) == 1 ? a : nil
}
func ip4str(_ a: in_addr) -> String {
    var a = a; var b = [CChar](repeating: 0, count: 32)
    return inet_ntop(AF_INET, &a, &b, 32) != nil ? String(cString: b) : ""
}
/// Waits for the socket to become readable. true = there is something to read.
func waitRead(_ s: Int32, _ ms: Int) -> Bool {
    var p = pollfd(fd: s, events: Int16(POLLIN), revents: 0)
    return poll(&p, 1, Int32(ms)) > 0 && p.revents & Int16(POLLIN) != 0
}
func waitWrite(_ s: Int32, _ ms: Int) -> Bool {
    var p = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
    return poll(&p, 1, Int32(ms)) > 0 && p.revents & Int16(POLLOUT | POLLHUP | POLLERR) != 0
}
/// >0 bytes appended, 0 closed by the peer, -1 nothing within the timeout.
func sockRead(_ s: Int32, _ to: inout [UInt8], _ ms: Int) -> Int {
    if !waitRead(s, ms) { return -1 }
    var b = [UInt8](repeating: 0, count: 16384)
    let n = recv(s, &b, b.count, 0)
    if n > 0 { to += b[0..<n] }
    return n <= 0 ? 0 : n
}
func sockWrite(_ s: Int32, _ d: [UInt8]) -> Bool {
    var off = 0
    while off < d.count {
        let k = d[off...].withUnsafeBytes { send(s, $0.baseAddress, min(65536, d.count - off), 0) }
        if k <= 0 { return false }
        off += k
    }
    return true
}

// ---------------------------------------------------------------- one DNS question over UDP
private var dnsIdCounter: UInt16 = UInt16.random(in: 1...60000)
private let dnsIdLock = NSLock()
private func nextDnsId() -> UInt16 { dnsIdLock.lock(); defer { dnsIdLock.unlock() }; dnsIdCounter &+= 1; return dnsIdCounter }

/// Asks one server one question, recording the query, the decoded answer, or the silence. 2 attempts, 2 s each.
@discardableResult
func trDnsQuery(_ r: TrRun, _ node: Int, _ server: String, _ name: String, _ type: Int, _ phase: Int, _ out: inout DnsMsg) -> Bool {
    let v6 = server.contains(":")
    let s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    if s < 0 { return false }
    defer { close(s) }
    var ok = false
    for _ in 0..<2 {
        if ok || !r.ok { break }
        r.gate()
        let id = nextDnsId(); let q = dnsBuild(id, name, UInt16(type)); let t = r.now()
        var m = trMk(t, 0, node, TK.dnsq, phase, true, "DNS query: \(name) \(dnsTypeName(type))?")
        m.f = [("question", "\(name)  type \(dnsTypeName(type))  class IN"), ("transaction id", trHex(UInt32(id))),
               ("flags", "standard query, recursion desired"), ("sent to", "\(server) port 53 over UDP"), ("size", trBytes(Double(q.count)))]
        m.raw = q
        let qi = r.add(m)
        if v6 { if var a = sa6(server, 53) { _ = q.withUnsafeBytes { b in withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(s, b.baseAddress, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } } } } }
        else { if var a = sa4(server, 53) { _ = q.withUnsafeBytes { b in withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(s, b.baseAddress, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } } } }
        var buf = [UInt8](repeating: 0, count: 4096)
        var n = -1
        if waitRead(s, 2000) { n = recv(s, &buf, 4096, 0) }
        let t2 = r.now()
        if n >= 12 {
            let got = Array(buf[0..<n])
            if let dm = dnsParse(got), dm.id == Int(id) {
                var na = 0; var first = ""
                for x in dm.rr where x.sec == 0 {
                    if na == 0 || (x.type == type && !first.hasPrefix(dnsTypeName(type))) { first = "\(dnsTypeName(x.type)) \(x.val)" }
                    na += 1
                }
                var a = trMk(t2, node, 0, TK.dnsr, phase, false, "", qi, (t2 - t) * 1000)
                a.title = dm.rcode != 0 ? "DNS answer: " + dnsRcode(dm.rcode)
                        : na > 0 ? "DNS answer: " + first + (na > 1 ? "  (+\(na - 1) more)" : "")
                        : "DNS answer: no \(dnsTypeName(type)) record for this name"
                a.f.append(("result", "\(dnsRcode(dm.rcode)) · \(na) answer record(s) · " + trMs(a.ms)))
                a.f.append(("flags", (dm.aa ? "authoritative answer" : "non-authoritative (from a resolver's cache or recursion)")
                            + (dm.ra ? ", recursion available" : "") + (dm.tc ? ", TRUNCATED (too large for UDP)" : "")))
                let secN = ["answer", "authority", "additional"]
                for x in dm.rr where x.type != 41 { a.f.append(("\(secN[x.sec]) \(dnsTypeName(x.type))", "\(x.name) → \(x.val)   (valid \(x.ttl) s)")) }
                a.f.append(("size", trBytes(Double(got.count))))
                a.raw = got
                r.add(a); out = dm; ok = true
            }
        }
        if !ok {
            var l = trMk(t2, node, node, TK.lost, phase, false, "No DNS answer from \(server) within 2 s", qi)
            l.f = [("what happened", "The query was sent but nothing came back. The server may be down, or UDP port 53 is blocked.")]
            r.add(l)
        }
    }
    return ok
}

/// A name to an IPv4 address. Asks the configured servers directly so the exchange can be shown; falls back to the system resolver.
func trResolve(_ r: TrRun, _ host: String, _ phase: Int, _ ip4: inout String, _ err: inout String, alsoV6: Bool = true) -> Bool {
    if validIp(host) && !host.contains(":") { ip4 = host; return true }
    var tried = 0
    for srv in trDnsServers() {
        if tried >= 2 || !r.ok { break }
        tried += 1
        let node = r.addNode(TN.dns, srv, "DNS server")
        r.link(0, node)
        var dm = DnsMsg()
        if !trDnsQuery(r, node, srv, host, 1, phase, &dm) { continue }
        var got = false
        for x in dm.rr where x.sec == 0 && x.type == 1 && !got { ip4 = x.val; got = true }
        if alsoV6 && dm.rcode == 0 { var d6 = DnsMsg(); trDnsQuery(r, node, srv, host, 28, phase, &d6) }
        if got { return true }
        if dm.rcode == 3 { err = "The name \(host) does not exist (NXDOMAIN)."; return false }
        if dm.rcode == 0 { err = "\(host) has no IPv4 address (no A record). IPv6-only targets are not supported yet."; return false }
    }
    // the system resolver may know more: /etc/hosts, mDNS (.local), a search domain, encrypted DNS from a profile
    let node = r.addNode(TN.dns, "system", "macOS resolver")
    r.link(0, node)
    r.gate()
    let t = r.now()
    let qi = r.add(trMk(t, 0, node, TK.dnsq, phase, true, "Ask macOS to resolve \(host)"))
    var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
    var ai: UnsafeMutablePointer<addrinfo>? = nil
    let rc = getaddrinfo(host, nil, &hints, &ai)
    let t2 = r.now()
    if rc == 0, let a = ai {
        var addr = in_addr()
        a.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { addr = $0.pointee.sin_addr }
        freeaddrinfo(ai)
        ip4 = ip4str(addr)
        var m = trMk(t2, node, 0, TK.dnsr, phase, false, "macOS resolver: \(host) is \(ip4)", qi, (t2 - t) * 1000)
        m.f = [("address", ip4), ("note", "Answered by the system resolver (its cache, /etc/hosts, mDNS, a search domain or encrypted DNS). The exchange behind it is not visible to this trace.")]
        r.add(m)
        return true
    }
    if ai != nil { freeaddrinfo(ai) }
    r.add(trMk(t2, node, node, TK.lost, phase, false, "macOS could not resolve \(host)", qi))
    err = "The name \(host) could not be resolved."
    return false
}

// ---------------------------------------------------------------- the route (ICMP echo with a limited TTL)
struct TrHop { var got = false; var status = -1, code = 0; var addr = ""; var ms = -1.0; var rttl = 0 }
/// ICMP status, in the same words the Windows version uses.
func icmpText(_ status: Int, _ code: Int) -> String {
    switch status {
    case 0: return "echo reply"
    case 11: return code == 0 ? "TTL expired in transit" : "fragment reassembly time exceeded"
    case 3:
        switch code { case 0: return "destination network unreachable"; case 1: return "destination host unreachable"
        case 2: return "destination protocol unreachable"; case 3: return "destination port unreachable"
        case 9, 10, 13: return "administratively prohibited (a firewall dropped it)"
        default: return "destination unreachable (code \(code))" }
    case -1: return "no answer (timed out)"
    default: return "ICMP type \(status)"
    }
}
func icmpCksum(_ d: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0, i = 0
    while i + 1 < d.count { sum &+= UInt32(d[i]) << 8 | UInt32(d[i + 1]); i += 2 }
    if i < d.count { sum &+= UInt32(d[i]) << 8 }
    while sum >> 16 != 0 { sum = (sum & 0xffff) &+ (sum >> 16) }
    return UInt16(~sum & 0xffff)
}

/// An unprivileged ICMP socket. macOS allows SOCK_DGRAM/IPPROTO_ICMP to any process, and delivers both echo replies
/// and the "time exceeded" errors that a traceroute needs, so no helper and no root are involved.
final class IcmpSock {
    let fd: Int32
    let ident = UInt16.random(in: 1...60000)
    init?() {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        if fd < 0 { return nil }
        var on: Int32 = 1
        setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, 4)
    }
    func close() { if fd >= 0 { Darwin.close(fd) } }
    func setTTL(_ t: Int) { var v = Int32(t); setsockopt(fd, IPPROTO_IP, IP_TTL, &v, 4) }
    @discardableResult func sendEcho(_ dst: String, seq: UInt16) -> Bool {
        var p = [UInt8](repeating: 0, count: 40)
        p[0] = 8; p[1] = 0
        p[4] = UInt8(ident >> 8); p[5] = UInt8(ident & 0xff)
        p[6] = UInt8(seq >> 8); p[7] = UInt8(seq & 0xff)
        for i in 8..<40 { p[i] = UInt8(0x40 + (i % 24)) }       // "MatrixSys route trace probe" sized payload
        let c = icmpCksum(p); p[2] = UInt8(c >> 8); p[3] = UInt8(c & 0xff)
        guard var a = sa4(dst, 0) else { return false }
        return p.withUnsafeBytes { b in withUnsafePointer(to: &a) { ap in ap.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            sendto(fd, b.baseAddress, p.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } } == p.count
    }
    /// One ICMP message: who it came from, what it says, which probe it answers.
    struct Rx { var from = "", type = 0, code = 0, seq = 0, ttl = 0 }
    func recvOne(_ ms: Int) -> Rx? {
        if !waitRead(fd, ms) { return nil }
        var buf = [UInt8](repeating: 0, count: 1500)
        var ctl = [UInt8](repeating: 0, count: 256)
        var src = sockaddr_storage()
        var rx = Rx()
        let n: Int = buf.withUnsafeMutableBytes { bp -> Int in
            var iov = iovec(iov_base: bp.baseAddress, iov_len: bp.count)
            return withUnsafeMutablePointer(to: &iov) { iovp in
             withUnsafeMutablePointer(to: &src) { sp in
                sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    ctl.withUnsafeMutableBytes { cp -> Int in
                        var mh = msghdr(msg_name: UnsafeMutableRawPointer(sa), msg_namelen: socklen_t(MemoryLayout<sockaddr_storage>.size),
                                        msg_iov: iovp, msg_iovlen: 1, msg_control: cp.baseAddress, msg_controllen: socklen_t(cp.count), msg_flags: 0)
                        let got = recvmsg(fd, &mh, 0)
                        // walk the control messages by hand: the CMSG_* macros are not available from Swift
                        if got > 0, let base = cp.baseAddress {
                            let hdrSize = MemoryLayout<cmsghdr>.size
                            var off = 0
                            let total = Int(mh.msg_controllen)
                            while off + hdrSize <= total {
                                let h = base.load(fromByteOffset: off, as: cmsghdr.self)
                                let clen = Int(h.cmsg_len)
                                if clen < hdrSize || off + clen > total { break }
                                if h.cmsg_level == IPPROTO_IP && h.cmsg_type == IP_RECVTTL {
                                    rx.ttl = Int(base.load(fromByteOffset: off + ((hdrSize + 3) & ~3), as: UInt8.self))
                                }
                                off += (clen + 3) & ~3
                            }
                        }
                        return got
                    }
                }
             }
            }
        }
        if n <= 0 { return nil }
        if src.ss_family == sa_family_t(AF_INET) {
            withUnsafePointer(to: &src) { $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { rx.from = ip4str($0.pointee.sin_addr) } }
        }
        var o = 0
        if n > 20 && buf[0] & 0xF0 == 0x40 { o = Int(buf[0] & 0x0F) * 4; if rx.ttl == 0 { rx.ttl = Int(buf[8]) } }   // some paths hand us the IP header too
        if n < o + 8 { return nil }
        rx.type = Int(buf[o]); rx.code = Int(buf[o + 1])
        if rx.type == 0 { rx.seq = Int(buf[o + 6]) << 8 | Int(buf[o + 7]) }
        else if rx.type == 11 || rx.type == 3 {   // the error carries the start of the packet that caused it
            let ipo = o + 8
            if n > ipo + 20, buf[ipo] & 0xF0 == 0x40 {
                let ihl = Int(buf[ipo] & 0x0F) * 4
                if n >= ipo + ihl + 8 { rx.seq = Int(buf[ipo + ihl + 6]) << 8 | Int(buf[ipo + ihl + 7]) }
            }
        } else { return nil }
        return rx
    }
}

/// One probe at a time, so the wall clock is the round trip. Used by a step-by-step run and by the ICMP protocol phase.
func trProbeOne(_ s: IcmpSock, _ dst: String, _ ttl: Int, _ seq: UInt16, _ timeoutMs: Int) -> TrHop {
    var h = TrHop()
    s.setTTL(ttl)
    let t = nowSec()
    if !s.sendEcho(dst, seq: seq) { return h }
    let deadline = t + Double(timeoutMs) / 1000
    while nowSec() < deadline {
        let left = Int((deadline - nowSec()) * 1000)
        guard let rx = s.recvOne(max(1, left)) else { break }
        if rx.seq != Int(seq) { continue }
        h.got = true; h.status = rx.type; h.code = rx.code; h.addr = rx.from
        h.ms = max(0.05, (nowSec() - t) * 1000); h.rttl = rx.ttl
        return h
    }
    return h
}

/// Finds the hops to dst; each joins the chain as it is found, then the node that stands for dst.
/// Full speed: all probes leave in one burst, 10 ms apart. Step by step: one at a time, each waiting at the gate.
func trRoute(_ r: TrRun, _ dst: String, _ endNode: Int) {
    let MAXH = 30
    var endInChain = false, unreachable = false
    guard let sock = IcmpSock() else {
        r.add(trMk(r.now(), 0, endNode, TK.info, 1, false, "The route cannot be traced: this Mac refused an ICMP socket."))
        r.set { t in t.chain.append(endNode) }
        return
    }
    defer { sock.close() }

    func join(_ node: Int) {
        r.set { t in t.chain.append(node); t.links.removeAll { $0.1 == node } }
    }
    func emit(_ ttl: Int, _ h: TrHop, _ tq: Double) {
        let isEnd = h.got && h.status == 0
        let hip = h.got ? h.addr : ""
        let node = isEnd ? endNode : h.got ? r.addNode(TN.hop, hip, "", ttl) : r.addNode(TN.silent, "", "", ttl)
        join(node)
        var q = trMk(tq, 0, node, TK.probe, 1, true, "ICMP echo request with TTL \(ttl)" + (isEnd ? " — reaches the target" : ""))
        q.f = [("destination", dst), ("TTL (hop limit)", "\(ttl) — the packet is dropped by hop \(ttl), which reports back"), ("payload", "32 bytes")]
        let qi = r.add(q)
        if h.got {
            var a = trMk(tq + h.ms / 1000, node, 0, isEnd ? TK.echor : TK.ttlx, 1, false, "", qi, h.ms)
            a.title = isEnd ? "Echo reply from the target \(hip) in " + trMs(h.ms)
                    : h.status == 11 ? "Hop \(ttl): \(hip) answers \"TTL exceeded\" in " + trMs(h.ms)
                    : "Hop \(ttl): \(hip) answers \"\(icmpText(h.status, h.code))\""
            a.f = [("from", hip), ("ICMP message", icmpText(h.status, h.code)), ("round trip", trMs(h.ms))]
            if isEnd && h.rttl > 0 { a.f.append(("TTL of the reply", "\(h.rttl)")) }
            r.add(a)
            r.set { t in
                t.nodes[node].ms = h.ms; t.nodes[node].ttl = ttl
                if !isEnd && h.status != 11 { t.nodes[node].note = "reports: " + icmpText(h.status, h.code) }
            }
        } else {
            var l = trMk(tq + 1.5, node, node, TK.lost, 1, false, "Hop \(ttl) does not answer (2 probes, 1.5 s each)", qi)
            l.f = [("what this means", "Many routers forward traffic but are configured not to send ICMP errors. The path continues through it.")]
            r.add(l)
        }
        if isEnd { endInChain = true }
        if h.got && h.status == 3 { unreachable = true }
    }

    if r.live {
        var silent = 0, ttl = 1
        while ttl <= MAXH && !endInChain && !unreachable && silent < 5 {
            r.gate(); if !r.ok { return }
            let tq = r.now()
            var h = trProbeOne(sock, dst, ttl, UInt16(ttl), 1500)
            if !h.got { h = trProbeOne(sock, dst, ttl, UInt16(ttl &+ 100), 1500); if h.got { } }
            silent = h.got ? 0 : silent + 1
            emit(ttl, h, tq)
            ttl += 1
        }
    } else {
        var hops = [Int: TrHop]()
        var sent = [Int: Double]()
        let tb = r.now()
        // Probes leave 10 ms apart, but replies are collected the whole time: a hop that answers in 8 ms must not be
        // timed as if it answered after the last probe was sent.
        func burst(_ ttls: [Int], _ base: UInt16) {
            var i = 0, nextSend = nowSec()
            var lastSend = nowSec()
            while true {
                if i < ttls.count && nowSec() >= nextSend {
                    let ttl = ttls[i]
                    sock.setTTL(ttl); sent[ttl] = nowSec()
                    sock.sendEcho(dst, seq: UInt16(ttl) &+ base)
                    lastSend = nowSec(); nextSend = lastSend + 0.01
                    i += 1
                }
                if i >= ttls.count && (hops.count == ttls.count || nowSec() > lastSend + 1.5) { break }
                if !r.ok { break }
                let waitMs = i < ttls.count ? max(1, Int((nextSend - nowSec()) * 1000)) : max(1, Int((lastSend + 1.5 - nowSec()) * 1000))
                guard let rx = sock.recvOne(min(waitMs, 200)) else { continue }
                let ttl = rx.seq - Int(base)
                guard ttls.contains(ttl), hops[ttl] == nil, let t0 = sent[ttl] else { continue }
                var h = TrHop(); h.got = true; h.status = rx.type; h.code = rx.code; h.addr = rx.from
                h.ms = max(0.05, (nowSec() - t0) * 1000); h.rttl = rx.ttl
                hops[ttl] = h
            }
        }
        burst(Array(1...MAXH), 0)
        if !r.ok { return }
        var reached = 0, stop = 0, lastGot = 0
        for ttl in 1...MAXH {
            guard let h = hops[ttl] else { continue }
            lastGot = ttl
            if h.status == 0 && reached == 0 { reached = ttl }
            if h.status == 3 && stop == 0 { stop = ttl }
        }
        var last = reached != 0 ? reached : stop != 0 ? stop : lastGot
        if stop != 0 && reached != 0 && stop < reached { last = stop }
        if last > 1 {   // silent hops before the end get a second chance
            let retry = (1..<last).filter { hops[$0] == nil }
            if !retry.isEmpty { burst(retry, 200) }
        }
        if !r.ok { return }
        if last == 0 { last = MAXH }
        var ttl = 1
        while ttl <= last && !endInChain {
            emit(ttl, hops[ttl] ?? TrHop(), tb + Double(ttl - 1) * 0.01)
            ttl += 1
        }
    }
    if !r.ok { return }
    if !endInChain {
        join(endNode)
        r.set { t in t.nodes[endNode].note = unreachable
            ? "A router on the way reports the destination as unreachable."
            : "Does not answer ICMP echo. The hops after the last reply are unknown; the target may still accept other protocols." }
    }
}

// ---------------------------------------------------------------- TCP
/// Opens a connection and records what the socket interface reports: open, refused (RST) or no answer (filtered).
func trConnect(_ r: TrRun, _ node: Int, _ ip: String, _ port: Int, _ phase: Int) -> Int32 {
    let s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    if s < 0 { return -1 }
    var one: Int32 = 1; setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)
    let fl = fcntl(s, F_GETFL, 0); _ = fcntl(s, F_SETFL, fl | O_NONBLOCK)
    guard var a = sa4(ip, UInt16(port)) else { close(s); return -1 }
    r.gate()
    let t = r.now()
    _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    let writable = waitWrite(s, 6000)
    let t2 = r.now(), ms = (t2 - t) * 1000
    var l = sockaddr_in(); var ll = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &l) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &ll) } }
    let local = "\(ip4str(l.sin_addr)):\(UInt16(bigEndian: l.sin_port))", remote = "\(ip):\(port)"
    var q = trMk(t, 0, node, TK.syn, phase, true, "TCP SYN → \(remote)  (open a connection)")
    q.f = [("from", local), ("to", remote), ("note", "Reported by the socket interface. The handshake packets themselves are not captured by this trace.")]
    let qi = r.add(q)
    var soerr: Int32 = 0; var sl = socklen_t(4)
    getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &sl)
    if writable && soerr == 0 {
        var m = trMk(t2, node, 0, TK.synack, phase, false, "TCP SYN/ACK — port \(port) is open, connected in " + trMs(ms), qi, ms)
        m.f = [("connection", "\(local) ↔ \(remote)"), ("time to connect", trMs(ms))]
        r.add(m)
        _ = fcntl(s, F_SETFL, fl)
        return s
    }
    if writable {
        let why = soerr == ECONNREFUSED ? "TCP RST — port \(port) is closed (connection refused)"
                : (soerr == ENETUNREACH || soerr == EHOSTUNREACH) ? "Unreachable — no route to \(remote)"
                : "Connection failed (\(String(cString: strerror(soerr))))"
        r.add(trMk(t2, node, 0, TK.refused, phase, false, why, qi, ms))
    } else {
        r.add(trMk(t2, node, node, TK.lost, phase, false, "No answer to the SYN within 6 s (filtered by a firewall, or the host is down)", qi))
    }
    close(s)
    return -1
}
/// The greeting of a server that speaks first (SSH, SMTP, FTP, ...).
func trBanner(_ r: TrRun, _ node: Int, _ s: Int32, _ port: Int, _ phase: Int) {
    var b = [UInt8](); let t = r.now()
    let n = sockRead(s, &b, 1500)
    let t2 = r.now()
    if n > 0 {
        let txt = trText(b, 2000)
        let line = String(txt.prefix(while: { $0 != "\n" }))
        var what: String
        if txt.hasPrefix("SSH-") { what = "SSH server identifies itself: " + line }
        else if txt.hasPrefix("220") { what = (port == 21 ? "FTP" : "SMTP") + " greeting: " + line }
        else if txt.hasPrefix("+OK") { what = "POP3 greeting: " + line }
        else if txt.hasPrefix("* OK") { what = "IMAP greeting: " + line }
        else if txt.hasPrefix("RFB ") { what = "VNC server, protocol " + String(line.dropFirst(4)) }
        else if txt.hasPrefix("HTTP/") { what = "HTTP reply: " + line }
        else if b.count > 5 && b[4] == 0x0a {
            let v = b[5...].prefix(while: { $0 != 0 })
            what = "MySQL / MariaDB handshake, server version " + String(decoding: v, as: UTF8.self)
        } else { what = "The server speaks first: " + trBytes(Double(b.count)) + " of data" }
        var m = trMk(t2, node, 0, TK.banner, phase, false, what, -1, (t2 - t) * 1000)
        m.f = [("received", trBytes(Double(b.count)) + " " + trMs((t2 - t) * 1000) + " after connecting")]
        m.body = txt; m.raw = b
        r.add(m)
    } else if n == 0 {
        r.add(trMk(t2, node, 0, TK.fin, phase, false, "The server closed the connection right away"))
    } else {
        var m = trMk(t2, node, node, TK.info, phase, false, "No greeting within 1.5 s — this service waits for the client to speak first")
        m.f = [("what this means", "The port is open. Protocols such as HTTP and TLS expect the client to send the first message; use HTTP or HTTPS to see such an exchange.")]
        r.add(m)
    }
}

// ---------------------------------------------------------------- TLS record decoding
func tlsVer(_ v: Int) -> String {
    switch v { case 0x0300: return "SSL 3.0"; case 0x0301: return "TLS 1.0"; case 0x0302: return "TLS 1.1"; case 0x0303: return "TLS 1.2"; case 0x0304: return "TLS 1.3"
    default: return trHex(UInt32(v)) }
}
func tlsSuite(_ id: Int) -> String {
    switch id {
    case 0x1301: return "TLS_AES_128_GCM_SHA256"; case 0x1302: return "TLS_AES_256_GCM_SHA384"; case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256"
    case 0xC02B: return "ECDHE_ECDSA_AES_128_GCM_SHA256"; case 0xC02C: return "ECDHE_ECDSA_AES_256_GCM_SHA384"
    case 0xC02F: return "ECDHE_RSA_AES_128_GCM_SHA256"; case 0xC030: return "ECDHE_RSA_AES_256_GCM_SHA384"
    case 0xCCA8: return "ECDHE_RSA_CHACHA20_POLY1305"; case 0xCCA9: return "ECDHE_ECDSA_CHACHA20_POLY1305"
    case 0x009C: return "RSA_AES_128_GCM_SHA256"; case 0x009D: return "RSA_AES_256_GCM_SHA384"
    case 0xC013: return "ECDHE_RSA_AES_128_CBC_SHA"; case 0xC014: return "ECDHE_RSA_AES_256_CBC_SHA"
    case 0xC027: return "ECDHE_RSA_AES_128_CBC_SHA256"; case 0xC028: return "ECDHE_RSA_AES_256_CBC_SHA384"
    case 0x002F: return "RSA_AES_128_CBC_SHA"; case 0x0035: return "RSA_AES_256_CBC_SHA"
    default: return "cipher suite " + trHex(UInt32(id))
    }
}
private struct TlsRd {
    let p: [UInt8]; let lo: Int, hi: Int; var o: Int; var ok = true
    init(_ p: [UInt8], _ lo: Int, _ n: Int) { self.p = p; self.lo = lo; self.hi = min(p.count, lo + n); self.o = lo }
    mutating func u(_ bytes: Int) -> Int {
        if o + bytes > hi { ok = false; o = hi; return 0 }
        var v = 0; for _ in 0..<bytes { v = (v << 8) | Int(p[o]); o += 1 }
        return v
    }
    mutating func skip(_ k: Int) { if o + k > hi { ok = false; o = hi } else { o += k } }
}
/// Names the TLS records in one flight and decodes the hello messages. `enc` remembers that this direction switched to encryption.
func tlsDescribe(_ d: [UInt8], _ enc: inout Bool, _ f: inout TrFields) -> String {
    var names: [String] = []; var encRecs = 0; var o = 0
    while o + 5 <= d.count {
        let type = Int(d[o]); let len = Int(d[o + 3]) << 8 | Int(d[o + 4])
        let bodyStart = o + 5, avail = max(0, min(len, d.count - bodyStart))
        var nm = ""
        if type == 20 { nm = "ChangeCipherSpec"; enc = true }
        else if type == 21 {
            nm = "Alert"
            if !enc && avail >= 2 { nm += d[bodyStart + 1] == 0 ? " (close notify)" : " (code \(d[bodyStart + 1])\(d[bodyStart] == 2 ? ", fatal" : ""))" }
        }
        else if type == 23 { encRecs += 1; nm = "encrypted record" }
        else if type == 22 && enc { nm = "Finished (encrypted)" }
        else if type == 22 {
            var p = 0
            while p + 4 <= avail {
                let ht = Int(d[bodyStart + p])
                let hl = Int(d[bodyStart + p + 1]) << 16 | Int(d[bodyStart + p + 2]) << 8 | Int(d[bodyStart + p + 3])
                var rd = TlsRd(d, bodyStart + p + 4, min(hl, avail - p - 4))
                var hn: String
                switch ht {
                case 1: hn = "ClientHello"; case 2: hn = "ServerHello"; case 4: hn = "NewSessionTicket"; case 11: hn = "Certificate"
                case 12: hn = "ServerKeyExchange"; case 13: hn = "CertificateRequest"; case 14: hn = "ServerHelloDone"
                case 16: hn = "ClientKeyExchange"; case 20: hn = "Finished"; case 22: hn = "CertificateStatus"
                default: hn = "handshake message \(ht)"
                }
                if ht == 1 {
                    let ver = rd.u(2); rd.skip(32); rd.skip(rd.u(1))
                    let cs = rd.u(2); rd.skip(cs); rd.skip(rd.u(1))
                    let el = rd.u(2); let end = min(rd.hi, rd.o + el)
                    var sni = "", alpn = "", vers = ""
                    while rd.ok && rd.o + 4 <= end {
                        let et = rd.u(2); let xl = rd.u(2)
                        var x = TlsRd(d, rd.o, xl); rd.skip(xl)
                        if et == 0 { x.skip(2); x.skip(1); let l = x.u(2); if x.ok && x.o + l <= x.hi { sni = String(decoding: d[x.o..<(x.o + l)], as: UTF8.self) } }
                        else if et == 16 { x.skip(2); while x.ok && x.o < x.hi { let l = x.u(1); if x.o + l > x.hi { break }; if !alpn.isEmpty { alpn += ", " }; alpn += String(decoding: d[x.o..<(x.o + l)], as: UTF8.self); x.skip(l) } }
                        else if et == 43 { let l = x.u(1); var i = 0; while i + 1 < l && x.ok { let v = x.u(2); i += 2; if v & 0x0f0f == 0x0a0a { continue }; if !vers.isEmpty { vers += ", " }; vers += tlsVer(v) } }
                    }
                    f.append(("ClientHello", "offers \(cs / 2) cipher suites" + (vers.isEmpty ? ", version " + tlsVer(ver) : ", versions " + vers)))
                    if !sni.isEmpty { f.append(("server name (SNI)", sni + "  — sent unencrypted")) }
                    if !alpn.isEmpty { f.append(("application protocols (ALPN)", alpn)) }
                }
                if ht == 2 {
                    var ver = rd.u(2); rd.skip(32); rd.skip(rd.u(1))
                    let suite = rd.u(2); rd.skip(1)
                    let el = rd.u(2); let end = min(rd.hi, rd.o + el)
                    while rd.ok && rd.o + 4 <= end {
                        let et = rd.u(2); let xl = rd.u(2)
                        if et == 43 && xl == 2 { var x = TlsRd(d, rd.o, xl); ver = x.u(2) }
                        rd.skip(xl)
                    }
                    f.append(("ServerHello", "server chose " + tlsVer(ver) + " with " + tlsSuite(suite)))
                }
                if !nm.isEmpty { nm += ", " }
                nm += hn
                p += 4 + hl
            }
            if nm.isEmpty { nm = "handshake (continued)" }
        }
        else { nm = "record type \(type)" }
        if type != 23 { names.append(nm) }
        f.append(("record", "\(nm) · \(len) bytes"))
        o += 5 + len
    }
    if encRecs > 0 { names.append("\(encRecs) encrypted record" + (encRecs > 1 ? "s" : "")) }
    var t = names.joined(separator: ", ")
    if t.isEmpty { t = trBytes(Double(d.count)) }
    f.append(("size", trBytes(Double(d.count))))
    return t
}

// ---------------------------------------------------------------- TLS over Network.framework, with the records kept visible
/// A pass-through framer placed BELOW TLS in the protocol stack: it sees every byte of the handshake and of the
/// encrypted records in both directions, and hands them on untouched. macOS's own TLS does the cryptography.
final class TlsPeek: NWProtocolFramerImplementation {
    static let label = "MatrixSysTlsPeek"
    static let definition = NWProtocolFramer.Definition(implementation: TlsPeek.self)
    static let reg = NSLock()
    static var sink: ((Bool, [UInt8]) -> Void)?       // (inbound, bytes)
    static var onStart: (() -> Void)?
    private let sink: ((Bool, [UInt8]) -> Void)?
    private let onStart: (() -> Void)?
    init(framer: NWProtocolFramer.Instance) {
        TlsPeek.reg.lock(); sink = TlsPeek.sink; onStart = TlsPeek.onStart; TlsPeek.reg.unlock()
    }
    func start(framer: NWProtocolFramer.Instance) -> NWProtocolFramer.StartResult { onStart?(); return .ready }
    func wakeup(framer: NWProtocolFramer.Instance) {}
    func stop(framer: NWProtocolFramer.Instance) -> Bool { true }
    func cleanup(framer: NWProtocolFramer.Instance) {}
    func handleInput(framer: NWProtocolFramer.Instance) -> Int {
        while true {
            var got = 0
            let parsed = framer.parseInput(minimumIncompleteLength: 1, maximumLength: 65535) { buf, _ in
                guard let buf = buf, !buf.isEmpty else { return 0 }
                got = buf.count
                self.sink?(true, Array(UnsafeRawBufferPointer(buf)))
                return 0                                    // looked at, not consumed: TLS still gets every byte
            }
            if !parsed || got == 0 { return 0 }
            if !framer.deliverInputNoCopy(length: got, message: NWProtocolFramer.Message(instance: framer), isComplete: false) { return 0 }
        }
    }
    func handleOutput(framer: NWProtocolFramer.Instance, message: NWProtocolFramer.Message, messageLength: Int, isComplete: Bool) {
        var left = messageLength
        while left > 0 {
            var chunk: [UInt8] = []
            let parsed = framer.parseOutput(minimumIncompleteLength: 1, maximumLength: left) { buf, _ in
                guard let buf = buf, !buf.isEmpty else { return 0 }
                chunk = Array(UnsafeRawBufferPointer(buf))
                return buf.count
            }
            if !parsed || chunk.isEmpty { break }
            sink?(false, chunk)
            framer.writeOutput(data: Data(chunk))
            left -= chunk.count
        }
    }
}

/// Everything the trace needs from one connection, plain or TLS.
final class TrIo {
    var s: Int32 = -1                      // plain TCP
    var conn: NWConnection? = nil          // TLS
    var tls = false
    var wireIn = 0, wireOut = 0
    let lock = NSLock()
    var pend: [(inb: Bool, b: [UInt8], t: Double)] = []      // handshake chunks in the order they crossed the wire
    var rx: [UInt8] = []
    var closed = false, ready = false
    var failure: String? = nil
    var tcpAt: Double? = nil
    var sawRecords = false
    func close() {
        if s >= 0 { Darwin.close(s); s = -1 }
        if let c = conn { c.forceCancel(); conn = nil }
        TlsPeek.reg.lock(); TlsPeek.sink = nil; TlsPeek.onStart = nil; TlsPeek.reg.unlock()
    }
}

private func certValues(_ c: SecCertificate, _ oids: [CFString]) -> [CFString: Any] {
    guard let d = SecCertificateCopyValues(c, oids as CFArray, nil) as? [CFString: Any] else { return [:] }
    return d
}
private func certDate(_ c: SecCertificate, _ oid: CFString) -> String {
    guard let e = certValues(c, [oid])[oid] as? [CFString: Any], let v = e[kSecPropertyKeyValue] as? NSNumber else { return "" }
    let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; f.timeZone = TimeZone(identifier: "UTC")
    return f.string(from: Date(timeIntervalSinceReferenceDate: v.doubleValue))
}
private func certSANs(_ c: SecCertificate) -> [String] {
    guard let e = certValues(c, [kSecOIDSubjectAltName])[kSecOIDSubjectAltName] as? [CFString: Any],
          let list = e[kSecPropertyKeyValue] as? [[CFString: Any]] else { return [] }
    var out: [String] = []
    for item in list {
        let label = item[kSecPropertyKeyLabel] as? String ?? ""
        if label == "DNS Name" || label == "dNSName", let v = item[kSecPropertyKeyValue] as? String { out.append(v) }
    }
    return out
}
private func certName(_ c: SecCertificate) -> String { (SecCertificateCopySubjectSummary(c) as String?) ?? "certificate" }

/// Opens a TLS connection, recording each flight of records, then what the handshake produced.
/// The trace continues even when the certificate is not trusted, so that you can see what the server answers;
/// it says so in the message, and MatrixSys only ever sends a plain GET over it.
func trTls(_ r: TrRun, _ node: Int, _ io: TrIo, _ host: String, _ ip: String, _ port: Int, _ phase: Int) -> String? {
    let q = DispatchQueue(label: "matrixsys.trace.tls")
    var certs: [SecCertificate] = []
    var verdict = "not checked", trusted = false

    TlsPeek.reg.lock()
    TlsPeek.onStart = { io.lock.lock(); if io.tcpAt == nil { io.tcpAt = r.now() }; io.lock.unlock() }
    TlsPeek.sink = { inbound, bytes in
        io.lock.lock()
        io.pend.append((inbound, bytes, nowSec()))
        if inbound { io.wireIn += bytes.count } else { io.wireOut += bytes.count }
        io.sawRecords = true
        io.lock.unlock()
    }
    TlsPeek.reg.unlock()

    let tlsOpts = NWProtocolTLS.Options()
    let sec = tlsOpts.securityProtocolOptions
    sec_protocol_options_set_tls_server_name(sec, host)
    sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
    sec_protocol_options_set_verify_block(sec, { _, trustRef, complete in
        let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
        var err: CFError?
        trusted = SecTrustEvaluateWithError(trust, &err)
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] { certs = chain }
        if trusted { verdict = "trusted by macOS for " + host }
        else {
            let d = (err as Error?)?.localizedDescription ?? "the certificate could not be verified"
            verdict = "NOT TRUSTED: " + d
        }
        complete(true)      // a diagnostic tool: it shows what the server says, and reports the verdict above
    }, q)

    let tcpOpts = NWProtocolTCP.Options(); tcpOpts.connectionTimeout = 8; tcpOpts.noDelay = true
    let params = NWParameters(tls: tlsOpts, tcp: tcpOpts)
    params.defaultProtocolStack.applicationProtocols.append(NWProtocolFramer.Options(definition: TlsPeek.definition))   // below TLS

    let conn = NWConnection(host: NWEndpoint.Host(ip), port: NWEndpoint.Port(rawValue: UInt16(port))!, using: params)
    io.conn = conn; io.tls = true
    r.gate()
    let t0 = r.now()
    conn.stateUpdateHandler = { st in
        io.lock.lock()
        switch st {
        case .ready: io.ready = true
        case .failed(let e): io.failure = e.localizedDescription; io.closed = true
        case .cancelled: io.closed = true
        default: break
        }
        io.lock.unlock()
    }
    conn.start(queue: q)

    var encC = false, encS = false
    /// A flight ends when the other side starts talking, or when this side has been quiet for a moment.
    /// Each flight is published in the order it crossed the wire.
    func flush(_ force: Bool) {
        io.lock.lock()
        var runs: [(Bool, [UInt8], Double)] = []
        while !io.pend.isEmpty {
            let dir = io.pend[0].inb
            var k = 0
            while k < io.pend.count && io.pend[k].inb == dir { k += 1 }
            let closed = k < io.pend.count                       // the direction turned round: that flight is over
            if !closed && !force && nowSec() - io.pend[k - 1].t < 0.04 { break }
            var bytes: [UInt8] = []; let t = io.pend[0].t
            for i in 0..<k { bytes += io.pend[i].b }
            io.pend.removeFirst(k)
            runs.append((dir, bytes, t))
        }
        io.lock.unlock()
        for (inb, bytes, t) in runs {
            var m = trMk(max(0, t - r.t0 - r.held), inb ? node : 0, inb ? 0 : node, inb ? TK.tlss : TK.tlsc, phase, !inb, "")
            var enc = inb ? encS : encC
            m.title = (inb ? "TLS ← " : "TLS → ") + tlsDescribe(bytes, &enc, &m.f)
            if inb { encS = enc } else { encC = enc }
            m.raw = bytes
            r.add(m)
        }
    }

    var sawTcp = false
    let deadline = nowSec() + 15
    while nowSec() < deadline {
        io.lock.lock(); let ready = io.ready, fail = io.failure, tcpAt = io.tcpAt; io.lock.unlock()
        if !sawTcp, let ta = tcpAt {
            sawTcp = true
            let ms = (ta - t0) * 1000
            var m = trMk(t0, 0, node, TK.syn, phase, true, "TCP SYN → \(ip):\(port)  (open a connection)")
            m.f = [("to", "\(ip):\(port)"), ("note", "Timed by the networking stack; the handshake packets themselves are not captured by this trace.")]
            let qi = r.add(m)
            var a = trMk(ta, node, 0, TK.synack, phase, false, "TCP SYN/ACK — port \(port) is open, connected in " + trMs(ms), qi, ms)
            a.f = [("time to connect", trMs(ms))]
            r.add(a)
        }
        flush(false)
        if ready || fail != nil { break }
        if !r.ok { break }
        usleep(15000)
    }
    flush(true)
    io.lock.lock(); let ready = io.ready, fail = io.failure, saw = io.sawRecords; io.lock.unlock()
    if !ready { return fail ?? "the TLS handshake did not complete within 15 s" }

    var m = trMk(r.now(), node, node, TK.info, phase, false, "")
    var proto = "TLS", suite = ""
    if let md = conn.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata {
        let s = md.securityProtocolMetadata
        let v = Int(sec_protocol_metadata_get_negotiated_tls_protocol_version(s).rawValue)
        let c = Int(sec_protocol_metadata_get_negotiated_tls_ciphersuite(s).rawValue)
        proto = tlsVer(v); suite = tlsSuite(c)
        m.f.append(("protocol", proto))
        m.f.append(("cipher suite", suite))
        let kx = suite.hasPrefix("TLS_AES") || suite.hasPrefix("TLS_CHACHA") ? "ECDHE — TLS 1.3 always uses forward secrecy"
               : suite.hasPrefix("ECDHE") ? "ECDHE — forward secrecy" : suite.hasPrefix("RSA") ? "RSA — no forward secrecy" : "not reported"
        m.f.append(("key exchange", kx))
        if let alpn = sec_protocol_metadata_get_negotiated_protocol(s) { m.f.append(("application protocol (ALPN)", String(cString: alpn))) }
    }
    var subj = ""
    if let leaf = certs.first {
        subj = certName(leaf)
        m.f.append(("certificate issued to", subj))
        if certs.count > 1 { m.f.append(("issued by", certName(certs[1]))) }
        let nb = certDate(leaf, kSecOIDX509V1ValidityNotBefore), na = certDate(leaf, kSecOIDX509V1ValidityNotAfter)
        if !nb.isEmpty || !na.isEmpty {
            let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; f.timeZone = TimeZone(identifier: "UTC")
            let today = f.string(from: Date())
            m.f.append(("valid", "\(nb) to \(na)" + (na < today && !na.isEmpty ? "  — EXPIRED" : nb > today && !nb.isEmpty ? "  — not valid yet" : "")))
        }
        let sans = certSANs(leaf)
        if !sans.isEmpty { m.f.append(("covers the names", sans.prefix(12).joined(separator: ", ") + (sans.count > 12 ? "  (+\(sans.count - 12) more)" : ""))) }
        m.f.append(("chain of trust", certs.map { certName($0) }.joined(separator: "  ←  ")))
    } else {
        m.f.append(("certificate", "the chain was not handed to this trace"))
    }
    m.f.append(("verdict", verdict))
    m.f.append(("note", "The trace continues even when the certificate is not trusted, so that you can see what the server answers. A browser would stop here. MatrixSys only sends a plain GET."))
    if !saw { m.f.append(("records", "The raw handshake records were not visible on this connection; the figures above come from the TLS stack itself.")) }
    m.title = "Secure channel ready — " + proto + (subj.isEmpty ? "" : ", certificate for " + subj) + (trusted ? " (trusted)" : " — NOT TRUSTED")
    m.ms = trusted ? 1 : 0
    r.add(m)
    return nil
}

// ---------------------------------------------------------------- reading and writing, plain or through TLS
private func tlsPump(_ io: TrIo) {
    guard let c = io.conn else { return }
    c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, err in
        io.lock.lock()
        if let d = data, !d.isEmpty { io.rx += [UInt8](d) }
        if isComplete || err != nil { io.closed = true }
        let again = !io.closed
        io.lock.unlock()
        if again { tlsPump(io) }
    }
}
func ioSend(_ io: TrIo, _ s: String) -> Bool {
    let d = Array(s.utf8)
    if !io.tls { io.wireOut += d.count; return sockWrite(io.s, d) }
    guard let c = io.conn else { return false }
    let sem = DispatchSemaphore(value: 0); var ok = true
    c.send(content: Data(d), completion: .contentProcessed { e in ok = e == nil; sem.signal() })
    _ = sem.wait(timeout: .now() + 10)
    return ok
}
/// >0 bytes appended, 0 closed by the peer, -1 nothing within the timeout.
func ioRecv(_ io: TrIo, _ out: inout [UInt8], _ ms: Int) -> Int {
    if !io.tls {
        let n = sockRead(io.s, &out, ms)
        if n > 0 { io.wireIn += n }
        return n
    }
    let deadline = nowSec() + Double(ms) / 1000
    while nowSec() < deadline {
        io.lock.lock()
        if !io.rx.isEmpty { let d = io.rx; io.rx = []; io.lock.unlock(); out += d; return d.count }
        let done = io.closed
        io.lock.unlock()
        if done { return 0 }
        usleep(10000)
    }
    return -1
}

// ---------------------------------------------------------------- HTTP
struct TrHttp { var status = 0; var location = "" }
func trHttpExchange(_ r: TrRun, _ node: Int, _ io: TrIo, _ host: String, _ port: Int, _ path: String, _ tls: Bool, _ phase: Int, _ res: inout TrHttp) -> Bool {
    if io.tls { tlsPump(io) }
    let hostHdr = host + (port != (tls ? 443 : 80) ? ":\(port)" : "")
    let hd: TrFields = [("Host", hostHdr), ("User-Agent", "MatrixSys/1.0 (route and protocol trace)"),
                        ("Accept", "*/*"), ("Accept-Encoding", "identity"), ("Connection", "close")]
    var req = "GET \(path) HTTP/1.1\r\n"
    for h in hd { req += "\(h.0): \(h.1)\r\n" }
    req += "\r\n"
    r.gate()
    let w0 = io.wireOut
    let t = r.now()
    let sent = ioSend(io, req)
    var q = trMk(t, 0, node, TK.httpq, phase, true, "HTTP request: GET " + path)
    q.f.append(("request line", "GET \(path) HTTP/1.1"))
    for h in hd { q.f.append(h) }
    q.f.append(("on the wire", tls ? "encrypted inside TLS, " + trBytes(Double(max(0, io.wireOut - w0))) + " (shown here before encryption)"
                                   : "plain text, " + trBytes(Double(req.utf8.count)) + " — readable by every hop on the way"))
    q.raw = Array(req.utf8)
    let qi = r.add(q)
    if !sent { r.add(trMk(r.now(), node, node, TK.lost, phase, false, "The request could not be sent (connection lost)", qi)); return false }

    let CAP = 512 * 1024
    var buf = [UInt8]()
    let wi0 = io.wireIn
    var tFirst = -1.0, closed = false, complete = false, cut = false, chunked = false
    var hdrEnd = -1
    var clen = -1
    while r.ok {
        let n = ioRecv(io, &buf, buf.isEmpty ? 10000 : 4000)
        if n > 0 && tFirst < 0 { tFirst = r.now() }
        if n == 0 { closed = true; break }
        if n < 0 { break }
        if hdrEnd < 0 {
            var i = 0
            while i + 3 < buf.count { if buf[i] == 13 && buf[i+1] == 10 && buf[i+2] == 13 && buf[i+3] == 10 { hdrEnd = i; break }; i += 1 }
            if hdrEnd >= 0 {
                // header by header: a CRLF is one Character in Swift, so searching for a leading "\n" never matches
                for line in String(decoding: buf[0..<hdrEnd], as: UTF8.self).components(separatedBy: "\r\n").dropFirst() {
                    guard let c = line.firstIndex(of: ":") else { continue }
                    let k = line[..<c].lowercased(), v = line[line.index(after: c)...].trimmingCharacters(in: .whitespaces).lowercased()
                    if k == "content-length" { clen = Int(v) ?? -1 }
                    if k == "transfer-encoding" && v.contains("chunked") { chunked = true }
                }
            }
        }
        if hdrEnd >= 0 {
            let body = buf.count - hdrEnd - 4
            if clen >= 0 && body >= clen { complete = true; break }
            if chunked && buf.count >= 5 && Array(buf.suffix(5)) == [48, 13, 10, 13, 10] { complete = true; break }
        }
        if buf.count > CAP { cut = true; break }
    }
    let t2 = tFirst < 0 ? r.now() : tFirst
    if buf.isEmpty {
        r.add(trMk(t2, node, node, TK.lost, phase, false, closed ? "The server closed the connection without answering" : "No HTTP response within 10 s", qi))
        return false
    }
    if hdrEnd < 0 || buf.count < 5 || Array(buf.prefix(5)) != Array("HTTP/".utf8) {
        var m = trMk(t2, node, 0, TK.banner, phase, false, "The reply is not HTTP (" + trBytes(Double(buf.count)) + ")", qi, (t2 - t) * 1000)
        m.body = trText(buf, 2000); m.raw = buf
        r.add(m)
        return false
    }
    let head = String(decoding: buf[0..<hdrEnd], as: UTF8.self)
    var m = trMk(t2, node, 0, TK.httpr, phase, false, "", qi, (t2 - t) * 1000)
    var statusLine = "", ctype = ""
    for (i, lineS) in head.components(separatedBy: "\r\n").enumerated() {
        let line = lineS
        if i == 0 {
            statusLine = line
            let parts = line.split(separator: " ")
            res.status = parts.count > 1 ? Int(parts[1]) ?? 0 : 0
            m.f.append(("status", line)); continue
        }
        guard let c = line.firstIndex(of: ":") else { continue }
        let k = String(line[..<c]); let v = String(line[line.index(after: c)...]).trimmingCharacters(in: .whitespaces)
        m.f.append((k, v))
        let lk = k.lowercased()
        if lk == "location" { res.location = v }
        if lk == "content-type" { ctype = v }
        if lk == "content-security-policy" { m.csp += (m.csp.isEmpty ? "" : ", ") + v }
    }
    var body = Array(buf[(hdrEnd + 4)...])
    if chunked {   // undo the chunked framing so the body reads as the page it is
        var de = [UInt8](); var p = 0
        while p < body.count {
            var e = p
            while e + 1 < body.count && !(body[e] == 13 && body[e + 1] == 10) { e += 1 }
            if e + 1 >= body.count { break }
            let sz = Int(String(decoding: body[p..<e], as: UTF8.self).trimmingCharacters(in: .whitespaces), radix: 16) ?? 0
            p = e + 2
            if sz == 0 { break }
            let take = min(sz, body.count - p)
            de += body[p..<(p + take)]
            p += take + 2
        }
        body = de
    }
    let lct = ctype.lowercased()
    var texty = ["text", "json", "xml", "javascript", "html"].contains { lct.contains($0) }
    if !texty && !body.isEmpty {
        let n = min(body.count, 512); var pr = 0
        for i in 0..<n where body[i] >= 32 || body[i] == 10 || body[i] == 13 || body[i] == 9 { pr += 1 }
        texty = pr * 100 >= n * 95
    }
    if texty { m.body = trText(body, 8000) }
    if !body.isEmpty && (lct.contains("html") || (ctype.isEmpty && body[0] == 60)) {
        m.page = String(decoding: body, as: UTF8.self); m.ctype = ctype
        m.url = (tls ? "https://" : "http://") + hostHdr + path
    }
    m.f.append(("body", body.isEmpty ? "empty" : trBytes(Double(body.count))
        + (texty ? "" : " of binary data (not shown as text)")
        + (body.count > 8000 && texty ? ", first 8000 characters shown" : "")
        + (cut ? " — download stopped at 512 KB" : !complete && !closed ? " — incomplete (the server stopped sending)" : "")))
    m.f.append(("time to first byte", trMs((t2 - t) * 1000)))
    m.f.append(("on the wire", tls ? "encrypted inside TLS, " + trBytes(Double(max(0, io.wireIn - wi0))) + " (shown here after decryption)"
                                   : "plain text, " + trBytes(Double(buf.count))))
    let ct = ctype.split(separator: ";").first.map(String.init) ?? ""
    m.title = statusLine + (ct.isEmpty ? "" : " · " + ct) + (body.isEmpty ? "" : " · " + trBytes(Double(body.count)))
            + (res.status >= 300 && res.status < 400 && !res.location.isEmpty ? "  → " + res.location : "")
    m.raw = buf
    r.add(m)
    return true
}

// ---------------------------------------------------------------- the whole run
private func trLocalAddr(_ dst: String) -> String {
    let u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if u < 0 { return "" }
    defer { close(u) }
    guard var a = sa4(dst, 53) else { return "" }
    if withUnsafePointer(to: &a, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(u, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }) != 0 { return "" }
    var l = sockaddr_in(); var ll = socklen_t(MemoryLayout<sockaddr_in>.size)
    if withUnsafeMutablePointer(to: &l, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(u, $0, &ll) } }) != 0 { return "" }
    return ip4str(l.sin_addr)
}

func trRun(_ gen: Int, _ input: String, _ protoSel: Int, _ live: Bool) {
    let r = TrRun(gen, live)
    let (tg, perr) = trParse(input, protoSel)
    func finish(_ e: String) {
        r.set { t in t.err = e; t.running = false; t.status = e.isEmpty ? "done" : "stopped"; t.took = r.now() }
    }
    if let e = perr { finish(e); return }
    var hn = [CChar](repeating: 0, count: 256); gethostname(&hn, 256)
    let myName = String(cString: hn)
    r.set { t in
        t.proto = tg.proto; t.port = tg.port; t.host = tg.host; t.path = tg.path
        var me = TrNode(); me.kind = TN.me; me.name = myName
        t.nodes.append(me); t.chain = [0]; t.status = "resolving the name"
    }
    func setLocal(_ dst: String) { let ip = trLocalAddr(dst); if !ip.isEmpty { r.set { t in t.nodes[0].ip = ip } } }

    if tg.proto == TP.dns {
        var srv = ""
        if !tg.server.isEmpty {
            var sip = "", e = ""
            if !trResolve(r, tg.server, 0, &sip, &e, alsoV6: false) { finish("DNS server \(tg.server): \(e)"); return }
            srv = sip
        } else {
            let sv = trDnsServers()
            srv = sv.first(where: { !$0.contains(":") }) ?? sv.first ?? ""
        }
        if srv.isEmpty { finish("No DNS server is configured on this Mac."); return }
        let node = r.addNode(TN.dns, srv, tg.server.isEmpty ? "DNS server" : tg.server)
        if !srv.contains(":") {
            setLocal(srv)
            r.set { t in t.status = "tracing the route to the DNS server " + srv }
            trRoute(r, srv, node)
        } else { r.link(0, node) }
        r.set { t in t.status = "asking the DNS server" }
        if validIp(tg.host) && !tg.host.contains(":") {
            let p = tg.host.split(separator: ".")
            if p.count == 4 {
                let rev = "\(p[3]).\(p[2]).\(p[1]).\(p[0]).in-addr.arpa"
                var dm = DnsMsg(); trDnsQuery(r, node, srv, rev, 12, 2, &dm)
            }
        } else {
            for ty in [1, 28, 5, 15, 2, 16, 6] {
                if !r.ok { break }
                var dm = DnsMsg()
                if !trDnsQuery(r, node, srv, tg.host, ty, 2, &dm) { break }
                if dm.rcode == 3 { break }
            }
        }
        finish(""); return
    }

    var ip = "", err = ""
    if !trResolve(r, tg.host, 0, &ip, &err) { finish(err); return }
    if !r.ok { return }
    setLocal(ip)
    let literal = ip == tg.host
    let target = r.addNode(TN.target, ip, literal ? "" : tg.host)
    r.set { t in t.status = "tracing the route to " + ip }
    trRoute(r, ip, target)
    if !r.ok { return }

    if tg.proto == TP.icmp {
        r.set { t in t.status = "pinging " + ip }
        guard let sock = IcmpSock() else { finish("This Mac refused an ICMP socket."); return }
        defer { sock.close() }
        var got = 0; var mn = 1e9, mx = 0.0, sum = 0.0
        for i in 0..<4 {
            if !r.ok { break }
            r.gate()
            let t = r.now()
            let h = trProbeOne(sock, ip, 64, UInt16(900 + i), 2000)
            var q = trMk(t, 0, target, TK.echoq, 2, true, "ICMP echo request #\(i + 1) → " + ip)
            q.f = [("payload", "32 bytes"), ("TTL", "64")]
            let qi = r.add(q)
            if h.got && h.status == 0 {
                got += 1; mn = min(mn, h.ms); mx = max(mx, h.ms); sum += h.ms
                var a = trMk(t + h.ms / 1000, target, 0, TK.echor, 2, false,
                             "Echo reply #\(i + 1) in " + trMs(h.ms) + (h.rttl > 0 ? "  (TTL \(h.rttl))" : ""), qi, h.ms)
                a.f = [("round trip", trMs(h.ms))]
                if h.rttl > 0 {
                    a.f.append(("TTL of the reply", "\(h.rttl)" + (h.rttl > 128 ? " — started at 255 (typical for network equipment)"
                        : h.rttl > 64 ? " — started at 128 (typical for Windows)" : " — started at 64 (typical for Linux, macOS, phones)")))
                }
                r.add(a)
            } else {
                r.add(trMk(r.now(), target, target, TK.lost, 2, false, "Echo request #\(i + 1): " + icmpText(h.status, h.code), qi))
            }
            usleep(250000)
        }
        var s = trMk(r.now(), target, target, TK.info, 2, false,
            "Ping summary: 4 sent, \(got) answered" + (got > 0 ? ", " + trMs(mn) + " / " + trMs(sum / Double(got)) + " / " + trMs(mx) + " (min / avg / max)" : ""))
        s.ms = got > 0 ? 1 : 0
        r.add(s)
        finish(""); return
    }

    if tg.proto == TP.tcp {
        r.set { t in t.status = "connecting to \(ip):\(tg.port)" }
        let s = trConnect(r, target, ip, tg.port, 2)
        if s >= 0 {
            trBanner(r, target, s, tg.port, 2)
            r.gate()
            let t = r.now()
            close(s)
            r.add(trMk(t, 0, target, TK.fin, 2, true, "TCP FIN — this Mac closes the connection"))
        }
        finish(""); return
    }

    // HTTP / HTTPS, following redirects
    var host = tg.host, path = tg.path, port = tg.port, node = target, tls = tg.proto == TP.https, cip = ip
    for step in 0..<6 {
        if !r.ok { break }
        r.set { t in t.status = (tls ? "HTTPS" : "HTTP") + " exchange with " + host }
        let io = TrIo()
        var ok = true
        if tls {
            if let e = trTls(r, node, io, host, cip, port, 2) {
                ok = false
                r.add(trMk(r.now(), node, node, TK.lost, 2, false, "TLS failed: " + e))
            }
        } else {
            io.s = trConnect(r, node, cip, port, 2)
            if io.s < 0 { io.close(); break }
        }
        var h = TrHttp()
        if ok { ok = trHttpExchange(r, node, io, host, port, path, tls, 2, &h) }
        r.gate()
        let tf = r.now()
        io.close()
        r.add(trMk(tf, 0, node, TK.fin, 2, true, "TCP FIN — connection closed"))
        if !ok || h.status < 300 || h.status >= 400 || h.location.isEmpty { break }
        if step == 5 { r.add(trMk(r.now(), node, node, TK.info, 2, false, "Stopped after 5 redirects")); break }
        var loc = h.location, nh = host, np = port
        var ntls = tls
        if let sc = loc.range(of: "://") {
            let s = loc[..<sc.lowerBound].lowercased()
            if s != "http" && s != "https" { break }
            ntls = s == "https"; loc = String(loc[sc.upperBound...])
            var hp = loc
            if let sl = loc.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
                hp = String(loc[..<sl]); path = loc[sl] == "/" ? String(loc[sl...]) : "/" + String(loc[sl...])
            } else { path = "/" }
            np = ntls ? 443 : 80
            if let at = hp.lastIndex(of: "@") { hp = String(hp[hp.index(after: at)...]) }
            if let col = hp.lastIndex(of: ":"), !hp.contains("]") { np = Int(hp[hp.index(after: col)...]) ?? np; hp = String(hp[..<col]) }
            nh = hp.lowercased()
        } else if loc.hasPrefix("/") { path = loc }
        else {
            let base = path.split(separator: "?").first.map(String.init) ?? path
            let dir = base.lastIndex(of: "/").map { String(base[..<base.index(after: $0)]) } ?? "/"
            path = dir + loc
        }
        if let hs = path.firstIndex(of: "#") { path = String(path[..<hs]) }
        if np <= 0 || np > 65535 || nh.isEmpty { break }
        if nh != host {
            var nip = "", e = ""
            if !trResolve(r, nh, 2, &nip, &e) {
                r.add(trMk(r.now(), node, node, TK.info, 2, false, "The redirect target cannot be resolved: " + e)); break
            }
            if nip != cip {
                node = r.addNode(TN.target, nip, nh)
                r.link(0, node)
                let n2 = node
                r.set { t in if t.nodes[n2].note.isEmpty && n2 != target { t.nodes[n2].note = "Reached through a redirect. The route to it was not traced hop by hop." } }
                cip = nip
            }
        }
        host = nh; port = np; tls = ntls
    }
    finish("")
}

func traceStart(_ input: String, _ proto: Int, live: Bool = false) {
    let gen = TrShared.i.begin(input, live)
    Thread { trRun(gen, input, proto, live) }.start()
}
func traceStop() { TrShared.i.stop() }
