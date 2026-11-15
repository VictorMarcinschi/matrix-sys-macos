// LAN view: every machine on the local networks this Mac is attached to — found passively from the ARP/NDP table and
// from the multicast announcements already on the wire, or actively with an ICMP sweep and a TCP connect scan when you
// ask for one. Names come from reverse DNS, mDNS (Bonjour), NetBIOS and SSDP; the gateway is additionally asked the
// one thing routers answer by a standard: UPnP IGD.
//
// Nothing here runs on its own. The passive listener only reads what is already being broadcast; the sweep, the scan
// and the router query each need a button press, and each says beforehand how many packets it is about to send.
import Foundation
import Darwin

// ================================================================ model

let LAN_OPEN = 0, LAN_CLOSED = 1, LAN_FILTERED = 2

struct LanPort {
    var port = 0, state = LAN_FILTERED
    var banner = "", server = ""
    var ms = 0.0
}

/// One machine. Hosts persist for the life of the app once seen, so the scene does not flicker when an ARP entry
/// expires; `lastSeen` is what the view fades on.
struct LanHost {
    var ip = "", mac = "", ifn = ""
    var vendor = "", rdns = "", mdns = "", nbns = "", ssdpName = "", ssdpModel = ""
    var services: [String] = []
    var gw = false, me = false, randomMac = false
    var firstSeen = 0.0, lastSeen = 0.0, arpAt = 0.0
    var ports: [LanPort] = []
    var snmp = SnmpInfo()
    var fromRouter = false       // learned from the gateway's own ARP table, not from ours
    var scanState = 0            // 0 never scanned, 1 running, 2 finished
    var scanDone = 0, scanTotal = 0, scanAt = 0.0
    var replied = false          // answered an ICMP echo in the last sweep

    /// The best label this host has earned. Never invented: an address when nothing else is known.
    var label: String {
        for c in [mdns, ssdpName, nbns, snmp.name, rdns] where !c.isEmpty && c != "-" { return c }
        return ip
    }
    var named: Bool { label != ip }
    var openPorts: [LanPort] { ports.filter { $0.state == LAN_OPEN }.sorted { $0.port < $1.port } }
}

struct LanIf {
    var name = "", ip = "", mask = ""
    var cidr = 0, hosts = 0
    var net: UInt32 = 0, bcast: UInt32 = 0
    var display = ""
    var cidrText: String { "\(ipFromU32(net))/\(cidr)" }
}

/// What a router told us through UPnP IGD. Everything optional: most of it is missing on most routers.
struct LanRouter {
    var queried = false, ok = false
    var at = 0.0
    var friendlyName = "", model = "", manufacturer = "", serial = ""
    var location = "", controlURL = "", service = ""
    var externalIP = "", status = "", uptime = ""
    var linkUp = "", downRate = "", upRate = ""
    var maps: [String] = []
    var note = ""
}

final class LanSnap {
    var hosts: [LanHost] = []
    var ifs: [LanIf] = []
    var t = 0.0
    var router = LanRouter()
    var busy = ""          // what is running right now, for the panel
    var progress = 0.0     // 0..1 of that
    var lastSweep = 0.0, sweepSent = 0
    var listening = false
}
var LN: LanSnap? = nil

func ipToU32(_ s: String) -> UInt32 {
    var a = in_addr()
    guard inet_pton(AF_INET, s, &a) == 1 else { return 0 }
    return UInt32(bigEndian: a.s_addr)
}
func ipFromU32(_ v: UInt32) -> String {
    "\((v >> 24) & 255).\((v >> 16) & 255).\((v >> 8) & 255).\(v & 255)"
}

/// The networks this Mac is on: IPv4, up, not loopback, not point-to-point, with a netmask we can enumerate.
func lanInterfaces() -> [LanIf] {
    var out: [LanIf] = []
    var ap: UnsafeMutablePointer<ifaddrs>? = nil
    guard getifaddrs(&ap) == 0, let first = ap else { return out }
    defer { freeifaddrs(ap) }
    var p: UnsafeMutablePointer<ifaddrs>? = first
    while let cur = p {
        defer { p = cur.pointee.ifa_next }
        guard let sa = cur.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET) else { continue }
        let flags = Int32(cur.pointee.ifa_flags)
        if flags & IFF_UP == 0 || flags & IFF_LOOPBACK != 0 || flags & IFF_POINTOPOINT != 0 { continue }
        let name = String(cString: cur.pointee.ifa_name)
        let ip = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ip4str($0.pointee.sin_addr) }
        guard let mp = cur.pointee.ifa_netmask else { continue }
        let mask = mp.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ip4str($0.pointee.sin_addr) }
        let mv = ipToU32(mask), iv = ipToU32(ip)
        if mv == 0 || iv == 0 || ip.hasPrefix("169.254.") { continue }
        var i = LanIf()
        i.name = name; i.ip = ip; i.mask = mask
        i.cidr = mv.nonzeroBitCount
        i.net = iv & mv
        i.bcast = i.net | ~mv
        i.hosts = i.cidr >= 31 ? 0 : Int(~mv) - 1
        i.display = name
        out.append(i)
    }
    return out
}

// ================================================================ the collector

final class Lan {
    static let shared = Lan()
    var wanted = false { didSet { if wanted && !started { started = true; Thread { self.loop() }.start(); Thread { self.listen() }.start() } } }
    private var started = false
    private let lock = NSLock()
    private var hosts: [String: LanHost] = [:]
    private var snap: LanSnap? = nil
    private var router = LanRouter()
    private var busy = "", progress = 0.0
    private var lastSweep = 0.0, sweepSent = 0
    private var working = false
    private var listening = false
    private var cancelFlag = false

    func latest() -> LanSnap? { lock.lock(); defer { lock.unlock() }; return snap }
    func isBusy() -> Bool { lock.lock(); defer { lock.unlock() }; return working }
    func cancel() { lock.lock(); cancelFlag = true; lock.unlock() }
    private func cancelled() -> Bool { lock.lock(); defer { lock.unlock() }; return cancelFlag }

    private func edit(_ ip: String, _ fn: (inout LanHost) -> Void) {
        lock.lock()
        var h = hosts[ip] ?? { var n = LanHost(); n.ip = ip; n.firstSeen = nowSec(); return n }()
        fn(&h)
        hosts[ip] = h
        lock.unlock()
    }
    private func setBusy(_ s: String, _ p: Double) { lock.lock(); busy = s; progress = p; lock.unlock() }

    // ---- the 1 s loop: merge the ARP/NDP table, keep names topped up, publish a snapshot
    private func loop() {
        var lastNames = -100.0
        while true {
            if !wanted { usleep(400000); continue }
            let ifs = lanInterfaces()
            let gws = Devices.shared.gateways()
            let gwIps = Set(gws.map { $0.0 })
            let mine = Set(ifs.map { $0.ip })

            for i in ifs {
                edit(i.ip) { h in
                    h.me = true; h.ifn = i.name; h.lastSeen = nowSec()
                    if h.mac.isEmpty { h.mac = macOf(i.name) }
                }
            }
            for (ip, mac, ifn) in Devices.shared.neighbours() where !ip.contains(":") {
                edit(ip) { h in
                    h.mac = mac; h.ifn = ifn; h.arpAt = nowSec(); h.lastSeen = nowSec()
                    h.randomMac = macIsRandom(mac)
                    h.vendor = h.randomMac ? "" : ouiVendor(mac)
                    h.gw = gwIps.contains(ip)
                }
            }
            for (ip, ifn) in gws where !ip.contains(":") {
                edit(ip) { h in h.gw = true; if h.ifn.isEmpty { h.ifn = ifn }; h.lastSeen = max(h.lastSeen, nowSec()) }
            }

            // reverse DNS for everything on screen, through the cache that already exists
            if nowSec() - lastNames > 4 {
                lastNames = nowSec()
                lock.lock(); let ips = Array(hosts.keys); lock.unlock()
                for ip in ips {
                    let nm = DNS.shared.lookup(ip)
                    if !nm.isEmpty { edit(ip) { h in h.rdns = (nm == "-" || nm == ip) ? "" : nm } }
                }
            }

            let s = LanSnap()
            lock.lock()
            s.t = nowSec(); s.ifs = ifs; s.router = router; s.busy = busy; s.progress = progress
            s.lastSweep = lastSweep; s.sweepSent = sweepSent; s.listening = listening
            s.hosts = hosts.values.sorted { ipToU32($0.ip) < ipToU32($1.ip) }
            for i in s.hosts.indices where mine.contains(s.hosts[i].ip) { s.hosts[i].me = true }
            snap = s
            lock.unlock()
            usleep(900000)
        }
    }

    // ---- passive: read the multicast announcements already on the wire. Sends nothing but the group joins.
    private func listen() {
        let m = udpListener(port: 5353, group: "224.0.0.251")
        let s = udpListener(port: 1900, group: "239.255.255.250")
        lock.lock(); listening = m >= 0 || s >= 0; lock.unlock()
        if m < 0 && s < 0 { return }
        var buf = [UInt8](repeating: 0, count: 9000)
        while true {
            if !wanted { usleep(500000); continue }
            var fds = [pollfd]()
            if m >= 0 { fds.append(pollfd(fd: m, events: Int16(POLLIN), revents: 0)) }
            if s >= 0 { fds.append(pollfd(fd: s, events: Int16(POLLIN), revents: 0)) }
            if poll(&fds, UInt32(fds.count), 500) <= 0 { continue }
            for f in fds where f.revents & Int16(POLLIN) != 0 {
                var src = sockaddr_in(); var sl = socklen_t(MemoryLayout<sockaddr_in>.size)
                let n = withUnsafeMutablePointer(to: &src) { sp in
                    sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(f.fd, &buf, buf.count, 0, $0, &sl) }
                }
                if n <= 0 { continue }
                let from = ip4str(src.sin_addr)
                let d = Array(buf[0..<n])
                if f.fd == m { absorbMdns(d, from) } else { absorbSsdp(d, from) }
            }
        }
    }

    /// mDNS answers name hosts without asking anything: an A record maps a .local name to an address, a PTR names a
    /// service on it. Only records about addresses on our own networks are kept.
    private func absorbMdns(_ d: [UInt8], _ from: String) {
        guard let msg = dnsParse(d) else { return }
        var aNames: [String: String] = [:]      // ip -> name
        var svcs: [String] = []
        for r in msg.rr {
            switch r.type {
            case 1: if validIp(r.val) { aNames[r.val] = r.name }
            case 12:
                if r.name.hasSuffix(".in-addr.arpa") {
                    let parts = r.name.dropLast(13).split(separator: ".").reversed().map(String.init)
                    if parts.count == 4 { aNames[parts.joined(separator: ".")] = r.val }
                } else if r.name.hasPrefix("_") {
                    let t = String(r.name.split(separator: ".").first ?? "")
                    if !t.isEmpty && !svcs.contains(t) { svcs.append(t) }
                }
            default: break
            }
        }
        func clean(_ s: String) -> String {
            var n = s
            if n.hasSuffix(".") { n.removeLast() }
            if n.hasSuffix(".local") { n.removeLast(6) }
            return n
        }
        for (ip, name) in aNames {
            let c = clean(name)
            if c.isEmpty { continue }
            edit(ip) { h in h.mdns = c; h.lastSeen = nowSec() }
        }
        if !svcs.isEmpty {
            edit(from) { h in
                h.lastSeen = nowSec()
                for s in svcs where !h.services.contains(s) { h.services.append(s) }
            }
        }
    }

    /// An SSDP NOTIFY or an M-SEARCH answer. The SERVER header is a free model string; LOCATION points at the
    /// description, which is fetched only for the gateway and only when you ask.
    private func absorbSsdp(_ d: [UInt8], _ from: String) {
        let txt = String(decoding: d, as: UTF8.self)
        var server = "", location = ""
        for line in txt.split(separator: "\r\n") {
            let l = line.lowercased()
            if l.hasPrefix("server:") { server = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            if l.hasPrefix("location:") { location = String(line.dropFirst(9)).trimmingCharacters(in: .whitespaces) }
        }
        if server.isEmpty && location.isEmpty { return }
        edit(from) { h in
            h.lastSeen = nowSec()
            if h.ssdpModel.isEmpty && !server.isEmpty { h.ssdpModel = server }
            if !h.services.contains("_upnp") { h.services.append("_upnp") }
        }
    }

    // ---- active: ICMP sweep of one interface's subnet, then re-read the ARP table
    func sweep(_ ifn: String) {
        guard !isBusy() else { return }
        lock.lock(); working = true; cancelFlag = false; lock.unlock()
        Thread {
            defer { self.lock.lock(); self.working = false; self.busy = ""; self.lock.unlock() }
            self.sweepBody(ifn)
        }.start()
    }
    private func sweepBody(_ ifn: String) {
        do {
            guard let i = lanInterfaces().first(where: { $0.name == ifn }) else { return }
            if i.hosts <= 0 || i.hosts > LAN_SWEEP_MAX {
                toast("Refusing to sweep \(i.cidrText): \(i.hosts) addresses (limit \(LAN_SWEEP_MAX))", .warn)
                return
            }
            guard let s = IcmpSock() else { toast("Cannot open an ICMP socket", .warn); return }
            defer { s.close() }
            self.setBusy("sweeping \(i.cidrText)", 0)
            var sent = 0
            let base = i.net, total = i.hosts
            // one echo per address, paced so the send buffer never overflows; replies are drained as we go
            for k in 1...total {
                if self.cancelled() { break }
                let a = base + UInt32(k)
                if a == i.bcast { continue }
                let ip = ipFromU32(a)
                if s.sendEcho(ip, seq: UInt16(k & 0xffff)) { sent += 1 }
                if k % 16 == 0 {
                    self.setBusy("sweeping \(i.cidrText)", Double(k) / Double(total) * 0.8)
                    while let rx = s.recvOne(1) { self.noteReply(rx.from) }
                }
                usleep(1500)
            }
            // the hosts that answer slowest are the ones worth waiting for
            let deadline = nowSec() + 2.0
            while nowSec() < deadline && !self.cancelled() {
                self.setBusy("listening for replies", 0.8 + (1 - (deadline - nowSec()) / 2.0) * 0.2)
                if let rx = s.recvOne(120) { self.noteReply(rx.from) }
            }
            self.lock.lock(); self.lastSweep = nowSec(); self.sweepSent = sent; self.lock.unlock()
            // A host that ignores the ping still had to answer the ARP request before it could be sent, so the ARP
            // table now holds its MAC: presence at layer 2 is the evidence, not the echo reply.
            let arp = Devices.shared.neighbours()
            var found = 0
            for (ip, mac, nm) in arp where !ip.contains(":") {
                let known: Bool = { self.lock.lock(); defer { self.lock.unlock() }; return self.hosts[ip]?.arpAt ?? 0 > 0 }()
                if !known { found += 1 }
                self.edit(ip) { h in
                    h.mac = mac; h.ifn = nm; h.arpAt = nowSec(); h.lastSeen = nowSec()
                    h.randomMac = macIsRandom(mac); h.vendor = h.randomMac ? "" : ouiVendor(mac)
                }
            }
            toast("Sweep of \(i.cidrText): \(sent) probes sent, \(arp.filter { !$0.0.contains(":") }.count) hosts in the ARP table" + (found > 0 ? ", \(found) new" : ""), .safe)
        }
    }
    private func noteReply(_ ip: String) {
        if ip.isEmpty { return }
        edit(ip) { h in h.replied = true; h.lastSeen = nowSec() }
    }

    // ---- active: TCP connect scan of one host
    func scan(_ ip: String, _ ports: [Int], banners: Bool = true) {
        guard !isBusy() else { return }
        lock.lock(); working = true; cancelFlag = false; lock.unlock()
        // A big range needs more sockets in flight and a shorter wait, or it takes twenty minutes. On a LAN the
        // round trip is under a few ms, so 600 ms is still many times what an answer needs.
        let (parallel, timeout) = lanScanPace(ports.count)
        raiseFdLimit(parallel * 2 + 256)
        Thread {
            defer { self.lock.lock(); self.working = false; self.busy = ""; self.lock.unlock() }
            self.edit(ip) { h in h.scanState = 1; h.scanDone = 0; h.scanTotal = ports.count; h.ports = []; h.scanAt = nowSec() }
            var done = 0
            let t0 = nowSec()
            for batch in stride(from: 0, to: ports.count, by: parallel) {
                if self.cancelled() { break }
                let slice = Array(ports[batch..<min(batch + parallel, ports.count)])
                let res = tcpConnectBatch(ip, slice, timeoutMs: timeout)
                for var r in res {
                    if r.state == LAN_OPEN && banners {
                        (r.banner, r.server) = lanBanner(ip, r.port)
                    }
                    self.edit(ip) { h in h.ports.append(r) }
                }
                done += slice.count
                self.edit(ip) { h in h.scanDone = done }
                let frac = Double(done) / Double(ports.count)
                var msg = "scanning \(ip) · \(done) of \(ports.count)"
                if frac > 0.02 {
                    let left = (nowSec() - t0) / frac * (1 - frac)
                    if left > 20 { msg += " · about \(Int(left / 60) + 1) min left" }
                }
                self.setBusy(msg, frac)
            }
            self.edit(ip) { h in h.scanState = 2; h.scanDone = done }
            let open: Int = { self.lock.lock(); defer { self.lock.unlock() }; return self.hosts[ip]?.openPorts.count ?? 0 }()
            toast("\(ip): \(open) open of \(done) ports tried", open > 0 ? .safe : .dim)
        }.start()
    }

    // ---- the one thing routers answer by a standard
    func queryRouter(_ ip: String) {
        guard !isBusy() else { return }
        lock.lock(); working = true; cancelFlag = false; router = LanRouter(); router.queried = true; lock.unlock()
        Thread {
            defer { self.lock.lock(); self.working = false; self.busy = ""; self.lock.unlock() }
            self.setBusy("asking \(ip) over UPnP", 0.1)
            var r = upnpQuery(ip) { p, s in self.setBusy(s, p) }
            r.queried = true; r.at = nowSec()
            self.lock.lock(); self.router = r; self.lock.unlock()
            toast(r.ok ? "\(ip) answered UPnP: " + (r.friendlyName.isEmpty ? r.model : r.friendlyName) : "No UPnP answer from \(ip)", r.ok ? .safe : .warn)
        }.start()
    }

    /// SNMP read-only, and then the part no other source can give: the agent's own ARP table, which lists
    /// machines it has seen even when this Mac never has.
    func querySnmp(_ ip: String) {
        guard !isBusy() else { return }
        lock.lock(); working = true; cancelFlag = false; lock.unlock()
        let community = snmpCommunity(), port = snmpPort(), v3 = snmpV3Configured()
        Thread {
            defer { self.lock.lock(); self.working = false; self.busy = ""; self.lock.unlock() }
            let info = snmpQuery(ip, community: community, port: port, v3: v3) { p, s in self.setBusy(s, p) }
            self.edit(ip) { h in h.snmp = info }
            guard info.ok else { toast("No SNMP answer from \(ip) with community \"\(community)\"", .warn); return }
            var added = 0
            let mine = Set(lanInterfaces().map { $0.ip })
            for (addr, mac) in info.arp where validIp(addr) && !isLoop(addr) && !mine.contains(addr) {
                let known: Bool = { self.lock.lock(); defer { self.lock.unlock() }; return self.hosts[addr] != nil }()
                if !known { added += 1 }
                self.edit(addr) { h in
                    if h.mac.isEmpty { h.mac = mac }
                    if h.ifn.isEmpty { h.ifn = lanInterfaces().first?.name ?? "" }
                    h.randomMac = macIsRandom(mac)
                    if h.vendor.isEmpty && !h.randomMac { h.vendor = ouiVendor(mac) }
                    if !known { h.fromRouter = true; h.lastSeen = nowSec() }
                }
            }
            toast("\(ip): " + (info.name.isEmpty ? info.descr.prefix(40).description : info.name)
                  + " · \(info.ifs.count) interfaces · \(info.arp.count) in its ARP table"
                  + (added > 0 ? ", \(added) new here" : ""), .safe)
        }.start()
    }

    func wake(_ mac: String) {
        let parts = mac.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard parts.count == 6 else { toast("Not a MAC address: " + mac, .warn); return }
        var pkt = [UInt8](repeating: 0xFF, count: 6)
        for _ in 0..<16 { pkt += parts }
        var ok = false
        for target in ["255.255.255.255"] + lanInterfaces().map({ ipFromU32($0.bcast) }) {
            let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            if s < 0 { continue }
            var on: Int32 = 1
            setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, 4)
            for port: UInt16 in [9, 7] {
                guard var a = sa4(target, port) else { continue }
                let n = pkt.withUnsafeBytes { b in withUnsafePointer(to: &a) { ap in ap.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(s, b.baseAddress, pkt.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } }
                if n == pkt.count { ok = true }
            }
            Darwin.close(s)
        }
        toast(ok ? "Wake-on-LAN packet sent to " + mac : "Could not send the wake packet", ok ? .safe : .warn)
    }

    /// Every host at once, one query each, on a worker so the view keeps drawing. This is what makes the list
    /// readable: the passive listener only hears the machines that announce themselves.
    func askAllNames(_ thenSweepFirst: String = "") {
        guard !isBusy() else { return }
        lock.lock(); working = true; cancelFlag = false; lock.unlock()
        Thread {
            defer { self.lock.lock(); self.working = false; self.busy = ""; self.lock.unlock() }
            if !thenSweepFirst.isEmpty { self.sweepBody(thenSweepFirst) }
            self.lock.lock(); let ips = self.hosts.values.filter { !$0.me }.map { $0.ip }; self.lock.unlock()
            var found = 0
            for (i, ip) in ips.enumerated() {
                if self.cancelled() { break }
                self.setBusy("asking \(ip) for its name", Double(i) / Double(max(1, ips.count)))
                let md = mdnsReverse(ip)
                if !md.isEmpty { self.edit(ip) { h in h.mdns = md }; found += 1; continue }
                let nb = nbnsName(ip)
                if !nb.isEmpty { self.edit(ip) { h in h.nbns = nb }; found += 1 }
            }
            toast("\(found) of \(ips.count) machines answered with a name", found > 0 ? .safe : .dim)
        }.start()
    }

    /// NetBIOS and mDNS asked of one host directly, for a name the passive listener never heard.
    func askName(_ ip: String) {
        Thread {
            let nb = nbnsName(ip)
            if !nb.isEmpty { self.edit(ip) { h in h.nbns = nb } }
            let md = mdnsReverse(ip)
            if !md.isEmpty { self.edit(ip) { h in h.mdns = md } }
            if nb.isEmpty && md.isEmpty { toast("No name from \(ip) (mDNS, NetBIOS)", .dim) } else { toast("\(ip) is " + (md.isEmpty ? nb : md), .safe) }
        }.start()
    }
}

/// How hard to push a scan, by how much of the port space it covers. Small lists stay slow and careful; a full
/// 65535-port sweep of one machine on your own LAN gets the wide, short-timeout treatment or it is unusable.
func lanScanPace(_ count: Int) -> (parallel: Int, timeoutMs: Int) {
    if count <= 256 { return (LAN_SCAN_PARALLEL, LAN_SCAN_TIMEOUT_MS) }
    if count <= 4096 { return (160, 700) }
    return (320, 600)
}

/// A wide scan wants more open descriptors than the default soft limit allows. Raised only towards the hard limit,
/// which needs no privilege; if the system refuses, the scan still runs, just with fewer sockets in flight.
func raiseFdLimit(_ want: Int) {
    var r = rlimit()
    guard getrlimit(RLIMIT_NOFILE, &r) == 0 else { return }
    let target = rlim_t(want)
    if r.rlim_cur >= target { return }
    r.rlim_cur = min(r.rlim_max, max(target, r.rlim_cur))
    setrlimit(RLIMIT_NOFILE, &r)
}

// ================================================================ limits, deliberately low

let LAN_SWEEP_MAX = 1024              // /22. A wider subnet is refused rather than flooded.
let LAN_SCAN_PARALLEL = 48
let LAN_SCAN_TIMEOUT_MS = 900

/// Ports worth trying on a home or office network, including the ones a router's own admin interfaces sit on.
let LAN_PORTS_COMMON: [Int] = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 427, 443, 445, 465,
    500, 515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1080, 1433, 1521, 1723, 1883, 1900, 2049, 2082, 2083,
    2181, 2375, 3000, 3128, 3306, 3389, 3478, 3689, 4444, 4500, 5000, 5001, 5060, 5222, 5353, 5357, 5432, 5555,
    5683, 5900, 5901, 6000, 6379, 6443, 6668, 7000, 7547, 8000, 8008, 8009, 8080, 8081, 8088, 8123, 8181, 8200, 8291, 8443, 8554, 8883,
    8728, 8888, 9000, 9090, 9100, 9200, 10000, 11211, 27017, 32400, 49152, 62078]
let LAN_PORTS_ADMIN: [Int] = [22, 23, 80, 443, 7547, 8080, 8291, 8443, 8728, 8729, 10000, 161, 1900, 5000, 49152]
/// Every well-known port. A device that listens at all usually listens here.
let LAN_PORTS_LOW: [Int] = Array(1...1023)
/// Everything. The only way to find a listener on a port nobody would guess, which is where consumer IoT often is.
let LAN_PORTS_ALL: [Int] = Array(1...65535)
func lanPortSet(_ name: String) -> [Int] {
    switch name {
    case "admin": return LAN_PORTS_ADMIN
    case "low": return LAN_PORTS_LOW
    case "full": return LAN_PORTS_ALL
    default: return LAN_PORTS_COMMON
    }
}

// ================================================================ MAC addresses

/// The second-least-significant bit of the first octet marks a locally administered address. iOS and Android set it
/// for their per-network private addresses, so the MAC says nothing about the hardware and will change.
func macIsRandom(_ mac: String) -> Bool {
    guard let f = mac.split(separator: ":").first, let b = UInt8(f, radix: 16) else { return false }
    return b & 0x02 != 0
}
func macOf(_ ifn: String) -> String {
    var ap: UnsafeMutablePointer<ifaddrs>? = nil
    guard getifaddrs(&ap) == 0 else { return "" }
    defer { freeifaddrs(ap) }
    var p = ap
    while let cur = p {
        defer { p = cur.pointee.ifa_next }
        guard String(cString: cur.pointee.ifa_name) == ifn, let sa = cur.pointee.ifa_addr,
              sa.pointee.sa_family == sa_family_t(AF_LINK) else { continue }
        return sa.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { dl -> String in
            let n = Int(dl.pointee.sdl_alen), off = Int(dl.pointee.sdl_nlen)
            guard n == 6 else { return "" }
            return withUnsafeBytes(of: dl.pointee.sdl_data) { b in
                (0..<6).map { String(format: "%02x", b[off + $0]) }.joined(separator: ":")
            }
        }
    }
    return ""
}

/// Vendor names come from a table generated at build time by scripts/make_oui.sh. When it is not bundled, the OUI is
/// shown as the raw prefix and no vendor is claimed.
final class Oui {
    static let shared = Oui()
    private var map: [String: String] = [:]
    private var loaded = false, present = false
    private let lock = NSLock()
    var bundled: Bool { lock.lock(); defer { lock.unlock() }; load(); return present }
    private func load() {
        if loaded { return }
        loaded = true
        guard let p = Bundle.main.path(forResource: "oui", ofType: "txt"),
              let txt = try? String(contentsOfFile: p, encoding: .utf8) else { return }
        for line in txt.split(separator: "\n") {
            let f = line.split(separator: "\t", maxSplits: 1)
            if f.count == 2 { map[String(f[0]).uppercased()] = String(f[1]) }
        }
        present = !map.isEmpty
    }
    func vendor(_ mac: String) -> String {
        lock.lock(); defer { lock.unlock() }
        load()
        let hex = mac.split(separator: ":").joined().uppercased()
        guard hex.count >= 6 else { return "" }
        return map[String(hex.prefix(6))] ?? ""
    }
}
func ouiVendor(_ mac: String) -> String { Oui.shared.vendor(mac) }
func ouiPrefix(_ mac: String) -> String { mac.split(separator: ":").prefix(3).joined(separator: ":").uppercased() }

// ================================================================ TCP connect scan

/// One batch of non-blocking connects. Open, closed (the host answered with a reset) and filtered (silence) are the
/// three states the kernel can actually distinguish, and the three this reports.
func tcpConnectBatch(_ ip: String, _ ports: [Int], timeoutMs: Int) -> [LanPort] {
    var fds: [Int32] = [], out: [LanPort] = [], pending: [Int: Int] = [:]   // fd index -> port
    let t0 = nowSec()
    for port in ports {
        let s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        if s < 0 { out.append(LanPort(port: port, state: LAN_FILTERED)); continue }
        var fl = fcntl(s, F_GETFL, 0); fl |= O_NONBLOCK; _ = fcntl(s, F_SETFL, fl)
        var nosig: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &nosig, 4)
        guard var a = sa4(ip, UInt16(port)) else { Darwin.close(s); out.append(LanPort(port: port, state: LAN_FILTERED)); continue }
        let r = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        if r == 0 {
            out.append(LanPort(port: port, state: LAN_OPEN, ms: (nowSec() - t0) * 1000))
            Darwin.close(s); continue
        }
        if errno != EINPROGRESS {
            out.append(LanPort(port: port, state: errno == ECONNREFUSED ? LAN_CLOSED : LAN_FILTERED))
            Darwin.close(s); continue
        }
        pending[fds.count] = port
        fds.append(s)
    }
    var settled = Set<Int>()
    let deadline = nowSec() + Double(timeoutMs) / 1000
    while settled.count < fds.count && nowSec() < deadline {
        var ps: [pollfd] = []
        var idx: [Int] = []
        for (k, fd) in fds.enumerated() where !settled.contains(k) {
            ps.append(pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)); idx.append(k)
        }
        if ps.isEmpty { break }
        let left = Int32(max(1, (deadline - nowSec()) * 1000))
        if poll(&ps, UInt32(ps.count), left) <= 0 { break }
        for (j, p) in ps.enumerated() where p.revents != 0 {
            let k = idx[j]
            settled.insert(k)
            var err: Int32 = 0, l = socklen_t(4)
            getsockopt(fds[k], SOL_SOCKET, SO_ERROR, &err, &l)
            let port = pending[k] ?? 0
            if err == 0 { out.append(LanPort(port: port, state: LAN_OPEN, ms: (nowSec() - t0) * 1000)) }
            else if err == ECONNREFUSED { out.append(LanPort(port: port, state: LAN_CLOSED)) }
            else { out.append(LanPort(port: port, state: LAN_FILTERED)) }
        }
    }
    for (k, fd) in fds.enumerated() {
        if !settled.contains(k) { out.append(LanPort(port: pending[k] ?? 0, state: LAN_FILTERED)) }
        Darwin.close(fd)
    }
    return out
}

/// Router pages like to write their own title as numeric character references. Decoded here so the panel shows the
/// text and not the escapes; nothing else about the page is interpreted.
func htmlUnescape(_ s: String) -> String {
    guard s.contains("&") else { return s }
    var out = "", i = s.startIndex
    while i < s.endIndex {
        guard s[i] == "&", let semi = s[i...].firstIndex(of: ";"), s.distance(from: i, to: semi) <= 10 else {
            out.append(s[i]); i = s.index(after: i); continue
        }
        let body = String(s[s.index(after: i)..<semi])
        var rep: Character? = nil
        if body.hasPrefix("#x") || body.hasPrefix("#X") {
            if let v = UInt32(body.dropFirst(2), radix: 16), let u = Unicode.Scalar(v) { rep = Character(u) }
        } else if body.hasPrefix("#") {
            if let v = UInt32(body.dropFirst()), let u = Unicode.Scalar(v) { rep = Character(u) }
        } else {
            rep = ["amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'", "nbsp": " "][body.lowercased()]
        }
        if let r = rep { out.append(r); i = s.index(after: semi) } else { out.append(s[i]); i = s.index(after: i) }
    }
    return out
}

/// What is listening, from the server itself: the greeting of a protocol that speaks first, or the Server header of
/// an HTTP answer. Nothing is sent but a plain GET, and only to a port that is already open.
func lanBanner(_ ip: String, _ port: Int) -> (String, String) {
    let s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    if s < 0 { return ("", "") }
    defer { Darwin.close(s) }
    var fl = fcntl(s, F_GETFL, 0); fl |= O_NONBLOCK; _ = fcntl(s, F_SETFL, fl)
    var nosig: Int32 = 1
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &nosig, 4)
    guard var a = sa4(ip, UInt16(port)) else { return ("", "") }
    _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    if !waitWrite(s, 800) { return ("", "") }
    var err: Int32 = 0, l = socklen_t(4)
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &l)
    if err != 0 { return ("", "") }
    var buf: [UInt8] = []
    // a server that speaks first says so within a moment; otherwise ask, but only in HTTP
    if sockRead(s, &buf, 700) > 0 {
        return (trText(buf, 180).trimmingCharacters(in: .whitespacesAndNewlines), "")
    }
    if port == 443 || port == 8443 || port == 993 || port == 995 || port == 465 { return ("TLS — the Trace tab decodes this handshake", "") }
    let req = "GET / HTTP/1.0\r\nHost: \(ip)\r\nUser-Agent: MatrixSys\r\nConnection: close\r\n\r\n"
    if !sockWrite(s, Array(req.utf8)) { return ("", "") }
    var t = 0
    while buf.count < 4096 && t < 1200 {
        let n = sockRead(s, &buf, 300)
        if n <= 0 { break }
        t += 300
    }
    if buf.isEmpty { return ("", "") }
    let txt = String(decoding: buf.prefix(4096), as: UTF8.self)
    var server = "", title = ""
    for line in txt.split(separator: "\r\n") {
        let low = line.lowercased()
        if low.hasPrefix("server:") { server = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
        if low.hasPrefix("www-authenticate:") && server.isEmpty { server = String(line.dropFirst(17)).trimmingCharacters(in: .whitespaces) }
    }
    if let a = txt.range(of: "<title>", options: .caseInsensitive), let b = txt.range(of: "</title>", options: .caseInsensitive, range: a.upperBound..<txt.endIndex) {
        title = htmlUnescape(String(txt[a.upperBound..<b.lowerBound])).trimmingCharacters(in: .whitespacesAndNewlines)
    }
    let first = txt.split(separator: "\r\n").first.map(String.init) ?? ""
    return ((title.isEmpty ? first : title).prefix(180).description, server)
}

// ================================================================ UDP helpers and name probes

/// A socket bound to a multicast port, sharing it with whatever already has it (mDNSResponder has 5353).
func udpListener(port: UInt16, group: String) -> Int32 {
    let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    if s < 0 { return -1 }
    var on: Int32 = 1
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, 4)
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, 4)
    var a = sockaddr_in()
    a.sin_family = sa_family_t(AF_INET); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    a.sin_port = port.bigEndian; a.sin_addr.s_addr = INADDR_ANY.bigEndian
    let ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    if ok != 0 { Darwin.close(s); return -1 }
    for i in lanInterfaces() {
        var mr = ip_mreq()
        inet_pton(AF_INET, group, &mr.imr_multiaddr)
        inet_pton(AF_INET, i.ip, &mr.imr_interface)
        setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, socklen_t(MemoryLayout<ip_mreq>.size))
    }
    return s
}

/// One UDP question, one answer, no state kept.
func udpAsk(_ ip: String, _ port: UInt16, _ payload: [UInt8], _ timeoutMs: Int, multicast: Bool = false) -> [UInt8]? {
    let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    if s < 0 { return nil }
    defer { Darwin.close(s) }
    if multicast { var ttl: UInt8 = 1; setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1) }
    var on: Int32 = 1
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, 4)
    guard var a = sa4(ip, port) else { return nil }
    let sent = payload.withUnsafeBytes { b in withUnsafePointer(to: &a) { ap in ap.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        sendto(s, b.baseAddress, payload.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } }
    if sent != payload.count { return nil }
    if !waitRead(s, timeoutMs) { return nil }
    var buf = [UInt8](repeating: 0, count: 9000)
    let n = recv(s, &buf, buf.count, 0)
    return n > 0 ? Array(buf[0..<n]) : nil
}

/// A NetBIOS node status request: the one question a Windows or Samba machine answers with its own name.
func nbnsName(_ ip: String) -> String {
    var q: [UInt8] = [0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
    // first-level encoding of "*" padded with nulls, suffix 0x00
    var name = [UInt8](repeating: 0, count: 16); name[0] = 0x2A
    q.append(32)
    for b in name { q.append(0x41 + (b >> 4)); q.append(0x41 + (b & 0x0F)) }
    q.append(0)
    q += [0x00, 0x21, 0x00, 0x01]        // NBSTAT, IN
    guard let d = udpAsk(ip, 137, q, 900), d.count > 56 else { return "" }
    var o = 12
    while o < d.count && d[o] != 0 { o += Int(d[o]) + 1 }   // the echoed name
    o += 1 + 4 + 4                                          // null, type/class, ttl
    guard o + 3 <= d.count else { return "" }
    o += 2                                                  // rdlength
    let count = Int(d[o]); o += 1
    var best = ""
    for _ in 0..<count {
        guard o + 18 <= d.count else { break }
        let raw = String(decoding: d[o..<(o + 15)], as: UTF8.self).trimmingCharacters(in: .whitespaces)
        let suffix = d[o + 15], flags = Int(d[o + 16]) << 8 | Int(d[o + 17])
        let group = flags & 0x8000 != 0
        if suffix == 0x00 && !group && !raw.isEmpty && best.isEmpty { best = raw }
        o += 18
    }
    return best
}

/// A reverse PTR asked over multicast DNS: how a Mac, an iPhone or anything else running Bonjour names itself.
func mdnsReverse(_ ip: String) -> String {
    let parts = ip.split(separator: ".").reversed().map(String.init)
    guard parts.count == 4 else { return "" }
    let qname = parts.joined(separator: ".") + ".in-addr.arpa"
    var q = dnsBuild(0, qname, 12)
    q[0] = 0; q[1] = 0; q[2] = 0; q[3] = 0        // mDNS: id 0, no recursion desired
    guard let d = udpAsk("224.0.0.251", 5353, q, 1200, multicast: true), let m = dnsParse(d) else { return "" }
    for r in m.rr where r.type == 12 {
        var n = r.val
        if n.hasSuffix(".") { n.removeLast() }
        if n.hasSuffix(".local") { n.removeLast(6) }
        if !n.isEmpty { return n }
    }
    return ""
}

// ================================================================ UPnP IGD — the one standard a router answers

private func xmlTag(_ s: String, _ tag: String) -> String {
    guard let a = s.range(of: "<\(tag)", options: .caseInsensitive),
          let gt = s.range(of: ">", range: a.upperBound..<s.endIndex),
          let b = s.range(of: "</\(tag)>", options: .caseInsensitive, range: gt.upperBound..<s.endIndex) else { return "" }
    return String(s[gt.upperBound..<b.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
}

/// A minimal HTTP/1.0 request over a plain socket. Used for the device description and the SOAP calls, both of which
/// are plain HTTP on the gateway by specification.
func lanHttp(_ ip: String, _ port: Int, _ method: String, _ path: String, _ headers: [String: String] = [:], _ body: String = "", timeoutMs: Int = 3000) -> (Int, String)? {
    let s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    if s < 0 { return nil }
    defer { Darwin.close(s) }
    var fl = fcntl(s, F_GETFL, 0); fl |= O_NONBLOCK; _ = fcntl(s, F_SETFL, fl)
    var nosig: Int32 = 1
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &nosig, 4)
    guard var a = sa4(ip, UInt16(port)) else { return nil }
    _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    if !waitWrite(s, min(2000, timeoutMs)) { return nil }
    var err: Int32 = 0, l = socklen_t(4)
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &l)
    if err != 0 { return nil }
    var req = "\(method) \(path) HTTP/1.0\r\nHost: \(ip):\(port)\r\nUser-Agent: MatrixSys\r\nConnection: close\r\n"
    for (k, v) in headers { req += "\(k): \(v)\r\n" }
    if !body.isEmpty { req += "Content-Length: \(body.utf8.count)\r\n" }
    req += "\r\n" + body
    if !sockWrite(s, Array(req.utf8)) { return nil }
    var buf: [UInt8] = []
    var waited = 0
    while buf.count < 262144 && waited < timeoutMs {
        let n = sockRead(s, &buf, 400)
        if n <= 0 { break }
        waited += 400
    }
    if buf.isEmpty { return nil }
    let txt = String(decoding: buf, as: UTF8.self)
    guard let sp = txt.range(of: "\r\n\r\n") else { return (0, txt) }
    let head = String(txt[txt.startIndex..<sp.lowerBound])
    let status = Int(head.split(separator: " ").dropFirst().first.map(String.init) ?? "") ?? 0
    return (status, String(txt[sp.upperBound...]))
}

private func parseUrl(_ u: String) -> (String, Int, String)? {
    guard u.lowercased().hasPrefix("http://") else { return nil }
    let rest = String(u.dropFirst(7))
    let slash = rest.firstIndex(of: "/")
    let hostPart = slash == nil ? rest : String(rest[rest.startIndex..<slash!])
    let path = slash == nil ? "/" : String(rest[slash!...])
    let hp = hostPart.split(separator: ":")
    let host = String(hp.first ?? "")
    let port = hp.count > 1 ? Int(hp[1]) ?? 80 : 80
    return host.isEmpty ? nil : (host, port, path)
}

/// SSDP discovery aimed at one address: three M-SEARCHes, answers collected for two seconds.
func ssdpSearch(_ ip: String, _ st: String, _ seconds: Double) -> [String] {
    let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    if s < 0 { return [] }
    defer { Darwin.close(s) }
    var ttl: UInt8 = 2
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1)
    let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: \(st)\r\n\r\n"
    let d = Array(msg.utf8)
    guard var a = sa4(ip, 1900) else { return [] }
    for _ in 0..<3 {
        _ = d.withUnsafeBytes { b in withUnsafePointer(to: &a) { ap in ap.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            sendto(s, b.baseAddress, d.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } }
        usleep(120000)
    }
    var out: [String] = []
    let deadline = nowSec() + seconds
    var buf = [UInt8](repeating: 0, count: 4096)
    while nowSec() < deadline {
        let left = Int((deadline - nowSec()) * 1000)
        if left <= 0 || !waitRead(s, min(600, left)) { continue }
        let n = recv(s, &buf, buf.count, 0)
        if n > 0 { out.append(String(decoding: buf[0..<n], as: UTF8.self)) }
    }
    return out
}

/// Asks the gateway what UPnP IGD defines: who it is, the WAN address and status, and the port mappings anything on
/// this network has opened. No credentials are involved; a router with UPnP off simply does not answer.
func upnpQuery(_ ip: String, _ note: @escaping (Double, String) -> Void) -> LanRouter {
    var r = LanRouter()
    note(0.15, "looking for a UPnP description on \(ip)")
    var location = ""
    for st in ["urn:schemas-upnp-org:device:InternetGatewayDevice:1", "upnp:rootdevice"] {
        for answer in ssdpSearch(ip, st, 2.2) {
            for line in answer.split(separator: "\r\n") where line.lowercased().hasPrefix("location:") {
                let v = String(line.dropFirst(9)).trimmingCharacters(in: .whitespaces)
                if let (h, _, _) = parseUrl(v), h == ip { location = v }
            }
            if !location.isEmpty { break }
        }
        if !location.isEmpty { break }
    }
    // some routers never answer a unicast M-SEARCH but serve the usual description paths
    var desc = ""
    if location.isEmpty {
        for (port, path) in [(49152, "/rootDesc.xml"), (5000, "/rootDesc.xml"), (80, "/rootDesc.xml"),
                             (49000, "/tr64desc.xml"), (49152, "/description.xml"), (80, "/description.xml"),
                             (1900, "/rootDesc.xml"), (2048, "/etc/linuxigd/gatedesc.xml")] {
            note(0.3, "trying \(ip):\(port)\(path)")
            if let (st, body) = lanHttp(ip, port, "GET", path, [:], "", timeoutMs: 1500), st == 200, body.contains("<device") {
                location = "http://\(ip):\(port)\(path)"; desc = body; break
            }
        }
    }
    guard !location.isEmpty, let (h, port, path) = parseUrl(location) else {
        r.note = "No UPnP description. The router either has UPnP off or does not implement it — neither is a fault."
        return r
    }
    r.location = location
    if desc.isEmpty {
        note(0.45, "reading the device description")
        guard let (st, body) = lanHttp(h, port, "GET", path), st == 200 else {
            r.note = "The description at \(location) could not be read."
            return r
        }
        desc = body
    }
    r.friendlyName = xmlTag(desc, "friendlyName")
    r.model = [xmlTag(desc, "modelName"), xmlTag(desc, "modelNumber")].filter { !$0.isEmpty }.joined(separator: " ")
    r.manufacturer = xmlTag(desc, "manufacturer")
    r.serial = xmlTag(desc, "serialNumber")
    r.ok = !r.friendlyName.isEmpty || !r.model.isEmpty

    // find the WAN connection service and its control URL
    var control = "", service = ""
    for want in ["WANIPConnection", "WANPPPConnection"] {
        guard let sr = desc.range(of: want) else { continue }
        let tail = String(desc[sr.lowerBound...])
        // the controlURL that follows this serviceType in the same <service> block
        if let cu = tail.range(of: "<controlURL>"), let ce = tail.range(of: "</controlURL>", range: cu.upperBound..<tail.endIndex) {
            control = String(tail[cu.upperBound..<ce.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
            service = "urn:schemas-upnp-org:service:\(want):" + (desc.contains("\(want):2") ? "2" : "1")
            break
        }
    }
    if control.isEmpty {
        r.note = "The router describes itself but exposes no WAN connection service, so there is no external address or port-mapping table to read."
        return r
    }
    if !control.hasPrefix("/") { control = "/" + control }
    r.controlURL = control; r.service = service

    func soap(_ action: String, _ args: String = "") -> String? {
        let body = "<?xml version=\"1.0\"?>\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:\(action) xmlns:u=\"\(service)\">\(args)</u:\(action)></s:Body></s:Envelope>"
        let hdr = ["Content-Type": "text/xml; charset=\"utf-8\"", "SOAPAction": "\"\(service)#\(action)\""]
        guard let (st, out) = lanHttp(h, port, "POST", control, hdr, body) else { return nil }
        return st == 200 ? out : nil
    }

    note(0.6, "asking for the WAN address")
    if let x = soap("GetExternalIPAddress") { r.externalIP = xmlTag(x, "NewExternalIPAddress") }
    if let x = soap("GetStatusInfo") {
        r.status = xmlTag(x, "NewConnectionStatus")
        if let up = Int(xmlTag(x, "NewUptime")) {
            let d = up / 86400, hh = (up % 86400) / 3600, mm = (up % 3600) / 60
            r.uptime = d > 0 ? "\(d)d \(hh)h \(mm)m" : "\(hh)h \(mm)m"
        }
    }
    if let x = soap("GetCommonLinkProperties") {
        r.linkUp = xmlTag(x, "NewPhysicalLinkStatus")
        if let d = Double(xmlTag(x, "NewLayer1DownstreamMaxBitRate")), d > 0 { r.downRate = fmtBits(d) }
        if let u = Double(xmlTag(x, "NewLayer1UpstreamMaxBitRate")), u > 0 { r.upRate = fmtBits(u) }
    }
    note(0.8, "reading the port-mapping table")
    for i in 0..<64 {
        guard let x = soap("GetGenericPortMappingEntry", "<NewPortMappingIndex>\(i)</NewPortMappingIndex>") else { break }
        let ext = xmlTag(x, "NewExternalPort"), proto = xmlTag(x, "NewProtocol")
        let host = xmlTag(x, "NewInternalClient"), inp = xmlTag(x, "NewInternalPort")
        if ext.isEmpty && host.isEmpty { break }
        let desc2 = xmlTag(x, "NewPortMappingDescription")
        let lease = xmlTag(x, "NewLeaseDuration")
        r.maps.append("\(proto) \(ext) → \(host):\(inp)" + (desc2.isEmpty ? "" : "  " + desc2) + (lease == "0" || lease.isEmpty ? "" : "  \(lease)s"))
    }
    r.ok = true
    if r.maps.isEmpty { r.note = "No port mappings: nothing on this network has opened a hole through the router by UPnP." }
    return r
}
