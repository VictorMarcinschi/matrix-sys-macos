// The LAN view's scene and panel: this Mac at the centre, one node per network it is on, every machine found on a
// ring around it, and each machine's open ports stacked above it the way listening ports stack in the Network view.
import Foundation
import AppKit

var lanHAng: [String: Float] = [:]          // host angle on the ring, kept so a host appearing does not re-pack the scene
var lanRing: Float = 0                      // ring radius, grows when crowded, shrinks only when clearly too wide
var lanScanTarget = ""                      // the host whose scan the panel is following

func lanHostColor(_ h: LanHost) -> Col {
    if h.me { return C_CYAN }
    if h.gw { return C_WARN }
    if !h.openPorts.isEmpty { return C_UDP }
    if h.named { return C_SAFE }
    return C_BLUE
}

/// How long ago we had evidence of this host, as an opacity: a machine whose ARP entry has expired fades rather than
/// vanishing, because "not seen for a minute" is not the same as "gone".
func lanFresh(_ h: LanHost, _ t: Double) -> Float {
    let age = t - h.lastSeen
    return age < 60 ? 1 : age < 600 ? 0.65 : 0.35
}

func buildLan() {
    let L = LY[7]; L.gen += 1; var lanes: [Lane] = []
    guard let LN = LN else { endNodes(L); setLanes(L, lanes); return }
    let t = LN.t

    // ---- this Mac
    let me = up(L, "lanme", .ico, .pc, V3(0, -20, 0), S3(5), C_CYAN)
    me.name = S?.host ?? "this Mac"; me.label = me.name
    me.glow = 0.5
    me.lp = 9
    me.cnt = LN.hosts.count

    // ---- one node per network, on a small ring of their own
    var ifPos: [String: V3] = [:]
    let ifs = LN.ifs
    for (i, nif) in ifs.enumerated() {
        let a = Float(i) * 6.2832 / Float(max(1, ifs.count)) + 0.4
        let p = V3(cos(a) * 15, -11, sin(a) * 15)
        ifPos[nif.name] = p
        let q = up(L, "lanif:" + nif.name, .octa, .dev, p, S3(1.6), C_CYAN, me.tpos)
        q.name = nif.name; q.label = nif.name + " · " + nif.cidrText; q.s1 = nif.name
        q.glow = 0.5; q.lp = 4
        let l = mkLane("lanifl:" + nif.name, "lanme", "lanif:" + nif.name, C_DEEP, w: 0.6, tree: true)
        l.proto = "network \(nif.cidrText)"; l.from = me.name; l.to = nif.name; l.tree = true
        lanes.append(l)
    }

    // ---- the hosts, on one ring around the Mac
    let others = LN.hosts.filter { !$0.me }
    for h in others where lanHAng[h.ip] == nil {
        lanHAng[h.ip] = Float(fnv(h.ip) % 628) / 100
    }
    for k in lanHAng.keys where !others.contains(where: { $0.ip == k }) { lanHAng.removeValue(forKey: k) }
    let n = max(1, others.count)
    let want = max(34, Float(n) * 4.6 / 6.2832 + 14)
    if want > lanRing || want < lanRing * 0.62 { lanRing = want }
    relaxRing(&lanHAng, min(0.5, 6.2832 / Float(n) * 0.85))

    for h in others {
        guard let a = lanHAng[h.ip] else { continue }
        let p = V3(cos(a) * lanRing, -14, sin(a) * lanRing)
        let open = h.openPorts
        let size: Float = (h.gw ? 1.9 : h.named ? 1.4 : 1.1) + min(0.8, Float(open.count) * 0.08)
        let spawn = ifPos[h.ifn] ?? me.tpos
        let q = up(L, "lh:" + h.ip, h.gw ? .box : .tetra, .lhost, p, S3(size), lanHostColor(h), spawn)
        q.name = h.label.lowercased() + " " + h.ip + " " + h.vendor.lowercased()   // what the type-to-filter matches
        q.label = h.label + (h.gw ? " · gateway" : "")
        q.s1 = h.ip
        q.op = lanFresh(h, t)
        q.glow = h.replied ? 0.75 : 0.4
        // a meaningful order, not three big ties: the gateway, then named machines, then whatever has open ports,
        // then the rest — with the address breaking remaining ties so the same label always wins
        q.lp = (h.gw ? 6 : h.named ? 2.4 : 1) + min(0.7, Float(open.count) * 0.1)
             + Float(ipToU32(h.ip) & 0xff) / 1000
        let anchor = ifPos[h.ifn] != nil ? "lanif:" + h.ifn : "lanme"
        let l = mkLane("lhl:" + h.ip, anchor, "lh:" + h.ip, h.gw ? C_WARN : C_DEEP, w: h.gw ? 0.8 : 0.45, tree: true)
        l.proto = h.gw ? "default route" : "same network"
        l.from = ifPos[h.ifn] != nil ? h.ifn : me.name
        l.to = h.label
        l.tree = true
        lanes.append(l)

        // open ports stack above the host
        for (i, pt) in open.enumerated() {
            let pp = V3(p.x, p.y + 5 + Float(i) * 2.6, p.z)
            let pq = up(L, "lp:\(h.ip):\(pt.port)", .octa, .lport, pp, S3(0.75), C_SAFE, p)
            pq.name = "\(pt.port) " + svcName(pt.port).lowercased()
            pq.label = "\(pt.port) " + svcName(pt.port)
            pq.port = pt.port; pq.s1 = h.ip; pq.owner = "lh:" + h.ip
            pq.glow = 0.7; pq.op = q.op
            pq.lp = 0.9 - Float(i) * 0.02          // the lowest port's label wins when a stack crowds
            let pl = mkLane("lpl:\(h.ip):\(pt.port)", "lh:" + h.ip, "lp:\(h.ip):\(pt.port)", C_SAFE, w: 0.35, tree: true)
            pl.proto = "TCP \(pt.port) open"; pl.from = h.label; pl.to = "\(pt.port) " + svcName(pt.port); pl.tree = true
            lanes.append(pl)
        }
    }
    L.ext = max(60, lanRing + 22)
    endNodes(L); setLanes(L, lanes)
}

func lanSpawnFlow(_ f: Flow) {}   // the LAN view draws reachability, not traffic: the Network view already has the traffic

func lanHost(_ ip: String) -> LanHost? { LN?.hosts.first { $0.ip == ip } }

/// A list row: the name and the address when they differ, the address alone when the host has no name.
func lanRow(_ h: LanHost) -> String {
    var s = h.named ? h.label + "  " + h.ip : h.ip
    if !h.openPorts.isEmpty { s += "  \(h.openPorts.count) open" }
    else if !h.named { s += h.vendor.isEmpty ? (h.randomMac ? "  private MAC" : "") : "  " + h.vendor }
    return s
}

func lanTip(_ n: Node) -> [TL] {
    guard let LN = LN else { return [] }
    if n.kind == .lport {
        guard let h = lanHost(n.s1), let p = h.openPorts.first(where: { $0.port == n.port }) else { return [] }
        var t = [TL(s: "TCP \(n.port) " + svcName(n.port), c: .cyan), TL(s: "open on " + h.label, c: .text)]
        if !p.server.isEmpty { t.append(TL(s: p.server, c: .text)) }
        if !p.banner.isEmpty { t.append(TL(s: p.banner.prefix(70).description, c: .dim)) }
        return t
    }
    if n.kind == .pc {
        return [TL(s: (S?.host ?? "this Mac"), c: .cyan),
                TL(s: "\(LN.hosts.count) machines on \(LN.ifs.count) network(s)", c: .text),
                TL(s: LN.listening ? "listening to mDNS and SSDP announcements" : "passive listener not running", c: .dim)]
    }
    if n.kind == .dev, let nif = LN.ifs.first(where: { "lanif:" + $0.name == n.key }) {
        return [TL(s: nif.name, c: .cyan), TL(s: nif.cidrText + " · \(nif.hosts) addresses", c: .text),
                TL(s: "this Mac is " + nif.ip, c: .dim)]
    }
    guard let h = lanHost(n.s1) else { return [] }
    var t = [TL(s: h.label + (h.gw ? " · gateway" : ""), c: .cyan)]
    if h.named { t.append(TL(s: h.ip, c: .text)) }
    if !h.mac.isEmpty {
        t.append(TL(s: "MAC " + h.mac + (h.randomMac ? "  (private address)" : h.vendor.isEmpty ? "" : "  " + h.vendor), c: h.randomMac ? .dim : .text))
    } else {
        t.append(TL(s: "no MAC: never answered on this network", c: .dim))
    }
    let open = h.openPorts
    if h.scanState == 1 { t.append(TL(s: "scanning… \(h.scanDone)/\(h.scanTotal)", c: .warn)) }
    else if h.scanState == 2 { t.append(TL(s: open.isEmpty ? "no open ports among the \(h.scanDone) tried" : "open: " + open.prefix(8).map { "\($0.port)" }.joined(separator: " "), c: open.isEmpty ? .dim : .safe)) }
    else { t.append(TL(s: "not scanned", c: .dim)) }
    if !h.services.isEmpty { t.append(TL(s: h.services.prefix(6).joined(separator: " "), c: .dim)) }
    let age = LN.t - h.lastSeen
    if age > 60 { t.append(TL(s: "last seen \(Int(age / 60)) min ago", c: .dim)) }
    return t
}

// ---------------------------------------------------------------- panel

private func lanPortRow(_ p: LanPort) {
    let nm = svcName(p.port)
    P(3, "TCP \(p.port)" + (nm.isEmpty ? "" : " " + nm), p.server.isEmpty ? "open" : p.server, .safe)
    if !p.banner.isEmpty {
        for line in wrapText(p.banner.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " "), 44).prefix(2) { P(1, "   " + line) }
    }
}


/// What an SNMP agent said. Offered for every host, because printers, NAS boxes and managed switches answer it as
/// readily as routers do — but only ever read, and only when you press the button.
private func lanSnmpSection(_ h: LanHost) {
    let s = h.snmp
    P(2, "SNMP")
    let openNow = h.openPorts.contains { $0.port == 161 }
    if !s.asked {
        if openNow { P(1, "UDP 161 answered a scan, so this one is worth asking.") }
        P(1, "Read-only: the system description, the interface table and the agent's own ARP table. MatrixSys never")
        P(1, "writes an SNMP object.")
        if let u = snmpV3Configured() {
            P(1, "v3 as \"" + u.name + "\" (" + u.level + (u.authProto == .none ? "" : ", " + u.authProto.name)
                 + (u.privProto == .none ? "" : " + " + u.privProto.name) + "), passwords from your keychain.")
        } else {
            P(1, "v2c, community \"" + snmpCommunity() + "\"" + (snmpCommunity() == "public" ? " (the default)" : " (from your preferences)") + ".")
            P(1, "For v3: defaults write com.matrixsys.app snmpV3User <name>, then add its passwords to the keychain.")
        }
    }
    P(5, s.asked && s.ok ? "ASK IT AGAIN (SNMP)" : "ASK IT OVER SNMP", "", .cyan, "act:lansnmp:" + h.ip)
    guard s.asked else { return }
    if !s.ok {
        for line in wrapText(s.note, 46) { P(1, line) }
        return
    }
    if !s.how.isEmpty { P(3, "reached over", s.how, .dim) }
    if !s.engineID.isEmpty { P(3, "engine id", s.engineID, .dim) }
    if !s.name.isEmpty { P(3, "system name", s.name, .safe) }
    if !s.descr.isEmpty {
        P(3, "description", "", .text)
        for line in wrapText(s.descr, 46).prefix(4) { P(1, "   " + line) }
    }
    if !s.uptime.isEmpty { P(3, "up for", s.uptime, .text) }
    if !s.location.isEmpty { P(3, "location", s.location, .text) }
    if !s.contact.isEmpty { P(3, "contact", s.contact, .text) }
    if !s.ifs.isEmpty {
        P(2, "ITS INTERFACES (\(s.ifs.count))")
        for i in s.ifs.prefix(24) {
            let rate = i.speed > 0 ? "  " + fmtBits(Double(i.speed)) : ""
            P(3, "\(i.index) " + (i.name.isEmpty ? "-" : i.name), (i.up ? "up" : "down") + rate, i.up ? .safe : .dim)
            if i.inOctets > 0 || i.outOctets > 0 {
                P(1, "   ▼ " + fmtB(Double(i.inOctets)) + "  ▲ " + fmtB(Double(i.outOctets)) + " since it last restarted")
            }
        }
    }
    if !s.arp.isEmpty {
        P(2, "MACHINES IT HAS SEEN (\(s.arp.count))")
        P(1, "Its own ARP table. Anything here that this Mac has never spoken to has been added to the view.")
        for (ip, mac) in s.arp.prefix(40) {
            let known = lanHost(ip)
            P(4, ip + "  " + mac + (known?.named == true ? "  " + known!.label : ""), "", known?.fromRouter == true ? .warn : .dim, "lh:" + ip)
        }
    }
    if !s.note.isEmpty { for line in wrapText(s.note, 46) { P(1, line) } }
}

private func lanRouterSection(_ h: LanHost) {
    guard let LN = LN else { return }
    let r = LN.router
    P(2, "ROUTER")
    P(1, "There is no cross-vendor standard for changing a router's settings from here. Two standards can be read:")
    P(1, "SNMP (above) and UPnP IGD (below). Both are read-only in MatrixSys.")
    P(5, r.queried && r.ok ? "ASK IT AGAIN (UPNP)" : "ASK IT OVER UPNP", "", .cyan, "act:lanrouter:" + h.ip)
    if r.queried && r.at > 0 {
        if !r.friendlyName.isEmpty { P(3, "calls itself", r.friendlyName, .text) }
        if !r.manufacturer.isEmpty { P(3, "made by", r.manufacturer, .text) }
        if !r.model.isEmpty { P(3, "model", r.model, .text) }
        if !r.externalIP.isEmpty { P(3, "address on the internet", r.externalIP, .cyan) }
        if !r.status.isEmpty { P(3, "WAN connection", r.status, r.status == "Connected" ? .safe : .warn) }
        if !r.uptime.isEmpty { P(3, "connected for", r.uptime, .text) }
        if !r.linkUp.isEmpty { P(3, "physical link", r.linkUp, .text) }
        if !r.downRate.isEmpty || !r.upRate.isEmpty { P(3, "line rate", "▼" + r.downRate + " ▲" + r.upRate, .text) }
        if !r.maps.isEmpty {
            P(2, "PORT MAPPINGS (\(r.maps.count))")
            P(1, "Holes through the router that something on this network asked for.")
            for m in r.maps.prefix(40) { P(3, m, "", .warn) }
        }
        if !r.note.isEmpty { for line in wrapText(r.note, 46) { P(1, line) } }
        if !r.location.isEmpty { P(1, "description: " + r.location) }
    }
    P(2, "ITS OWN ADMIN INTERFACE")
    P(1, "MatrixSys does not log in anywhere and stores no credentials. These hand the session to something that does.")
    var row = "OPEN ADMIN PAGE|act:lanadmin:" + h.ip
    row += ";SSH|act:lanssh:" + h.ip
    row += ";TELNET|act:lantelnet:" + h.ip
    P(7, row)
    let open = Set(h.openPorts.map { $0.port })
    if h.scanState == 2 {
        let web = [80, 443, 8080, 8443, 8000, 81].filter { open.contains($0) }
        P(1, web.isEmpty ? "No web port answered a scan, so the admin page may be elsewhere." : "Web ports open: " + web.map(String.init).joined(separator: ", "))
        if open.contains(22) { P(1, "Port 22 is open: SSH opens a Terminal window, where your own key or password is used.") }
        if open.contains(23) { P(1, "Port 23 is open. Telnet sends the password in clear text; prefer SSH where the router offers it.") }
        if open.contains(7547) { P(1, "Port 7547 is open: TR-069, which exists for your ISP to manage this router, not for you.") }
        if open.contains(161) { P(1, "Port 161 is open: SNMP, which the section above reads.") }
    } else {
        P(1, "Scan it first to see which admin ports it actually has open.")
    }
}

func lanPanel() {
    guard let LN = LN else { P(0, "LAN"); P(1, "Reading the local networks…"); return }

    if !LN.busy.isEmpty {
        P(0, "Working")
        P(1, LN.busy)
        P(3, "progress", String(format: "%.0f%%", LN.progress * 100), .cyan)
        P(5, "STOP", "", .warn, "act:lancancel:")
    }

    // ---- a host
    if sel.hasPrefix("lh:") {
        let ip = String(sel.dropFirst(3))
        guard let h = lanHost(ip) else { sel = ""; computeFocus(); return }
        P(0, h.label)
        if h.named { P(1, h.ip) }
        var sub = h.me ? "this Mac" : h.gw ? "default gateway" : "machine on " + (h.ifn.isEmpty ? "the local network" : h.ifn)
        if h.fromRouter { sub += " · known to the router, not seen by this Mac" }
        if !h.mac.isEmpty { sub += " · MAC " + h.mac }
        P(1, sub)
        if h.randomMac {
            P(1, "This is a private (randomised) address, so it names no hardware and will change. iOS and Android use")
            P(1, "one per network by default.")
        } else if !h.mac.isEmpty {
            if !h.vendor.isEmpty { P(1, "hardware vendor: " + h.vendor + " (OUI " + ouiPrefix(h.mac) + ")") }
            else { P(1, "OUI " + ouiPrefix(h.mac) + (Oui.shared.bundled ? " — not in the bundled vendor table" : " — no vendor table is bundled (scripts/make_oui.sh builds one)")) }
        }

        P(2, "NAMES")
        var any = false
        if !h.mdns.isEmpty { P(3, "mDNS (Bonjour)", h.mdns, .safe); any = true }
        if !h.rdns.isEmpty { P(3, "reverse DNS", h.rdns, .text); any = true }
        if !h.nbns.isEmpty { P(3, "NetBIOS", h.nbns, .text); any = true }
        if !h.ssdpName.isEmpty { P(3, "UPnP", h.ssdpName, .text); any = true }
        if !h.ssdpModel.isEmpty { P(3, "announces itself as", h.ssdpModel.prefix(44).description, .dim); any = true }
        if !any { P(1, "No name from any source yet. ASK ITS NAME sends one mDNS and one NetBIOS query.") }
        if !h.services.isEmpty { P(3, "services", h.services.prefix(8).joined(separator: " "), .dim) }

        P(7, "ASK ITS NAME|act:lanname:\(ip);PING|act:ping:\(ip);COPY ADDRESS|act:copy:\(ip);WHO OWNS IT|act:whois:\(ip)")
        if !h.mac.isEmpty && !h.me { P(5, "WAKE IT (WAKE-ON-LAN)", "", .cyan, "act:lanwake:" + h.mac) }

        P(2, "OPEN PORTS")
        if h.scanState == 1 {
            P(1, "Scanning… \(h.scanDone) of \(h.scanTotal) ports tried.")
        } else if h.scanState == 0 {
            P(1, "Not scanned. A scan opens one TCP connection per port — \(LAN_PORTS_COMMON.count) picked ones for the")
            P(1, "common list, 1023 or all 65535 for a range — and asks an open port what it is.")
        }
        let open = h.openPorts
        if h.scanState == 2 {
            let closed = h.ports.filter { $0.state == LAN_CLOSED }.count, filtered = h.ports.filter { $0.state == LAN_FILTERED }.count
            P(1, "\(open.count) open · \(closed) closed (refused) · \(filtered) filtered (no answer) of \(h.ports.count) tried")
        }
        for p in open { lanPortRow(p) }
        if h.scanState == 2 && open.isEmpty { P(1, "Nothing answered. A host can be up and have every port closed.") }
        P(7, "SCAN COMMON PORTS|act:lanscan:\(ip);SCAN ADMIN PORTS|act:lanscanadmin:\(ip)")
        P(7, "SCAN 1-1023|act:lanscanlow:\(ip);SCAN EVERY PORT|act:lanscanfull:\(ip)")
        if h.scanState == 2 && open.isEmpty && h.scanTotal < 60000 {
            P(1, "SCAN EVERY PORT tries all 65535. It takes a few minutes and is the loudest thing here.")
        }
        if h.scanState == 2 && open.isEmpty && h.scanTotal >= 60000 {
            P(1, "Nothing listens on any of the 65535 ports. A device like this is reached by its own outbound")
            P(1, "connection to a maker's server, not by anything connecting to it, so there is nothing here to open.")
        }

        lanSnmpSection(h)
        if h.gw { lanRouterSection(h) }

        P(2, "OPEN IN")
        P(5, "TRACE THROUGH IT", "", .dim, "act:lantrace:" + ip)
        P(5, "DEVICES VIEW", "", .dim, "nb:" + ip, 5)
        netSection(-1, ip)
        return
    }

    // ---- one open port
    if sel.hasPrefix("lp:") {
        let f = sel.dropFirst(3).split(separator: ":")
        guard f.count == 2, let h = lanHost(String(f[0])), let port = Int(f[1]),
              let p = h.openPorts.first(where: { $0.port == port }) else { sel = ""; computeFocus(); return }
        P(0, "TCP \(port) " + svcName(port))
        P(1, "open on " + h.label + " (" + h.ip + ")")
        if !p.server.isEmpty { P(3, "server", p.server, .text) }
        if p.ms > 0 { P(3, "connected in", trMs(p.ms), .text) }
        if !p.banner.isEmpty {
            P(2, "WHAT IT SAID")
            for line in wrapText(p.banner.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " "), 46).prefix(8) { P(1, line) }
        } else {
            P(1, "It accepted the connection and said nothing, and it is not HTTP.")
        }
        if [80, 8080, 8000, 81, 443, 8443].contains(port) {
            P(5, "OPEN IN BROWSER", "", .cyan, "act:lanopen:\(h.ip):\(port)")
        }
        P(5, "TRACE THIS PORT", "", .dim, "act:lantraceport:\(h.ip):\(port)")
        P(2, "ON")
        P(4, h.label + "  " + h.ip, "", .dim, "lh:" + h.ip)
        return
    }

    // ---- an interface
    if sel.hasPrefix("lanif:") {
        let name = String(sel.dropFirst(6))
        guard let nif = LN.ifs.first(where: { $0.name == name }) else { sel = ""; computeFocus(); return }
        P(0, nif.name)
        P(1, nif.cidrText + " · this Mac is " + nif.ip + " · netmask " + nif.mask)
        P(1, "\(nif.hosts) addresses in this subnet")
        let here = LN.hosts.filter { $0.ifn == name && !$0.me }
        P(3, "machines found here", "\(here.count)", .text)
        if nif.hosts > LAN_SWEEP_MAX {
            P(1, "Too wide to sweep: \(nif.hosts) addresses against a limit of \(LAN_SWEEP_MAX). Nothing is sent.")
        } else {
            P(5, "SWEEP THIS SUBNET", "", .cyan, "act:lansweep:" + name)
            P(1, "One ICMP echo to each of \(nif.hosts) addresses, then the ARP table is read again. A host that ignores")
            P(1, "the ping is still found, because it had to answer the ARP request first.")
        }
        P(2, "MACHINES")
        for h in here.prefix(60) { P(4, lanRow(h), "", .dim, "lh:" + h.ip) }
        return
    }

    // ---- summary
    P(0, "LAN")
    let others = LN.hosts.filter { !$0.me }
    P(1, "\(others.count) machines on \(LN.ifs.count) network\(LN.ifs.count == 1 ? "" : "s")" +
        (LN.lastSweep > 0 ? " · last sweep \(Int(LN.t - LN.lastSweep)) s ago, \(LN.sweepSent) probes" : " · no sweep yet"))
    P(1, LN.listening ? "Listening to the mDNS and SSDP announcements already on the wire. Nothing is sent for this."
                      : "The passive listener could not bind its ports; names will only come from what you ask for.")

    P(2, "NETWORKS")
    for nif in LN.ifs {
        let here = LN.hosts.filter { $0.ifn == nif.name && !$0.me }.count
        P(4, nif.name + "  " + nif.cidrText + "  \(here) found", "", .dim, "lanif:" + nif.name)
    }
    if LN.ifs.isEmpty { P(1, "No usable IPv4 network: every interface is down, loopback or point-to-point.") }
    if let first = LN.ifs.first, first.hosts <= LAN_SWEEP_MAX {
        P(5, "SWEEP " + first.cidrText, "", .cyan, "act:lansweep:" + first.name)
    }

    P(7, "ASK EVERY NAME|act:lannames:;SWEEP AND NAME|act:lansweepnames:" + (LN.ifs.first?.name ?? ""))
    P(1, "ASK EVERY NAME sends one mDNS and one NetBIOS query per machine already found — a few packets each, no sweep.")

    let gw = others.filter { $0.gw }
    if !gw.isEmpty {
        P(2, "GATEWAY")
        for h in gw { P(4, lanRow(h), "", .warn, "lh:" + h.ip) }
    }

    let named = others.filter { $0.named && !$0.gw }, anon = others.filter { !$0.named && !$0.gw }
    if !named.isEmpty {
        P(2, "NAMED (\(named.count))")
        for h in named.prefix(40) { P(4, lanRow(h), "", .dim, "lh:" + h.ip) }
    }
    if !anon.isEmpty {
        P(2, "NO NAME (\(anon.count))")
        for h in anon.prefix(40) { P(4, lanRow(h), "", .dim, "lh:" + h.ip) }
    }
    if others.isEmpty {
        P(1, "Nothing yet. The ARP table only holds machines this Mac has spoken to recently; sweep a subnet to find")
        P(1, "the rest.")
    }
    P(1, "IPv6 neighbours are in the Devices view; this view is IPv4, like the Trace tab.")
}
