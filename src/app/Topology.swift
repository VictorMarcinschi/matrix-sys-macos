// Physical topology, read from a switch's own forwarding database over SNMP.
//
// Everything else in the LAN view is what this Mac can see from where it sits, and from there a switch is invisible:
// it forwards frames without appearing in any of them, so no amount of pinging, scanning or listening can tell you
// that four machines sit behind one port rather than four. The bridge knows, because that is its job — it keeps a
// table of which MAC it last heard on which port — and BRIDGE-MIB exposes that table. So this is the one part of
// the view whose structure comes from somewhere other than our own observation.
//
// The inference below follows the approach taken by netpulse (github.com/gnacho/netpulse, AGPL-3.0), which reads
// the same table over SSH on OpenWrt. The rules are its idea; the code is ours, and reaches the table over SNMP
// instead, so it works against any managed switch rather than one Linux distribution.
import Foundation

// ================================================================ what the bridge tells us

struct FdbEntry {
    var mac = ""
    var bridgePort = 0
    var ifIndex = 0
    var ifName = ""
    var vlan = 0
}

struct LldpNeighbor {
    var localPort = 0
    var chassisMac = "", sysName = "", portID = "", mgmtIP = ""
    var caps: [String] = []
}

/// What a port turned out to have behind it. `direct` means one machine, cabled straight in; the rest mean several
/// machines on one port, which is only possible if something is multiplexing it.
enum TopoKind: String {
    case direct, inferred, hypervisor, managed
    var shown: String {
        switch self {
        case .direct: return "directly attached"
        case .inferred: return "something multiplexing this port"
        case .hypervisor: return "a host running virtual machines"
        case .managed: return "identified by LLDP"
        }
    }
}

struct TopoNode {
    var id = ""                 // "topo:<agent ip>:<port>"
    var kind = TopoKind.inferred
    var agentIP = ""            // the switch or router whose table this came from
    var port = 0
    var ifName = ""
    var label = ""
    var mgmtIP = ""
    var caps: [String] = []
    var macs: [String] = []     // everything learned on this port, self-MACs already removed
    var note = ""
}

// ================================================================ OIDs

enum BridgeOID {
    /// dot1dBasePortIfIndex: bridge port number → ifIndex, so a port can be named from the interface table.
    static let basePortIfIndex = [1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2]
    /// dot1dTpFdbPort: the forwarding database. The MAC is the last six arcs of the OID; the value is the port.
    static let fdbPort = [1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2]
    /// dot1dTpFdbStatus: 3 = learned. Static and self entries are not evidence of anything being plugged in.
    static let fdbStatus = [1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3]
    /// dot1qTpFdbPort: the VLAN-aware table. Many modern switches populate only this one, and index it by
    /// VLAN followed by the six MAC bytes.
    static let qFdbPort = [1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2]
}

/// LLDP-MIB lives under the IEEE 802.1AB arc, not the usual 1.3.6.1 one.
enum LldpOID {
    static let remChassisIdSubtype = [1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 4]
    static let remChassisId        = [1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 5]
    static let remPortId           = [1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 7]
    static let remSysName          = [1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9]
    static let remSysCapEnabled    = [1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 12]
}

// ================================================================ reading them

private func macFromArcs(_ arcs: ArraySlice<Int>) -> String {
    guard arcs.count == 6, arcs.allSatisfy({ $0 >= 0 && $0 < 256 }) else { return "" }
    return arcs.map { String(format: "%02x", $0) }.joined(separator: ":")
}

/// The forwarding database, with each entry's port resolved to an interface name where the agent offers one.
func snmpReadFdb(_ t: SnmpTarget, ifNames: [Int: String], _ note: (Double, String) -> Void) -> [FdbEntry] {
    note(0.8, "reading the forwarding database")
    var portToIf: [Int: Int] = [:]
    for v in snmpWalk(t, root: BridgeOID.basePortIfIndex, max: 256, seconds: 6) {
        if let p = v.oid.last { portToIf[p] = v.int }
    }
    // learned entries only, where the agent says
    var learned: [String: Bool] = [:]
    for v in snmpWalk(t, root: BridgeOID.fdbStatus, max: 1024, seconds: 8) {
        let mac = macFromArcs(v.oid.suffix(6))
        if !mac.isEmpty { learned[mac] = (v.int == 3) }
    }

    var out: [FdbEntry] = []
    var seen = Set<String>()
    func add(_ mac: String, _ port: Int, _ vlan: Int) {
        guard !mac.isEmpty, port > 0, !seen.contains(mac) else { return }
        if let ok = learned[mac], !ok { return }
        seen.insert(mac)
        var e = FdbEntry(mac: mac, bridgePort: port, vlan: vlan)
        if let ifx = portToIf[port] { e.ifIndex = ifx; e.ifName = ifNames[ifx] ?? "" }
        out.append(e)
    }
    for v in snmpWalk(t, root: BridgeOID.fdbPort, max: 1024, seconds: 10) {
        add(macFromArcs(v.oid.suffix(6)), v.int, 0)
    }
    if out.isEmpty {
        note(0.85, "trying the VLAN-aware forwarding database")
        for v in snmpWalk(t, root: BridgeOID.qFdbPort, max: 1024, seconds: 10) {
            let tail = v.oid.suffix(7)                       // vlan + 6 MAC bytes
            guard tail.count == 7 else { continue }
            add(macFromArcs(tail.dropFirst()), v.int, tail.first ?? 0)
        }
    }
    return out
}

/// LLDP neighbours. The table is indexed by (timeMark, local port, index), so the local port comes from the OID.
func snmpReadLldp(_ t: SnmpTarget, _ note: (Double, String) -> Void) -> [LldpNeighbor] {
    note(0.9, "asking for LLDP neighbours")
    func walkByIndex(_ root: [Int]) -> [String: SnmpVar] {
        var m: [String: SnmpVar] = [:]
        for v in snmpWalk(t, root: root, max: 256, seconds: 6) {
            let idx = v.oid.suffix(3).map(String.init).joined(separator: ".")
            m[idx] = v
        }
        return m
    }
    let subtypes = walkByIndex(LldpOID.remChassisIdSubtype)
    let chassis = walkByIndex(LldpOID.remChassisId)
    if chassis.isEmpty { return [] }
    let names = walkByIndex(LldpOID.remSysName)
    let ports = walkByIndex(LldpOID.remPortId)
    let caps = walkByIndex(LldpOID.remSysCapEnabled)

    var out: [LldpNeighbor] = []
    for (idx, cv) in chassis {
        var n = LldpNeighbor()
        let parts = idx.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 3 else { continue }
        n.localPort = parts[1]
        // subtype 4 is macAddress; anything else is a name or an address we show as text
        if subtypes[idx]?.int == 4 || cv.raw.count == 6 {
            n.chassisMac = cv.raw.count == 6 ? cv.mac : ""
        }
        if n.chassisMac.isEmpty { n.sysName = cv.text }
        if let nm = names[idx]?.text, !nm.isEmpty { n.sysName = nm }
        n.portID = ports[idx]?.text ?? ""
        // sysCapEnabled is a bit string, most significant bit first: other, repeater, bridge, wlan, router, …
        if let c = caps[idx]?.raw.first {
            let labels = ["other", "repeater", "bridge", "access point", "router", "telephone", "cable", "station"]
            for (i, l) in labels.enumerated() where c & UInt8(0x80 >> i) != 0 { n.caps.append(l) }
        }
        out.append(n)
    }
    return out
}

// ================================================================ hypervisors

/// Prefixes assigned to virtualisation platforms. A MAC in one of these ranges belongs to a virtual machine, not to
/// anything you could unplug — which is worth saying, because the IEEE registry names the platform's vendor and
/// stops there.
let hypervisorOUIs: [(prefix: String, name: String)] = [
    ("bc:24:11", "Proxmox VE"),
    ("00:50:56", "VMware"),
    ("00:0c:29", "VMware"),
    ("00:05:69", "VMware"),
    ("00:1c:14", "VMware"),
    ("00:15:5d", "Hyper-V"),
    ("52:54:00", "KVM/QEMU"),
    ("08:00:27", "VirtualBox"),
    ("0a:00:27", "VirtualBox"),
    ("00:16:3e", "Xen"),
]
func hypervisorName(_ mac: String) -> String {
    let m = mac.lowercased()
    for (p, n) in hypervisorOUIs where m.hasPrefix(p) { return n }
    return ""
}
func isHypervisorMAC(_ mac: String) -> Bool { !hypervisorName(mac).isEmpty }

// ================================================================ the inference

/// Turns one agent's forwarding database into structure.
///
/// A port with one MAC is a machine cabled straight into it, and needs no node of its own. A port with several is
/// something multiplexing it — an unmanaged switch, a powerline adapter, a virtualisation host — and the table
/// cannot say which, so the kind depends on what other evidence there is:
///
///  * an LLDP neighbour on that port whose chassis MAC is among the learned ones **identifies** the device, and it
///    becomes `managed` with the name it announced;
///  * a hypervisor OUI among the MACs, with exactly one address that is not one, is a host and its virtual
///    machines, so it becomes `hypervisor`;
///  * anything else becomes `inferred`, which asserts only that something is there.
///
/// `isGateway` matters because of what a multi-MAC port means on a device that is not the gateway: almost always
/// its uplink, where it has learned the MACs of the whole network at once. That is indistinguishable from a switch
/// in the table alone, so on a non-gateway only positive evidence (LLDP or a hypervisor) may create a node.
func inferTopology(agentIP: String, fdb: [FdbEntry], lldp: [LldpNeighbor],
                   selfMacs: Set<String>, isGateway: Bool) -> (nodes: [TopoNode], parentOf: [String: String]) {
    var byPort: [Int: [FdbEntry]] = [:]
    for e in fdb {
        // the uplink is not local distribution, and naming it is the only clue SNMP gives us
        let n = e.ifName.lowercased()
        if n.contains("wan") || n.contains("ppp") || n.hasPrefix("lo") { continue }
        if selfMacs.contains(e.mac.lowercased()) { continue }
        byPort[e.bridgePort, default: []].append(e)
    }

    var nodes: [TopoNode] = []
    var parentOf: [String: String] = [:]

    for (port, entries) in byPort.sorted(by: { $0.key < $1.key }) {
        let macs = entries.map { $0.mac }
        if macs.count <= 1 { continue }                     // cabled straight in: no node, nothing multiplexing

        var node = TopoNode()
        node.id = "topo:\(agentIP):\(port)"
        node.agentIP = agentIP
        node.port = port
        node.ifName = entries.first?.ifName ?? ""
        node.macs = macs

        let learned = Set(macs.map { $0.lowercased() })
        if let nb = lldp.first(where: { $0.localPort == port && !$0.chassisMac.isEmpty && learned.contains($0.chassisMac.lowercased()) }) {
            node.kind = .managed
            node.label = nb.sysName.isEmpty ? nb.chassisMac : nb.sysName
            node.mgmtIP = nb.mgmtIP
            node.caps = nb.caps
            node.note = "announced itself over LLDP" + (nb.portID.isEmpty ? "" : " on its port " + nb.portID)
        } else {
            let vms = macs.filter { isHypervisorMAC($0) }
            let hosts = macs.filter { !isHypervisorMAC($0) }
            if !vms.isEmpty && hosts.count == 1 {
                node.kind = .hypervisor
                node.label = hypervisorName(vms[0]) + " host"
                node.note = "\(vms.count) virtual machine\(vms.count == 1 ? "" : "s") and one host on this port"
            } else if isGateway {
                node.kind = .inferred
                node.label = "switch?"
                node.note = "\(macs.count) machines answer on one port, so something unmanaged sits here. "
                          + "The forwarding table cannot say what it is."
            } else {
                // a multi-MAC port on a non-gateway is almost certainly its uplink; claim nothing
                continue
            }
        }
        for m in macs { parentOf[m.lowercased()] = node.id }
        nodes.append(node)
    }
    return (nodes, parentOf)
}
