// SNMP v2c, read-only: GET, GETNEXT and a walk, with just enough BER to speak them. No third-party code and no
// MIB files — the handful of standard MIB-2 objects worth showing are named by their numeric OID below.
//
// Read-only on purpose. SET is defined by the same protocol and deliberately not implemented: the objects a router
// lets you write are vendor-specific anyway, and nothing in MatrixSys changes another machine's configuration.
import Foundation
import Darwin

// ================================================================ BER, the subset SNMP uses

enum BER {
    static let int: UInt8 = 0x02, octet: UInt8 = 0x04, null: UInt8 = 0x05, oid: UInt8 = 0x06, sequence: UInt8 = 0x30
    static let ipAddress: UInt8 = 0x40, counter32: UInt8 = 0x41, gauge32: UInt8 = 0x42, timeTicks: UInt8 = 0x43
    static let opaque: UInt8 = 0x44, counter64: UInt8 = 0x46
    static let getRequest: UInt8 = 0xA0, getNextRequest: UInt8 = 0xA1, getResponse: UInt8 = 0xA2
    static let noSuchObject: UInt8 = 0x80, noSuchInstance: UInt8 = 0x81, endOfMibView: UInt8 = 0x82
}

func berLength(_ n: Int) -> [UInt8] {
    if n < 128 { return [UInt8(n)] }
    var v = n, out: [UInt8] = []
    while v > 0 { out.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
    return [UInt8(0x80 | out.count)] + out
}
func berTLV(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] { [tag] + berLength(body.count) + body }

func berInt(_ v: Int) -> [UInt8] {
    var body: [UInt8] = []
    if v == 0 { body = [0] } else {
        var x = v
        while x != 0 && x != -1 { body.insert(UInt8(truncatingIfNeeded: x), at: 0); x >>= 8 }
        // keep the sign unambiguous
        if v > 0 && (body.first ?? 0) & 0x80 != 0 { body.insert(0, at: 0) }
        if v < 0 && (body.first ?? 0) & 0x80 == 0 { body.insert(0xFF, at: 0) }
    }
    return berTLV(BER.int, body)
}
func berString(_ s: String) -> [UInt8] { berTLV(BER.octet, Array(s.utf8)) }

/// An OID on the wire: the first two arcs share a byte, the rest are base-128 with the high bit as a continuation.
func berOid(_ arcs: [Int]) -> [UInt8] {
    guard arcs.count >= 2 else { return berTLV(BER.oid, []) }
    var body: [UInt8] = [UInt8(arcs[0] * 40 + arcs[1])]
    for a in arcs.dropFirst(2) {
        if a == 0 { body.append(0); continue }
        var chunk: [UInt8] = [], v = a
        while v > 0 { chunk.insert(UInt8(v & 0x7F), at: 0); v >>= 7 }
        for i in 0..<(chunk.count - 1) { chunk[i] |= 0x80 }
        body += chunk
    }
    return berTLV(BER.oid, body)
}

/// Reads one tag-length-value header. Returns the tag and where its body is; `o` advances past the header only.
func berHeader(_ d: [UInt8], _ o: inout Int) -> (tag: UInt8, len: Int)? {
    guard o + 2 <= d.count else { return nil }
    let tag = d[o]; o += 1
    var len = Int(d[o]); o += 1
    if len & 0x80 != 0 {
        let n = len & 0x7F
        guard n > 0, n <= 4, o + n <= d.count else { return nil }
        len = 0
        for _ in 0..<n { len = (len << 8) | Int(d[o]); o += 1 }
    }
    guard len >= 0, o + len <= d.count else { return nil }
    return (tag, len)
}
func berReadInt(_ d: [UInt8], _ o: Int, _ len: Int) -> Int {
    guard len > 0, o + len <= d.count else { return 0 }
    var v = Int(Int8(bitPattern: d[o]))         // signed first byte
    for i in 1..<len { v = (v << 8) | Int(d[o + i]) }
    return v
}
func berReadUInt(_ d: [UInt8], _ o: Int, _ len: Int) -> UInt64 {
    var v: UInt64 = 0
    for i in 0..<min(len, 8) where o + i < d.count { v = (v << 8) | UInt64(d[o + i]) }
    return v
}
func berReadOid(_ d: [UInt8], _ o: Int, _ len: Int) -> [Int] {
    guard len > 0, o + len <= d.count else { return [] }
    var out = [Int(d[o]) / 40, Int(d[o]) % 40], i = o + 1, acc = 0
    while i < o + len {
        acc = (acc << 7) | Int(d[i] & 0x7F)
        if d[i] & 0x80 == 0 { out.append(acc); acc = 0 }
        i += 1
    }
    return out
}

// ================================================================ one variable binding

struct SnmpVar {
    var oid: [Int] = []
    var tag: UInt8 = BER.null
    var raw: [UInt8] = []
    var oidText: String { oid.map(String.init).joined(separator: ".") }
    var isEnd: Bool { tag == BER.endOfMibView || tag == BER.noSuchObject || tag == BER.noSuchInstance }

    var int: Int { berReadInt(raw, 0, raw.count) }
    var uint: UInt64 { berReadUInt(raw, 0, raw.count) }
    /// A MAC when it is six bytes, which is how ifPhysAddress and the ARP table carry one.
    var mac: String { raw.count == 6 ? raw.map { String(format: "%02x", $0) }.joined(separator: ":") : "" }

    var text: String {
        switch tag {
        case BER.octet:
            if raw.count == 6, raw.contains(where: { $0 < 0x20 || $0 > 0x7e }) { return mac }
            let printable = raw.allSatisfy { $0 == 0x09 || $0 == 0x0a || $0 == 0x0d || ($0 >= 0x20 && $0 < 0x7f) }
            if printable { return String(decoding: raw, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) }
            return raw.map { String(format: "%02x", $0) }.joined(separator: ":")
        case BER.int: return "\(int)"
        case BER.counter32, BER.gauge32, BER.counter64: return "\(uint)"
        case BER.timeTicks:
            let cs = uint, s = cs / 100
            let d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60
            return d > 0 ? "\(d)d \(h)h \(m)m" : h > 0 ? "\(h)h \(m)m" : "\(m)m \(s % 60)s"
        case BER.ipAddress: return raw.count == 4 ? raw.map(String.init).joined(separator: ".") : ""
        case BER.oid: return berReadOid(raw, 0, raw.count).map(String.init).joined(separator: ".")
        case BER.null: return ""
        case BER.noSuchObject: return "(not implemented)"
        case BER.noSuchInstance: return "(no such instance)"
        case BER.endOfMibView: return "(end of MIB)"
        default: return raw.map { String(format: "%02x", $0) }.joined()
        }
    }
}

// ================================================================ the request

private var snmpReqId: Int32 = Int32.random(in: 1000...60000)
private let snmpIdLock = NSLock()
private func nextReqId() -> Int { snmpIdLock.lock(); defer { snmpIdLock.unlock() }; snmpReqId &+= 1; return Int(snmpReqId & 0x7fffffff) }

struct SnmpError { var text = "" }

/// One GET or GETNEXT. nil means no answer at all; an empty array means the agent answered but had nothing.
func snmpRequest(_ ip: String, community: String, oids: [[Int]], next: Bool, timeoutMs: Int = 1200, port: UInt16 = 161) -> [SnmpVar]? {
    let id = nextReqId()
    var bindings: [UInt8] = []
    for o in oids { bindings += berTLV(BER.sequence, berOid(o) + berTLV(BER.null, [])) }
    let pdu = berTLV(next ? BER.getNextRequest : BER.getRequest,
                     berInt(id) + berInt(0) + berInt(0) + berTLV(BER.sequence, bindings))
    let msg = berTLV(BER.sequence, berInt(1) + berString(community) + pdu)   // version 1 == SNMPv2c

    guard let reply = udpAsk(ip, port, msg, timeoutMs) else { return nil }

    var o = 0
    guard let top = berHeader(reply, &o), top.tag == BER.sequence else { return nil }
    guard let ver = berHeader(reply, &o), ver.tag == BER.int else { return nil }
    o += ver.len
    guard let comm = berHeader(reply, &o), comm.tag == BER.octet else { return nil }
    o += comm.len
    guard let p = berHeader(reply, &o), p.tag == BER.getResponse else { return nil }
    guard let rid = berHeader(reply, &o), rid.tag == BER.int else { return nil }
    let gotId = berReadInt(reply, o, rid.len); o += rid.len
    guard gotId == id else { return nil }
    guard let es = berHeader(reply, &o), es.tag == BER.int else { return nil }
    let errStatus = berReadInt(reply, o, es.len); o += es.len
    guard let ei = berHeader(reply, &o), ei.tag == BER.int else { return nil }
    o += ei.len
    if errStatus != 0 { return [] }                     // the agent refused this object; the walk treats it as an end
    guard let list = berHeader(reply, &o), list.tag == BER.sequence else { return nil }
    let end = o + list.len

    var out: [SnmpVar] = []
    while o < end {
        guard let b = berHeader(reply, &o), b.tag == BER.sequence else { break }
        let bEnd = o + b.len
        guard let oh = berHeader(reply, &o), oh.tag == BER.oid else { break }
        var v = SnmpVar()
        v.oid = berReadOid(reply, o, oh.len); o += oh.len
        guard let vh = berHeader(reply, &o) else { break }
        v.tag = vh.tag
        v.raw = Array(reply[o..<min(o + vh.len, reply.count)])
        o = bEnd
        out.append(v)
    }
    return out
}

/// Walks a subtree with GETNEXT. Stops at the first OID outside the root, at `max` rows, or after `seconds`.
func snmpWalk(_ ip: String, community: String, root: [Int], max rows: Int = 256, seconds: Double = 8, port: UInt16 = 161) -> [SnmpVar] {
    var out: [SnmpVar] = []
    var cur = root
    let deadline = nowSec() + seconds
    while out.count < rows && nowSec() < deadline {
        guard let vs = snmpRequest(ip, community: community, oids: [cur], next: true, port: port), let v = vs.first else { break }
        if v.isEnd || v.oid.count < root.count || Array(v.oid.prefix(root.count)) != root { break }
        if v.oid == cur { break }                       // an agent that does not advance would loop forever
        out.append(v)
        cur = v.oid
    }
    return out
}

// ================================================================ the objects worth showing

enum OID {
    static let sysDescr    = [1, 3, 6, 1, 2, 1, 1, 1, 0]
    static let sysObjectID = [1, 3, 6, 1, 2, 1, 1, 2, 0]
    static let sysUpTime   = [1, 3, 6, 1, 2, 1, 1, 3, 0]
    static let sysContact  = [1, 3, 6, 1, 2, 1, 1, 4, 0]
    static let sysName     = [1, 3, 6, 1, 2, 1, 1, 5, 0]
    static let sysLocation = [1, 3, 6, 1, 2, 1, 1, 6, 0]
    static let ifDescr     = [1, 3, 6, 1, 2, 1, 2, 2, 1, 2]
    static let ifSpeed     = [1, 3, 6, 1, 2, 1, 2, 2, 1, 5]
    static let ifPhysAddr  = [1, 3, 6, 1, 2, 1, 2, 2, 1, 6]
    static let ifOperStatus = [1, 3, 6, 1, 2, 1, 2, 2, 1, 8]
    static let ifInOctets  = [1, 3, 6, 1, 2, 1, 2, 2, 1, 10]
    static let ifOutOctets = [1, 3, 6, 1, 2, 1, 2, 2, 1, 16]
    /// ipNetToMediaPhysAddress: the agent's own ARP table — machines it has seen that this Mac may never have.
    static let ipNetToMediaPhys = [1, 3, 6, 1, 2, 1, 4, 22, 1, 2]
}

struct SnmpIf {
    var index = 0, speed: UInt64 = 0
    var name = "", mac = ""
    var up = false
    var inOctets: UInt64 = 0, outOctets: UInt64 = 0
}

/// Everything MatrixSys asks an SNMP agent for, in one place.
struct SnmpInfo {
    var asked = false, ok = false
    var at = 0.0
    var community = ""
    var descr = "", name = "", contact = "", location = "", uptime = "", objectID = ""
    var ifs: [SnmpIf] = []
    var arp: [(ip: String, mac: String)] = []
    var note = ""
}

/// The community string. "public" is the documented default for read-only access, not a secret; a different one
/// goes in the app's own preferences (`defaults write com.matrixsys.app snmpCommunity <name>`) so that it is never
/// typed into, or stored by, MatrixSys itself.
func snmpCommunity() -> String {
    let v = UserDefaults.standard.string(forKey: "snmpCommunity") ?? ""
    return v.isEmpty ? "public" : v
}
/// 161 unless you keep your agents somewhere else (`defaults write com.matrixsys.app snmpPort <n>`).
func snmpPort() -> UInt16 {
    let v = UserDefaults.standard.integer(forKey: "snmpPort")
    return v > 0 && v < 65536 ? UInt16(v) : 161
}

func snmpQuery(_ ip: String, community: String, port: UInt16 = 161, _ note: @escaping (Double, String) -> Void) -> SnmpInfo {
    var s = SnmpInfo()
    s.asked = true; s.at = nowSec(); s.community = community

    note(0.1, "asking \(ip) for its description")
    guard let scalars = snmpRequest(ip, community: community,
                                    oids: [OID.sysDescr, OID.sysObjectID, OID.sysUpTime, OID.sysContact, OID.sysName, OID.sysLocation],
                                    next: false, timeoutMs: 1500, port: port), !scalars.isEmpty else {
        s.note = "No answer on UDP 161. Either SNMP is off, or it is on with a community other than \"\(community)\"."
        return s
    }
    for v in scalars {
        switch v.oid {
        case OID.sysDescr: s.descr = v.text
        case OID.sysObjectID: s.objectID = v.text
        case OID.sysUpTime: s.uptime = v.text
        case OID.sysContact: s.contact = v.text
        case OID.sysName: s.name = v.text
        case OID.sysLocation: s.location = v.text
        default: break
        }
    }
    s.ok = !s.descr.isEmpty || !s.name.isEmpty || !s.uptime.isEmpty
    if !s.ok {
        s.note = "The agent answered but gave nothing for the standard system objects."
        return s
    }

    note(0.4, "reading the interface table")
    var byIndex: [Int: SnmpIf] = [:]
    func walkInto(_ root: [Int], _ apply: (inout SnmpIf, SnmpVar) -> Void) {
        for v in snmpWalk(ip, community: community, root: root, max: 64, seconds: 6, port: port) {
            guard let idx = v.oid.last else { continue }
            var e = byIndex[idx] ?? { var n = SnmpIf(); n.index = idx; return n }()
            apply(&e, v)
            byIndex[idx] = e
        }
    }
    walkInto(OID.ifDescr) { e, v in e.name = v.text }
    walkInto(OID.ifOperStatus) { e, v in e.up = v.int == 1 }
    walkInto(OID.ifSpeed) { e, v in e.speed = v.uint }
    walkInto(OID.ifPhysAddr) { e, v in e.mac = v.mac }
    walkInto(OID.ifInOctets) { e, v in e.inOctets = v.uint }
    walkInto(OID.ifOutOctets) { e, v in e.outOctets = v.uint }
    s.ifs = byIndex.values.sorted { $0.index < $1.index }

    note(0.75, "reading its ARP table")
    // the address is the tail of the OID: ipNetToMediaPhysAddress.<ifIndex>.<a>.<b>.<c>.<d>
    for v in snmpWalk(ip, community: community, root: OID.ipNetToMediaPhys, max: 512, seconds: 10, port: port) {
        let tail = v.oid.suffix(4)
        guard tail.count == 4, tail.allSatisfy({ $0 >= 0 && $0 < 256 }) else { continue }
        let addr = tail.map(String.init).joined(separator: ".")
        let mac = v.mac
        if !mac.isEmpty && mac != "00:00:00:00:00:00" { s.arp.append((addr, mac)) }
    }
    if s.arp.isEmpty && s.ifs.isEmpty {
        s.note = "It answered the system objects but exposes neither an interface table nor an ARP table."
    }
    return s
}
