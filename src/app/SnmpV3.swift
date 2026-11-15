// SNMP v3 with the User-based Security Model (RFC 3414), plus AES privacy (RFC 3826) and the SHA-2 authentication
// protocols (RFC 7860). Still read-only: this gets GET and GETNEXT across an authenticated, optionally encrypted
// session, and nothing else.
//
// Everything here is CommonCrypto from the macOS SDK — MD5, SHA-1, SHA-256, HMAC and AES-CFB — so the project's
// no-third-party-dependencies rule holds.
//
// Why v3 is a different shape from v2c: there is no community string. Each message carries the authoritative
// engine's id, its boot count and its notion of the time, and is signed with a key derived from your password AND
// that engine id, so a key stolen from one agent is useless against another. That means a round trip of discovery
// before anything can be asked.
import Foundation
import CommonCrypto

// ================================================================ protocols

enum AuthProto: Int {
    case none = 0, md5, sha1, sha256
    /// RFC 3414 §6.3.1 and RFC 7860 §4.2: the digest is truncated, and by a different amount per protocol.
    var macLength: Int { self == .sha256 ? 24 : 12 }
    var digestLength: Int {
        switch self {
        case .none: return 0
        case .md5: return Int(CC_MD5_DIGEST_LENGTH)
        case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
        case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
        }
    }
    var name: String {
        switch self { case .none: return "none"; case .md5: return "MD5"; case .sha1: return "SHA-1"; case .sha256: return "SHA-256" }
    }
    static func named(_ s: String) -> AuthProto {
        switch s.uppercased().replacingOccurrences(of: "-", with: "") {
        case "MD5", "HMACMD5": return .md5
        case "SHA", "SHA1", "HMACSHA": return .sha1
        case "SHA256", "HMACSHA256": return .sha256
        default: return .none
        }
    }
}

enum PrivProto: Int {
    case none = 0, aes128
    var name: String { self == .aes128 ? "AES-128" : "none" }
    /// DES (RFC 3414) is deliberately absent: 56-bit keys, and every agent that offers it also offers AES.
    static func named(_ s: String) -> PrivProto {
        switch s.uppercased().replacingOccurrences(of: "-", with: "") {
        case "AES", "AES128", "AESCFB128": return .aes128
        default: return .none
        }
    }
}

struct SnmpV3User {
    var name = ""
    var authProto = AuthProto.none
    var privProto = PrivProto.none
    var authPassword = "", privPassword = ""
    var level: String {
        if authProto == .none { return "noAuthNoPriv" }
        return privProto == .none ? "authNoPriv" : "authPriv"
    }
    var usable: Bool {
        if name.isEmpty { return false }
        if authProto != .none && authPassword.isEmpty { return false }
        if privProto != .none && (privPassword.isEmpty || authProto == .none) { return false }
        return true
    }
}

// ================================================================ digests and keys

/// MD5 is deprecated by the SDK and rightly so, but HMAC-MD5-96 is what RFC 3414 specifies and what agents older
/// than RFC 7860 offer. It stays for those, and the panel names whichever was negotiated so you can see which.
private func digest(_ d: [UInt8], _ proto: AuthProto) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: proto.digestLength)
    switch proto {
    case .none: return []
    case .md5: CC_MD5(d, CC_LONG(d.count), &out)
    case .sha1: CC_SHA1(d, CC_LONG(d.count), &out)
    case .sha256: CC_SHA256(d, CC_LONG(d.count), &out)
    }
    return out
}

private func hmac(_ key: [UInt8], _ data: [UInt8], _ proto: AuthProto) -> [UInt8] {
    let alg: CCHmacAlgorithm
    switch proto {
    case .none: return []
    case .md5: alg = CCHmacAlgorithm(kCCHmacAlgMD5)
    case .sha1: alg = CCHmacAlgorithm(kCCHmacAlgSHA1)
    case .sha256: alg = CCHmacAlgorithm(kCCHmacAlgSHA256)
    }
    var out = [UInt8](repeating: 0, count: proto.digestLength)
    CCHmac(alg, key, key.count, data, data.count, &out)
    return out
}

/// RFC 3414 A.2: the password is repeated to exactly 1 MB and hashed. The million bytes are the point — they make
/// a dictionary attack on a captured message expensive, and they are why this is computed once per query, not
/// once per request.
func snmpPasswordToKey(_ password: String, _ proto: AuthProto) -> [UInt8] {
    let pw = Array(password.utf8)
    guard !pw.isEmpty, proto != .none else { return [] }
    var buf = [UInt8](repeating: 0, count: 1048576)
    for i in 0..<1048576 { buf[i] = pw[i % pw.count] }
    return digest(buf, proto)
}

/// RFC 3414 A.2 again: the key is then bound to one engine, so it is useless against any other agent.
func snmpLocalizeKey(_ ku: [UInt8], engineID: [UInt8], _ proto: AuthProto) -> [UInt8] {
    guard !ku.isEmpty, proto != .none else { return [] }
    return digest(ku + engineID + ku, proto)
}

// ================================================================ AES-128-CFB privacy (RFC 3826)

private func aesCFB(_ encrypt: Bool, key: [UInt8], iv: [UInt8], _ data: [UInt8]) -> [UInt8]? {
    guard key.count >= 16, iv.count == 16 else { return nil }
    var cryptor: CCCryptorRef? = nil
    let st = CCCryptorCreateWithMode(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), CCMode(kCCModeCFB),
                                     CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding),
                                     iv, Array(key.prefix(16)), 16, nil, 0, 0, 0, &cryptor)
    guard st == kCCSuccess, let c = cryptor else { return nil }
    defer { CCCryptorRelease(c) }
    var out = [UInt8](repeating: 0, count: data.count + 16)
    var moved = 0
    guard CCCryptorUpdate(c, data, data.count, &out, out.count, &moved) == kCCSuccess else { return nil }
    return Array(out[0..<moved])
}

/// RFC 3826 §3.1: the AES initialisation vector is the engine's boots and time followed by the 8-byte salt that
/// travels in the message, so the same plaintext never encrypts the same way twice.
private func aesIV(boots: Int, time: Int, salt: [UInt8]) -> [UInt8] {
    var iv: [UInt8] = []
    for s in [24, 16, 8, 0] { iv.append(UInt8((boots >> s) & 0xff)) }
    for s in [24, 16, 8, 0] { iv.append(UInt8((time >> s) & 0xff)) }
    return iv + salt
}

private var saltCounter = UInt64.random(in: 1...(UInt64.max / 2))
private let saltLock = NSLock()
private func nextSalt() -> [UInt8] {
    saltLock.lock(); saltCounter &+= 1; let v = saltCounter; saltLock.unlock()
    return (0..<8).map { UInt8((v >> (56 - $0 * 8)) & 0xff) }
}

// ================================================================ the engine we are talking to

struct SnmpEngine {
    var id: [UInt8] = []
    var boots = 0, time = 0
    var discoveredAt = 0.0
    /// The agent checks our time against its own within 150 seconds, so it has to advance while we work.
    var currentTime: Int { time + Int(nowSec() - discoveredAt) }
    var idText: String { "0x" + id.map { String(format: "%02x", $0) }.joined() }
}

// ================================================================ message building

private var v3MsgId: Int32 = Int32.random(in: 1000...1000000)
private let v3IdLock = NSLock()
private func nextMsgId() -> Int { v3IdLock.lock(); defer { v3IdLock.unlock() }; v3MsgId &+= 1; return Int(v3MsgId & 0x7fffffff) }

/// The USM security parameters, and where inside them the authentication digest will go. The digest is computed
/// over the whole finished message with those bytes zeroed, then spliced back in — which is why the offset matters.
private func usmParams(_ engine: SnmpEngine, _ user: SnmpV3User, salt: [UInt8], authLen: Int) -> (bytes: [UInt8], authOffset: Int) {
    var body: [UInt8] = []
    body += berTLV(BER.octet, engine.id)
    body += berInt(engine.boots)
    body += berInt(engine.currentTime)
    body += berTLV(BER.octet, Array(user.name.utf8))
    let authField = [UInt8](repeating: 0, count: authLen)
    let authTLV = berTLV(BER.octet, authField)
    let offsetInBody = body.count + (authTLV.count - authLen)
    body += authTLV
    body += berTLV(BER.octet, salt)
    let seq = berTLV(BER.sequence, body)
    return (seq, (seq.count - body.count) + offsetInBody)
}

private func scopedPDU(_ engineID: [UInt8], _ pdu: [UInt8]) -> [UInt8] {
    berTLV(BER.sequence, berTLV(BER.octet, engineID) + berTLV(BER.octet, []) + pdu)
}

/// Builds one complete v3 message, signed and encrypted as the user's security level requires.
private func buildV3(_ engine: SnmpEngine, _ user: SnmpV3User, pdu: [UInt8], msgID: Int,
                     authKey: [UInt8], privKey: [UInt8], reportable: Bool) -> [UInt8] {
    let auth = user.authProto != .none, priv = user.privProto != .none && auth
    var flags: UInt8 = reportable ? 0x04 : 0
    if auth { flags |= 0x01 }
    if priv { flags |= 0x02 }

    let global = berTLV(BER.sequence, berInt(msgID) + berInt(65507) + berTLV(BER.octet, [flags]) + berInt(3))

    var salt: [UInt8] = []
    var data: [UInt8]
    if priv {
        salt = nextSalt()
        let plain = scopedPDU(engine.id, pdu)
        guard let enc = aesCFB(true, key: privKey, iv: aesIV(boots: engine.boots, time: engine.currentTime, salt: salt), plain) else {
            return []
        }
        data = berTLV(BER.octet, enc)
    } else {
        data = scopedPDU(engine.id, pdu)
    }

    let authLen = auth ? user.authProto.macLength : 0
    let (secBytes, authOffsetInSec) = usmParams(engine, user, salt: salt, authLen: authLen)
    let secOctet = berTLV(BER.octet, secBytes)
    let secHeaderLen = secOctet.count - secBytes.count

    let version = berInt(3)
    var body = version + global + secOctet + data
    let authOffsetInBody = version.count + global.count + secHeaderLen + authOffsetInSec

    let whole = berTLV(BER.sequence, body)
    let wholeHeaderLen = whole.count - body.count
    var msg = whole

    if auth {
        let mac = hmac(authKey, msg, user.authProto)
        let at = wholeHeaderLen + authOffsetInBody
        guard at + authLen <= msg.count else { return msg }
        for i in 0..<authLen { msg[at + i] = mac[i] }
    }
    return msg
}

// ================================================================ parsing

struct V3Reply {
    var engine = SnmpEngine()
    var vars: [SnmpVar] = []
    var isReport = false
    var reportOid: [Int] = []
}

/// Walks a v3 response far enough to recover the engine parameters, decrypt the payload if need be, and read the
/// variable bindings or the report that replaced them.
private func parseV3(_ d: [UInt8], _ user: SnmpV3User, privKey: [UInt8]) -> V3Reply? {
    var r = V3Reply()
    var o = 0
    guard let top = berHeader(d, &o), top.tag == BER.sequence else { return nil }
    guard let v = berHeader(d, &o), v.tag == BER.int else { return nil }
    o += v.len
    guard let g = berHeader(d, &o), g.tag == BER.sequence else { return nil }
    let gEnd = o + g.len
    guard let mid = berHeader(d, &o), mid.tag == BER.int else { return nil }
    o += mid.len
    guard let mms = berHeader(d, &o), mms.tag == BER.int else { return nil }
    o += mms.len
    guard let fl = berHeader(d, &o), fl.tag == BER.octet, fl.len >= 1 else { return nil }
    let flags = d[o]
    o = gEnd

    guard let sp = berHeader(d, &o), sp.tag == BER.octet else { return nil }
    var so = o
    let spEnd = o + sp.len
    guard let ss = berHeader(d, &so), ss.tag == BER.sequence else { return nil }
    guard let eid = berHeader(d, &so), eid.tag == BER.octet else { return nil }
    r.engine.id = Array(d[so..<(so + eid.len)]); so += eid.len
    guard let eb = berHeader(d, &so), eb.tag == BER.int else { return nil }
    r.engine.boots = berReadInt(d, so, eb.len); so += eb.len
    guard let et = berHeader(d, &so), et.tag == BER.int else { return nil }
    r.engine.time = berReadInt(d, so, et.len); so += et.len
    guard let un = berHeader(d, &so), un.tag == BER.octet else { return nil }
    so += un.len
    guard let ap = berHeader(d, &so), ap.tag == BER.octet else { return nil }
    so += ap.len
    guard let pp = berHeader(d, &so), pp.tag == BER.octet else { return nil }
    let salt = Array(d[so..<(so + pp.len)])
    r.engine.discoveredAt = nowSec()
    o = spEnd

    // the payload: encrypted when the message says so, otherwise a scoped PDU in the clear
    var scoped: [UInt8]
    if flags & 0x02 != 0 {
        guard let enc = berHeader(d, &o), enc.tag == BER.octet else { return nil }
        let cipher = Array(d[o..<(o + enc.len)])
        guard salt.count == 8,
              let plain = aesCFB(false, key: privKey,
                                 iv: aesIV(boots: r.engine.boots, time: r.engine.time, salt: salt), cipher) else { return nil }
        scoped = plain
    } else {
        scoped = Array(d[o..<d.count])
    }

    var po = 0
    guard let sc = berHeader(scoped, &po), sc.tag == BER.sequence else { return nil }
    guard let ce = berHeader(scoped, &po), ce.tag == BER.octet else { return nil }
    po += ce.len
    guard let cn = berHeader(scoped, &po), cn.tag == BER.octet else { return nil }
    po += cn.len
    guard let pdu = berHeader(scoped, &po) else { return nil }
    r.isReport = pdu.tag == 0xA8
    guard pdu.tag == BER.getResponse || pdu.tag == 0xA8 else { return nil }
    guard let rid = berHeader(scoped, &po), rid.tag == BER.int else { return nil }
    po += rid.len
    guard let es = berHeader(scoped, &po), es.tag == BER.int else { return nil }
    po += es.len
    guard let ei = berHeader(scoped, &po), ei.tag == BER.int else { return nil }
    po += ei.len
    guard let list = berHeader(scoped, &po), list.tag == BER.sequence else { return nil }
    let listEnd = po + list.len
    while po < listEnd {
        guard let b = berHeader(scoped, &po), b.tag == BER.sequence else { break }
        let bEnd = po + b.len
        guard let oh = berHeader(scoped, &po), oh.tag == BER.oid else { break }
        var sv = SnmpVar()
        sv.oid = berReadOid(scoped, po, oh.len); po += oh.len
        guard let vh = berHeader(scoped, &po) else { break }
        sv.tag = vh.tag
        sv.raw = Array(scoped[po..<min(po + vh.len, scoped.count)])
        po = bEnd
        r.vars.append(sv)
        if r.isReport && r.reportOid.isEmpty { r.reportOid = sv.oid }
    }
    return r
}

/// A Report PDU is the agent telling us why it will not answer. These are the ones worth translating.
func snmpReportReason(_ oid: [Int]) -> String {
    let usm = [1, 3, 6, 1, 6, 3, 15, 1, 1]
    guard oid.count >= 10, Array(oid.prefix(9)) == usm else {
        if oid.count >= 9, Array(oid.prefix(8)) == [1, 3, 6, 1, 6, 3, 11, 2] { return "the agent could not parse the message" }
        return "the agent sent a report: " + oid.map(String.init).joined(separator: ".")
    }
    switch oid[9] {
    case 1: return "that security level is not supported for this user"
    case 2: return "the message was outside the agent's time window — it may have rebooted; try again"
    case 3: return "unknown user name"
    case 4: return "unknown engine id (this is normal during discovery)"
    case 5: return "wrong digest: the authentication password does not match"
    case 6: return "decryption error: the privacy password does not match"
    default: return "the agent refused the message (usmStats.\(oid[9]))"
    }
}

// ================================================================ discovery and the request

/// The first round trip of every v3 conversation: ask with no user and no security, and read the engine id, boot
/// count and time out of the report that comes back.
func snmpV3Discover(_ ip: String, port: UInt16, timeoutMs: Int = 1500) -> SnmpEngine? {
    let empty = SnmpV3User()
    let pdu = berTLV(BER.getRequest, berInt(nextMsgId()) + berInt(0) + berInt(0) + berTLV(BER.sequence, []))
    let msg = buildV3(SnmpEngine(), empty, pdu: pdu, msgID: nextMsgId(), authKey: [], privKey: [], reportable: true)
    guard !msg.isEmpty, let reply = udpAsk(ip, port, msg, timeoutMs), let r = parseV3(reply, empty, privKey: []) else { return nil }
    return r.engine.id.isEmpty ? nil : r.engine
}

/// Keys are derived from a million-byte hash, so they are computed once and carried for the whole query.
struct SnmpV3Session {
    var engine = SnmpEngine()
    var user = SnmpV3User()
    var authKey: [UInt8] = [], privKey: [UInt8] = []
    var error = ""
}

func snmpV3Open(_ ip: String, port: UInt16, user: SnmpV3User) -> SnmpV3Session {
    var s = SnmpV3Session()
    s.user = user
    guard let e = snmpV3Discover(ip, port: port) else {
        s.error = "No answer on UDP \(port). Either SNMP is off, or it does not offer v3."
        return s
    }
    s.engine = e
    if user.authProto != .none {
        s.authKey = snmpLocalizeKey(snmpPasswordToKey(user.authPassword, user.authProto), engineID: e.id, user.authProto)
    }
    if user.privProto != .none {
        // the privacy key is localized with the authentication hash, then cut to the cipher's key length
        s.privKey = snmpLocalizeKey(snmpPasswordToKey(user.privPassword, user.authProto), engineID: e.id, user.authProto)
    }
    return s
}

/// One authenticated GET or GETNEXT. Returns nil on silence, or throws the agent's own reason into `reason`.
func snmpV3Request(_ ip: String, port: UInt16, session: inout SnmpV3Session, oids: [[Int]], next: Bool,
                   timeoutMs: Int = 1500, reason: inout String) -> [SnmpVar]? {
    var bindings: [UInt8] = []
    for o in oids { bindings += berTLV(BER.sequence, berOid(o) + berTLV(BER.null, [])) }
    let reqId = nextReqIdV3()
    let pdu = berTLV(next ? BER.getNextRequest : BER.getRequest,
                     berInt(reqId) + berInt(0) + berInt(0) + berTLV(BER.sequence, bindings))
    let msg = buildV3(session.engine, session.user, pdu: pdu, msgID: nextMsgId(),
                      authKey: session.authKey, privKey: session.privKey, reportable: true)
    guard !msg.isEmpty else { reason = "could not encrypt the request"; return nil }
    guard let reply = udpAsk(ip, port, msg, timeoutMs) else { return nil }
    guard let r = parseV3(reply, session.user, privKey: session.privKey) else {
        reason = "the answer could not be decoded or decrypted"
        return nil
    }
    // an agent that has rebooted hands us its new boots/time in the report; adopt them and let the caller retry
    if r.isReport {
        session.engine.boots = r.engine.boots
        session.engine.time = r.engine.time
        session.engine.discoveredAt = nowSec()
        reason = snmpReportReason(r.reportOid)
        return nil
    }
    return r.vars
}

private var v3ReqId: Int32 = Int32.random(in: 1000...60000)
private func nextReqIdV3() -> Int { v3IdLock.lock(); defer { v3IdLock.unlock() }; v3ReqId &+= 1; return Int(v3ReqId & 0x7fffffff) }
