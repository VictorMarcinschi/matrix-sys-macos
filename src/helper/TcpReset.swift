// Closing another program's TCP connection, the way tcpkill does it: macOS has no API for that, so the helper reads the
// connection's sequence numbers from the kernel's TCP table (sysctl net.inet.tcp.pcblist64, as netstat does) and sends one
// valid RST to each end through a raw socket: remote -> local is looped back into this Mac's stack and closes the local socket
// (ECONNRESET), local -> remote tells the peer. IPv4 only: a raw IPv6 socket cannot set its own source address.
import Foundation
import Darwin

struct PcbSeq { var sndNxt: UInt32; var rcvNxt: UInt32; var state: Int32 }

func findTcp(_ la: String, _ lp: Int, _ ra: String, _ rp: Int) -> PcbSeq? {
    var len = 0
    guard sysctlbyname("net.inet.tcp.pcblist64", nil, &len, nil, 0) == 0, len > 0 else { return nil }
    len += len / 4
    var buf = [UInt8](repeating: 0, count: len)
    guard sysctlbyname("net.inet.tcp.pcblist64", &buf, &len, nil, 0) == 0 else { return nil }
    var la4 = in_addr(), ra4 = in_addr()
    guard inet_pton(AF_INET, la, &la4) == 1, inet_pton(AF_INET, ra, &ra4) == 1 else { return nil }
    return buf.withUnsafeBytes { raw -> PcbSeq? in
        var off = Int(raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self))   // xinpgen header
        while off + MemoryLayout<xtcpcb64>.size <= len {
            let xl = Int(raw.loadUnaligned(fromByteOffset: off, as: UInt32.self))
            if xl < MemoryLayout<xtcpcb64>.size { break }
            let t = raw.loadUnaligned(fromByteOffset: off, as: xtcpcb64.self)
            let i = t.xt_inpcb
            let lport = Int(UInt16(bigEndian: i.inp_lport)), fport = Int(UInt16(bigEndian: i.inp_fport))
            let l = i.inp_dependladdr.inp46_local.ia46_addr4.s_addr, f = i.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr
            if lport == lp && fport == rp && l == la4.s_addr && f == ra4.s_addr { return PcbSeq(sndNxt: t.snd_nxt, rcvNxt: t.rcv_nxt, state: t.t_state) }
            off += xl
        }
        return nil
    }
}

private func csum(_ b: [UInt8]) -> UInt16 {
    var s: UInt32 = 0; var i = 0
    while i + 1 < b.count { s += UInt32(b[i]) << 8 | UInt32(b[i + 1]); i += 2 }
    if i < b.count { s += UInt32(b[i]) << 8 }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16) }
    return ~UInt16(s)
}
/// One TCP RST with the given addresses and sequence number, sent through a raw IPv4 socket (root only).
func sendRst(src: in_addr, sport: UInt16, dst: in_addr, dport: UInt16, seq: UInt32) -> Bool {
    let fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); if fd < 0 { return false }
    defer { close(fd) }
    var one: Int32 = 1; setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, 4)
    var p = [UInt8](repeating: 0, count: 40)
    p[0] = 0x45; p[8] = 64; p[9] = 6
    // macOS raw sockets take ip_len and ip_off in host byte order
    let total = UInt16(40); p[2] = UInt8(total & 0xff); p[3] = UInt8(total >> 8)
    var s = src, d = dst
    withUnsafeBytes(of: &s) { for k in 0..<4 { p[12 + k] = $0[k] } }; withUnsafeBytes(of: &d) { for k in 0..<4 { p[16 + k] = $0[k] } }
    p[20] = UInt8(sport >> 8); p[21] = UInt8(sport & 0xff); p[22] = UInt8(dport >> 8); p[23] = UInt8(dport & 0xff)
    p[24] = UInt8(seq >> 24); p[25] = UInt8((seq >> 16) & 0xff); p[26] = UInt8((seq >> 8) & 0xff); p[27] = UInt8(seq & 0xff)
    p[32] = 0x50; p[33] = 0x04   // data offset 5, RST
    var pseudo = Array(p[12..<20]); pseudo += [0, 6, 0, 20]; pseudo += p[20..<40]
    let c = csum(pseudo); p[36] = UInt8(c >> 8); p[37] = UInt8(c & 0xff)
    var to = sockaddr_in(); to.sin_family = sa_family_t(AF_INET); to.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); to.sin_addr = dst
    let n = p.withUnsafeBytes { b in withUnsafePointer(to: &to) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, b.baseAddress, 40, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } }
    return n == 40
}
/// Resets one IPv4 TCP connection. Returns nil on success, otherwise the reason.
func resetConnection(_ la: String, _ lp: Int, _ ra: String, _ rp: Int) -> String? {
    if la.contains(":") || ra.contains(":") { return "IPv6" }
    guard let pcb = findTcp(la, lp, ra, rp) else { return "not in the TCP table any more" }
    var l = in_addr(), r = in_addr(); inet_pton(AF_INET, la, &l); inet_pton(AF_INET, ra, &r)
    let a = sendRst(src: r, sport: UInt16(rp), dst: l, dport: UInt16(lp), seq: pcb.rcvNxt)   // closes the local socket
    let b = sendRst(src: l, sport: UInt16(lp), dst: r, dport: UInt16(rp), seq: pcb.sndNxt)   // tells the peer
    usleep(150_000)
    if findTcp(la, lp, ra, rp) == nil || !a { return a || b ? nil : "raw socket send failed" }
    return a ? nil : "raw socket send failed"
}
