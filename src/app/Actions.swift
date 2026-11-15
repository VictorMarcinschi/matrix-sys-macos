// Actions: every control goes through one dispatcher keyed "act:<verb>:<target>". requestAction() applies the guards and opens the
// red confirmation for anything dangerous; performAction() does the work and reports through a toast.
import AppKit
import Darwin

func async(_ f: @escaping () -> Void) { Thread { f() }.start() }
func procLabel(_ pid: Int32) -> String { "\(S?.get(pid)?.name ?? "process") (pid \(pid))" }
func helperUp() -> Bool { Model.shared.helperConnected }

/// Processes whose loss takes macOS down with them, or that are this app and its helper, are never touched.
func procCritical(_ pid: Int32, _ why: inout String) -> Bool {
    if pid <= 1 { why = pid == 0 ? "kernel_task is the kernel itself." : "launchd is the root of every process; killing it panics the Mac."; return true }
    if pid == getpid() { why = "that is MatrixSys itself — use Quit instead."; return true }
    if let p = S?.get(pid) {
        if p.name == "MatrixSys" || p.path.hasSuffix("/MatrixSys") { why = "that is a MatrixSys instance — use Quit instead."; return true }
        if p.name == "com.matrixsys.helper" { why = "that is the MatrixSys helper — remove it with Uninstall helper instead."; return true }
        if criticalNames.contains(p.name) { why = "stopping \(p.name) would crash, hang or log out this Mac."; return true }
    }
    return false
}
func treeOf(_ pid: Int32, _ out: inout [Int32], _ depth: Int = 0) {
    guard let S = S else { return }
    if depth < 64 { for p in S.procs where p.ppid == pid && p.pid != pid { treeOf(p.pid, &out, depth + 1) } }
    out.append(pid)   // children first
}
/// Sends a signal; falls back to the helper for processes of other users.
func signalProc(_ pid: Int32, _ sig: Int32) -> (Bool, String) {
    if kill(pid, sig) == 0 { return (true, "") }
    let e = errno
    if e == ESRCH { return (false, "it is no longer running") }
    if e == EPERM {
        if helperUp(), let r = Model.shared.helperRequest("SIG\t\(pid)\t\(sig)"), let f = r.first {
            if f == "OK" { return (true, "") }; return (false, String(f.dropFirst(4)))
        }
        return (false, "it belongs to another user — needs the helper (FULL ACCESS)")
    }
    return (false, String(cString: strerror(e)))
}
func prioOf(_ p: ProcInfo) -> String {
    let bg = getpriority(PRIO_DARWIN_PROCESS, id_t(p.pid))
    return "nice \(p.nice)" + (bg > 0 ? " · background (E-cores, throttled I/O)" : "")
}

struct Conn4 { var la: String; var lp: Int; var ra: String; var rp: Int }
func connsFor(_ pid: Int32, _ host: String) -> [Conn4] {
    var out: [Conn4] = []
    for (p, rs) in SM_remote where pid < 0 || p == pid { for c in rs where c.proto == "TCP" && c.st != "recent" && (host.isEmpty || c.ra == host) { out.append(Conn4(la: c.la, lp: c.lp, ra: c.ra, rp: c.rp)) } }
    return out
}
func closeConns(_ cs: [Conn4]) {
    async {
        let spec = cs.map { "\($0.la)|\($0.lp)|\($0.ra)|\($0.rp)" }.joined(separator: ",")
        guard let r = Model.shared.helperRequest("PF\tkill\t" + spec), let f = r.first else { toast("The helper did not answer", .red); return }
        if f.hasPrefix("OK") {
            let n = f.split(separator: " ").dropFirst().compactMap { Int($0) }
            let ok = n.first ?? 0, v6 = n.count > 1 ? n[1] : 0, bad = n.count > 2 ? n[2] : 0
            toast("Closed \(ok) connection(s) with a TCP reset" + (v6 > 0 ? ", \(v6) IPv6 blocked by pf for 8 s (they time out instead)" : "") + (bad > 0 ? ", \(bad) already gone" : ""), bad > 0 || v6 > 0 ? .warn : .safe)
        }
        else { toast("pf refused: " + f, .red) }
        Firewall.shared.refresh()
    }
}

// ------------------------------------------------------------ request: guards and confirmation
func requestAction(_ key: String) {
    let body = key.dropFirst(4); let verb = String(body.prefix { $0 != ":" }); let rest = String(body.dropFirst(verb.count + 1))
    var why = ""; cf = Confirm(); cf.key = key
    let pid = Int32(rest.prefix { $0 != ":" }) ?? -1
    let arg = rest.contains(":") ? String(rest[rest.index(after: rest.firstIndex(of: ":")!)...]) : ""
    switch verb {
    // ---- immediate
    case "copy": NSPasteboard.general.clearContents(); NSPasteboard.general.setString(rest, forType: .string); toast("Copied " + rest, .safe)
    case "reveal":
        if rest.isEmpty { toast("No path known for this process", .warn) } else { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: rest)]) }
    case "openf": NSWorkspace.shared.open(URL(fileURLWithPath: rest))
    case "terminal":
        let url = URL(fileURLWithPath: rest)
        NSWorkspace.shared.open([url], withApplicationAt: URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app"), configuration: NSWorkspace.OpenConfiguration()) { _, e in if let e = e { toast("Terminal: " + e.localizedDescription, .red) } }
    case "whois": if validIp(rest) { Whois.shared.lookup(rest) }
    case "ping": ping(rest)
    // ---- LAN view. Nothing here stores a credential; the two that send many packets ask first.
    case "lanname": Lan.shared.askName(rest)
    case "lannames": Lan.shared.askAllNames()
    case "lanwake": Lan.shared.wake(rest)
    case "lanrouter": Lan.shared.queryRouter(rest)
    case "lansnmp": Lan.shared.querySnmp(rest)
    case "lancancel": Lan.shared.cancel(); toast("Stopping", .warn)
    case "lanadmin":
        let open = Set(lanHost(rest)?.openPorts.map { $0.port } ?? [])
        var url = "http://" + rest
        if open.contains(443) { url = "https://" + rest }
        else if open.contains(8443) { url = "https://\(rest):8443" }
        else if open.contains(80) { url = "http://" + rest }
        else if open.contains(8080) { url = "http://\(rest):8080" }
        else if open.contains(81) { url = "http://\(rest):81" }
        if let u = URL(string: url) { NSWorkspace.shared.open(u); toast("Opened " + url + " in your browser", .safe) }
    case "lanopen":
        let f = rest.split(separator: ":")
        if f.count == 2, let p = Int(f[1]) {
            let scheme = (p == 443 || p == 8443) ? "https" : "http"
            let url = scheme + "://" + f[0] + ((p == 80 || p == 443) ? "" : ":\(p)")
            if let u = URL(string: url) { NSWorkspace.shared.open(u); toast("Opened " + url + " in your browser", .safe) }
        }
    case "lanssh":
        openInTerminal("ssh \(rest)", "ssh-" + rest)
    case "lantelnet":
        let hasTelnet = FileManager.default.isExecutableFile(atPath: "/usr/bin/telnet")
        openInTerminal(hasTelnet ? "telnet \(rest) 23" : "nc \(rest) 23", "telnet-" + rest)
        if !hasTelnet { toast("macOS has no telnet; opened nc instead", .warn) }
    case "lantrace":
        trInput = rest; trInputChanged(); setView(6); trGo(false)
    case "lantraceport":
        let f = rest.split(separator: ":")
        if f.count == 2 { trInput = "tcp://" + f[0] + ":" + f[1]; trInputChanged(); setView(6); trGo(false) }
    // ---- LAN view, with a confirmation: these are the only things in MatrixSys that address machines you did not type
    case "lansweep", "lansweepnames":
        guard let i = lanInterfaces().first(where: { $0.name == rest }) else { toast("No such network: " + rest, .warn); return }
        if i.hosts <= 0 || i.hosts > LAN_SWEEP_MAX {
            toast("Refusing to sweep \(i.cidrText): \(i.hosts) addresses, limit \(LAN_SWEEP_MAX)", .warn); return
        }
        cf.title = verb == "lansweepnames" ? "Sweep \(i.cidrText) and ask every name?" : "Sweep \(i.cidrText)?"
        cf.detail = "Sends one ICMP echo to each of the \(i.hosts) addresses on \(rest), then reads the ARP table again. Hosts that ignore the ping are still found."
            + (verb == "lansweepnames" ? " Then one mDNS and one NetBIOS query to each machine found." : "")
        cf.warn = "This is visible to every machine on the network and to anything watching it. Some workplaces forbid it."
        cf.yes = "SWEEP"; cf.red = false; cf.open = true
    case "lanscan", "lanscanadmin", "lanscanlow", "lanscanfull":
        let set = verb == "lanscanadmin" ? "admin" : verb == "lanscanlow" ? "low" : verb == "lanscanfull" ? "full" : "common"
        let n = lanPortSet(set).count
        cf.title = "Scan \(n) TCP ports on \(rest)?"
        cf.detail = "Opens one connection per port. An open port is asked what it is — the greeting it sends by itself, or a plain GET on a web port. Nothing is sent to a closed port."
            + (n > 4096 ? " Every port from 1 to 65535 takes a few minutes; the panel counts down and STOP ends it." : "")
        cf.warn = "A port scan is visible to the target and to anything watching the network."
            + (n > 4096 ? " A full-range scan is the loudest thing MatrixSys does." : "")
        cf.yes = "SCAN"; cf.red = false; cf.open = true
    case "front":
        if let a = NSRunningApplication(processIdentifier: pid) { a.unhide(); if !a.activate(options: [.activateAllWindows]) { toast("\(procLabel(pid)) did not come to the front", .warn) } } else { toast(procLabel(pid) + " has no windows", .warn) }
    case "quit":
        if let a = NSRunningApplication(processIdentifier: pid) { if a.terminate() { toast("Asked " + procLabel(pid) + " to quit (it may ask to save)", .safe) } else { toast(procLabel(pid) + " refused the quit request", .warn) } }
    case "suspend", "resume":
        let res = verb == "resume"
        if !res && procCritical(pid, &why) { toast("Not suspended: " + why, .red); return }
        let (ok, err) = signalProc(pid, res ? SIGCONT : SIGSTOP)
        toast(ok ? (res ? "Resumed " : "Suspended ") + procLabel(pid) + (res ? "" : " — it is frozen until you resume it") : "Could not \(res ? "resume" : "suspend") \(procLabel(pid)): \(err)", ok ? .safe : .red)
    case "prio":
        let lv = max(0, min(4, Int(arg) ?? 2)); let nice: Int32 = [19, 10, 0, -5, -10][lv]
        async {
            var ok = setpriority(PRIO_PROCESS, id_t(pid), nice) == 0; var err = ok ? "" : String(cString: strerror(errno))
            if !ok && helperUp(), let r = Model.shared.helperRequest("PRIO\t\(pid)\t\(nice)"), let f = r.first { ok = f == "OK"; err = ok ? "" : String(f.dropFirst(4)) }
            else if !ok && nice < 0 { err = "raising priority needs the helper (FULL ACCESS)" }
            toast(ok ? "Priority of \(procLabel(pid)) set to nice \(nice)" : "Could not change the priority of \(procLabel(pid)): \(err)", ok ? .safe : .red)
        }
    case "bg":
        let on = arg == "1"
        var ok = setpriority(PRIO_DARWIN_PROCESS, id_t(pid), on ? PRIO_DARWIN_BG : 0) == 0
        if !ok && helperUp(), let r = Model.shared.helperRequest("BG\t\(pid)\t\(on ? 1 : 0)") { ok = r.first == "OK" }
        toast(ok ? (on ? "\(procLabel(pid)) clamped to background: efficiency cores, throttled disk and network" : "\(procLabel(pid)) back to normal scheduling") : "Could not change \(procLabel(pid)) — not your process; the helper can do it", ok ? .safe : .red)
    case "sample":
        let out = NSTemporaryDirectory() + "MatrixSys-sample-\(pid).txt"
        toast("Sampling \(procLabel(pid)) for 3 s…", .text)
        async {
            let (st, txt) = run("/usr/bin/sample", ["\(pid)", "3", "-file", out], timeout: 30)
            if st == 0 { toast("Sample written to \(out)", .safe); DispatchQueue.main.async { NSWorkspace.shared.open(URL(fileURLWithPath: out)) } }
            else { toast("sample failed: " + (txt.split(separator: "\n").last.map(String.init) ?? "error \(st)"), .red) }
        }
    case "dkrescan1": Disks.shared.rescan(rest); toast("Rescanning " + rest, .safe)
    case "helperinstall": Helper.install(boot: rest == "1")
    case "fda": NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
    case "sysinfo": NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/System Information.app"))
    case "flushdns":
        if !helperUp() { cf.title = "Flush the DNS cache?"; cf.warn = "Clears cached host names (dscacheutil + mDNSResponder)."; cf.needHelper = true; cf.red = false; cf.open = true; return }
        async { let r = Model.shared.helperRequest("FLUSHDNS"); toast(r?.first == "OK" ? "DNS cache flushed" : "Could not flush the DNS cache", r?.first == "OK" ? .safe : .red) }
    // ---- confirmation first
    case "term", "kill", "killtree":
        if procCritical(pid, &why) { toast("Not ended: " + why, .red); return }
        var t: [Int32] = []; treeOf(pid, &t); let tree = verb == "killtree"
        cf.title = (tree ? "Kill the process tree of " : verb == "term" ? "Terminate " : "Kill ") + procLabel(pid) + "?"
        cf.warn = verb == "term" ? "WARNING: SIGTERM asks the process to exit now. Well-behaved programs clean up first, but unsaved work in them is lost."
            : "DANGER: " + (tree ? "all \(t.count) processes are" : "the process is") + " killed immediately (SIGKILL), with no chance to save or clean up. Unsaved work is lost and open files may be left damaged."
        cf.detail = tree ? "Includes every child process started by it." : t.count > 1 ? "Its \(t.count - 1) child process(es) keep running." : ""
        if NSRunningApplication(processIdentifier: pid) != nil && verb != "killtree" { cf.detail += (cf.detail.isEmpty ? "" : " ") + "This is an app: QUIT asks it to close properly first." }
        cf.yes = tree ? "KILL TREE" : verb == "term" ? "TERMINATE" : "KILL"; cf.open = true
    case "closeconn", "closeproc", "closehost":
        cf.needHelper = !helperUp(); cf.yes = "CLOSE"
        if verb == "closeconn" { cf.title = "Close this connection?"; cf.detail = "local / remote: " + rest.replacingOccurrences(of: "|", with: " ") }
        else {
            let cs = verb == "closeproc" ? connsFor(pid, "") : connsFor(-1, rest)
            if cs.isEmpty { toast("No open TCP connections to close", .warn); return }
            cf.title = "Close \(cs.count) connection(s) " + (verb == "closeproc" ? "of " + procLabel(pid) : "to " + rest) + "?"; cf.yes = "CLOSE ALL"
        }
        cf.warn = "WARNING: connections are cut immediately with a TCP reset sent to both ends (macOS has no call for this; the helper does what tcpkill does). The application sees a network error; downloads, calls or unsaved online work in progress can be lost. It may simply reconnect."
        cf.open = true
    case "fwblock":
        guard validIp(rest) else { return }
        cf.title = "Block all traffic with \(rest)?"; cf.warn = "DANGER: this adds pf firewall rules that cut this Mac off from that address, in both directions and for every program, until you unblock it. Sites and services hosted there stop working."
        cf.detail = "Rules live in the pf anchor \(PF_ANCHOR). Remove them from the Network panel or with the uninstaller."; cf.yes = "BLOCK HOST"; cf.needHelper = !helperUp(); cf.open = true
    case "fwblockport":
        guard let port = Int(arg), port > 0, port < 65536 else { return }
        let udp = rest.hasPrefix("UDP")
        cf.title = "Block inbound \(udp ? "UDP" : "TCP") port \(port)?"
        cf.warn = "DANGER: this adds a pf rule so that nothing from the network can reach this port. Whatever relies on it (file sharing, screen sharing, AirPlay, a server you run) stops accepting connections from other machines."
        cf.detail = "Remove it again from the Network panel."; cf.yes = "BLOCK PORT"; cf.needHelper = !helperUp(); cf.open = true
    case "fwunblock": cf.title = "Remove the pf rule \"\(rest)\"?"; cf.warn = "WARNING: the traffic this rule was blocking is allowed again."; cf.yes = "UNBLOCK"; cf.needHelper = !helperUp(); cf.open = true
    case "fwflush": cf.title = "Remove every MatrixSys firewall rule?"; cf.warn = "WARNING: all hosts and ports blocked from MatrixSys are allowed again."; cf.yes = "REMOVE ALL"; cf.needHelper = !helperUp(); cf.open = true
    case "svcstop", "svcrestart":
        let re = verb == "svcrestart"; let label = String(rest.split(separator: "/").last ?? "")
        let essential = ["com.apple.WindowServer", "com.apple.loginwindow", "com.apple.logd", "com.apple.configd", "com.apple.notifyd", "com.apple.opendirectoryd",
                         "com.apple.securityd", "com.apple.diskarbitrationd", "com.apple.coreservicesd", "com.apple.runningboardd", "com.apple.launchservicesd", HELPER_LABEL]
        if essential.contains(label) { toast("Not \(re ? "restarted" : "stopped"): macOS cannot run without \(label).", .red); return }
        let system = rest.hasPrefix("system/")
        cf.title = (re ? "Restart" : "Stop") + " the launchd job \(label)?"
        cf.warn = "DANGER: everything that depends on this job stops working " + (re ? "while it restarts" : "until launchd starts it again — for most jobs that is the next time something asks for it, or the next login") + ". Stopping system jobs can break networking, sign-in, audio, printing or updates."
        cf.detail = "launchctl " + (re ? "kickstart -k " : "kill SIGTERM ") + rest; cf.yes = re ? "RESTART JOB" : "STOP JOB"; cf.needHelper = system && !helperUp(); cf.open = true
    case "trash":
        if trashRefuse(rest, &why) { toast("Not moved: " + why, .red); return }
        cf.title = "Move this folder to the Trash?"
        cf.warn = "DANGER: the whole folder and everything inside it is moved to the Trash. Programs that depend on it will break. It can be put back from the Trash until the Trash is emptied."
        cf.detail = rest; cf.yes = "MOVE TO TRASH"; cf.open = true
    case "emptytrash":
        let (n, sz) = trashInfo()
        cf.title = "Empty the Trash?"
        cf.warn = "DANGER: this permanently deletes everything in the Trash" + (n >= 0 ? " (\(n) item(s), \(fmtB(Double(sz))))" : "") + ". It cannot be undone."
        cf.detail = "Finder empties it; macOS asks once whether MatrixSys may control Finder."; cf.yes = "EMPTY TRASH"; cf.open = true
    case "eject":
        if rest == "/" || rest.hasPrefix("/System/Volumes") { toast("Not ejected: that is the startup volume.", .red); return }
        cf.title = "Eject \(rest)?"; cf.warn = "WARNING: the volume is unmounted and ejected. Data that a program has not finished writing to it can be lost; programs with open files on it may refuse."
        cf.yes = "EJECT"; cf.red = false; cf.open = true
    case "ifdown", "ifup":
        let down = verb == "ifdown"
        if down && Devices.shared.isPrimary(rest) { cf.detail = "This is the interface of your default route: the Mac loses its internet connection." }
        cf.title = (down ? "Turn off " : "Turn on ") + "network interface \(rest)?"
        cf.warn = down ? "DANGER: every connection through \(rest) drops at once and the interface stays down until you turn it on here, or until restart." : "The interface is brought up again (ifconfig up)."
        cf.yes = down ? "INTERFACE DOWN" : "INTERFACE UP"; cf.red = down; cf.needHelper = !helperUp(); cf.open = true
    default: toast("Unknown action " + verb, .warn)
    }
}

// ------------------------------------------------------------ perform
func performAction(_ key: String) {
    let body = key.dropFirst(4); let verb = String(body.prefix { $0 != ":" }); let rest = String(body.dropFirst(verb.count + 1))
    let pid = Int32(rest.prefix { $0 != ":" }) ?? -1
    let arg = rest.contains(":") ? String(rest[rest.index(after: rest.firstIndex(of: ":")!)...]) : ""
    var why = ""
    switch verb {
    case "term", "kill":
        if procCritical(pid, &why) { return }
        let (ok, err) = signalProc(pid, verb == "term" ? SIGTERM : SIGKILL)
        toast(ok ? (verb == "term" ? "Sent SIGTERM to " : "Killed ") + procLabel(pid) : "Could not end \(procLabel(pid)): \(err)", ok ? .safe : .red)
    case "killtree":
        var t: [Int32] = []; treeOf(pid, &t); var ok = 0, fail = 0
        for q in t { if procCritical(q, &why) { fail += 1; continue }; if signalProc(q, SIGKILL).0 { ok += 1 } else { fail += 1 } }
        toast("Killed \(ok) process(es) in the tree of \(procLabel(pid))" + (fail > 0 ? ", \(fail) could not be ended" : ""), fail > 0 ? .warn : .safe)
    case "closeconn":
        let a = rest.split(separator: "|").map(String.init); if a.count == 4 { closeConns([Conn4(la: a[0], lp: Int(a[1]) ?? 0, ra: a[2], rp: Int(a[3]) ?? 0)]) }
    case "closeproc": closeConns(connsFor(pid, ""))
    case "closehost": closeConns(connsFor(-1, rest))
    case "fwblock", "fwblockport", "fwunblock", "fwflush":
        let cmd = verb == "fwblock" ? "block\t" + rest : verb == "fwblockport" ? "blockport\t" + rest : verb == "fwunblock" ? "unblock\t" + rest : "flush"
        async {
            let r = Model.shared.helperRequest("PF\t" + cmd)
            let f = r?.first ?? "ERR the helper did not answer"
            toast(f.hasPrefix("OK") ? (verb == "fwblock" ? "Blocked \(rest) with pf" : verb == "fwblockport" ? "Blocked inbound \(rest)" : verb == "fwflush" ? "Removed all MatrixSys pf rules" : "Removed the rule \(rest)") : "pf refused: " + f.dropFirst(4), f.hasPrefix("OK") ? .safe : .red)
            Firewall.shared.refresh()
        }
    case "svcstop", "svcrestart":
        let re = verb == "svcrestart"; let system = rest.hasPrefix("system/")
        async {
            let args = re ? ["kickstart", "-k", rest] : ["kill", "SIGTERM", rest]
            var st: Int32 = -1, out = ""
            if system { if let r = Model.shared.helperRequest("LAUNCHCTL\t" + args.joined(separator: "\t")) { st = r.first == "OK" ? 0 : 1; out = r.dropFirst().joined(separator: " ") } }
            else { (st, out) = run("/bin/launchctl", args) }
            toast(st == 0 ? (re ? "Restarted " : "Stopped ") + rest : "launchctl failed: " + out.trimmingCharacters(in: .whitespacesAndNewlines), st == 0 ? .safe : .red)
        }
    case "trash":
        if trashRefuse(rest, &why) { return }
        do { try FileManager.default.trashItem(at: URL(fileURLWithPath: rest), resultingItemURL: nil); toast("Moved \(rest) to the Trash", .safe); Disks.shared.rescan((rest as NSString).deletingLastPathComponent) }
        catch { toast("Not moved: " + error.localizedDescription, .red) }
    case "emptytrash":
        async {
            var err: NSDictionary? = nil
            DispatchQueue.main.sync { _ = NSAppleScript(source: "tell application \"Finder\" to empty trash")?.executeAndReturnError(&err) }
            if let e = err { toast("Trash not emptied: " + ((e[NSAppleScript.errorMessage] as? String) ?? "Finder refused"), .red) } else { toast("Trash emptied", .safe) }
        }
    case "eject":
        async { let (st, out) = run("/usr/sbin/diskutil", ["eject", rest], timeout: 60)
            toast(st == 0 ? "Ejected \(rest) — safe to unplug" : "Could not eject: " + out.trimmingCharacters(in: .whitespacesAndNewlines), st == 0 ? .safe : .red) }
    case "ifdown", "ifup":
        async { let r = Model.shared.helperRequest("IFACE\t\(rest)\t\(verb == "ifdown" ? "down" : "up")")
            toast(r?.first == "OK" ? "\(rest) is \(verb == "ifdown" ? "down" : "up")" : "ifconfig failed: " + (r?.first ?? "no answer"), r?.first == "OK" ? .safe : .red) }
    case "flushdns": requestAction(key)
    case "lansweep": Lan.shared.sweep(rest)
    case "lansweepnames": Lan.shared.askAllNames(rest)
    case "lanscan": Lan.shared.scan(rest, LAN_PORTS_COMMON)
    case "lanscanadmin": Lan.shared.scan(rest, LAN_PORTS_ADMIN)
    case "lanscanlow": Lan.shared.scan(rest, LAN_PORTS_LOW)
    case "lanscanfull": Lan.shared.scan(rest, LAN_PORTS_ALL)
    case "helperinstall": Helper.install(boot: rest == "1")
    default: _ = arg
    }
}

// ------------------------------------------------------------ helpers for actions
/// Hands a command to Terminal by writing a .command file and opening it. No Apple events, so no Automation
/// permission, and no credential ever passes through MatrixSys: whatever the command asks for, you type there.
func openInTerminal(_ cmd: String, _ name: String) {
    let dir = NSTemporaryDirectory() + "matrixsys"
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let safe = name.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." ? $0 : "-" }.map(String.init).joined()
    let path = dir + "/" + safe + ".command"
    let body = "#!/bin/sh\n# written by MatrixSys; it only runs what is on the next line\nexec " + cmd + "\n"
    guard (try? body.write(toFile: path, atomically: true, encoding: .utf8)) != nil else { toast("Could not write the command file", .red); return }
    chmod(path, 0o700)
    NSWorkspace.shared.open(URL(fileURLWithPath: path))
    toast("Opened Terminal: " + cmd, .safe)
}

func ping(_ ip: String) {
    async {
        let v6 = ip.contains(":")
        let (st, out) = run(v6 ? "/sbin/ping6" : "/sbin/ping", v6 ? ["-c", "1", "-i", "1", ip] : ["-c", "1", "-t", "2", ip], timeout: 5)
        if st == 0, let r = out.range(of: "time=") { toast("\(ip) replied in " + String(out[r.upperBound...].prefix { $0 != "\n" }), .safe) }
        else { toast("\(ip) did not reply to ping", .warn) }
    }
}
func trashRefuse(_ path: String, _ why: inout String) -> Bool {
    let home = NSHomeDirectory()
    let p = (path as NSString).standardizingPath
    if p == "/" || p.split(separator: "/").count < 2 && !p.hasPrefix("/Volumes") { why = "a top-level system folder cannot be deleted here."; return true }
    for s in ["/System", "/usr", "/bin", "/sbin", "/private", "/Library", "/Applications", "/etc", "/var", "/cores", "/opt", "/dev", "/Volumes", "/Users", home, home + "/Library", home + "/Documents", home + "/Desktop"] where p == s {
        why = "it is a system folder that macOS and your programs rely on."; return true }
    for s in ["/System/", "/usr/", "/bin/", "/sbin/", "/private/var/db/"] where p.hasPrefix(s) && !p.hasPrefix("/usr/local/") { why = "it is part of macOS (protected by SIP)."; return true }
    if p.hasPrefix("/System/Volumes/") && p.split(separator: "/").count <= 4 { why = "it is a volume mount point."; return true }
    if Disks.shared.isMountPoint(p) { why = "it is a whole volume — eject it instead."; return true }
    return false
}
func trashInfo() -> (Int, UInt64) {
    let t = NSHomeDirectory() + "/.Trash"
    guard let items = try? FileManager.default.contentsOfDirectory(atPath: t) else { return (-1, 0) }
    var sz: UInt64 = 0
    if let en = FileManager.default.enumerator(at: URL(fileURLWithPath: t), includingPropertiesForKeys: [.totalFileAllocatedSizeKey]) {
        for case let u as URL in en { sz += UInt64((try? u.resourceValues(forKeys: [.totalFileAllocatedSizeKey]).totalFileAllocatedSize) ?? 0) }
    }
    return (items.filter { $0 != ".DS_Store" }.count, sz)
}

// ------------------------------------------------------------ reverse DNS (background, cached) and whois (on demand only)
final class DNS {
    static let shared = DNS()
    private let lock = NSLock(); private var names: [String: String] = [:]; private var queue: [String] = []; private var started = false
    /// "" = pending, "-" = no name
    func lookup(_ ip: String) -> String {
        lock.lock(); defer { lock.unlock() }
        if let n = names[ip] { return n }
        names[ip] = ""; queue.append(ip)
        if !started { started = true; for _ in 0..<2 { Thread { self.worker() }.start() } }
        return ""
    }
    private func worker() {
        while true {
            lock.lock(); let ip = queue.isEmpty ? nil : queue.removeFirst(); lock.unlock()
            guard let ip = ip else { usleep(100000); continue }
            var r = "-"
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            var a4 = sockaddr_in(), a6 = sockaddr_in6()
            if inet_pton(AF_INET, ip, &a4.sin_addr) == 1 {
                a4.sin_family = sa_family_t(AF_INET); a4.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                if withUnsafePointer(to: &a4, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) } }) == 0 { r = String(cString: host) }
            } else if inet_pton(AF_INET6, ip, &a6.sin6_addr) == 1 {
                a6.sin6_family = sa_family_t(AF_INET6); a6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                if withUnsafePointer(to: &a6, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in6>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) } }) == 0 { r = String(cString: host) }
            }
            lock.lock(); names[ip] = r; lock.unlock()
        }
    }
}
final class Whois {
    static let shared = Whois()
    private let lock = NSLock(); private var res: [String: String] = [:]
    static let RIR = ["whois.arin.net", "whois.ripe.net", "whois.apnic.net", "whois.lacnic.net", "whois.afrinic.net"]
    func result(_ ip: String) -> String? { lock.lock(); defer { lock.unlock() }; return res[ip] }
    func lookup(_ ip: String) {
        lock.lock(); if let r = res[ip], r != "lookup failed (no answer from the registry)" { lock.unlock(); return }; res[ip] = "looking up…"; lock.unlock()
        async {
            let r = Whois.query("whois.iana.org", ip)
            let ref = Whois.field(r, ["refer", "whois"]).lowercased()
            var t = r
            if Whois.RIR.contains(ref) { t = Whois.query(ref, (ref == "whois.arin.net" ? "n + " : "") + ip) }   // only follow referrals to the five registries
            let org = Whois.field(t, ["orgname", "org-name", "organization", "organisation", "owner", "descr", "netname"]), cc = Whois.field(t, ["country"])
            let out = t.isEmpty ? "lookup failed (no answer from the registry)" : org.isEmpty ? "no owner record found" : org + (cc.isEmpty ? "" : " (\(cc))")
            self.lock.lock(); self.res[ip] = out; self.lock.unlock()
        }
    }
    static func query(_ server: String, _ q: String) -> String {
        var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM; var ai: UnsafeMutablePointer<addrinfo>? = nil
        guard getaddrinfo(server, "43", &hints, &ai) == 0, let a = ai else { return "" }
        defer { freeaddrinfo(ai) }
        let s = socket(a.pointee.ai_family, SOCK_STREAM, IPPROTO_TCP); if s < 0 { return "" }
        defer { close(s) }
        var tv = timeval(tv_sec: 6, tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size)); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1; setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)
        guard connect(s, a.pointee.ai_addr, a.pointee.ai_addrlen) == 0 else { return "" }
        _ = writeAll(s, q + "\r\n")
        var out = [UInt8](); var b = [UInt8](repeating: 0, count: 4096)
        while out.count < 65536 { let n = recv(s, &b, 4096, 0); if n <= 0 { break }; out += b[0..<n] }
        return String(decoding: out, as: UTF8.self)
    }
    static func field(_ txt: String, _ keys: [String]) -> String {
        for k in keys {
            for line in txt.split(separator: "\n") {
                guard let c = line.firstIndex(of: ":") else { continue }
                if line[..<c].trimmingCharacters(in: .whitespaces).lowercased() != k { continue }
                let v = line[line.index(after: c)...].trimmingCharacters(in: .whitespacesAndNewlines)
                if !v.isEmpty { return v }
            }
        }
        return ""
    }
}

// ------------------------------------------------------------ pf rules owned by MatrixSys (kept by the helper)
final class Firewall {
    static let shared = Firewall()
    private let lock = NSLock(); private var rules: [String] = []; private var lastT = -100.0
    func list() -> [String] {
        lock.lock(); let r = rules, t = lastT; lock.unlock()
        if helperUp() && nowSec() - t > 10 { refresh() }
        return r
    }
    func refresh() {
        lock.lock(); lastT = nowSec(); lock.unlock()
        async { let r = Model.shared.helperRequest("PF\tlist") ?? []
            self.lock.lock(); self.rules = r.filter { $0.hasPrefix("block ") }; self.lock.unlock() }
    }
}

// ------------------------------------------------------------ launchd jobs by pid
final class LaunchJobs {
    static let shared = LaunchJobs()
    struct Job { var domain: String; var label: String }
    private let lock = NSLock(); private var map: [Int32: Job] = [:]; private var lastT = -100.0; private var busy = false
    func label(for pid: Int32) -> Job? {
        lock.lock(); defer { lock.unlock() }
        if nowSec() - lastT > 15 && !busy { busy = true; async { self.load() } }
        return map[pid]
    }
    private func load() {
        var m: [Int32: Job] = [:]
        let uid = getuid()
        func parse(_ txt: String, _ domain: String) {
            for line in txt.split(separator: "\n").dropFirst() {
                let f = line.split(separator: "\t"); if f.count >= 3, let pid = Int32(f[0]) { m[pid] = Job(domain: domain, label: String(f[2])) }
            }
        }
        parse(run("/bin/launchctl", ["list"]).1, "gui/\(uid)")
        if helperUp(), let r = Model.shared.helperRequest("LAUNCHCTL\tlist") { parse(r.joined(separator: "\n"), "system") }
        lock.lock(); map = m; lastT = nowSec(); busy = false; lock.unlock()
    }
}
