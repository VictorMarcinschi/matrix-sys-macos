// Installing, starting and removing the privileged helper.
// A running Mac app cannot raise its own privileges. With an ad-hoc signature SMAppService cannot register a daemon,
// so the helper is installed as a classic LaunchDaemon by a script run once with your administrator password
// (the standard macOS authorisation prompt, through `do shell script … with administrator privileges`).
import AppKit

enum Helper {
    static var bundledHelper: String { (Bundle.main.executablePath.map { ($0 as NSString).deletingLastPathComponent } ?? "") + "/com.matrixsys.helper" }
    static var installScript: String { Bundle.main.path(forResource: "install-helper", ofType: "sh") ?? "" }
    static var uninstallScript: String { Bundle.main.path(forResource: "uninstall", ofType: "sh") ?? "" }

    static func offerInstall() {
        cf = Confirm(); cf.red = false
        cf.title = "Give MatrixSys full access?"
        cf.warn = "This installs a small helper that runs as root (a LaunchDaemon) and asks for your administrator password once. It adds: real packet capture attributed to processes, memory, disk and file counters of every process, per-file disk I/O, process memory reading, pf firewall rules, and actions on other users' processes."
        cf.detail = "The helper only counts packets. Packet contents are read by this app itself, and only while the packet viewer is open. It listens on a local socket that only admins and the logged-in user may use. Remove it any time from the menu bar: Uninstall Helper."
        cf.key = "act:helperinstall:0"; cf.yes = "START NOW (UNTIL RESTART)"; cf.extra = [("START NOW AND AT EVERY BOOT", "act:helperinstall:1")]
        cf.open = true
    }
    static func install(boot: Bool) {
        guard FileManager.default.isExecutableFile(atPath: bundledHelper), !installScript.isEmpty else { toast("The helper is missing from the app bundle — rebuild with scripts/build.sh", .red); return }
        let app = Bundle.main.bundlePath
        // the authorisation dialog belongs to another process and appears behind a background app, so come forward first
        (NSApp.delegate as? AppDelegate)?.showWindow()
        NSApp.activate(ignoringOtherApps: true)
        toast("Waiting for your administrator password… (look for the macOS dialog)", .text)
        runAdmin("/bin/bash \(q(installScript)) \(q(app)) \(boot ? 1 : 0)") { ok, msg in
            let why = msg.contains("-128") || msg.lowercased().contains("cancel") || msg.isEmpty ? "the password prompt was cancelled" : msg
            toast(ok ? "Helper installed" + (boot ? " and set to start at every boot" : " — runs until restart") + "; connecting…" : "Helper not installed: " + why, ok ? .safe : .red)
        }
    }
    static func uninstall() {
        let a = NSAlert(); a.messageText = "Remove the MatrixSys helper?"
        a.informativeText = "This stops the helper, removes its LaunchDaemon, deletes every pf firewall rule MatrixSys added and its settings. MatrixSys keeps working with the data available without privileges."
        a.addButton(withTitle: "Remove Helper"); a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        _ = Model.shared.helperRequest("PF\tflush", timeout: 3)
        runAdmin("/bin/bash \(q(uninstallScript)) --system") { ok, msg in
            LoginItem.set(false)
            toast(ok ? "Helper, LaunchDaemon and pf rules removed" : "Uninstall failed: " + msg, ok ? .safe : .red)
        }
    }
    static func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    /// Runs a shell command as root after the standard macOS administrator prompt.
    static func runAdmin(_ cmd: String, _ done: @escaping (Bool, String) -> Void) {
        let script = "do shell script \"" + cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\" with administrator privileges"
        async {
            let (st, out) = run("/usr/bin/osascript", ["-e", script], timeout: 300)
            DispatchQueue.main.async { done(st == 0, out.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "execution error: ", with: "")) }
        }
    }
    /// Command-line switches: --install-helper [--boot], --uninstall, --service-console (run the helper in the foreground; needs sudo).
    static func cli(_ a: [String]) {
        if a.contains("--service-console") {
            guard getuid() == 0 else { print("Run it as root: sudo \"\(bundledHelper)\"   (or: sudo \(a[0]) --service-console)"); exit(1) }
            print("MatrixSys helper in the foreground; Ctrl-C stops it.")
            let argv: [UnsafeMutablePointer<CChar>?] = [strdup(bundledHelper), nil]
            execv(bundledHelper, argv); perror("execv"); exit(1)
        }
        let sem = DispatchSemaphore(value: 0); var code: Int32 = 0
        if a.contains("--install-helper") {
            runAdminSync("/bin/bash \(q(installScript)) \(q(Bundle.main.bundlePath)) \(a.contains("--boot") ? 1 : 0)", &code)
        } else if a.contains("--uninstall") {
            runAdminSync("/bin/bash \(q(uninstallScript)) --system", &code)
            let (_, o) = run("/bin/bash", [uninstallScript, "--user"]); print(o)
        }
        _ = sem; exit(code)
    }
    static func runAdminSync(_ cmd: String, _ code: inout Int32) {
        let script = "do shell script \"" + cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\" with administrator privileges"
        let (st, out) = run("/usr/bin/osascript", ["-e", script], timeout: 300); print(out); code = st
    }
}
