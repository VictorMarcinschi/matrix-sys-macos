// Window, input, menu bar item, command-line test hooks.
import AppKit
import MetalKit
import ServiceManagement

final class Globals { var gfx: Gfx?; var LW: Float = 1280; var LH: Float = 800; var view: MatrixView?; var window: NSWindow?; var testSocket = "" }
let G = Globals()
let args = CommandLine.arguments
func argValue(_ name: String) -> String? { if let i = args.firstIndex(of: name), i + 1 < args.count { return args[i + 1] }; return nil }

final class MatrixView: MTKView, MTKViewDelegate {
    var lDown = false, rDown = false, downX: CGFloat = 0, downY: CGFloat = 0, lastT = nowSec(), uiCapture = false
    override var acceptsFirstResponder: Bool { true }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
    func setup() {
        delegate = self; preferredFramesPerSecond = 60; enableSetNeedsDisplay = false; isPaused = false
        let ta = NSTrackingArea(rect: .zero, options: [.mouseMoved, .activeAlways, .inVisibleRect], owner: self, userInfo: nil); addTrackingArea(ta)
        // the display link stops while the window is occluded or the display sleeps; keep the model and screenshots going at 4 fps
        Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            guard let self = self, !self.isPaused, nowSec() - self.lastT > 0.4 else { return }
            self.draw()
        }
    }
    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {}
    func draw(in mtk: MTKView) {   // not named `view`: that is the global view index
        guard let gfx = G.gfx else { return }
        let s = Float(window?.backingScaleFactor ?? 2); gfx.rebuildAtlas(scale: s)
        G.LW = Float(bounds.width); G.LH = Float(bounds.height); gfx.LW = G.LW; gfx.LH = G.LH
        let t = nowSec(); let dt = Float(min(0.1, t - lastT)); lastT = t
        frameScene(dt)
        drawUi()
        if UIS.clickNow && !UIS.mouseOverUi && !cf.open { UIS.panelScroll = 0; if view == 6 && trHovOrb >= 0 { trPick(trHovOrb) } else { selectKey(hov) } }
        UIS.clickNow = false; UIS.wheelUi = 0; navKey = 0
        gfx.draw(view: self, vp: VP, fog: 0.0019)
    }
    // ---- mouse
    func pt(_ e: NSEvent) -> (Float, Float) { let p = convert(e.locationInWindow, from: nil); return (Float(p.x), Float(bounds.height - p.y)) }
    override func mouseMoved(with e: NSEvent) { (UIS.mouseX, UIS.mouseY) = pt(e) }
    override func mouseDown(with e: NSEvent) {
        window?.makeFirstResponder(self)
        (UIS.mouseX, UIS.mouseY) = pt(e); downX = e.locationInWindow.x; downY = e.locationInWindow.y
        uiCapture = UIS.mouseY < 50 || UIS.overUi(UIS.mouseX, UIS.mouseY) || cf.open
        lDown = !uiCapture
    }
    override func mouseDragged(with e: NSEvent) {
        (UIS.mouseX, UIS.mouseY) = pt(e)
        guard lDown else { return }
        if e.modifierFlags.contains(.shift) { panBy(Float(e.deltaX), Float(e.deltaY)) }
        else if abs(e.locationInWindow.x - downX) > 4 || abs(e.locationInWindow.y - downY) > 4 {
            camYaw -= Float(e.deltaX) * 0.006; camPitch = max(-1.45, min(1.5, camPitch + Float(e.deltaY) * 0.006)); flying = false
        }
    }
    override func mouseUp(with e: NSEvent) {
        (UIS.mouseX, UIS.mouseY) = pt(e)
        if abs(e.locationInWindow.x - downX) < 5 && abs(e.locationInWindow.y - downY) < 5 { UIS.clickNow = true }
        lDown = false
    }
    override func rightMouseDown(with e: NSEvent) { (UIS.mouseX, UIS.mouseY) = pt(e); rDown = !(UIS.mouseY < 50 || UIS.overUi(UIS.mouseX, UIS.mouseY)) }
    override func rightMouseDragged(with e: NSEvent) { (UIS.mouseX, UIS.mouseY) = pt(e); if rDown { panBy(Float(e.deltaX), Float(e.deltaY)) } }
    override func rightMouseUp(with e: NSEvent) { rDown = false }
    override func otherMouseDown(with e: NSEvent) { rightMouseDown(with: e) }
    override func otherMouseDragged(with e: NSEvent) { rightMouseDragged(with: e) }
    override func otherMouseUp(with e: NSEvent) { rDown = false }
    /// Mouse wheel and two-finger scroll zoom; with ⌥ (or a horizontal trackpad swipe) they pan.
    override func scrollWheel(with e: NSEvent) {
        (UIS.mouseX, UIS.mouseY) = pt(e)
        let precise = e.hasPreciseScrollingDeltas
        let dy = Float(e.scrollingDeltaY) / (precise ? 12 : 1), dx = Float(e.scrollingDeltaX) / (precise ? 12 : 1)
        if UIS.mouseY < 50 || UIS.overUi(UIS.mouseX, UIS.mouseY) { UIS.wheelUi += dy; return }
        if e.modifierFlags.contains(.option) || (precise && abs(dx) > abs(dy) * 1.5) { panBy(Float(e.scrollingDeltaX) * (precise ? 1 : 8), Float(e.scrollingDeltaY) * (precise ? 1 : 8)); return }
        camDist = max(6, min(1500, camDist * pow(0.88, dy))); flyDist = camDist; flying = false
    }
    override func magnify(with e: NSEvent) {
        (UIS.mouseX, UIS.mouseY) = pt(e)
        if UIS.overUi(UIS.mouseX, UIS.mouseY) { return }
        camDist = max(6, min(1500, camDist / Float(1 + e.magnification))); flyDist = camDist; flying = false
    }
    // ---- keyboard
    override func keyDown(with e: NSEvent) { handleKey(code: e.keyCode, chars: e.characters ?? "", mods: e.modifierFlags) }
    func handleKey(code: UInt16, chars: String, mods: NSEvent.ModifierFlags) {
        if mods.contains(.command) {
            if view == 6 && hexMode == 0 && chars.lowercased() == "v", let s = NSPasteboard.general.string(forType: .string) {
                for u in s.unicodeScalars where u.value >= 33 && u.value < 127 && trInput.count < 240 { trInput.append(Character(u)) }
                trInputChanged()
            }
            return
        }
        let navMap: [UInt16: Int] = [126: NK.up, 125: NK.down, 123: NK.left, 124: NK.right, 116: NK.pgUp, 121: NK.pgDn, 115: NK.home, 119: NK.end, 36: NK.enter, 76: NK.enter]
        if code == 53 { // Esc: confirmation, then list window, then search text and selection
            if cf.open { cf.open = false } else if hexMode != 0 { hexClose() }
            else if view == 6 { trSel = -1; if !(TR.live && TR.running) { trPaused = false }; selectKey("", fly: false) }
            else { query = ""; UIS.panelScroll = 0; selectKey("", fly: false) }
            return
        }
        // while a list window is open, typing and the navigation keys belong to it, not to the filter or the 3D view
        if hexMode != 0 && !cf.open { if let k = navMap[code] { navKey = k }; if chars == "[" || chars == "]" { stepWindow(chars == "]") }; return }
        if cf.open { if code == 36 || code == 76 { } ; return }
        if view == 6 {   // in the trace tab the keyboard writes the target and drives the replay
            if code == 123 || code == 124 { trStepKey(code == 123 ? -1 : 1); return }   // ← → step, never pan
            if code == 126 || code == 125 { navKey = code == 126 ? NK.up : NK.down; return }
            if code == 36 || code == 76 { trGo(mods.contains(.shift)); return }          // Enter / Shift+Enter
            if chars == " " { trTogglePause(); return }                                   // Space never reaches the target box
            if code == 51 { if !trInput.isEmpty { trInput.removeLast(); trInputChanged() }; return }
            if code == 115 { LY[6].framed = false; camYaw = 0; camPitch = 0.55; rebuild(); return }
            for u in chars.unicodeScalars where u.value >= 33 && u.value < 127 && trInput.count < 240 { trInput.append(Character(u)) }
            trInputChanged()
            return
        }
        let s: Float = 28
        switch code {
        case 123: panBy(s, 0)
        case 124: panBy(-s, 0)
        case 126, 125: var f = camT - eyePos(); f.y = 0; f = norm(f); camT += f * ((code == 126 ? 1 : -1) * camDist * 0.045); flying = false
        case 116: panBy(0, s)
        case 121: panBy(0, -s)
        case 115: LY[view].framed = false; camYaw = 0; camPitch = 0.55; sel = ""; rebuild()
        case 51:   // Backspace: the filter first, then (Disks) one folder up
            if !query.isEmpty { query.removeLast(); computeFocus() }
            else if view == 4 && !diskRoot.isEmpty { selectKey("dkroot:" + diskParent(diskRoot)) }
        default:
            if chars == "[" || chars == "]" { stepWindow(chars == "]"); return }
            for u in chars.unicodeScalars where u.value >= 32 && u.value < 127 && query.count < 24 { query.append(Character(u).lowercased()); computeFocus() }
        }
    }
    func stepWindow(_ up: Bool) { let ws = [1, 5, 10, 30, 60]; let i = ws.firstIndex(of: winSec) ?? 0; winSec = ws[max(0, min(4, i + (up ? 1 : -1)))] }
}
func panBy(_ dx: Float, _ dy: Float) {
    let f = norm(camT - eyePos()), r = norm(simd_cross(f, V3(0, 1, 0))), u = simd_cross(r, f); let s = camDist * 0.0016
    camT = camT + r * (-dx * s) + u * (dy * s); flying = false
}

// ================================================================ app delegate, menu bar
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuDelegate {
    var window: NSWindow!; var status: NSStatusItem!; let menu = NSMenu()
    var keepInMenuBar: Bool { get { UserDefaults.standard.bool(forKey: "keepInMenuBar") } set { UserDefaults.standard.set(newValue, forKey: "keepInMenuBar") } }
    func applicationDidFinishLaunching(_ n: Notification) {
        buildGeo()
        if let s = argValue("--helper-socket") { HELPER_SOCKET = s }
        buildMainMenu()
        let startHidden = args.contains("--menubar")
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1500, height: 950), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "MatrixSys — system visualizer"; window.minSize = NSSize(width: 900, height: 600); window.center(); window.delegate = self
        window.backgroundColor = NSColor(red: 1 / 255, green: 6 / 255, blue: 15 / 255, alpha: 1)
        window.setFrameAutosaveName("MatrixSysMain")
        let v = MatrixView(frame: window.contentView!.bounds); v.autoresizingMask = [.width, .height]
        guard let gfx = Gfx(view: v) else { let a = NSAlert(); a.messageText = "Metal is not available on this Mac."; a.runModal(); NSApp.terminate(nil); return }
        G.gfx = gfx; G.view = v; G.window = window
        v.setup(); window.contentView = v; window.makeFirstResponder(v)
        gfx.shotDone = { p, ok in TestHooks.shotFinished(p, ok) }
        if !startHidden { window.makeKeyAndOrderFront(nil); if !args.contains("--background") { NSApp.activate(ignoringOtherApps: true) } } else { v.isPaused = true }
        setupStatusItem()
        Model.shared.start()
        if let s = argValue("--select"), let pid = Int32(s) { pendingSel = pid }
        if let s = argValue("--memory"), let pid = Int32(s) { DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { hexOpenMem(pid) } }
        if let s = argValue("--size"), let m = Int(s) { procSizeMode = max(0, min(2, m)) }   // 0 memory, 1 lane traffic, 2 CPU load
        if let s = argValue("--view"), let v = Int(s) { DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { setView(v) } }
        if let t = argValue("--trace") {   // --trace <target> [icmp|tcp|http|https|dns] [step]
            let names = ["icmp", "tcp", "http", "https", "dns"]
            var proto = TP.https, step = false
            if let i = args.firstIndex(of: "--trace") {
                for a in args.dropFirst(i + 2) {
                    if let k = names.firstIndex(of: a.lowercased()) { proto = k }
                    if a.lowercased() == "step" { step = true }
                }
            }
            trInput = t; trProto = proto; trInputChanged()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { setView(6); trGo(step) }
        }
        if args.contains("--demo-packets") { Packets.shared.demo = true; DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { hexOpenPkts(-1, "") } }
        if let p = argValue("--test-socket") { TestHooks.start(p) }
    }
    func buildMainMenu() {
        let main = NSMenu(); let appItem = NSMenuItem(); main.addItem(appItem)
        let am = NSMenu()
        am.addItem(withTitle: "About MatrixSys", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        am.addItem(.separator())
        am.addItem(withTitle: "Full Access (Install Helper)…", action: #selector(installHelper), keyEquivalent: "")
        am.addItem(withTitle: "Uninstall Helper and Firewall Rules…", action: #selector(uninstallHelper), keyEquivalent: "")
        am.addItem(.separator())
        am.addItem(withTitle: "Hide MatrixSys", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        am.addItem(withTitle: "Quit MatrixSys", action: #selector(quit), keyEquivalent: "q")
        appItem.submenu = am
        let wItem = NSMenuItem(); main.addItem(wItem); let wm = NSMenu(title: "Window")
        wm.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        wm.addItem(withTitle: "Minimize", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        wm.addItem(withTitle: "Enter Full Screen", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f").keyEquivalentModifierMask = [.command, .control]
        wItem.submenu = wm
        NSApp.mainMenu = main
    }
    // ---- status item (the counterpart of the Windows tray icon)
    func setupStatusItem() {
        status = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        status.button?.image = AppDelegate.octaImage(); status.button?.image?.isTemplate = true
        status.button?.toolTip = "MatrixSys"
        menu.delegate = self; status.menu = menu
    }
    func menuNeedsUpdate(_ m: NSMenu) {
        m.removeAllItems()
        let visible = window.isVisible
        m.addItem(withTitle: visible ? "Hide MatrixSys Window" : "Show MatrixSys Window", action: #selector(toggleWindow), keyEquivalent: "")
        let (st, _) = captureStatus()
        let si = NSMenuItem(title: "Capture: " + (st.isEmpty ? "off — counters only (no helper)" : st.replacingOccurrences(of: "● ", with: "")), action: nil, keyEquivalent: ""); si.isEnabled = false; m.addItem(si)
        m.addItem(.separator())
        let k = NSMenuItem(title: "Keep Running in Menu Bar When Window Closes", action: #selector(toggleKeep), keyEquivalent: ""); k.state = keepInMenuBar ? .on : .off; m.addItem(k)
        let l = NSMenuItem(title: "Start at Login (in the Menu Bar)", action: #selector(toggleLogin), keyEquivalent: ""); l.state = LoginItem.enabled ? .on : .off; m.addItem(l)
        m.addItem(.separator())
        if !Model.shared.helperConnected { m.addItem(withTitle: "Full Access (Install Helper)…", action: #selector(installHelper), keyEquivalent: "") }
        m.addItem(withTitle: "Uninstall Helper and Firewall Rules…", action: #selector(uninstallHelper), keyEquivalent: "")
        m.addItem(.separator())
        m.addItem(withTitle: "Quit MatrixSys", action: #selector(quit), keyEquivalent: "q")
        for i in m.items { i.target = self }
    }
    static func octaImage() -> NSImage {
        let img = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { r in
            let c = NSPoint(x: 9, y: 9); let p = NSBezierPath(); p.lineWidth = 1.3
            let top = NSPoint(x: 9, y: 16.5), bot = NSPoint(x: 9, y: 1.5), l = NSPoint(x: 2, y: 9.5), rr = NSPoint(x: 16, y: 8.5), f = NSPoint(x: 7, y: 7.5), b = NSPoint(x: 11.5, y: 10.5)
            for (a, z) in [(top, l), (top, rr), (top, f), (top, b), (bot, l), (bot, rr), (bot, f), (bot, b), (l, f), (f, rr), (rr, b), (b, l)] { p.move(to: a); p.line(to: z) }
            NSColor.black.setStroke(); p.stroke(); _ = c; _ = r; return true
        }
        return img
    }
    @objc func toggleWindow() { if window.isVisible { window.orderOut(nil); G.view?.isPaused = true } else { showWindow() } }
    func showWindow() { G.view?.isPaused = false; window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
    @objc func toggleKeep() { keepInMenuBar.toggle(); UserDefaults.standard.set(true, forKey: "keepAsked") }
    @objc func toggleLogin() { LoginItem.set(!LoginItem.enabled) }
    @objc func installHelper() { showWindow(); Helper.offerInstall() }
    @objc func uninstallHelper() { Helper.uninstall() }
    @objc func quit() { NSApp.terminate(nil) }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if !UserDefaults.standard.bool(forKey: "keepAsked") {
            let a = NSAlert(); a.messageText = "Keep MatrixSys running in the menu bar?"
            a.informativeText = "Closing the window can leave MatrixSys in the menu bar (the cube icon), where you can reopen it. You can change this later from that menu."
            a.addButton(withTitle: "Keep in Menu Bar"); a.addButton(withTitle: "Quit When Closed")
            keepInMenuBar = a.runModal() == .alertFirstButtonReturn; UserDefaults.standard.set(true, forKey: "keepAsked")
        }
        if keepInMenuBar { window.orderOut(nil); G.view?.isPaused = true; return false }
        NSApp.terminate(nil); return false
    }
    func applicationShouldHandleReopen(_ s: NSApplication, hasVisibleWindows: Bool) -> Bool { showWindow(); return true }
    func applicationWillTerminate(_ n: Notification) { Packets.shared.close() }
}

/// "Start at login" for the app (separate from the boot-time helper): a per-user LaunchAgent that opens it in the menu bar.
enum LoginItem {
    static var plist: String { NSHomeDirectory() + "/Library/LaunchAgents/com.matrixsys.app.plist" }
    static var enabled: Bool { FileManager.default.fileExists(atPath: plist) }
    static func set(_ on: Bool) {
        if on {
            let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
            let d: NSDictionary = ["Label": "com.matrixsys.app", "ProgramArguments": [exe, "--menubar"], "RunAtLoad": true, "ProcessType": "Interactive", "LimitLoadToSessionType": "Aqua"]
            try? FileManager.default.createDirectory(atPath: (plist as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            d.write(toFile: plist, atomically: true)
            toast("MatrixSys will start in the menu bar when you log in", .safe)
        } else { try? FileManager.default.removeItem(atPath: plist); toast("MatrixSys will no longer start at login", .safe) }
    }
}

// ================================================================ test hooks: drive the app from a script, only when asked for
enum TestHooks {
    static var waiting: [String: Int32] = [:]
    static func start(_ path: String) {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var a = sockaddr_un(); a.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &a.sun_path) { p in _ = path.utf8CString.withUnsafeBytes { memcpy(p.baseAddress!, $0.baseAddress!, min(p.count - 1, $0.count)) } }
        let ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        if ok != 0 { NSLog("test socket bind failed"); return }
        chmod(path, 0o600); listen(fd, 8)
        Thread {
            while true {
                let c = accept(fd, nil, nil); if c < 0 { continue }
                let rd = LineReader(fd: c)
                guard let line = rd.next() else { close(c); continue }
                DispatchQueue.main.async { handle(line, c) }
            }
        }.start()
    }
    static func reply(_ c: Int32, _ s: String) { _ = writeAll(c, s + "\n"); close(c) }
    static func shotFinished(_ p: String, _ ok: Bool) { if let c = waiting.removeValue(forKey: p) { reply(c, ok ? "ok " + p : "fail") } }
    static func handle(_ line: String, _ c: Int32) {
        let f = line.split(separator: " ", maxSplits: 1).map(String.init); let cmd = f.first ?? ""; let a = f.count > 1 ? f[1] : ""
        let v = G.view!
        switch cmd {
        case "shot": waiting[a] = c; G.gfx?.pendingShot = a; return
        case "view": setView(Int(a) ?? 0)
        case "select": if let p = Int32(a) { if view != 0 && !["1", "3"].contains(String(view)) { setView(0, "p:\(p)") } else { selectKey((view == 1 ? "n:" : view == 3 ? "f:" : "p:") + "\(p)") } }
        case "key":
            let codes: [String: UInt16] = ["esc": 53, "up": 126, "down": 125, "left": 123, "right": 124, "pgup": 116, "pgdn": 121, "home": 115, "end": 119, "enter": 36, "bs": 51]
            if let k = codes[a] { v.handleKey(code: k, chars: "", mods: []) } else { v.handleKey(code: 0, chars: a, mods: []) }
        case "type": for ch in a { v.handleKey(code: 0, chars: String(ch), mods: []) }
        case "move": let p = a.split(separator: " ").compactMap { Float($0) }; if p.count == 2 { UIS.mouseX = p[0]; UIS.mouseY = p[1] }
        case "click": let p = a.split(separator: " ").compactMap { Float($0) }; if p.count == 2 { UIS.mouseX = p[0]; UIS.mouseY = p[1]; UIS.clickNow = true }
        case "zoom": camDist = max(6, min(1500, Float(a) ?? camDist)); flyDist = camDist
        case "orbit": let p = a.split(separator: " ").compactMap { Float($0) }; if p.count == 2 { camYaw = p[0]; camPitch = p[1] }
        case "act": requestAction(a)
        case "confirm": if cf.open { cf.open = false; performAction(cf.key) }
        case "key2": selectKey(a)
        case "winsec": winSec = Int(a) ?? 1
        case "state":
            let L = LY[view]
            reply(c, "menubar=\((NSApp.delegate as? AppDelegate)?.status?.button != nil) view=\(view) sel=\(sel) hex=\(hexMode) nodes=\(L.nodes.count) lanes=\(L.lanes.count) parts=\(parts.count) procs=\(S?.procs.count ?? 0) conns=\(S?.conns.count ?? 0) helper=\(Model.shared.helperConnected) capture=\(Model.shared.captureLive) cam=\(camDist) confirm=\(cf.open ? cf.title : "-") toast=\(toastMsg) ext=\(L.ext)")
            return
        case "trace": trInput = a; trInputChanged(); if view != 6 { setView(6) }; trGo(args.contains("--trace-step"))
        case "trsel": if let i = Int(a) { trShow(i) }
        case "trrender": trOpenRender()
        case "trweb":
            let w = WebPage.shared
            let f = w.view?.frame ?? .zero
            reply(c, "view=\(w.view != nil) visible=\(w.visible) loaded=\(w.loaded) ok=\(w.loadOk) progress=\(w.view?.estimatedProgress ?? -1) title=\(w.view?.title ?? "-") frame=\(Int(f.origin.x)),\(Int(f.origin.y)),\(Int(f.width)),\(Int(f.height)) url=\(w.pageUrl) bytes=\(w.page.utf8.count)")
            return
        case "winid": reply(c, "\((NSApp.delegate as? AppDelegate)?.window.windowNumber ?? -1)"); return
        case "trshot": WebPage.shared.snapshot(a) { ok in reply(c, ok ? "ok " + a : "failed") }; return
        case "trstate":
            let selTitle = trSel >= 0 && trSel < TR.msgs.count ? TR.msgs[trSel].title : "-"
            reply(c, "msgs=\(TR.msgs.count) nodes=\(TR.nodes.count) chain=\(TR.chain.count) running=\(TR.running) status=\(TR.status) err=\(TR.err) sel=\(trSel) paused=\(trPaused) hex=\(hexMode) title=\(selTitle)")
            return
        case "panel": buildPanel(); reply(c, pitems.map { "\($0.type)|\($0.a)|\($0.b)|\($0.sel)" }.joined(separator: "\n")); return
        case "pos":   // every node's target position in this view, to measure how much a rebuild moves the scene
            reply(c, LY[view].nodes.values.map { "\($0.key) \($0.tpos.x) \($0.tpos.y) \($0.tpos.z)" }.sorted().joined(separator: "\n")); return
        default: reply(c, "unknown"); return
        }
        reply(c, "ok")
    }
}

// ================================================================ entry
if args.contains("--service-console") || args.contains("--install-helper") || args.contains("--uninstall") {
    Helper.cli(args)
    exit(0)
}
// Runs one trace with no window and prints every step as text. The same engine the TRACE tab uses.
if let target = argValue("--trace-dump") {
    let names = ["icmp", "tcp", "http", "https", "dns"]
    let proto = args.count > 3 ? (names.firstIndex(of: args[3].lowercased()) ?? TP.https) : TP.https
    traceStart(target, proto)
    var seen = 0
    let deadline = nowSec() + 90
    while nowSec() < deadline {
        let t = TrShared.i.snapshot()
        while seen < t.msgs.count {
            let m = t.msgs[seen]; seen += 1
            print(String(format: "%7.0f ms  %@ %@", m.t * 1000, m.from == m.to ? "*" : m.out ? "->" : "<-", m.title))
            for f in m.f { print("              \(f.0): \(f.1)") }
        }
        if !t.running { print("\n[\(t.status)] \(t.err.isEmpty ? "no error" : t.err) · \(t.nodes.count) nodes · \(t.chain.count) in the chain · \(String(format: "%.1f", t.took)) s"); break }
        usleep(150000)
    }
    exit(0)
}
/// RFC 3414 A.3: the published key-derivation test vectors. Password-to-key and localization are the parts of USM
/// most easily got subtly wrong — a mistake there looks exactly like a wrong password — so they are checked against
/// the RFC's own numbers rather than against another implementation of mine. Run: MatrixSys --snmp-selftest
if args.contains("--snmp-selftest") {
    func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    // RFC 3414 A.3.1 / A.3.2: password "maplesyrup", engine id 00:00:00:00:00:00:00:00:00:00:00:02
    let engine: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    let cases: [(String, AuthProto, String, String)] = [
        ("MD5",   .md5,  "9faf3283884e92834ebc9847d8edd963",
                         "526f5eed9fcce26f8964c2930787d82b"),
        ("SHA-1", .sha1, "9fb5cc0381497b37935289 39ff788d5d79145211".replacingOccurrences(of: " ", with: ""),
                         "6695febc9288e36282235fc7151f128497b38f3f"),
    ]
    var bad = 0
    for (name, proto, wantKu, wantKul) in cases {
        let ku = snmpPasswordToKey("maplesyrup", proto)
        let kul = snmpLocalizeKey(ku, engineID: engine, proto)
        let okKu = hex(ku) == wantKu, okKul = hex(kul) == wantKul
        if !okKu { bad += 1 }
        if !okKul { bad += 1 }
        print("\(name) Ku   \(hex(ku))  \(okKu ? "ok" : "WRONG, want " + wantKu)")
        print("\(name) Kul  \(hex(kul))  \(okKul ? "ok" : "WRONG, want " + wantKul)")
    }
    print(bad == 0 ? "\nRFC 3414 A.3 key derivation: all vectors match" : "\n\(bad) MISMATCHES")
    exit(bad == 0 ? 0 : 1)
}

/// Reads one SNMP agent and prints what it says. No window, read-only, the same code the LAN view uses.
if let ip = argValue("--snmp-dump") {
    let community = args.count > 3 && !args[3].hasPrefix("--") ? args[3] : snmpCommunity()
    let port = UInt16(argValue("--port") ?? "") ?? snmpPort()
    // --v3 <user> [--auth MD5|SHA|SHA256] [--authpass x] [--priv AES] [--privpass y]; passwords given here are for
    // testing only, and the panel never offers this route: in the app they come from the keychain.
    var v3: SnmpV3User? = nil
    if let u = argValue("--v3") {
        var x = SnmpV3User()
        x.name = u
        x.authProto = AuthProto.named(argValue("--auth") ?? "")
        x.privProto = PrivProto.named(argValue("--priv") ?? "")
        x.authPassword = argValue("--authpass") ?? keychainPassword(service: "com.matrixsys.snmp.auth", account: u)
        x.privPassword = argValue("--privpass") ?? keychainPassword(service: "com.matrixsys.snmp.priv", account: u)
        v3 = x
    } else { v3 = snmpV3Configured() }
    print("asking \(ip):\(port) over SNMP\n")
    let s = snmpQuery(ip, community: community, port: port, v3: v3) { _, m in FileHandle.standardError.write(Data(("  … " + m + "\n").utf8)) }
    print("reached    \(s.how)")
    if !s.engineID.isEmpty { print("engine     \(s.engineID)") }
    if !s.ok { print(s.note); exit(1) }
    if !s.name.isEmpty { print("name      \(s.name)") }
    if !s.descr.isEmpty { print("descr     \(s.descr)") }
    if !s.uptime.isEmpty { print("uptime    \(s.uptime)") }
    if !s.location.isEmpty { print("location  \(s.location)") }
    if !s.contact.isEmpty { print("contact   \(s.contact)") }
    if !s.ifs.isEmpty {
        print("\ninterfaces (\(s.ifs.count))")
        for i in s.ifs { print(String(format: "  %-4d %-22@ %-5@ in %@ out %@", i.index, i.name as NSString,
                                      (i.up ? "up" : "down") as NSString, fmtB(Double(i.inOctets)) as NSString, fmtB(Double(i.outOctets)) as NSString)) }
    }
    if !s.arp.isEmpty {
        print("\nits ARP table (\(s.arp.count))")
        for (a, m) in s.arp { print("  \(a.padding(toLength: 16, withPad: " ", startingAt: 0)) \(m)  \(macIsRandom(m) ? "private MAC" : ouiVendor(m))") }
    }
    if !s.note.isEmpty { print("\n" + s.note) }
    exit(0)
}

/// Finds the machines on the local networks and prints them as text. No window, the same code the LAN view uses.
if args.contains("--lan-dump") || argValue("--scan-dump") != nil {
    if let ip = argValue("--scan-dump") {
        let set = ["admin", "low", "full", "common"].first { args.contains($0) } ?? "common"
        let ports = lanPortSet(set)
        print("scanning \(ip): \(ports.count) TCP ports\n")
        var open: [LanPort] = []
        let (parallel, timeout) = lanScanPace(ports.count)
        raiseFdLimit(parallel * 2 + 256)
        for batch in stride(from: 0, to: ports.count, by: parallel) {
            for var r in tcpConnectBatch(ip, Array(ports[batch..<min(batch + parallel, ports.count)]), timeoutMs: timeout) where r.state == LAN_OPEN {
                (r.banner, r.server) = lanBanner(ip, r.port)
                open.append(r)
                print(String(format: "  %-6d %-12s open   %@", r.port, (svcName(r.port) as NSString).utf8String!, r.server.isEmpty ? r.banner.prefix(60).description : r.server))
            }
        }
        print("\n\(open.count) open of \(ports.count) tried")
        exit(0)
    }
    for i in lanInterfaces() {
        print("\(i.name)  \(i.ip)/\(i.cidr)  network \(i.cidrText)  \(i.hosts) addresses  mac \(macOf(i.name))")
    }
    if args.contains("--sweep") {
        for i in lanInterfaces() where i.hosts > 0 && i.hosts <= LAN_SWEEP_MAX {
            print("\nsweeping \(i.cidrText) …")
            guard let s = IcmpSock() else { break }
            var replies = Set<String>()
            for k in 1...i.hosts {
                let a = i.net + UInt32(k)
                if a == i.bcast { continue }
                _ = s.sendEcho(ipFromU32(a), seq: UInt16(k & 0xffff))
                if k % 16 == 0 { while let rx = s.recvOne(1) { replies.insert(rx.from) } }
                usleep(1500)
            }
            let deadline = nowSec() + 2
            while nowSec() < deadline { if let rx = s.recvOne(150) { replies.insert(rx.from) } }
            s.close()
            print("\(replies.count) answered the ping")
        }
    }
    let gws = Set(Devices.shared.gateways().map { $0.0 })
    print("")
    for (ip, mac, ifn) in Devices.shared.neighbours().sorted(by: { ipToU32($0.0) < ipToU32($1.0) }) where !ip.contains(":") {
        let md = args.contains("--names") ? mdnsReverse(ip) : ""
        let nb = args.contains("--names") && md.isEmpty ? nbnsName(ip) : ""
        let vendor = macIsRandom(mac) ? "private MAC" : ouiVendor(mac)
        print("\(ip.padding(toLength: 16, withPad: " ", startingAt: 0)) \(mac)  \(ifn)\(gws.contains(ip) ? "  gateway" : "")  \(md.isEmpty ? nb : md)  \(vendor)")
    }
    exit(0)
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
