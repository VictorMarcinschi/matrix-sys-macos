// WebPage.swift — the rendered view of an HTML answer the trace captured, in a WKWebView.
// The page that is shown is the captured response itself: the document request is answered from memory, never
// fetched again. Everything else the page asks for goes through one filter that applies the options below.
import AppKit
import WebKit

struct WebOpts { var js = false, cookies = false, resources = false, thirdParty = false, xssGuard = true }
var trWebOpts = WebOpts()

/// The registrable part of a host name, roughly: example.com for www.example.com, example.co.uk for www.example.co.uk.
func webSite(_ host: String) -> String {
    let l = host.split(separator: ".").map(String.init)
    if l.count <= 2 || l.last!.allSatisfy({ $0.isNumber }) { return host }   // short names and IP addresses stand for themselves
    let keep = l.last!.count == 2 && l[l.count - 2].count <= 3 ? 3 : 2
    return l.suffix(min(keep, l.count)).joined(separator: ".")
}
func webHostOf(_ url: String) -> String {
    guard let r = url.range(of: "://") else { return "" }
    let sc = url[..<r.lowerBound].lowercased()
    if !["http", "https", "ws", "wss"].contains(sc) { return "" }   // data:, blob:, about: stay inside the page
    var h = String(url[r.upperBound...])
    if let e = h.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) { h = String(h[..<e]) }
    if let at = h.lastIndex(of: "@") { h = String(h[h.index(after: at)...]) }
    if let c = h.lastIndex(of: ":"), !h.contains("]") { h = String(h[..<c]) }
    return h.lowercased()
}

final class WebPage: NSObject, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    static let shared = WebPage()
    var view: WKWebView?
    var pageUrl = "", pageHost = "", pageType = "", pageCsp = "", page = ""
    var visible = false, wantClose = false, loaded = false, loadOk = false
    var navAllowed = 0
    var blockedNav = ""
    /// What the filter is doing to subresources. WKWebView enforces this with a content rule list and reports no
    /// per-resource events, so MatrixSys states the rule rather than inventing counts it cannot measure.
    var filterText = ""
    var cookieCount = -1
    private var opts = WebOpts()
    private var store: WKWebsiteDataStore?

    private func make() -> WKWebView {
        let cfg = WKWebViewConfiguration()
        let ds = WKWebsiteDataStore.nonPersistent()        // the renderer's own store, emptied with the view
        store = ds
        cfg.websiteDataStore = ds
        cfg.defaultWebpagePreferences.allowsContentJavaScript = opts.js
        cfg.preferences.javaScriptCanOpenWindowsAutomatically = false
        cfg.preferences.isFraudulentWebsiteWarningEnabled = true
        if !opts.cookies {   // with cookies off, scripts also get a document without cookies
            let js = "try { Object.defineProperty(document, 'cookie', { get: function () { return ''; }, set: function () {} }); } catch (e) {}"
            cfg.userContentController.addUserScript(WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: false))
        }
        let v = WKWebView(frame: .zero, configuration: cfg)
        v.navigationDelegate = self
        v.uiDelegate = self
        v.allowsBackForwardNavigationGestures = false
        v.setValue(false, forKey: "drawsBackground")
        return v
    }
    /// Rebuilds the view so that a changed option takes effect, then shows the captured page again.
    func reload() {
        if let old = view { old.removeFromSuperview(); view = nil }
        opts = trWebOpts
        loaded = false; cookieCount = -1
        filterText = !opts.resources ? "only the captured document — every subresource is blocked before it leaves this Mac"
                   : !opts.thirdParty && !pageHost.isEmpty ? "subresources load from " + webSite(pageHost) + " only; other sites are blocked"
                   : "subresources load from any site — these are real, new requests"
        navAllowed = 1
        let v = make()
        view = v
        if let host = G.view { host.addSubview(v) }
        var html = page
        if opts.xssGuard {   // inline and foreign scripts cannot run
            let meta = "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'; object-src 'none'; base-uri 'self'\">"
            if let r = html.range(of: "<head", options: .caseInsensitive), let close = html.range(of: ">", range: r.upperBound..<html.endIndex) {
                html.insert(contentsOf: meta, at: close.upperBound)
            } else { html = meta + html }
        }
        if !opts.resources {   // only the captured document: every subresource is stopped before it leaves this Mac
            let block = """
            [{"trigger":{"url-filter":".*"},"action":{"type":"block"}}]
            """
            WKContentRuleListStore.default()?.compileContentRuleList(forIdentifier: "msys-block-all", encodedContentRuleList: block) { list, _ in
                if let list = list { v.configuration.userContentController.add(list) }
                v.loadHTMLString(html, baseURL: URL(string: self.pageUrl))
            }
            return
        }
        if !opts.thirdParty, !pageHost.isEmpty {   // only the page's own registrable domain
            let site = webSite(pageHost).replacingOccurrences(of: ".", with: "\\\\.")
            let rules = """
            [{"trigger":{"url-filter":".*"},"action":{"type":"block"}},
             {"trigger":{"url-filter":".*","if-domain":["*\(webSite(pageHost))"]},"action":{"type":"ignore-previous-rules"}}]
            """
            _ = site
            WKContentRuleListStore.default()?.compileContentRuleList(forIdentifier: "msys-same-site-" + webSite(pageHost), encodedContentRuleList: rules) { list, _ in
                if let list = list { v.configuration.userContentController.add(list) }
                v.loadHTMLString(html, baseURL: URL(string: self.pageUrl))
            }
            return
        }
        v.loadHTMLString(html, baseURL: URL(string: pageUrl))
    }
    func show(_ url: String, _ ctype: String, _ csp: String, _ body: String) {
        pageUrl = url; pageHost = webHostOf(url); pageType = ctype; pageCsp = csp; page = body
        visible = true; wantClose = false; blockedNav = ""
        reload()
    }
    func bounds(_ r: NSRect) { view?.frame = r }
    /// Writes a PNG of the page as rendered. The app's Metal screenshot cannot see an AppKit subview, so this is
    /// how the rendered view is checked.
    func snapshot(_ path: String, _ done: @escaping (Bool) -> Void) {
        guard let v = view else { done(false); return }
        v.takeSnapshot(with: nil) { img, _ in
            guard let img = img, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
                  let png = rep.representation(using: .png, properties: [:]) else { done(false); return }
            done((try? png.write(to: URL(fileURLWithPath: path))) != nil)
        }
    }
    func hide() {
        visible = false
        view?.removeFromSuperview(); view = nil
        if let ds = store { ds.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast) {} }
        store = nil; cookieCount = -1
    }
    func clearCookies() {
        store?.removeData(ofTypes: [WKWebsiteDataTypeCookies], modifiedSince: .distantPast) { self.cookieCount = 0 }
        toast("The renderer's cookie store is empty", .safe)
    }
    private func countCookies() {
        store?.httpCookieStore.getAllCookies { cs in
            self.cookieCount = cs.count
            if !self.opts.cookies && !cs.isEmpty { self.store?.removeData(ofTypes: [WKWebsiteDataTypeCookies], modifiedSince: .distantPast) {} }
        }
    }
    // ---- every policy is enforced here
    func webView(_ w: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if action.navigationType == .other && navAllowed > 0 && action.targetFrame?.isMainFrame == true {
            navAllowed -= 1; decisionHandler(.allow); return      // the captured document itself
        }
        if action.targetFrame?.isMainFrame == false { decisionHandler(.allow); return }   // a subframe is already filtered by the rule list
        if let u = action.request.url?.absoluteString, u != "about:blank" { blockedNav = u }
        decisionHandler(.cancel)                                   // links, forms and script redirects go nowhere
    }
    func webView(_ w: WKWebView, decidePolicyFor response: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        decisionHandler(response.canShowMIMEType ? .allow : .cancel)   // anything that would download instead of display is cancelled
    }
    func webView(_ w: WKWebView, didFinish navigation: WKNavigation!) { loaded = true; loadOk = true; countCookies() }
    func webView(_ w: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { loaded = true; loadOk = false; countCookies() }
    func webView(_ w: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { loaded = true; loadOk = false }
    func webView(_ w: WKWebView, createWebViewWith: WKWebViewConfiguration, for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let u = action.request.url?.absoluteString { blockedNav = u }
        return nil                                                  // no popups, no new windows
    }
    func webView(_ w: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo,
                 type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) { decisionHandler(.deny) }
    func webView(_ w: WKWebView, runJavaScriptAlertPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping () -> Void) { completionHandler() }
    func webView(_ w: WKWebView, runJavaScriptConfirmPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) { completionHandler(false) }
    func webView(_ w: WKWebView, runJavaScriptTextInputPanelWithPrompt p: String, defaultText: String?, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping (String?) -> Void) { completionHandler(nil) }
    func webView(_ w: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) { completionHandler(nil) }
    func userContentController(_ u: WKUserContentController, didReceive message: WKScriptMessage) {}
}

/// The rendered page fills the list window; its own toolbar carries the switches.
func drawTraceRender(_ X0: Float, _ Y0: Float, _ Wd: Float, _ Ht: Float) {
    let w = WebPage.shared
    if w.wantClose { hexClose(); return }
    let n = TR.msgs.count
    if navKey == NK.left && trSel > 0 { trSel -= 1 } else if navKey == NK.right && trSel + 1 < n { trSel += 1 }
    if !trCanRender(trSel) {   // no page here: the text view takes over
        let any = trSel >= 0 && trSel < n
        hexClose(); if any { hexMode = 5; trFullScroll = 0 }
        return
    }
    let m = TR.msgs[trSel]
    if trWebMsg != trSel { trWebMsg = trSel; w.show(m.url, m.ctype, m.csp, m.page) }
    // place the view in the window, in AppKit's bottom-left coordinates
    let px = X0 + 8, py = Y0 + 98, pw = Wd - 16, ph = max(60, Ht - 106)
    w.bounds(NSRect(x: CGFloat(px), y: CGFloat(G.LH - py - ph), width: CGFloat(pw), height: CGFloat(ph)))
    g.text(X0 + 12, Y0 + 9, "RENDERED PAGE · " + ellipsize(m.url, 90), uiCol(.cyan), bold: true)
    var bx = X0 + 12; let by = Y0 + 36
    var changed = false
    func tog(_ name: String, _ v: inout Bool, _ risky: Bool, _ enabled: Bool = true) {
        if button(&bx, by, name + (v ? ": ON" : ": OFF"), v && enabled, !enabled ? .dim : risky ? .warn : .safe) && enabled { v.toggle(); changed = true }
        bx += 4
    }
    tog("JAVASCRIPT", &trWebOpts.js, trWebOpts.js)
    tog("COOKIES", &trWebOpts.cookies, trWebOpts.cookies)
    tog("LOAD RESOURCES", &trWebOpts.resources, trWebOpts.resources)
    tog("OTHER SITES", &trWebOpts.thirdParty, trWebOpts.thirdParty, trWebOpts.resources)
    tog("XSS GUARD", &trWebOpts.xssGuard, !trWebOpts.xssGuard)
    bx += 10
    if button(&bx, by, "TEXT + BYTES", false) { hexClose(); hexMode = 5; trFullScroll = 0; return }
    bx += 4
    if button(&bx, by, "CLEAR COOKIES", false) { w.clearCookies() }
    if changed { w.reload() }
    var tip: String? = nil      // what each switch does, under the cursor
    if UIS.mouseY >= by && UIS.mouseY < by + 22 {
        var tx = X0 + 12
        let T: [(String, Bool, String)] = [
            ("JAVASCRIPT", trWebOpts.js, "Scripts in the page may run. Off: the page is static, as delivered."),
            ("COOKIES", trWebOpts.cookies, "On: cookies are kept in the renderer's own store while the page is open. Off: the store is emptied and scripts see no cookies."),
            ("LOAD RESOURCES", trWebOpts.resources, "On: images, styles, fonts and scripts are fetched from the network (new, real requests). Off: only the captured document is shown."),
            ("OTHER SITES", trWebOpts.thirdParty, "On: resources from other sites load too (third parties, trackers, CDNs). Off: only the page's own site."),
            ("XSS GUARD", trWebOpts.xssGuard, "On: only script files from the page's own site may run; inline scripts and scripts from other sites are blocked (Content-Security-Policy).")]
        for t in T {
            let bw = Float(t.0.unicodeScalars.count + (t.1 ? 4 : 5)) * CW + 18
            if UIS.mouseX >= tx && UIS.mouseX < tx + bw { tip = t.2 }
            tx += bw + 4
        }
    }
    if let tip = tip { g.text(X0 + 12, Y0 + 63, tip, .white) }
    else { g.text(X0 + 12, Y0 + 63, "This is the response the trace captured; it is not fetched again. Always blocked: links and redirects, popups, downloads, permission prompts, script dialogs.", .dim) }
    var s = "RESOURCES: " + w.filterText
    if w.cookieCount >= 0 { s += " · cookies in the store: \(w.cookieCount)" }
    if w.loaded && !w.loadOk { s += " · the page did not load completely" }
    g.text(X0 + 12, Y0 + 79, ellipsize(s, max(20, Int((Wd - 24) / CW))), trWebOpts.resources ? .warn : .text)
    if !w.blockedNav.isEmpty {
        let u = w.blockedNav; w.blockedNav = ""
        let ok = u.hasPrefix("http") && u.count < 240 && u.unicodeScalars.allSatisfy { $0.value >= 33 && $0.value <= 126 }
        if ok {
            trInput = u; trInputChanged()
            toast("Navigation is blocked in this view. The address is in the TARGET box: close the page and press Enter to trace it.", .warn)
        } else { toast("Navigation is blocked in this view.", .warn) }
    }
}
