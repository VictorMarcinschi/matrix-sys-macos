# MatrixSys for macOS

A native, fully offline 3D visualizer of everything running on this Mac — processes, the data they exchange,
network traffic, memory, open files, disks and devices — plus the machines on your own network, with controls to
act on what it shows.

Swift + AppKit + Metal, no third-party dependencies, no web view, no bundled runtime. Nothing is sent anywhere by
itself: reverse DNS through the system resolver, and then only what you press a button for — the owner (whois)
lookup, a trace, and the LAN view's sweep, port scan and router query.

---

## Getting it

Download `MatrixSys.dmg` from the **Releases** page of this repository, or build it yourself:

```
scripts/build.sh --dmg
```

Every push is built and smoke-tested on a macOS runner; pushing a `v*` tag publishes a release with the disk image,
a zipped app and `SHA256SUMS`.

## Running it

Drag **MatrixSys.app** to Applications and open it.

The app is **signed ad hoc** (no Developer ID). The first launch is therefore refused by Gatekeeper with
"MatrixSys cannot be opened because the developer cannot be verified". Either:

* right-click the app → **Open** → **Open**, or
* System Settings → Privacy & Security → **Open Anyway**.

Only the first launch needs this.

Ad-hoc signing has one further consequence, confirmed in practice: macOS ties a TCC permission to the
*exact binary*, so **rebuilding or replacing the app voids its Full Disk Access** even when the path is
unchanged. After an update, switch the entry off and on again in the Full Disk Access list, or remove it
with **−** and drag the new app in. Signing with a Developer ID avoids this. The privileged helper is
unaffected: it is a separate binary and keeps running across app updates.

## The three levels of access

| Level | How | What you get |
|---|---|---|
| **Unprivileged** (default) | just open the app | Every process, its memory and CPU; all sockets and listening ports with exact byte counts; your own processes' open files and disk counters; interface and disk device counters; the full disk and device views. Nothing is faked: anything MatrixSys cannot measure is shown as `-` or named as not readable. |
| **Helper, until restart** | **FULL ACCESS (HELPER)** in the top bar → *START NOW* | Adds real packet capture attributed to processes, open files and disk counters of **every** process, per-file disk I/O, process memory reading, pf firewall rules, and actions on other users' processes. |
| **Helper at boot** | same button → *START NOW AND AT EVERY BOOT* | The same, started by launchd at every boot, so the app has full data without asking again. |

Installing the helper asks for your administrator password once (the standard macOS prompt). It installs
`/Library/PrivilegedHelperTools/com.matrixsys.helper` and a LaunchDaemon, and nothing else.

**The helper never reads packet contents.** It counts packets and attributes them to processes. When you open the
packet viewer, the helper hands the app a capture descriptor and the *app* reads the bytes, only while that window
is open, at most 3000 packets of 512 bytes. Its socket is `/var/run/com.matrixsys.helper.sock`, and every
connection is checked: only root, the console user and members of the `admin` group are served.

### Permissions macOS may ask for

| Permission | Needed for | If you decline |
|---|---|---|
| Administrator password | installing or removing the helper | the app runs unprivileged |
| **Full Disk Access** (System Settings → Privacy & Security) | scanning Mail, Messages, Safari and other protected folders in the Disks view | those folders are counted as "not readable"; everything else still scans. The Disks panel has a button that opens the right pane |
| **Automation → Finder** | only the EMPTY TRASH action | that one action fails; nothing else is affected |
| **Local Network** (macOS 15 and later) | the LAN view: finding machines on your own network, and the sweep, scan and router query | the LAN view finds nothing beyond the ARP table macOS already keeps |

MatrixSys asks for no other permission.

## The eight views

* **Processes** — the process tree as a 3D cone tree, children above their parent, size = memory, glow = CPU.
  Lanes show data exchange: network, disk, and the pipes, unix sockets and loopback TCP between processes.
* **Network** — processes with sockets on an inner ring, their listening ports stacked above them, remote hosts on
  an outer ring, one lane per connection.
* **Memory** — a treemap of resident memory grouped by program, with system-wide totals (app, wired, compressed, cache, free).
* **Files** — which process has which files open; files held by several processes are highlighted.
* **Disks** — every volume and its folders as a treemap. APFS containers show their shared free space once.
* **Devices** — the IOKit hardware tree, plus network neighbours (ARP/NDP) and gateways hanging off their interface.
* **LAN** — every machine on the networks this Mac is on: address, MAC, hardware vendor, the names it answers to,
  and the TCP ports it has open. This Mac at the centre, each network next to it, the machines on a ring. See below.
* **Trace** — type a host, an IP or a URL and watch every step between this Mac and it: the name lookup, each router
  on the way, and the conversation in the chosen protocol. See below.

Every node has a tooltip. All "how much data" figures are for a time window of 1, 5, 10, 30 or 60 seconds,
changed with the buttons in the panel or the `[` and `]` keys.

In **Processes**, *SIZE PROCESSES BY* switches what a node's size stands for: **memory** (default), **lane traffic**
(everything its lanes carry, disk and network) or **CPU load**. In CPU mode the panel lists CPU now instead of traffic
over a window, as a share of the whole machine; the process list gains a CPU% column and a CPU sort.

Layouts are **stable**: a process appearing or leaving does not re-pack the scene. Each tree keeps its spot on the
floor, each child keeps its angle on its parent's ring, and a ring only shrinks when it is clearly too wide. Measured
on this Mac over a minute of normal churn: before, a single rebuild moved a node up to 232 units in Processes and 37
in Network; after, 0 and 4.6.

## The LAN tab

Who else is on your network, what they are called, and what they are listening on. This Mac is the icosahedron in
the middle, each network it is attached to hangs off it, and every machine found sits on the ring with its open
ports stacked above it. Amber is the default gateway, green a machine that has a name, violet one with open ports
found by a scan, blue one found but unnamed. A machine not seen for a while fades rather than disappearing.

**By default it sends nothing.** Two sources cost no packets at all:

* the **ARP and NDP tables** macOS already keeps — every machine this Mac has spoken to recently, with its MAC;
* the **mDNS and SSDP announcements** already being broadcast on the wire. MatrixSys joins the two multicast groups
  and listens. This is where names like `Cristinas-iMac` and `DESKTOP-ANVPCDP` come from without asking anyone.

Everything else is a button, and each says what it is about to send:

| Button | What it sends | What you get |
|---|---|---|
| **SWEEP** | one ICMP echo to every address in the subnet | every machine that is up. A host that *ignores* the ping is still found: it had to answer the ARP request before the ping could be sent, so its MAC is now in the ARP table. Presence at layer 2 is the evidence, not the reply. Refused above 1024 addresses (/22) rather than flooding a larger network |
| **ASK EVERY NAME** | one mDNS reverse query and one NetBIOS node-status query per machine | the name each machine calls itself |
| **SCAN COMMON PORTS** | one TCP connection per port, 91 picked ones | open, **closed** (the host sent a reset) and **filtered** (silence) — the three states the kernel can actually tell apart. An open port is then asked what it is: the greeting of a server that speaks first, or the `Server` header and page title from a plain `GET` on a web port |
| **SCAN 1-1023** / **SCAN EVERY PORT** | the same, over every well-known port or all 65535 | the only way to find a listener on a port nobody would guess, which is where consumer IoT usually is. A full range takes a little over two minutes on a LAN; the panel counts it down and **STOP** ends it, keeping what was found so far |
| **ASK IT OVER SNMP** | one SNMP v2c GET, then GETNEXT walks | see below |
| **ASK IT OVER UPNP** | SSDP discovery and a few SOAP calls to the gateway | see below |
| **WAKE IT** | one Wake-on-LAN magic packet | a machine that supports it powers on |

A MAC with the locally administered bit set is labelled **private address**, not given a vendor: iOS and Android
use a different random MAC per network by default, so it names no hardware and will change. Real vendors come from
the IEEE registry, which is **not bundled** — run `scripts/make_oui.sh` once to build `resources/oui.txt` (about
1 MB, 40 000 assignments) and rebuild. Without it the panel shows the raw OUI and claims no vendor.

### SNMP

Offered for every machine, not just the router: printers, NAS boxes and managed switches answer it as readily.
**Read-only.** `SET` is part of the same protocol and deliberately not implemented — nothing in MatrixSys changes
another machine's configuration.

| What | From |
|---|---|
| system name, description, uptime, location, contact | the MIB-2 `system` group |
| every interface, its state, link rate, MAC and byte counters | `ifTable` |
| **the machines that agent has seen** | `ipNetToMediaTable`, its own ARP table |

That last row is the one nothing else can give. Your Mac's ARP table holds only what *it* has spoken to; a router's
holds everything *it* has. Entries found there and not already known are added to the view and marked
"known to the router, not seen by this Mac".

The community string is `public` — the documented default for read-only access, not a secret. A different one goes
in the app's own preferences rather than being typed into MatrixSys:

```
defaults write com.matrixsys.app snmpCommunity <name>
defaults write com.matrixsys.app snmpPort <n>        # if your agents are not on 161
```

SNMP v1 and v2c send the community in the clear, which is why MatrixSys only ever reads with it.

**v3** is implemented too, and is used instead of v2c as soon as a user is configured. It authenticates every
message with a key derived from your password *and* the agent's engine id, and can encrypt the payload:

| | |
|---|---|
| Authentication | HMAC-MD5-96, HMAC-SHA-96 (RFC 3414) and HMAC-192-SHA-256 (RFC 7860) |
| Privacy | AES-128-CFB (RFC 3826). DES is not implemented: 56-bit keys, and every agent that offers it offers AES |
| Levels | noAuthNoPriv, authNoPriv, authPriv |

Nothing secret goes in preferences. The user name and the algorithms do; **the passwords come from your login
keychain**, which MatrixSys only ever reads — macOS asks you to allow that the first time, and again after a
rebuild, because an ad-hoc signature changes identity:

```
defaults write com.matrixsys.app snmpV3User <name>
defaults write com.matrixsys.app snmpV3Auth MD5|SHA|SHA256
defaults write com.matrixsys.app snmpV3Priv AES        # omit for authNoPriv

security add-generic-password -s com.matrixsys.snmp.auth -a <name> -w
security add-generic-password -s com.matrixsys.snmp.priv -a <name> -w
```

When an agent refuses, it says why, because USM reports the reason: an unknown user, a wrong digest (the
authentication password), or a message outside its time window. A wrong *privacy* password is the one case with no
report — the agent cannot decrypt the request, so it answers nothing at all, and the panel says so.

### Physical topology

Everything else in this view is what this Mac can see from where it sits, and from there a switch is invisible: it
forwards frames without appearing in them, so no amount of pinging, scanning or listening reveals that four
machines sit behind one port rather than four. The bridge itself knows, because that is its job, and **BRIDGE-MIB**
exposes the table — so a managed switch or router that answers SNMP can tell you the one thing observation cannot.

MatrixSys reads `dot1dTpFdbTable` (falling back to the VLAN-aware `dot1qTpFdbTable`), maps each bridge port to an
interface name through `dot1dBasePortIfIndex`, and then:

| What it finds | What it draws |
|---|---|
| one MAC on a port | nothing: that machine is cabled straight in, and sits on the ring like any other |
| several MACs, and an **LLDP** neighbour whose chassis MAC is among them | the device it announced itself to be, named, with its capabilities — green |
| several MACs, some with a **virtualisation OUI**, exactly one without | a virtualisation host with its VMs orbiting it — violet |
| several MACs, nothing else known | a pale node labelled `switch?`, which asserts only that *something* is there |

The machines on a multiplexed port stop being peers on the main ring and orbit whatever multiplexes them, so the
picture stops implying that your network is flat when it is not.

That last row is the honest case and the common one. The panel for such a node says so at length: it has no
address, cannot be pinged, scanned or named, and could as easily be a powerline adapter or a cable to another room
as a switch. An inferred node is only created from the **gateway's** table, because on any other device a port with
many MACs is almost certainly its uplink, which the table cannot distinguish from a switch.

The approach is taken from [netpulse](https://github.com/gnacho/netpulse), which reads the same table over SSH on
OpenWrt; the rules are its idea, the code here is ours and reaches the table over SNMP, so it works against any
managed switch rather than one distribution.

### Administering the router

There is no cross-vendor standard for *changing* a router's settings from a LAN client, so MatrixSys does not try,
and it stores no credentials. Two standards can be *read*, and both are read-only here: SNMP, above, and:

* **UPnP IGD**, the one thing most routers answer without a login: what the router calls itself, its
  model, the address your connection has on the internet, how long it has been connected, the line rate, and the
  **port-mapping table** — every hole something on your network has opened through the router. A router with UPnP
  off simply does not answer, and the panel says so rather than guessing.
* **OPEN ADMIN PAGE**, **SSH** and **TELNET** hand the session to something that does log in: your browser, or a
  Terminal window. The scan has already established which of those ports is actually open. MatrixSys never sees the
  password. (macOS ships no `telnet`; that button runs `nc` instead and says so.)

## The Trace tab

Type a host name, an IPv4 address or a URL, pick **ICMP / TCP / HTTP / HTTPS / DNS**, and press Enter. A scheme in the
address picks the protocol by itself (`https://`, `ssh://`, `dns://8.8.8.8/example.com`, `icmp://1.1.1.1`, …).

Every request leaves as a magenta orb and every answer comes back in the colour of its kind — violet DNS, amber router
reply, cyan echo, blue TCP, green TLS and HTTP success, yellow redirect, red error or silence, white greeting. Click an
orb, a node or a row in the step list to see that message fully decoded, with the bytes that were on the wire.

| Step | What you see |
|---|---|
| Name lookup | Raw DNS over UDP straight to the servers this Mac is configured to use, so the exchange itself is visible: query and answer decoded (A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, flags, rcode, per-record TTL). If they cannot answer, the system resolver is asked instead and says so. |
| Route | ICMP echo with a rising TTL, 1 to 30. Each hop is a node with its round trip; a router that forwards but does not answer appears as a small dark "* hop N". |
| ICMP | Four pings, with what the reply's TTL suggests about the far end, and a min / avg / max summary. |
| TCP | Connect (open, refused, or filtered), then the greeting of a server that speaks first — SSH, SMTP, FTP, POP3, IMAP, VNC, MySQL. Then FIN. |
| HTTPS | Each TLS flight as its own message with its records named and the hellos decoded (SNI, marked as sent unencrypted; ALPN; offered versions; chosen suite), then the negotiated parameters, the certificate chain, its validity and names, and a trust verdict. |
| HTTP | A plain GET, every response header as a field, chunked decoding, the body up to 512 KB, time to first byte, and up to 5 redirects followed. |
| DNS | The route to the DNS server, then every record type of the name; a PTR lookup for an IP. |

**Two run modes.** Enter runs the trace at network speed and then replays it. **Shift+Enter** runs it step by step:
nothing is sent until you press `→`, which allows exactly one real network step; `Space` switches to live, where each
step happens as the replay reaches it. Time spent waiting is subtracted from every timing. `←` walks back.
During a replay, `Space` pauses and `←` `→` step one message at a time.

**This sends real packets to the target**: about 30 ICMP probes for the route, then the protocol exchange. Nothing
else leaves this Mac; there is no telemetry, and the owner (whois) lookup still happens only when you press its button.

### The rendered page

When a response is HTML, the panel offers **RENDERED PAGE**: the captured bytes shown in a WKWebView, never fetched
again. Switches, all off by default except the guard: **JAVASCRIPT**, **COOKIES** (a non-persistent store, emptied
with the view), **LOAD RESOURCES** (off: nothing but the captured document leaves this Mac), **OTHER SITES** (only
with resources on), **XSS GUARD** (on: a `script-src 'self'` policy on top of the site's own).

Always blocked: every navigation after the first — links, forms, script redirects — plus new windows, downloads,
permission prompts (camera, microphone, location, notifications), script dialogs and autofill. A blocked http(s) link
is put into the TARGET box so you can trace it instead.

### Controls

Left-drag orbits · right-drag, shift-drag or option-scroll pans · scroll or pinch zooms · click selects ·
arrows pan, Page Up/Down pan vertically · Home resets · Esc closes the confirmation, then the open window, then the
search text and selection · typing filters by name · Backspace deletes (and in Disks, goes one folder up).
While a list window is open, every key belongs to that list.

## What differs from the Windows version, and why

| Windows feature | On macOS |
|---|---|
| ETW / raw-socket capture, "REQUEST ADMIN" relaunches elevated | A Mac app cannot elevate itself. A **privileged helper** (LaunchDaemon) does the privileged work and the app talks to it over a Unix socket. Capture uses **pktap**, the per-packet interface `tcpdump -k` uses, which carries the owning pid. |
| Per-process network bytes from the capture | Without the helper, exact per-process and per-connection byte counts come from **nettop**; only packet counts and contents need the helper. |
| Per-file disk I/O from ETW | From **fs_usage** (kdebug) in the helper; thread ids are mapped back to pids. |
| CPU affinity (all / half / one core) | **Dropped.** macOS has no public per-process CPU affinity. Replaced by **BACKGROUND (E-CORES)**, a real macOS clamp (`PRIO_DARWIN_BG`: efficiency cores, throttled disk and network) and **FOREGROUND** to undo it. |
| Trim working set | **Dropped.** No honest equivalent exists. |
| Force-close a file handle in another process | **Dropped.** macOS has no call for it. The file panel says so. |
| Close a TCP connection (`SetTcpEntry`) | macOS has no such call. The helper reads the connection's sequence numbers from the kernel's TCP table and sends a valid **RST to both ends**, which is what `tcpkill` does. IPv6 falls back to a short-lived pf rule, so those time out instead of closing instantly. |
| Windows Firewall rules via `netsh` | **pf** rules in MatrixSys's own anchor `com.apple/250.MatrixSys`, listed and removable in one step, and removed completely by the uninstaller. |
| Enable / disable a device | **Dropped** — generic device disable does not exist on macOS. Replaced by **eject** (DiskArbitration) for removable volumes and **interface up/down** for network interfaces. |
| Stop / restart a service | **launchctl** (`kill SIGTERM`, `kickstart -k`) for the launchd job that owns the process; the panel shows which job that is. |
| Tray icon | **Menu bar item**: show/hide the window, capture status, keep running in the menu bar, start at login, uninstall, quit. Closing the window asks once whether to keep MatrixSys in the menu bar. |
| Process memory viewer | Needs `task_for_pid`, which macOS grants only to root **and** refuses for Apple's own programs and hardened-runtime apps while SIP is on. Realistic coverage: your own programs and third-party apps without the hardened runtime. For the rest the viewer says exactly why. |
| Recycle Bin | **Trash** (`FileManager.trashItem`), and EMPTY TRASH via Finder. |
| Priority: five Windows classes | nice levels −10…19 (raising priority needs the helper). |
| Trace: ICMP route needs raw sockets / an elevated service | **No helper needed.** macOS gives any process `SOCK_DGRAM`/`IPPROTO_ICMP`, which carries both echo replies and the "time exceeded" errors a traceroute needs. The TTL is set with `IP_TTL` and the reply's own TTL read with `IP_RECVTTL`. |
| Trace: TLS handshake through Schannel, record by record | macOS's TLS is **Network.framework**, which does not hand out raw records. MatrixSys inserts a pass-through **`NWProtocolFramer` below TLS** in the protocol stack, so it sees every byte of the handshake in both directions and hands them on untouched, while Apple's stack does the cryptography and the trust evaluation. The flights, the hellos, the certificate chain and the verdict are all real; nothing is reimplemented. A direction change ends a flight, which is why ClientHello, ServerHello and the client's Finished appear as three messages. |
| Trace: DNS servers from `GetAdaptersAddresses` | From the system configuration (`State:/Network/Global/DNS`, what `scutil --dns` shows), IPv4 first, with `/etc/resolv.conf` as a fallback. |
| Rendered page: WebView2, an optional installer component | **WKWebView**, always present, so there is nothing optional to install. Subresource filtering uses a `WKContentRuleList`; navigations, popups, downloads and permission prompts are refused by the delegates. |
| Rendered page: counts of resources allowed and blocked | **Dropped as a number.** WKWebView enforces a content rule list without reporting per-resource events, so MatrixSys states the rule in force ("only the captured document — every subresource is blocked before it leaves this Mac") instead of showing a count it cannot measure. Cookies in the store are read and shown, because those it can count. |
| — | **New on macOS:** quit an app gracefully with an Apple event before offering to kill it, `sample` a process for 3 s, flush the DNS cache, reveal in Finder, open Terminal in a folder. |

### macOS-specific care in the Disks view

APFS volumes in one container share free space, so free space is shown **once per container**, not summed.
The read-only System volume and the Data volume are joined by firmlinks; the scan never crosses a device boundary,
so nothing is counted twice. Sizes are **allocated** sizes (`st_blocks`), so sparse files do not inflate totals, and
hard-linked files are counted once. Symlinks are never followed, network volumes and system-managed APFS volumes
(Preboot, VM, Update, xART) are not walked. Whatever a volume uses beyond the scanned folders — local Time Machine
snapshots, purgeable space, metadata, unreadable folders — is shown as its own block rather than hidden.

**APFS clones are the one case the folder sizes overstate.** A clone reports its full allocated size even though it
shares blocks with its twin, so the sum over files can exceed what the volume actually uses — on the machine this was
developed on, 364 GB of folders against 340 GB in use. Counting shared blocks once would mean tracking every extent
in the container, which this scan deliberately does not do. The panel always shows the volume's own **in use on the
volume** figure next to the scanned total, so the two can be compared instead of one being passed off as the other.

## Building from source

Requires Xcode (or the Command Line Tools) and macOS 13+.

```
scripts/build.sh          # builds build/MatrixSys.app (icon, app, helper, ad-hoc signature)
scripts/build.sh --dmg    # the same plus build/MatrixSys.dmg
```

`scripts/make_oui.sh` is separate and optional: it downloads the IEEE MAC-prefix registry and writes
`resources/oui.txt`, which the LAN view uses to name hardware vendors. It is the only script that touches the
network, it is never run by `build.sh`, and the file is not committed — without it the app claims no vendor.

The build output goes to `build/`, outside the source tree, and the app bundle is swapped in atomically, so
rebuilding works while MatrixSys is running. `scripts/make_icon.swift` draws the icon and `iconutil` turns it
into `MatrixSys.icns`; no hand-maintained Xcode project is involved.

Source layout: `src/shared` (process and descriptor collection, helper protocol, packet parsing), `src/app`
(scene, UI, views, actions, capture and memory viewers, helper client), `src/helper` (the privileged daemon),
`resources` (install and uninstall scripts). The LAN view is `src/app/Lan.swift` (discovery, scanning, UPnP) and
`src/app/LanView.swift` (its scene and panel), with `src/app/Snmp.swift` for BER and SNMP v2c and
`src/app/SnmpV3.swift` for USM and `src/app/Topology.swift` for the forwarding table and its inference.

### Command-line test hooks

```
MatrixSys --select <pid>            open with that process selected
MatrixSys --memory <pid>            open straight into its memory viewer
MatrixSys --view <0..7>             open on a view (6 = trace, 7 = LAN)
MatrixSys --size <0|1|2>            size processes by 0 memory, 1 lane traffic, 2 CPU load
MatrixSys --trace <target> [icmp|tcp|http|https|dns] [step]
                                    open the trace tab and start a trace
MatrixSys --trace-dump <target> [proto]
                                    run one trace with no window and print every step as text
MatrixSys --lan-dump [--sweep] [--names]
                                    print the local networks and every machine found, as text
MatrixSys --scan-dump <ip> [common|admin|low|full]
                                    port-scan one host with no window and print what answered
MatrixSys --snmp-dump <ip> [community] [--port n]
                                    read one SNMP agent and print its system info, interfaces and ARP table
          --v3 <user> [--auth MD5|SHA|SHA256] [--authpass p] [--priv AES] [--privpass p]
                                    ... over SNMP v3 instead; without --authpass the keychain is used
MatrixSys --snmp-selftest           check the USM key derivation against the RFC 3414 A.3 vectors
MatrixSys --demo-packets            synthetic packets shaped like this Mac's real connections,
                                    labelled DEMO everywhere, so the packet viewer can be tried without the helper
MatrixSys --menubar                 start hidden in the menu bar
MatrixSys --background              start without taking focus
MatrixSys --test-socket <path>      accept scripted commands (shot/view/select/key/click/act/state/panel/pos/
                                    trace/trsel/trrender/trstate/trweb/trshot/winid…)
MatrixSys --helper-socket <path>    talk to a helper on another socket (testing)
com.matrixsys.helper --socket <p>   run the helper in the foreground; without root it serves only what you can see
MatrixSys --install-helper [--boot] | --uninstall
```

## Uninstalling

From the menu bar item: **Uninstall Helper and Firewall Rules…**, or run **Uninstall MatrixSys.command** from the
disk image (also `resources/uninstall.sh`). It stops and removes the helper and its LaunchDaemon, deletes every pf
rule MatrixSys added and releases its pf reference, removes the start-at-login agent, preferences and caches, and
offers to move the app to the Trash.

## Honest limits

* Packet **contents** are only available with the helper, and only for traffic that passes a pktap-visible
  interface. TLS and QUIC payloads are ciphertext; the viewer says so.
* Without the helper, per-process *packet* counts do not exist — byte counts do, and are exact.
* Process memory reading cannot cover Apple's own programs or hardened apps while SIP is on.
* `fs_usage` attribution maps thread ids to pids; for a thread that exits in the same instant, MatrixSys falls
  back to matching the process name, and shows the I/O without a path rather than inventing one.
* Local Time Machine snapshots are reported as unaccounted space, not attributed to folders, because no folder owns them.
* The trace's TLS step **continues even when the certificate is not trusted**, so that you can see what the server
  answers; the verdict and the reason are shown in full, and the only thing MatrixSys ever sends over that connection
  is a plain `GET`. A browser would stop instead. The handshake and the trust evaluation are Apple's, not ours.
* The trace speaks IPv4. An IPv6-only target is refused with a clear message rather than silently falling back.
* The rendered page cannot report how many subresources were blocked (see the table above); it reports the rule instead.
* A trace sends real packets to the target, and only when you ask for it.
* The LAN view speaks IPv4. IPv6 neighbours are in the Devices view.
* A **port scan is a TCP connect scan**: the connection is completed and then closed, so it is visible in the
  target's own logs. A half-open SYN scan would need the helper and is not offered, because on a network you
  administer it buys nothing.
* "Filtered" means no answer before the timeout — 900 ms for a short list, 600 ms for a full range, against a LAN
  round trip of a few milliseconds. A host that rate-limits its resets can still report filtered for a closed port.
* A host with **nothing open** is a real and common answer, not a failure: a cloud-connected device reaches its
  maker's server by its own outbound connection, and nothing on your network can connect to it at all.
* Names are what each machine says about itself over mDNS, NetBIOS or SSDP. Nothing checks them: two machines can
  claim the same name, and a machine can claim any name at all.
* The MAC vendor table is a snapshot of the IEEE registry from the day you ran `make_oui.sh`, and the panel says so.
  A randomised MAC is labelled as one rather than being looked up.
* **Topology needs a managed switch.** The forwarding table comes from SNMP, so unmanaged switches — most of what
  sits in a home — reveal nothing, and the view falls back to a flat ring. That is a limit of what can be known
  from here, not a gap to be filled by guessing.
* **SNMP is read-only**, v2c and v3. No `SET` is ever sent, at any version.
  A community string travels in the clear in v1 and v2c; that is the protocol, not this app.
* v3 privacy is AES-128 only, and SHA-384/512 authentication is not implemented. An agent that requires either is
  not answered. The key derivation is checked against the RFC 3414 A.3 test vectors by `--snmp-selftest`.
* An agent's ARP table is what *it* believes. An entry can be stale, and a device that has been quiet for a long
  time may be missing from it entirely.
* The UPnP answers come from the router and are not verified. A router with UPnP off, or one that implements only
  part of IGD, gives less or nothing, and the panel reports exactly what came back.
