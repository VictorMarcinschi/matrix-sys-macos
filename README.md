# MatrixSys for macOS

A native, fully offline 3D visualizer of everything running on this Mac — processes, the data they exchange,
network traffic, memory, open files, disks and devices — with controls to act on what it shows.

Swift + AppKit + Metal, no third-party dependencies, no web view, no bundled runtime. The only network traffic
MatrixSys itself makes is reverse DNS through the system resolver, and the owner (whois) lookup, which happens
only when you press its button.

---

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

MatrixSys asks for no other permission, and sends nothing anywhere.

## The six views

* **Processes** — the process tree as a 3D cone tree, children above their parent, size = memory, glow = CPU.
  Lanes show data exchange: network, disk, and the pipes, unix sockets and loopback TCP between processes.
* **Network** — processes with sockets on an inner ring, their listening ports stacked above them, remote hosts on
  an outer ring, one lane per connection.
* **Memory** — a treemap of resident memory grouped by program, with system-wide totals (app, wired, compressed, cache, free).
* **Files** — which process has which files open; files held by several processes are highlighted.
* **Disks** — every volume and its folders as a treemap. APFS containers show their shared free space once.
* **Devices** — the IOKit hardware tree, plus network neighbours (ARP/NDP) and gateways hanging off their interface.

Every node has a tooltip. All "how much data" figures are for a time window of 1, 5, 10, 30 or 60 seconds,
changed with the buttons in the panel or the `[` and `]` keys.

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

The build output goes to `build/`, outside the source tree, and the app bundle is swapped in atomically, so
rebuilding works while MatrixSys is running. `scripts/make_icon.swift` draws the icon and `iconutil` turns it
into `MatrixSys.icns`; no hand-maintained Xcode project is involved.

Source layout: `src/shared` (process and descriptor collection, helper protocol, packet parsing), `src/app`
(scene, UI, views, actions, capture and memory viewers, helper client), `src/helper` (the privileged daemon),
`resources` (install and uninstall scripts).

### Command-line test hooks

```
MatrixSys --select <pid>            open with that process selected
MatrixSys --memory <pid>            open straight into its memory viewer
MatrixSys --view <0..5>             open on a view
MatrixSys --demo-packets            synthetic packets shaped like this Mac's real connections,
                                    labelled DEMO everywhere, so the packet viewer can be tried without the helper
MatrixSys --menubar                 start hidden in the menu bar
MatrixSys --background              start without taking focus
MatrixSys --test-socket <path>      accept scripted commands (shot/view/select/key/click/act/state/panel…)
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
