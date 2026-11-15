# Contributing to MatrixSys for macOS

## Building

```
scripts/build.sh          # build/MatrixSys.app (icon, app, helper, ad-hoc signature)
scripts/build.sh --dmg    # the same plus build/MatrixSys.dmg
```

Requires Xcode or the Command Line Tools and macOS 13+. There is no Xcode project: the script is the build.
Everything lands in `build/`, outside the source tree, and the app bundle is swapped in atomically, so you can
rebuild while MatrixSys is running.

## Layout

| Path | What lives there |
|---|---|
| `src/shared` | Code the app and the helper both use: process and descriptor collection, the helper line protocol, packet parsing. |
| `src/app` | `Gfx` (Metal renderer and glyph atlas), `Model` (collector), `Scene` (layouts, particles, camera), `UI` (overlay), `Actions`, `Disks`, `Devices`, `Capture`, `Trace` (the trace engine), `TraceUI`, `WebPage`, `Lan` (LAN discovery, scanning, UPnP), `LanView` (its scene and panel), `Snmp` (BER and SNMP v2c), `main`. |
| `src/helper` | The privileged LaunchDaemon: capture, fs_usage, pf, memory reads, TCP reset. |
| `resources` | Install and uninstall scripts shipped inside the bundle. |
| `scripts` | `build.sh`, `make_icon.swift`, `run-test.sh`, `make_oui.sh` (optional, builds the MAC vendor table). |

## House rules

* **Real data only.** Every number on screen comes from the system. If something cannot be measured, say so on
  screen — `-`, "not readable", or the rule in force — rather than showing a plausible zero.
* **No third-party dependencies**, no web view for the UI, no bundled runtime. The macOS SDK is the whole toolbox.
* **Offline by default, and never on a timer.** Nothing reaches the network unless you asked for it: reverse DNS
  through the system resolver, the whois lookup when its button is pressed, the Trace tab when you start a trace,
  and the LAN view's sweep, name queries, port scan, SNMP read and UPnP query — each behind its own button, each
  stating what it will send first. The LAN view's default sources cost no packets at all: the ARP table the kernel
  already keeps and the mDNS/SSDP announcements already on the wire. A new feature that sends anything belongs in
  that list, in `SECURITY.md`, and behind a button.
* **Read, do not reconfigure, other people's machines.** MatrixSys reads SNMP and UPnP; it issues no SNMP `SET`
  and no UPnP action that changes a setting. It also stores no credential for anything on the network: the admin
  page, SSH and telnet buttons hand the session to a browser or to Terminal, and SNMP v3 passwords are read from
  the login keychain, which the app never writes.
* **Check cryptography against the specification's own numbers, not against yourself.** The USM key derivation has
  the RFC 3414 A.3 vectors behind `--snmp-selftest`; a second implementation of your own misunderstanding proves
  nothing. Where a reference implementation exists, test against it too — v3 was verified against net-snmp,
  including that it *rejects* a wrong password.
* Comments explain *why*, not *what*. Keep them where the reasoning is not obvious from the code.
* Keep layouts stable: a process appearing or leaving must not re-pack the scene.

## Testing a change

Most of the app can be driven without touching the mouse:

```
scripts/run-test.sh --view 0                  # starts it with a command socket at $TMPDIR/msys.sock
printf 'shot /tmp/a.png\n' | nc -U $TMPDIR/msys.sock
printf 'trstate\n'         | nc -U $TMPDIR/msys.sock
```

`MatrixSys --trace-dump <target>` runs a whole trace with no window and prints every step, which is what CI checks.

When you change a layout, measure it: sample `pos` twice over a minute of normal process churn and compare, rather
than judging by eye.

**Never test a destructive action on a real target.** Use a throwaway process (`sleep`, `ping`), a temp folder, a
throwaway rule.

## Pull requests

* One change per pull request, with a short note on what you ran and what you saw.
* Say what you could not test, and why.
* If a feature has no honest equivalent on macOS, drop it and say so in the README's differences table instead of
  approximating it.
