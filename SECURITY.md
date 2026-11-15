# Security

## Reporting a vulnerability

Please report privately, through GitHub's **Report a vulnerability** button on this repository's Security tab,
not as a public issue. Include what you did, what happened, and the macOS version.

## What MatrixSys does

**The app** runs as you, with no entitlements beyond what you grant it in System Settings. It reads process, socket,
memory, descriptor, disk and device information through public macOS interfaces (`sysctl`, `libproc`, IOKit,
DiskArbitration, `nettop`).

**The privileged helper** is optional. Installing it asks for your administrator password once and places
`/Library/PrivilegedHelperTools/com.matrixsys.helper` plus a LaunchDaemon, and nothing else. It exists because macOS
will not let an app elevate itself. It does:

* packet capture through pktap, attributed to processes — **it counts packets, it never reads their contents**;
  when you open the packet viewer it hands the *app* a capture descriptor, and the app reads at most 3000 packets of
  512 bytes, only while that window is open
* open files and disk counters for processes that are not yours
* per-file disk I/O through `fs_usage`
* process memory reads through `task_for_pid`, which macOS still refuses for Apple's own binaries and hardened apps
* pf firewall rules, confined to MatrixSys's own anchor `com.apple/250.MatrixSys`
* actions on other users' processes that you ask for

Its socket is `/var/run/com.matrixsys.helper.sock`, and every connection is checked with `LOCAL_PEERCRED`: only root,
the console user and members of the `admin` group are served. The uninstaller removes the helper, its LaunchDaemon and
every pf rule MatrixSys added.

## What leaves this Mac

* **Reverse DNS**, through the system resolver, for addresses already on screen.
* **A whois lookup**, only when you press *WHO OWNS IT*. It queries IANA and follows a referral only to one of the
  five regional registries.
* **A trace**, only when you start one in the Trace tab: roughly 30 ICMP probes for the route, the DNS queries, and
  the exchange in the protocol you chose, all to the target you typed.
* **Subresources of a captured page**, only if you turn *LOAD RESOURCES* on in the rendered page view. It is off by
  default, and with it off nothing but the captured bytes is shown.

There is **no telemetry, no analytics, no update check, and no crash reporting**. MatrixSys never sends your data
anywhere, and it has no server side.

## Deliberate choices worth knowing

* The trace's TLS step **continues when a certificate is not trusted**, and shows the verdict and the reason. This is
  so you can see what a misconfigured or hostile server actually answers. The only thing sent over that connection is
  a plain `GET` with no credentials and no cookies.
* The app is **signed ad hoc**. It is not notarized, and Gatekeeper will refuse the first launch until you allow it.
  Verify the SHA256 of a downloaded build against `SHA256SUMS` in the release, or build it yourself from source.
