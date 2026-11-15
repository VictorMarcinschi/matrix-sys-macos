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
* **The LAN view**, and only to machines on your own networks. By default it sends nothing at all: it reads the ARP
  and NDP tables macOS already keeps, and listens to the mDNS and SSDP announcements already being broadcast. Each
  of the following is a separate button that states what it will send before it sends it:
  * *SWEEP*: one ICMP echo per address in the subnet, refused above 1024 addresses.
  * *ASK ITS NAME* / *ASK EVERY NAME*: one mDNS reverse query and one NetBIOS node-status query per machine.
  * *SCAN*: one TCP connection per port (87 in the common list). An open port is sent nothing except, on a web
    port, a plain `GET /` with no credentials and no cookies.
  * *ASK IT OVER SNMP*: SNMP v2c reads — one GET, then GETNEXT walks of the interface and ARP tables. **MatrixSys
    never issues an SNMP SET**, so it cannot change another machine's configuration. The community string defaults
    to the documented `public` and is otherwise read from this app's own preferences, never stored by MatrixSys.
  * *ASK IT OVER UPNP*: SSDP discovery and read-only SOAP calls to the gateway.
  * *WAKE IT*: one Wake-on-LAN broadcast.

  MatrixSys never logs in to anything and stores no credentials. *OPEN ADMIN PAGE*, *SSH* and *TELNET* hand the
  session to your browser or to Terminal, which is where any password you type goes.

There is **no telemetry, no analytics, no update check, and no crash reporting**. MatrixSys never sends your data
anywhere, and it has no server side.

## Deliberate choices worth knowing

* The trace's TLS step **continues when a certificate is not trusted**, and shows the verdict and the reason. This is
  so you can see what a misconfigured or hostile server actually answers. The only thing sent over that connection is
  a plain `GET` with no credentials and no cookies.
* A **port scan is a TCP connect scan**: the connection is completed, so it appears in the target's logs. This is
  deliberate — MatrixSys does not offer a half-open scan, and nothing it does is designed to be hard to notice.
  Scanning machines you do not administer is often against the rules of the network you are on; the confirmation
  says so before each sweep and each scan.
* The app is **signed ad hoc**. It is not notarized, and Gatekeeper will refuse the first launch until you allow it.
  Verify the SHA256 of a downloaded build against `SHA256SUMS` in the release, or build it yourself from source.
