#!/bin/bash
# Installs the MatrixSys helper as a LaunchDaemon. Run as root (the app runs it after the macOS administrator prompt).
# Usage: install-helper.sh <path to MatrixSys.app> <0 = start now only | 1 = also start at every boot>
set -euo pipefail
APP="$1"; BOOT="${2:-0}"
LABEL=com.matrixsys.helper
SRC="$APP/Contents/MacOS/$LABEL"
DST=/Library/PrivilegedHelperTools/$LABEL
PLIST=/Library/LaunchDaemons/$LABEL.plist
[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
[ -x "$SRC" ] || { echo "helper binary not found in $APP"; exit 1; }
# stop any previous instance and wait for it to go, so a reinstall cannot race its own start
launchctl bootout system/$LABEL 2>/dev/null || true
for _ in $(seq 1 25); do pgrep -x "$LABEL" >/dev/null 2>&1 || break; sleep 0.2; done
pkill -x "$LABEL" 2>/dev/null || true
mkdir -p /Library/PrivilegedHelperTools
install -m 755 -o root -g wheel "$SRC" "$DST"
KEEP="<dict><key>SuccessfulExit</key><false/></dict>"   # restart on crash only
if [ "$BOOT" = 1 ]; then RUN="<true/>"; else RUN="<false/>"; fi
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$DST</string></array>
  <key>RunAtLoad</key>$RUN
  <key>KeepAlive</key>$KEEP
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>/var/log/$LABEL.log</string>
</dict></plist>
EOF
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootstrap system "$PLIST" 2>/dev/null || true
launchctl kickstart -k system/$LABEL
for _ in $(seq 1 50); do [ -S /var/run/$LABEL.sock ] && break; sleep 0.2; done
if [ ! -S /var/run/$LABEL.sock ]; then echo "helper did not start; see /var/log/$LABEL.log"; exit 1; fi
echo "installed (start at boot: $BOOT)"
