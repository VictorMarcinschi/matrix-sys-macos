#!/bin/bash
# Builds MatrixSys.app (and the helper) from source. Output goes to ../MatrixSys-build (outside the source folder).
# Usage: scripts/build.sh [--dmg]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${MATRIXSYS_BUILD:-$ROOT/build}"
APP="$OUT/MatrixSys.app"
TMP="$OUT/.tmp"; mkdir -p "$TMP" "$OUT"
ARCH="$(uname -m)"
SDK="$(xcrun --show-sdk-path)"
FLAGS=(-O -swift-version 5 -sdk "$SDK" -target "$ARCH-apple-macos13.0" -module-cache-path "$TMP/mc")
if [ ! -f "$OUT/MatrixSys.icns" ] || [ "$ROOT/scripts/make_icon.swift" -nt "$OUT/MatrixSys.icns" ]; then
  echo "== icon"
  swiftc -O -module-cache-path "$TMP/mc" -o "$TMP/make_icon" "$ROOT/scripts/make_icon.swift" && "$TMP/make_icon" "$TMP/MatrixSys.iconset" && iconutil -c icns "$TMP/MatrixSys.iconset" -o "$OUT/MatrixSys.icns"
fi
echo "== compiling app ($ARCH)"
swiftc "${FLAGS[@]}" -o "$TMP/MatrixSys" "$ROOT"/src/shared/*.swift "$ROOT"/src/app/*.swift -framework AppKit -framework Metal -framework MetalKit -framework IOKit -framework DiskArbitration -framework SystemConfiguration -framework Network -framework Security -framework WebKit -lpcap
if ls "$ROOT"/src/helper/*.swift >/dev/null 2>&1; then
  echo "== compiling helper"
  swiftc "${FLAGS[@]}" -import-objc-header "$ROOT/src/helper/bridge.h" -o "$TMP/com.matrixsys.helper" "$ROOT"/src/shared/*.swift "$ROOT"/src/helper/*.swift -lpcap
fi
echo "== bundling"
STAGE="$TMP/MatrixSys.app"; rm -rf "$STAGE"; mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources"
cp "$TMP/MatrixSys" "$STAGE/Contents/MacOS/MatrixSys"
[ -f "$TMP/com.matrixsys.helper" ] && cp "$TMP/com.matrixsys.helper" "$STAGE/Contents/MacOS/com.matrixsys.helper"
[ -d "$ROOT/resources" ] && cp -R "$ROOT"/resources/. "$STAGE/Contents/Resources/" 2>/dev/null || true
[ -f "$OUT/MatrixSys.icns" ] && cp "$OUT/MatrixSys.icns" "$STAGE/Contents/Resources/MatrixSys.icns"
cat > "$STAGE/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.matrixsys.app</string>
<key>CFBundleName</key><string>MatrixSys</string>
<key>CFBundleDisplayName</key><string>MatrixSys</string>
<key>CFBundleExecutable</key><string>MatrixSys</string>
<key>CFBundleIconFile</key><string>MatrixSys</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSAppleEventsUsageDescription</key><string>MatrixSys asks Finder to empty the Trash when you choose EMPTY TRASH.</string>
<key>NSHumanReadableCopyright</key><string>MatrixSys — native offline system visualizer</string>
</dict></plist>
PL
codesign --force --sign - --identifier com.matrixsys.helper "$STAGE/Contents/MacOS/com.matrixsys.helper" 2>/dev/null || true
codesign --force --sign - --identifier com.matrixsys.app "$STAGE" >/dev/null
# swap in atomically so rebuilding works while the app is running
if [ -d "$APP" ]; then mv "$APP" "$TMP/old.app.$$"; fi
mv "$STAGE" "$APP"; rm -rf "$TMP"/old.app.* 2>/dev/null || true
echo "== built $APP"
if [ "${1:-}" = "--dmg" ]; then
  echo "== dmg"
  D="$OUT/.dmg"; rm -rf "$D"; mkdir -p "$D"
  cp -R "$APP" "$D/"
  ln -s /Applications "$D/Applications"
  cp "$ROOT/resources/uninstall.sh" "$D/Uninstall MatrixSys.command"; chmod +x "$D/Uninstall MatrixSys.command"
  cp "$ROOT/README.md" "$D/README.md"
  rm -f "$OUT/MatrixSys.dmg"
  hdiutil create -quiet -volname MatrixSys -srcfolder "$D" -fs HFS+ -format UDZO "$OUT/MatrixSys.dmg"
  rm -rf "$D"
  echo "== built $OUT/MatrixSys.dmg"
fi
