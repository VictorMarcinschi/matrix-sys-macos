#!/bin/bash
# Relaunch the built app with the test socket (for unattended checks). Usage: scripts/run-test.sh [extra args]
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; SOCK="$TMPDIR/msys.sock"
pkill -f "MatrixSys.app/Contents/MacOS/MatrixSys" 2>/dev/null; /bin/sleep 0.5
"$ROOT/build/MatrixSys.app/Contents/MacOS/MatrixSys" --background --test-socket "$SOCK" "$@" > "$TMPDIR/msys.log" 2>&1 &
for i in $(seq 1 20); do [ -S "$SOCK" ] && break; /bin/sleep 0.3; done
