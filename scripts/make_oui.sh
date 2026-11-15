#!/bin/bash
# Builds resources/oui.txt, the MAC-prefix -> vendor table the LAN view shows next to a hardware address.
#
# This is the one file in MatrixSys that comes from the network, and it is NOT built by scripts/build.sh: run it by
# hand when you want vendor names. Without it the app shows the raw OUI and claims no vendor, which is why it is
# optional rather than bundled stale.
#
# Source: the IEEE's public MA-L registry (https://standards-oui.ieee.org/oui/oui.csv), about 4 MB.
# Output:  resources/oui.txt, "AABBCC<tab>Vendor", one per line, plus a comment line with the date it was built.
#
# Usage: scripts/make_oui.sh [path-to-oui.csv]
#        With no argument it downloads the registry. Pass a file you already have to stay offline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/resources/oui.txt"
SRC="${1:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -z "$SRC" ]; then
  echo "== downloading the IEEE MA-L registry (about 4 MB)"
  curl -fsSL --max-time 120 -o "$TMP/oui.csv" "https://standards-oui.ieee.org/oui/oui.csv"
  SRC="$TMP/oui.csv"
fi
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 1; }

echo "== building $OUT"
{
  echo "# MAC prefix to vendor, from the IEEE MA-L registry, built $(date -u '+%Y-%m-%d')"
  # CSV columns: Registry,Assignment,Organization Name,Organization Address
  python3 - "$SRC" <<'PY'
import csv, sys, re
seen = set()
rows = []
with open(sys.argv[1], newline="", encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        a = (r.get("Assignment") or "").strip().upper()
        n = (r.get("Organization Name") or "").strip()
        if len(a) != 6 or not re.fullmatch(r"[0-9A-F]{6}", a) or not n or a in seen:
            continue
        seen.add(a)
        # one line, no tabs, and short enough for a panel row
        n = re.sub(r"\s+", " ", n.replace("\t", " "))
        for drop in (", Inc.", " Inc.", ", Inc", " Inc", ", Ltd.", " Ltd.", ", Ltd", " Ltd",
                     ", LLC", " LLC", " Corporation", " Corp.", " Co., Ltd.", " GmbH", " S.A.", " B.V."):
            if n.endswith(drop):
                n = n[: -len(drop)]
                break
        rows.append((a, n.strip()[:40]))
rows.sort()
for a, n in rows:
    print(f"{a}\t{n}")
print(f"# {len(rows)} assignments", file=sys.stderr)
PY
} > "$TMP/oui.txt"

mv "$TMP/oui.txt" "$OUT"
echo "== wrote $OUT ($(wc -l < "$OUT" | tr -d ' ') lines, $(du -h "$OUT" | cut -f1))"
echo "   rebuild the app to bundle it: scripts/build.sh"
