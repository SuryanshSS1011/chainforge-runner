#!/usr/bin/env bash
# Fuzz check for hunk tests (PR-4/PR-13 amendment). The tests applied each hunk with GNU patch's
# default fuzz. For one ARVO case: fetch the fix diff, split it as the tests did, find each
# test's hunk(s) by name, file and added-line count, and dry-run them on the vulnerable tree at
# fuzz 0, then at the default fuzz. No build. Prints one JSON line per test key:
#   strict      the hunk(s) apply with every context line matching
#   fuzzy       they apply only with fuzz: the test may have patched another place
#   none        they apply at neither level today
#   unresolved  the hunk(s) could not be found again in the re-split diff
# Keys are opaque; no hunk name, file or site reaches the output.
#
# Usage: fuzz_check.sh <arvo_id> <project> <fix url> <specs file: key \t name|file|added[;...]>
set -uo pipefail
ID="$1"; PROJECT="$2"; URL="$3"; SPECS="$4"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
W=$(mktemp -d); chmod 755 "$W"
emit_all() { cut -f1 "$SPECS" | while read -r k; do printf '{"arvo_id":"%s","key":"%s","status":"%s"}\n' "$ID" "$k" "$1"; done; rm -rf "$W"; exit 0; }
python3 - "$URL" "$W/fix.diff" "$HERE" <<'PY' || emit_all diff_unfetchable
import sys
sys.path.insert(0, sys.argv[3] + "/repo/infra/verify")
from fetch_fix_diffs import fetch
d = fetch(sys.argv[1])
if not d:
    raise SystemExit(1)
open(sys.argv[2], "w").write(d)
PY
python3 "$HERE/repo/infra/verify/split_hunks.py" "$W/fix.diff" "$W/hunks" >/dev/null 2>&1 || emit_all split_failed
# One patch per test key, from the hunks it names (by name if file and size agree, else the one
# hunk with that file and size).
mkdir -p "$W/keys"
python3 - "$W/hunks" "$SPECS" "$W/keys" <<'PY'
import json, sys
from pathlib import Path
hd, specs, kd = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
idx = json.loads((hd / "index.json").read_text())["hunks"]
for line in specs.read_text().splitlines():
    key, spec = line.split("\t")
    text = ""
    for part in spec.split(";"):
        name, file, added = part.split("|")
        h = next((x for x in idx if x["name"] == name and x["file"] == file
                  and str(x["added"]) == added), None)
        if h is None:
            same = [x for x in idx if x["file"] == file and str(x["added"]) == added]
            h = same[0] if len(same) == 1 else None
        if h is None:
            text = ""
            break
        text += (hd / h["name"]).read_text()
    if text:
        (kd / f"{key}.patch").write_text(text)
PY
IMG="n132/arvo:${ID}-vul"
# Docker Hub, then Google's Hub mirror (same manifest), backing off between rounds.
for w in 60 120 300 600 0; do
  docker pull -q "$IMG" >/dev/null 2>&1 && break
  docker pull -q "mirror.gcr.io/$IMG" >/dev/null 2>&1 && { docker tag "mirror.gcr.io/$IMG" "$IMG"; break; }
  sleep $w
done
docker image inspect "$IMG" >/dev/null 2>&1 || emit_all pull_failed
docker run --rm -v "$W/keys:/keys:ro" "$IMG" bash -c '
  WD=$PWD
  try() {
    for D in "/src/'"$PROJECT"'" "$WD" /src/*/; do
      for L in 1 0 2; do
        (cd "$D" 2>/dev/null && patch -p$L --fuzz=$2 --forward --batch --dry-run < "$1" >/dev/null 2>&1) && return 0
      done
    done
    return 1
  }
  for f in /keys/*.patch; do
    [ -e "$f" ] || continue
    k=$(basename "$f" .patch)
    if try "$f" 0; then echo "$k strict"; elif try "$f" 2; then echo "$k fuzzy"; else echo "$k none"; fi
  done' > "$W/res.txt" 2>/dev/null
cut -f1 "$SPECS" | while read -r k; do
  s=$(awk -v k="$k" '$1==k{print $2}' "$W/res.txt")
  [ -f "$W/keys/$k.patch" ] || s=unresolved
  printf '{"arvo_id":"%s","key":"%s","status":"%s"}\n' "$ID" "$k" "${s:-not_run}"
done
docker rmi -f "$IMG" >/dev/null 2>&1
rm -rf "$W"
