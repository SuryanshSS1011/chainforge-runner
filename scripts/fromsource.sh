#!/usr/bin/env bash
# PR-15: reproduce one ARVO-backed record from upstream source, without ARVO's images. OSS-Fuzz
# at its last commit before the fix date builds the project at the fix's first parent and at the
# fix (helper.py build_image / build_fuzzers); the record's input (taken from ARVO's vulnerable
# image, since only the build is in question) is replayed once on the vulnerable build and twice
# on the fixed build. Logs are kept; the verdict is made by CHAINFORGE.
# Usage: fromsource.sh <arvo_id> <project> <fix sha> <fix date> <target> <repo url> <sanitizer> <out>
set -uo pipefail
ID="$1"; P="$2"; FIX="$3"; DATE="$4"; T="$5"; REPO="$6"; SAN="$7"; OUT="$8"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"; W="$(mktemp -d)"
emit(){ printf '%s\n' "$1" > "$OUT/result.json"; rm -rf "$W"; exit 0; }
cd "$W"
git clone -q --filter=blob:none https://github.com/google/oss-fuzz ofz || emit '{"status":"ossfuzz_clone_failed"}'
OC=$(git -C ofz rev-list -1 --before="$DATE" HEAD)
git -C ofz checkout -q "$OC" || emit '{"status":"ossfuzz_checkout_failed"}'
[ -d "ofz/projects/$P" ] || emit "{\"status\":\"project_not_in_ossfuzz\",\"ossfuzz\":\"$OC\"}"
git clone -q --filter=blob:none "$REPO" "src/$P" > "$OUT/clone.log" 2>&1 || emit '{"status":"repo_clone_failed"}'
git -C "src/$P" cat-file -e "$FIX^{commit}" 2>/dev/null || emit '{"status":"fix_not_in_repo"}'
VUL=$(git -C "src/$P" rev-parse "$FIX^")
IMG="n132/arvo:${ID}-vul"
for w in 60 300 0; do docker pull -q "$IMG" >/dev/null 2>&1 && break; sleep $w; done
C=$(docker create "$IMG") && docker cp "$C:/tmp/poc" "$W/poc" >/dev/null 2>&1; docker rm -f "$C" >/dev/null 2>&1
docker rmi -f "$IMG" >/dev/null 2>&1
[ -s "$W/poc" ] || emit '{"status":"poc_unavailable"}'
cd ofz
timeout 3600 python3 infra/helper.py build_image --pull "$P" > "$OUT/image.log" 2>&1 || emit "{\"status\":\"image_build_failed\",\"ossfuzz\":\"$OC\"}"
side(){  # <rev> <name> <runs>
  git -C "../src/$P" checkout -q -f "$1" && git -C "../src/$P" submodule update -q --init --recursive >/dev/null 2>&1
  if ! timeout 5400 python3 infra/helper.py build_fuzzers --clean --sanitizer "$SAN" "$P" "../src/$P" > "$OUT/build_$2.log" 2>&1; then
    echo build_fail; return; fi
  for i in $(seq 1 "$3"); do
    timeout 600 python3 infra/helper.py reproduce "$P" "$T" "$W/poc" > "$OUT/run_$2_$i.log" 2>&1
  done
  echo built
}
BV=$(side "$VUL" vul 1)
BF=$(side "$FIX" fix 2)
printf '{"arvo_id":"%s","status":"ok","ossfuzz":"%s","vul_rev":"%s","fix_rev":"%s","vul_build":"%s","fix_build":"%s"}\n' \
  "$ID" "$OC" "$VUL" "$FIX" "$BV" "$BF" > "$OUT/result.json"
rm -rf "$W"
