#!/usr/bin/env bash
# Guard ablation for one ARVO case on a clean Docker host (the ROAR ablate.sh, minus Apptainer).
# Rebuild the vulnerable image unmodified (the control), then with exactly one hunk of the
# developer's fix applied, replaying the PoV each time; a hunk that alone stops the crash is the
# guard. Docker honours the image's WORKDIR and runs as root, which removes the cwd, read-only
# /out and home-quota failures seen under Apptainer. Every variant gets a fresh container:
# OSS-Fuzz build.sh is not idempotent. All logs are kept; the verdict is made by CHAINFORGE.
#
# Usage: ablate_docker.sh <arvo_id> <project> <patch_url> <outdir>
set -uo pipefail
ID="$1"; PROJECT="$2"; URL="$3"; OUT="$4"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$OUT"
log(){ echo "[$ID] $*" >&2; }
emit(){ printf '%s\n' "$1" > "$OUT/result.json"; exit 0; }
IMG="n132/arvo:${ID}-vul"

python3 - "$URL" "$OUT/fix.diff" "$HERE" <<'PY' || emit '{"status":"diff_unfetchable"}'
import sys
sys.path.insert(0, sys.argv[3] + "/repo/infra/verify")
from fetch_fix_diffs import fetch
d = fetch(sys.argv[1])
if not d:
    raise SystemExit(1)
open(sys.argv[2], "w").write(d)
PY
python3 "$HERE/repo/infra/verify/split_hunks.py" "$OUT/fix.diff" "$OUT/hunks" > "$OUT/split.log" 2>&1 \
  || emit '{"status":"hunk_split_failed"}'
N=$(python3 -c "import json;print(json.load(open('$OUT/hunks/index.json'))['written'])" 2>/dev/null || echo 0)
[ "$N" -gt 0 ] || emit '{"status":"no_code_hunks"}'
for t in 1 2 3; do docker pull -q "$IMG" >/dev/null 2>&1 && break; sleep 60; done
docker image inspect "$IMG" >/dev/null 2>&1 || emit '{"status":"image_pull_failed"}'
log "$N candidate hunks"

variant(){  # <log> [patch] : fresh container, optional patch, full rebuild, replay
  local P="${2:-}"
  timeout 7200 docker run --rm ${P:+-v "$P:/tmp/cf_p.patch:ro"} "$IMG" bash -c '
    if [ -f /tmp/cf_p.patch ]; then
      for L in 1 0 2; do patch -p$L --forward --batch --dry-run < /tmp/cf_p.patch >/dev/null 2>&1 && break; done
      patch -p$L --forward --batch < /tmp/cf_p.patch > /tmp/p.log 2>&1 || { echo CF_PATCH_FAIL; cat /tmp/p.log; exit 9; }
    fi
    arvo compile > /tmp/b.log 2>&1 || { echo CF_BUILD_FAIL; tail -40 /tmp/b.log; exit 8; }
    arvo run 2>&1 | head -80' > "$1" 2>&1
}
verdict(){
  grep -q CF_PATCH_FAIL "$1" && { echo patchfail; return; }
  grep -q CF_BUILD_FAIL "$1" && { echo buildfail; return; }
  [ -s "$1" ] || { echo infrafail; return; }
  grep -qE "ERROR: (Address|Memory|Leak)Sanitizer|WARNING: MemorySanitizer|runtime error:|SUMMARY: .*Sanitizer" "$1" \
    && echo crashed || echo clean
}

variant "$OUT/control.log"
CTRL=$(verdict "$OUT/control.log"); log "control -> $CTRL"
[ "$CTRL" = "crashed" ] || emit "{\"arvo_id\":\"$ID\",\"project\":\"$PROJECT\",\"status\":\"control_$([ "$CTRL" = clean ] && echo did_not_crash || echo infrastructure_failed)\",\"control\":\"$CTRL\"}"

RESULTS="[]"
for i in $(seq 0 $((N-1))); do
  H=$(printf "hunk%02d.patch" "$i")
  variant "$OUT/$H.log" "$OUT/hunks/$H"
  R=$(verdict "$OUT/$H.log"); log "  $H -> $R"
  RESULTS=$(python3 -c "
import json
r=json.loads('''$RESULTS''')
h={x['name']:x for x in json.load(open('$OUT/hunks/index.json'))['hunks']}.get('$H',{})
r.append({'hunk':'$H','file':h.get('file'),'added':h.get('added'),'removed':h.get('removed'),'outcome':'$R'})
print(json.dumps(r))")
  [ "$R" = clean ] && break
done
docker rmi -f "$IMG" >/dev/null 2>&1
python3 - <<PY > "$OUT/result.json"
import json
res = json.loads('''$RESULTS''')
g = next((r for r in res if r["outcome"] == "clean"), None)
print(json.dumps({"arvo_id": "$ID", "project": "$PROJECT", "status": "ok", "control": "$CTRL",
                  "host": "github-actions", "n_hunks": $N, "n_tried": len(res), "results": res,
                  "guard_hunk": g, "source_causally_proven": bool(g)}, indent=1))
PY
