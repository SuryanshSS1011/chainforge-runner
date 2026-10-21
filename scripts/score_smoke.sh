#!/usr/bin/env bash
# Smoke test of score_patch.sh on one case: the unmodified build must score "crash" and the
# developer's own fix must score "pass". With a fuzz target, both runs also record seed-corpus
# coverage (CF_CORPUS). Usage: score_smoke.sh <arvo_id> <project> <fix url> <out> [target]
set -uo pipefail
ID="$1"; PROJECT="$2"; URL="$3"; OUT="$4"; TARGET="${5:-}"
[ -n "$TARGET" ] && export CF_CORPUS=1 CF_TARGET="$TARGET"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$OUT"
python3 - "$URL" "$OUT/fix.diff" "$HERE" <<'PY' || { echo '{"status":"diff_unfetchable"}' > "$OUT/smoke.json"; exit 0; }
import sys
sys.path.insert(0, sys.argv[3] + "/repo/infra/verify")
from fetch_fix_diffs import fetch
d = fetch(sys.argv[1])
if not d:
    raise SystemExit(1)
open(sys.argv[2], "w").write(d)
PY
bash "$HERE/scripts/score_patch.sh" "$ID" "$PROJECT" - "$OUT/nopatch"
bash "$HERE/scripts/score_patch.sh" "$ID" "$PROJECT" "$OUT/fix.diff" "$OUT/devfix"
docker rmi -f "n132/arvo:${ID}-vul" >/dev/null 2>&1
python3 -c "
import json
A=json.load(open('$OUT/nopatch/result.json')); B=json.load(open('$OUT/devfix/result.json'))
a=A['outcome']; b=B['outcome']
json.dump({'arvo_id':'$ID','nopatch':a,'devfix':b,'as_expected':a=='crash' and b=='pass','corpus_nopatch':A.get('corpus'),'corpus_devfix':B.get('corpus')},open('$OUT/smoke.json','w'),indent=1)"
cat "$OUT/smoke.json"
