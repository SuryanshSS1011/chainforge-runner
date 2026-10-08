#!/usr/bin/env bash
# Replay one ARVO case on a clean Docker host: the vulnerable image once, the patched image twice,
# keeping every log. Classification matches the CHAINFORGE pipeline exactly:
#   crashed  a sanitizer / libFuzzer crash line is present
#   clean    no crash AND the engine reports the input executed (libFuzzer "Executed /tmp/poc",
#            AFL "Execution successful", honggfuzz "Accepting input ..." then its usage line)
#   not_run  neither: the binary never reached the input (an environment failure, not a result)
# A 32-bit ASan binary that aborts on its shadow-memory layout is retried once with ASLR off.
#
# Usage: rerun.sh <arvo_id> <outdir>
set -uo pipefail
ID="${1:?usage: rerun.sh <arvo_id> <outdir>}"
OUT="${2:?missing outdir}"
mkdir -p "$OUT"
CRASH_RE='(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer|libFuzzer: deadly signal|DEADLYSIGNAL|SUMMARY: .*Sanitizer|runtime error:)'
EXEC_RE='Executed /tmp/poc|Execution successful'

pull() { for t in 1 2 3; do docker pull -q "n132/arvo:$1" >>"$OUT/pull.log" 2>&1 && return 0; sleep 60; done; return 1; }
run() {  # tag log -> crashed | clean | not_run
  timeout 600 docker run --rm "n132/arvo:$1" arvo >"$2" 2>&1
  if grep -q "Shadow memory range interleaves" "$2"; then
    sudo sysctl -qw kernel.randomize_va_space=0
    timeout 600 docker run --rm "n132/arvo:$1" arvo >"$2" 2>&1
    sudo sysctl -qw kernel.randomize_va_space=2
    echo "aslr-off retry" >>"$OUT/notes.txt"
  fi
  if grep -Eq "$CRASH_RE" "$2"; then echo crashed
  elif grep -Eq "$EXEC_RE" "$2" || { grep -q "Accepting input from '/tmp/poc'" "$2" && grep -q "Usage for fuzzing" "$2"; }; then echo clean
  else echo not_run; fi
}

pull "$ID-vul" || { echo '{"status":"pull_failed","side":"vul"}' >"$OUT/result.json"; exit 0; }
pull "$ID-fix" || { echo '{"status":"pull_failed","side":"fix"}' >"$OUT/result.json"; exit 0; }
V=$(run "$ID-vul" "$OUT/vul.sanitizer.txt")
F1=$(run "$ID-fix" "$OUT/fix1.sanitizer.txt")
F2=$(run "$ID-fix" "$OUT/fix2.sanitizer.txt")
VD=$(docker image inspect --format '{{index .RepoDigests 0}}' "n132/arvo:$ID-vul" 2>/dev/null)
FD=$(docker image inspect --format '{{index .RepoDigests 0}}' "n132/arvo:$ID-fix" 2>/dev/null)
docker rmi -f "n132/arvo:$ID-vul" "n132/arvo:$ID-fix" >/dev/null 2>&1
python3 - "$OUT/result.json" "$ID" "$V" "$F1" "$F2" "$VD" "$FD" <<'PY'
import json, sys
out, i, v, f1, f2, vd, fd = sys.argv[1:]
two = v == "crashed" and f1 == "clean" and f2 == "clean"
json.dump({"local_id": i, "host": "github-actions", "vul": v, "fix": [f1, f2],
           "vul_digest": vd or None, "fix_digest": fd or None,
           "status": "differential" if two else "not_differential"}, open(out, "w"), indent=1)
PY
echo "[$ID] vul=$V fix=$F1,$F2"
