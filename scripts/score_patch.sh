#!/usr/bin/env bash
# Score one candidate patch against one ARVO-backed record: the replay outcome a repair reward
# can use. This is the IMPLEMENTED reward signal; nothing here judges root cause or semantics.
#
#   1. start a fresh container of the record's VULNERABLE image (pin it by digest for training);
#   2. apply the candidate patch where it dry-runs (project dir first, -p1/-p0/-p2);
#   3. rebuild with the image's own build (`arvo compile`);
#   4. replay the record's crashing input RUNS times (default 2, as GOLD's patched side);
#   5. classify each replay exactly as the GOLD pipeline does:
#        crashed  a sanitizer or libFuzzer crash line is present
#        clean    no crash line AND the engine reports the input executed (libFuzzer
#                 "Executed /tmp/poc", AFL "Execution successful", honggfuzz "Accepting input"
#                 followed by its usage line)
#        not_run  neither: the binary never reached the input
#
# outcome (result.json "outcome"):
#   pass        patch applied, build succeeded, every replay clean
#   crash       at least one replay crashed (the witnessed bug, or another sanitizer report)
#   build_fail  the patched tree did not build
#   patch_fail  the patch applies nowhere
#   not_run     some replay never reached the input: an environment failure, NOT a negative
#               reward (R10); retry it rather than scoring it
#
# What "clean" proves: the program read this one input to completion under the sanitizer and
# no report fired. It does not prove the patch fixes the root cause, keeps intended behaviour,
# or handles other inputs; a patch that rejects the input early also scores clean. Pair it with
# the project's tests or other inputs if those properties matter for the reward.
#
# Usage: score_patch.sh <arvo_id> <project> <patch_file|-> <outdir> [runs]
#        (patch "-" scores the unmodified vulnerable build: it should crash)
set -uo pipefail
ID="${1:?usage: score_patch.sh <arvo_id> <project> <patch|-> <outdir> [runs]}"
PROJECT="${2:?project}"
PATCH="${3:?patch file or -}"
OUT="${4:?outdir}"
RUNS="${5:-2}"
IMG="${CF_IMAGE:-n132/arvo:${ID}-vul}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
CRASH_RE='(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer|libFuzzer: deadly signal|DEADLYSIGNAL|SUMMARY: .*Sanitizer|runtime error:)'
EXEC_RE='Executed /tmp/poc|Execution successful'
MNT=()
if [ "$PATCH" != "-" ]; then
  PATCH="$(cd "$(dirname "$PATCH")" && pwd)/$(basename "$PATCH")"
  MNT=(-v "$PATCH:/tmp/cf_p.patch:ro")
fi

for t in 1 2 3; do docker pull -q "$IMG" >"$OUT/pull.log" 2>&1 && break; sleep 60; done
docker image inspect "$IMG" >/dev/null 2>&1 || {
  echo '{"outcome":"not_run","why":"image pull failed"}' >"$OUT/result.json"; exit 0; }

# One container: patch, rebuild once, replay RUNS times. Each replay's output is delimited.
timeout 7200 docker run --rm "${MNT[@]}" -e CF_RUNS="$RUNS" "$IMG" bash -c '
  if [ -f /tmp/cf_p.patch ]; then
    WD=$PWD; at=""
    for D in "/src/'"$PROJECT"'" "$WD" /src/*/; do
      for L in 1 0 2; do
        (cd "$D" 2>/dev/null && patch -p$L --forward --batch --dry-run < /tmp/cf_p.patch >/dev/null 2>&1) \
          && { at=$D; break 2; }
      done
    done
    [ -n "$at" ] || { echo CF_PATCH_FAIL; exit 9; }
    (cd "$at" && patch -p$L --forward --batch < /tmp/cf_p.patch > /tmp/p.log 2>&1) || { echo CF_PATCH_FAIL; cat /tmp/p.log; exit 9; }
    echo "CF_PATCHED_AT $at -p$L"
    cd "$WD"
  fi
  sed -i -E "s/(^|[;&|[:space:]])mkdir ([^-])/\1mkdir -p \2/" "$SRC/build.sh" 2>/dev/null
  t0=$(date +%s)
  arvo compile > /tmp/b.log 2>&1 || { echo CF_BUILD_FAIL; tail -40 /tmp/b.log; exit 8; }
  echo "CF_BUILD_SECONDS $(( $(date +%s) - t0 ))"
  for i in $(seq 1 "$CF_RUNS"); do
    t0=$(date +%s)
    echo "CF_RUN_BEGIN $i"
    timeout 600 arvo run 2>&1 | head -c 20000000
    echo "CF_RUN_END $i"
    echo "CF_RUN_SECONDS $i $(( $(date +%s) - t0 ))"
  done
  # Peak memory of this container (cgroup v2), for the README resource figures.
  echo "CF_PEAK_MEM_BYTES $(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo 0)"' >"$OUT/score.log" 2>&1

SIZE=$(docker image inspect --format '{{.Size}}' "$IMG" 2>/dev/null || echo 0)
python3 - "$OUT" "$RUNS" "$CRASH_RE" "$EXEC_RE" "$PATCH" "$SIZE" <<'PY'
import json, re, sys
out, runs, crash_re, exec_re, patch = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
size = int(sys.argv[6] or 0)
log = open(f"{out}/score.log", errors="replace").read()
def classify(t):
    if re.search(crash_re, t):
        return "crashed"
    if re.search(exec_re, t) or ("Accepting input from '/tmp/poc'" in t and "Usage for fuzzing" in t):
        return "clean"
    return "not_run"
res = {"patch": None if patch == "-" else patch, "runs": []}
if "CF_PATCH_FAIL" in log:
    res["outcome"] = "patch_fail"
elif "CF_BUILD_FAIL" in log:
    res["outcome"] = "build_fail"
else:
    for i in range(1, runs + 1):
        m = re.search(rf"CF_RUN_BEGIN {i}\n(.*?)CF_RUN_END {i}", log, re.S)
        res["runs"].append(classify(m.group(1)) if m else "not_run")
    r = res["runs"]
    res["outcome"] = (
        "crash" if "crashed" in r else "not_run" if "not_run" in r or not r else "pass"
    )
b = re.search(r"CF_BUILD_SECONDS (\d+)", log)
mem = re.search(r"CF_PEAK_MEM_BYTES (\d+)", log)
res["resources"] = {
    "image_bytes": size,
    "build_seconds": int(b.group(1)) if b else None,
    "replay_seconds": [int(x) for x in re.findall(r"CF_RUN_SECONDS \d+ (\d+)", log)],
    "peak_memory_bytes": int(mem.group(1)) if mem and mem.group(1) != "0" else None,
}
json.dump(res, open(f"{out}/result.json", "w"), indent=1)
print(res["outcome"], res["runs"])
PY
