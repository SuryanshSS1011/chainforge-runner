#!/usr/bin/env bash
# Score one candidate patch against one ARVO-backed record: the replay outcome a repair reward
# can use. This is the IMPLEMENTED reward signal; nothing here judges root cause or semantics.
#
#   1. start a fresh container of the record's VULNERABLE image (pin it by digest for training);
#   2. apply the candidate patch where it dry-runs (project dir first, -p1/-p0/-p2); if the
#      whole patch applies nowhere, apply it file by file, each where it dry-runs (a fix can span
#      repositories under /src). A file may be left out only if the image cannot build from it:
#      it is absent from the image, or it is neither code nor build glue (docs, CI, changelogs,
#      test data). Any code or build file that exists and does not apply is `patch_fail`.
#      The same rule holds for a policy's patch and the developer's; result.json "apply" lists
#      every file and what happened to it;
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
#   patch_fail  a code or build file the image contains could not be patched
#   not_run     some replay never reached the input: an environment failure, NOT a negative
#               reward (R10); retry it rather than scoring it
#
# With CF_CORPUS=1 and CF_TARGET=<fuzz target> (libFuzzer only), the same container then loads
# the project's seed corpus (/out/<target>_seed_corpus.zip, at most 2000 inputs) into the
# patched build with -runs=0 and records libFuzzer's INITED coverage (result.json "corpus").
# Compared with the unpatched build's figure, it shows a patch that rejects inputs early.
# It is a shaping signal, not a correctness check (chainforge.reward.coverage_kept).
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
  # One patch per file, for the file-by-file fallback (the image may have no python3).
  rm -rf "$OUT/files"; mkdir -p "$OUT/files"
  python3 - "$PATCH" "$OUT/files" <<'PY'
import re, sys
from pathlib import Path
text, out = Path(sys.argv[1]).read_text(errors="replace"), Path(sys.argv[2])
CODE = re.compile(r"\.(c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx|inc|ipp|inl|S|s|asm)$", re.I)
BUILD = re.compile(
    r"(^|/)(CMakeLists\.txt|Makefile[^/]*|GNUmakefile|meson\.build|meson_options\.txt|BUILD(\.gn|\.bazel)?"
    r"|configure(\.ac|\.in)?|build\.sh|Kconfig[^/]*|Kbuild)$|\.(am|ac|mk|cmake|gn|gni|gyp|gypi|bzl|pro|pri)$",
    re.I,
)
parts = re.split(r"(?m)^(?=diff --git )", text)
rows = []
for part in parts:
    m = re.match(r"diff --git a/(\S+) b/(\S+)", part)
    if not m:
        continue
    path = m.group(2)
    kind = "code" if CODE.search(path) else "build" if BUILD.search(path) else "other"
    new = "new" if re.search(r"(?m)^(new file mode|--- /dev/null)", part) else "old"
    n = len(rows)
    (out / f"{n:03d}.patch").write_text(part)
    rows.append(f"{n:03d}\t{kind}\t{new}\t{path}")
(out / "index.tsv").write_text("\n".join(rows) + ("\n" if rows else ""))
PY
  MNT+=(-v "$OUT/files:/tmp/cf_files:ro")
fi

for t in 1 2 3; do docker pull -q "$IMG" >"$OUT/pull.log" 2>&1 && break; sleep 60; done
docker image inspect "$IMG" >/dev/null 2>&1 || {
  echo '{"outcome":"not_run","why":"image pull failed"}' >"$OUT/result.json"; exit 0; }

# One container: patch, rebuild once, replay RUNS times. Each replay's output is delimited.
timeout 7200 docker run --rm "${MNT[@]}" -e CF_RUNS="$RUNS" -e CF_CORPUS="${CF_CORPUS:-0}" \
  -e CF_TARGET="${CF_TARGET:-}" "$IMG" bash -c '
  if [ -f /tmp/cf_p.patch ]; then
    WD=$PWD
    # Where a patch dry-runs: the project directory first, then the working directory, then
    # every repository under /src, at -p1, -p0, -p2.
    where() {
      for D in "/src/'"$PROJECT"'" "$WD" /src/*/; do
        for L in 1 0 2; do
          (cd "$D" 2>/dev/null && patch -p$L --fuzz=$2 --forward --batch --dry-run < "$1" >/dev/null 2>&1) \
            && { echo "$D $L"; return 0; }
        done
      done
      return 1
    }
    # Strict first: context must match exactly (offsets allowed). Only if that fails anywhere,
    # GNU patch default fuzz (2 context lines may mismatch), which result.json reports, because a
    # fuzzed hunk can land where its context does not match.
    ok=0
    for FZ in 0 2; do
      if loc=$(where /tmp/cf_p.patch $FZ); then
        set -- $loc
        (cd "$1" && patch -p$2 --fuzz=$FZ --forward --batch < /tmp/cf_p.patch > /tmp/p.log 2>&1) || { echo CF_PATCH_FAIL; cat /tmp/p.log; exit 9; }
        echo "CF_PATCHED_AT $1 -p$2"; echo "CF_APPLY_MODE whole"; echo "CF_APPLY_FUZZ $FZ"; ok=1; break
      fi
      # File by file, each where it dry-runs. A file is left out only if the image cannot build
      # from it: absent from the image, or neither code nor build glue.
      [ -s /tmp/cf_files/index.tsv ] || continue
      # Dry-run every file first and apply only if all are placed, so a failed strict attempt
      # leaves the tree untouched for the lenient one.
      plan=""; out=""; fail=0
      while IFS="$(printf "\t")" read -r n kind new path; do
        if loc=$(where /tmp/cf_files/$n.patch $FZ); then
          plan="$plan$n $loc;"; out="$out CF_APPLY $n applied;"; continue
        fi
        exists=0
        for D in "/src/'"$PROJECT"'" "$WD" /src/*/; do
          { [ -e "$D/$path" ] || [ -e "$D/${path#*/}" ]; } && { exists=1; break; }
        done
        if [ "$kind" = other ]; then out="$out CF_APPLY $n skipped_not_built;"
        elif [ "$exists" = 0 ] && [ "$new" = old ]; then out="$out CF_APPLY $n skipped_absent;"
        else out="$out CF_APPLY $n failed;"; fail=1
        fi
      done < /tmp/cf_files/index.tsv
      [ "$fail" = 0 ] || continue
      echo "$plan" | tr ";" "\n" | grep . | while read -r n D L; do
        (cd "$D" && patch -p$L --fuzz=$FZ --forward --batch < /tmp/cf_files/$n.patch >/dev/null 2>&1) || echo "CF_APPLY $n failed_on_apply"
      done > /tmp/apply_err
      [ -s /tmp/apply_err ] && { cat /tmp/apply_err; echo CF_PATCH_FAIL; exit 9; }
      echo "CF_APPLY_MODE per-file"; echo "CF_APPLY_FUZZ $FZ"
      echo "$out" | tr ";" "\n" | sed "s/^ *//" | grep .; ok=1; break
    done
    [ "$ok" = 1 ] || { echo CF_PATCH_FAIL; echo "$out" | tr ";" "\n"; exit 9; }
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
  if [ "$CF_CORPUS" = 1 ] && [ -n "$CF_TARGET" ] && [ -x "/out/$CF_TARGET" ]; then
    Z="/out/${CF_TARGET}_seed_corpus.zip"
    if [ -f "$Z" ]; then
      mkdir -p /tmp/cz /tmp/corpus && { unzip -qo "$Z" -d /tmp/cz >/dev/null 2>&1 || python3 -m zipfile -e "$Z" /tmp/cz >/dev/null 2>&1; }
      i=0; find /tmp/cz -type f | sort | head -n 2000 | while read -r f; do cp "$f" "/tmp/corpus/$i"; i=$((i+1)); done
      echo "CF_CORPUS_INPUTS $(ls /tmp/corpus | wc -l)"
      timeout 1200 "/out/$CF_TARGET" -runs=0 -timeout=25 -rss_limit_mb=2560 /tmp/corpus 2>&1 \
        | grep -E "INITED|ERROR: (Address|Memory|UndefinedBehavior)Sanitizer|deadly signal|runtime error:" | head -5 \
        | sed "s/^/CF_CORPUS_LINE /"
    else
      echo "CF_CORPUS_NONE no seed corpus for $CF_TARGET"
    fi
  fi
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
mode = re.search(r"CF_APPLY_MODE (\S+)", log)
if mode:
    idx = {}
    try:
        for line in open(f"{out}/files/index.tsv"):
            n, kind, new, path = line.rstrip("\n").split("\t")
            idx[n] = {"file": path, "kind": kind}
    except OSError:
        pass
    status = dict(re.findall(r"CF_APPLY (\d{3}) (\S+)", log))
    res["apply"] = {
        "mode": mode.group(1),
    "fuzz": int(fz.group(1)) if (fz := re.search(r"CF_APPLY_FUZZ (\d)", log)) else None,
        "files": [v | {"status": status.get(k, "applied" if mode.group(1) == "whole" else "not tried")}
                  for k, v in sorted(idx.items())],
    }
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
if "CF_CORPUS_INPUTS" in log or "CF_CORPUS_NONE" in log:
    n = re.search(r"CF_CORPUS_INPUTS (\d+)", log)
    i = re.search(r"CF_CORPUS_LINE .*INITED cov: (\d+) ft: (\d+)", log)
    res["corpus"] = {
        "inputs": int(n.group(1)) if n else 0,
        "cov": int(i.group(1)) if i else None,
        "ft": int(i.group(2)) if i else None,
        "crashed": bool(re.search(r"CF_CORPUS_LINE .*(Sanitizer|deadly signal|runtime error)", log)),
    }
json.dump(res, open(f"{out}/result.json", "w"), indent=1)
print(res["outcome"], res["runs"])
PY
