#!/usr/bin/env bash
# DOCKER-ONLY: witness the CWE-190 integer-overflow MIDDLE link of a length-3 chain by
# recompiling the VULNERABLE source with UndefinedBehaviorSanitizer and replaying its
# own PoV.
#
# Method: the ARVO image `n132/arvo:<id>-vul` already carries the vulnerable tree at
# /src/<project> plus OSS-Fuzz's /usr/local/bin/compile. Re-running `compile` with
# SANITIZER=undefined re-instruments THAT EXACT SOURCE, then /out/<target> /tmp/poc
# replays the same baked-in PoV. Same revision the ASan sink witness came from, just
# rebuilt -- which is what a middle-link witness requires.
#
# Why not OSS-Fuzz `helper.py build_fuzzers`: it clones the project at current upstream
# HEAD, where these bugs are long fixed. Verified on 42477544 -- that path builds and
# runs cleanly ("Executed ... in 102 ms", zero findings), so it can never witness the
# middle link for any historical case.
#
# Why not the in-image `arvo` helper for the replay: it exports
# UBSAN_OPTIONS=...silence_unsigned_overflow=1, which suppresses exactly the unsigned
# integer overflow we are trying to witness. Run the target binary directly instead.
#
# Why Docker and not ROAR: ROAR has Apptainer, which can run a prebuilt SIF but cannot
# perform the in-container rebuild this needs.
#
# Usage: ubsan_rebuild.sh <arvo_id> [project] [--keep]
# Output: out/ubsan/<id>/{ubsan.txt,result.json}
#
# MEMORY SAFETY. The project build.sh runs `make -j$(nproc)`, so the container's
# visible CPU count sets the number of parallel compilers. On a memory-constrained
# host that OOM-kills the build -- and an OOM looks exactly like "no UBSan findings",
# a silent false negative. Two guards:
#   * CF_BUILD_CPUS (default 4) is applied via --cpuset-cpus, which nproc honours,
#     capping build parallelism (each clang can take ~1-2 GB on large C++ projects).
#   * CF_BUILD_MEM (default 6g) caps container memory so a runaway build is killed
#     inside its container instead of taking down the Docker VM or the host.
# The result records build_ok / oom_suspected so a killed build is never silently
# reported as "no findings". Raise both on a large-memory machine.
set -uo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${CF_UBSAN_OUT:-$HERE/out/ubsan}"
PLATFORM="${ARVO_PLATFORM:-linux/amd64}"
NS="${ARVO_NS:-n132/arvo}"
BUILD_CPUS="${CF_BUILD_CPUS:-4}"
BUILD_MEM="${CF_BUILD_MEM:-6g}"

id=""; project=""; keep=0
for a in "$@"; do
  case "$a" in
    --keep) keep=1 ;;
    *) if [ -z "$id" ]; then id="$a"; elif [ -z "$project" ]; then project="$a"; fi ;;
  esac
done
[ -n "$id" ] || { echo "usage: ubsan_rebuild.sh <arvo_id> [project] [--keep]" >&2; exit 2; }

SIDE="${CF_SIDE:-vul}"  # vul or fix: the CWE-190 witness must fire at vul and not at fix
dst="$OUT/$id/$SIDE"; mkdir -p "$dst"
img="$NS:$id-$SIDE"
say(){ printf '[ubsan] %s\n' "$*" >&2; }

say "pull $img"
attempt=0
until docker pull --platform "$PLATFORM" "$img" >/dev/null 2>&1; do
  attempt=$((attempt+1))
  if [ "$attempt" -ge "${CF_PULL_RETRIES:-4}" ]; then
    echo "{\"id\":\"$id\",\"error\":\"pull failed\"}" | tee "$dst/result.json"; exit 1
  fi
  say "pull retry $attempt in $((attempt*15))s"; sleep $((attempt*15))
done

# The arvo helper runs `/out/<target> /tmp/poc`; recover the target name from it.
target="$(docker run --rm --platform "$PLATFORM" "$img" \
  sh -c 'grep -oE "/out/[a-zA-Z0-9_.-]+" /bin/arvo | head -1 | sed "s|/out/||"' 2>/dev/null)"
[ -n "$target" ] || { echo "{\"id\":\"$id\",\"error\":\"cannot determine fuzz target\"}" | tee "$dst/result.json"; exit 1; }
say "target=$target ${project:+project=$project}"

# Recompile the vulnerable tree with UBSan, then replay the PoV directly. OSS-Fuzz's
# 'compile' needs FUZZING_LANGUAGE and FUZZING_ENGINE (ARVO's 'arvo compile' wrapper sets them;
# bare 'compile' aborts with "unbound variable"), and /work holds the ASan build's
# intermediates, which would otherwise be linked into the UBSan build (undefined __asan_*).
# silence_unsigned_overflow=0 is essential: unsigned wraparound IS the CWE-190 signal.
say "recompiling with SANITIZER=undefined and replaying (cpus=$BUILD_CPUS mem=$BUILD_MEM; minutes)"
last_cpu=$((BUILD_CPUS - 1)); [ "$last_cpu" -ge 0 ] || last_cpu=0
docker run --rm --platform "$PLATFORM" \
  --cpuset-cpus="0-${last_cpu}" --memory="$BUILD_MEM" --memory-swap="$BUILD_MEM" \
  -e SANITIZER=undefined \
  -e FUZZING_LANGUAGE="${CF_LANG:-c++}" -e FUZZING_ENGINE="${CF_ENGINE:-libfuzzer}" \
  -e ARCHITECTURE=x86_64 \
  -e UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=0:silence_unsigned_overflow=0:symbolize=1' \
  "$img" \
  bash -c "rm -rf /work/* 2>/dev/null; compile >/tmp/build.log 2>&1; echo \"BUILD_EXIT=\$?\"; grep -nE 'error|Error [0-9]' /tmp/build.log | head -8; tail -5 /tmp/build.log; echo '=== REPLAY ==='; /out/$target /tmp/poc 2>&1" \
  >"$dst/ubsan.txt" 2>&1
run_rc=$?
[ "$run_rc" -eq 0 ] || say "docker run exit=$run_rc (137 = OOM-killed)"
echo "DOCKER_RUN_RC=$run_rc" >> "$dst/ubsan.txt"

[ "$keep" -eq 1 ] || docker rmi "$img" >/dev/null 2>&1 || true

python3 - "$id" "${project:-}" "$target" "$dst" <<'PY' | tee "$dst/result.json"
import json, re, sys
id_, project, target, dst = sys.argv[1:5]
text = open(f"{dst}/ubsan.txt", errors="replace").read()
build_ok = "BUILD_EXIT=0" in text
rc = re.search(r"DOCKER_RUN_RC=(\d+)", text)
run_rc = int(rc.group(1)) if rc else None
# 137 = SIGKILL, the cgroup OOM killer. Also catch the compiler being killed mid-build.
oom = run_rc == 137 or bool(re.search(r"(Killed|virtual memory exhausted|"
                                      r"cc1plus: out of memory|signal 9)", text))
# each UBSan finding: "<file>:<line>:<col>: runtime error: <kind>" + a stack whose
# frame #0 names the function. Both the kind and the location are the link evidence.
findings = []
for m in re.finditer(r"^(/\S+?):(\d+):(\d+): runtime error: (.+)$", text, re.M):
    findings.append({"file": m.group(1), "line": int(m.group(2)), "kind": m.group(4).strip()})
for f in findings:
    fr = re.search(rf"#0 0x\w+ in (\S+) {re.escape(f['file'])}:{f['line']}", text)
    if fr:
        f["function"] = fr.group(1)
overflow = [f for f in findings if "overflow" in f["kind"]]
rec = {
    "id": id_, "project": project or None, "target": target,
    "build_ok": build_ok,
    "oom_suspected": oom,
    "docker_run_rc": run_rc,
    "ubsan_findings": len(findings),
    "findings": findings,
    # Only a SUCCESSFUL build can assert absence. A failed/OOM-killed build is
    # inconclusive, never "no middle link" -- otherwise OOM reads as a real result.
    "witnesses_cwe190": bool(overflow),
    "conclusive": bool(build_ok and not oom),
    "middle_link_evidence": overflow[:3],
}
print(json.dumps(rec, separators=(",", ":")))
PY

say "done -> $dst/result.json"
