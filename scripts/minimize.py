#!/usr/bin/env python3
"""PR-13(b): shrink a proving hunk to a 1-minimal set of its added lines (ddmin).

For one ARVO case: fetch the fix, split it exactly as the single-hunk test did, take the named
proving hunk, then remove added lines while a full rebuild plus one replay of the record's input
stays clean. Each variant is a fresh container (OSS-Fuzz build.sh is not idempotent).

Usage: minimize.py <arvo_id> <project> <patch_url> <hunk name> <out dir>
Writes <out>/result.json: the kept added-line indices (0-based, in hunk order), the number of
added lines, the number of tests, and status. Nothing else; the caller encrypts it.
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "repo" / "infra" / "verify"))
from fetch_fix_diffs import fetch  # noqa: E402
from split_hunks import split  # noqa: E402

CRASH = re.compile(r"ERROR: (Address|Memory|Leak)Sanitizer|WARNING: MemorySanitizer|runtime error:|SUMMARY: .*Sanitizer")
RAN = re.compile(r"Executed /tmp/poc|Execution successful")


def variant_patch(hunk: str, keep: set[int]) -> str:
    """The hunk with only the added lines in `keep`; header counts recomputed."""
    head, _, body = hunk.partition("\n@@")
    body = "@@" + body
    lines = body.split("\n")
    hdr, rest = lines[0], lines[1:]
    m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", hdr)
    out, k, old, new = [], 0, 0, 0
    for ln in rest:
        if ln.startswith("+"):
            if k in keep:
                out.append(ln)
                new += 1
            k += 1
        elif ln.startswith("-"):
            out.append(ln)
            old += 1
        elif ln.startswith(" ") or ln == "":
            if ln == "" and ln is rest[-1]:
                continue
            out.append(ln)
            old += 1
            new += 1
        else:
            out.append(ln)
    hdr = f"@@ -{m.group(1)},{old} +{m.group(3)},{new} @@{m.group(5)}"
    return head + "\n" + hdr + "\n" + "\n".join(out) + "\n"


def run(img: str, project: str, patch: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as f:
        f.write(patch)
    script = (
        'WD=$PWD; at=""; for D in "/src/' + project + '" "$WD" /src/*/; do for L in 1 0 2; do '
        '(cd "$D" 2>/dev/null && patch -p$L --forward --batch --dry-run < /tmp/p.patch >/dev/null 2>&1) '
        '&& { at=$D; break 2; }; done; done; [ -n "$at" ] || { echo CF_PATCH_FAIL; exit 9; }; '
        '(cd "$at" && patch -p$L --forward --batch < /tmp/p.patch >/dev/null 2>&1) || { echo CF_PATCH_FAIL; exit 9; }; '
        'cd "$WD"; sed -i -E "s/(^|[;&|[:space:]])mkdir ([^-])/\\1mkdir -p \\2/" "$SRC/build.sh" 2>/dev/null; '
        'arvo compile >/tmp/b.log 2>&1 || { echo CF_BUILD_FAIL; exit 8; }; arvo run 2>&1 | head -80'
    )
    p = subprocess.run(
        ["timeout", "7200", "docker", "run", "--rm", "-v", f"{f.name}:/tmp/p.patch:ro", img, "bash", "-c", script],
        capture_output=True, text=True, errors="replace",
    )
    log = p.stdout + p.stderr
    if "CF_PATCH_FAIL" in log:
        return "patchfail"
    if "CF_BUILD_FAIL" in log:
        return "buildfail"
    if CRASH.search(log):
        return "crashed"
    return "clean" if RAN.search(log) else "infrafail"


def main() -> int:
    aid, project, url, hunk_name, out = sys.argv[1:6]
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    def emit(d):
        (out / "result.json").write_text(json.dumps({"arvo_id": aid, **d}))
        return 0

    diff = fetch(url)
    if not diff:
        return emit({"status": "diff_unfetchable"})
    hunks = sorted(split(diff), key=lambda h: h["added"] + h["removed"])
    i = int(hunk_name[4:6]) if hunk_name.startswith("hunk") else -1
    if not 0 <= i < len(hunks):
        return emit({"status": "hunk_not_reproduced"})
    hunk = hunks[i]["patch"]
    n = hunks[i]["added"]
    if n < 1 or n > 12:
        return emit({"status": "out_of_range", "added": n})
    img = f"n132/arvo:{aid}-vul"
    for _ in range(3):
        if subprocess.run(["docker", "pull", "-q", img], capture_output=True).returncode == 0:
            break
    tests = 0
    full = run(img, project, variant_patch(hunk, set(range(n))))
    tests += 1
    if full != "clean":
        subprocess.run(["docker", "rmi", "-f", img], capture_output=True)
        return emit({"status": f"full_hunk_{full}", "added": n, "tests": tests})
    # ddmin over the added lines: find a 1-minimal subset that still runs clean.
    cur, gran = list(range(n)), 2
    while len(cur) >= 2:
        size = max(1, len(cur) // gran)
        chunks = [cur[k : k + size] for k in range(0, len(cur), size)]
        reduced = False
        for c in chunks:
            comp = [x for x in cur if x not in c]
            if not comp:
                continue
            v = run(img, project, variant_patch(hunk, set(comp)))
            tests += 1
            if v == "infrafail":
                subprocess.run(["docker", "rmi", "-f", img], capture_output=True)
                return emit({"status": "infrafail", "added": n, "tests": tests})
            if v == "clean":
                cur, gran, reduced = comp, max(gran - 1, 2), True
                break
        if not reduced:
            if gran >= len(cur):
                break
            gran = min(len(cur), gran * 2)
    subprocess.run(["docker", "rmi", "-f", img], capture_output=True)
    return emit({"status": "ok", "added": n, "kept": cur, "tests": tests})


if __name__ == "__main__":
    raise SystemExit(main())
