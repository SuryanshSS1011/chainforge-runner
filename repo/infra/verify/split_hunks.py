#!/usr/bin/env python3
"""Split a fix diff into individually-appliable single-hunk patches.

The ablation asks a causal question the corpus cannot currently answer: does THIS hunk of the
developer's fix stop the crash? Answering it needs each hunk as a standalone patch, carrying
its own file header so `patch -p1` can apply it alone.

Splitting also does useful work before any model is involved. A fix with one hunk needs no
ranking at all - there is only one candidate, so the ablation alone decides it. Only
multi-hunk fixes need something to choose an order, which is the narrow job an agent would
have.

Usage: split_hunks.py <fix.diff> <outdir> [--max-hunks N]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import is_non_guard_path  # noqa: E402

FILE_HDR = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.M)
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")
# Files whose changes cannot be the guard: build glue and changelogs here; tests, docs and the
# fuzz harness via the shared rule in chainforge.evidence. A harness hunk CAN silence the crash
# (lwan's clamps the input size), so in the candidate set it yields a "causally proven" source
# for a change that fixed nothing.
IGNORE = re.compile(
    r"(^|/)(\.github|m4|po)/|(ChangeLog|NEWS|README|\.md|\.txt|\.am|\.ac|\.in|configure)$", re.I
)
CODE = re.compile(r"\.(c|cc|cpp|cxx|h|hpp|inc)$", re.I)


def split(diff_text: str):
    """Yield {file, header, hunk_text, added, removed} per hunk, code files only."""
    out = []
    blocks = re.split(r"(?=^diff --git )", diff_text, flags=re.M)
    for b in blocks:
        if not b.strip():
            continue
        m = FILE_HDR.search(b)
        if not m:
            continue
        path = m.group(2)
        if IGNORE.search(path) or is_non_guard_path(path) or not CODE.search(path):
            continue
        lines = b.splitlines(keepends=True)
        # header = everything up to the first @@, needed for each standalone patch
        first = next((i for i, ln in enumerate(lines) if HUNK.match(ln)), None)
        if first is None:
            continue
        header = "".join(lines[:first])
        cur, bodies = [], []
        for ln in lines[first:]:
            if HUNK.match(ln) and cur:
                bodies.append("".join(cur))
                cur = []
            cur.append(ln)
        if cur:
            bodies.append("".join(cur))
        for body in bodies:
            added = sum(
                1 for x in body.splitlines() if x.startswith("+") and not x.startswith("+++")
            )
            removed = sum(
                1 for x in body.splitlines() if x.startswith("-") and not x.startswith("---")
            )
            out.append({"file": path, "patch": header + body, "added": added, "removed": removed})
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("diff")
    ap.add_argument("outdir")
    ap.add_argument("--max-hunks", type=int, default=24)
    args = ap.parse_args(argv)

    with open(args.diff, errors="replace") as fh:
        hunks = split(fh.read())
    os.makedirs(args.outdir, exist_ok=True)
    # Smallest first: a guard is usually a short addition, and a minimal hunk that stops the
    # crash is a far stronger claim than a large one that also happens to.
    hunks.sort(key=lambda h: h["added"] + h["removed"])
    index = []
    for i, h in enumerate(hunks[: args.max_hunks]):
        name = f"hunk{i:02d}.patch"
        with open(os.path.join(args.outdir, name), "w") as fh:
            fh.write(h["patch"])
        index.append(
            {"name": name, "file": h["file"], "added": h["added"], "removed": h["removed"]}
        )
    with open(os.path.join(args.outdir, "index.json"), "w") as fh:
        json.dump({"n_hunks": len(hunks), "written": len(index), "hunks": index}, fh, indent=1)
    print(f"{len(hunks)} code hunks; wrote {len(index)}")
    for h in index:
        print(f"  {h['name']}  +{h['added']:<4} -{h['removed']:<4} {h['file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
