#!/usr/bin/env python3
"""Fetch the fix diff for every case in a PR-7 selection, for guard ablation.

Uses the host-aware URL variants of rescue_patches.py (GitHub, GitLab, googlesource, gitweb,
cgit, hg). A case whose diff cannot be fetched is listed, not guessed.

Usage: fetch_fix_diffs.py data/validation/pr7_pilot.json --out <dir>
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from rescue_patches import get, variants  # noqa: E402

from chainforge.evidence import clip_patch  # noqa: E402


def fetch(url: str) -> str | None:
    for kind, v in variants(url):
        try:
            b = get(v)
        except Exception:
            continue
        if kind == "b64":
            with contextlib.suppress(Exception):
                b = base64.b64decode(b)
        txt = b.decode("utf-8", "replace")
        if "diff --git" in txt or txt.startswith("From ") or re.search(r"^--- ", txt, re.M):
            return clip_patch(txt, 200_000)
        time.sleep(0.2)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("selection")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sel = json.loads(Path(args.selection).read_text())["selected"]
    missing = []
    with open(out / "targets.tsv", "w") as t:
        for s in sel:
            d = fetch(s["patch_url"])
            if not d:
                missing.append(s["localId"])
                continue
            (out / f"{s['localId']}.diff").write_text(d)
            t.write(f"{s['localId']}\t{s['project']}\n")
    print(f"{len(sel) - len(missing)} diffs fetched; {len(missing)} unfetchable: {missing[:10]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
