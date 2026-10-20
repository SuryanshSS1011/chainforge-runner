#!/usr/bin/env python3
"""Fetch the fix diff for every case in a PR-7 selection, for guard ablation.

Uses the host-aware URL variants of rescue_patches.py (GitHub, GitLab, googlesource, gitweb,
cgit, hg). If none answers and the pointer names a 40-hex git id, the commit is fetched with git
from the forge, then from its official GitHub mirror, and kept only if `format-patch` reports the
same id. A case whose diff cannot be fetched is listed, not guessed.

Usage: fetch_fix_diffs.py data/validation/pr7_pilot.json --out <dir>
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from rescue_patches import get, variants  # noqa: E402

from chainforge.evidence import clip_patch  # noqa: E402

_SHA = re.compile(r"([0-9a-f]{40})\s*$")
_FROM = re.compile(r"^From ([0-9a-f]{40}) ", re.M)

# Forge host (or host:project) -> official GitHub mirror. Git forges only: the id must be a git id.
MIRROR = {
    "git.ffmpeg.org": "FFmpeg/FFmpeg",
    "skia.googlesource.com": "google/skia",
    "boringssl.googlesource.com": "google/boringssl",
    "aomedia.googlesource.com": "AOMediaCodec/aom",
    "android.googlesource.com:aac": "aosp-mirror/platform_external_aac",
    "gitlab.freedesktop.org:poppler": "freedesktop/poppler",
    "anongit.freedesktop.org:gstreamer": "GStreamer/gstreamer",
    "gitlab.gnome.org:libxslt": "GNOME/libxslt",
    "gitlab.gnome.org:libxml2": "GNOME/libxml2",
    "gitlab.gnome.org:glib": "GNOME/glib",
    "code.videolan.org:dav1d": "videolan/dav1d",
    "gitlab.xiph.org:speex": "xiph/speex",
    "gitlab.xiph.org:opus": "xiph/opus",
    "git.libreoffice.org:core": "LibreOffice/core",
    "invent.kde.org:kimageformats": "KDE/kimageformats",
    "code.qt.io": "qt/qtbase",
    "git.qemu.org": "qemu/qemu",
    "cgit.ghostscript.com": "ArtifexSoftware/ghostpdl",
    "git.torproject.org": "torproject/tor",
    "thekelleys.org.uk": "imp/dnsmasq",
    "github.com:usrsctp": "sctplab/usrsctp",
}


def git_remotes(url: str) -> tuple[str | None, list[str]]:
    """(sha, git URLs to try in order) for a fix pointer naming a 40-hex git id.

    ARVO pointers come as forge commit URLs, "<repo url><sha>" glued together, or
    "git://host/repo.git -> <sha>". The forge itself is tried first, then its GitHub mirror.
    """
    m = _SHA.search(url)
    if not m:
        return None, []
    sha, base = m.group(1), url[: m.start()]
    base = re.sub(r"\s*->\s*$", "", base)
    base = re.sub(r"/(-/)?commits?/?$", "", base).rstrip("/")
    base = re.sub(r"\.git$", "", base)
    host = re.sub(r"^\w+://", "", base).split("/")[0]
    proj = base.rsplit("/", 1)[-1].lower()
    out = [base if base.startswith(("https://", "git://")) else "https://" + base.split("://")[-1]]
    mirror = MIRROR.get(f"{host}:{proj}") or MIRROR.get(host)
    if mirror:
        out.append(f"https://github.com/{mirror}")
    return sha, out


def fetch_git(url: str, cache: Path) -> str | None:
    """The commit as `git format-patch` output, only if its From header names the same id."""
    sha, remotes = git_remotes(url)
    for remote in remotes:
        repo = cache / re.sub(r"\W+", "_", remote)
        try:
            if not (repo / ".git").is_dir():
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
            git = ["git", "-C", str(repo)]
            got = subprocess.run(
                [*git, "fetch", "-q", "--depth", "2", "--filter=blob:none", remote, sha],
                capture_output=True,
                timeout=900,
            )
            if got.returncode:
                continue
            pat = subprocess.run(
                [*git, "format-patch", "-1", "--stdout", sha],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=900,
            ).stdout
        except (subprocess.SubprocessError, OSError):
            continue
        m = _FROM.search(pat or "")
        if m and m.group(1) == sha and "diff --git" in pat:
            return clip_patch(pat, 200_000)
    return None


def fetch(url: str, cache: Path | None = None) -> str | None:
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
    # Web views can refuse (rate limits, bot walls, glued pointers); git itself names the commit.
    return fetch_git(url, cache or Path(tempfile.gettempdir()) / "cf_git_cache")


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
