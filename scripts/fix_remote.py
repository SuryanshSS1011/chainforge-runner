#!/usr/bin/env python3
"""Map a fix URL to (git remote, commit sha), or (None, None) when no git remote serves it
(Mercurial, Subversion, a bare sha). Shared by git_fix_date.py; git_fix_diff.py keeps its own
narrower table. Usage as a script: fix_remote.py <url>  -> prints "<remote> <sha>" or nothing.
"""
import re
import sys

MIRRORS = {
    "github.com/bminor/binutils-gdb": "https://sourceware.org/git/binutils-gdb.git",
    "git.ffmpeg.org/gitweb/ffmpeg.git": "https://git.ffmpeg.org/ffmpeg.git",
    "cgit.ghostscript.com/ghostpdl.git": "https://github.com/ArtifexSoftware/ghostpdl.git",
    "git.ghostscript.com/jbig2dec.git": "https://github.com/ArtifexSoftware/jbig2dec.git",
    "w1.fi/cgit/hostap": "https://w1.fi/hostap.git",
    "git.torproject.org/tor.git": "https://gitlab.torproject.org/tpo/core/tor.git",
    "git.qemu.org/git/qemu.git": "https://gitlab.com/qemu-project/qemu.git",
    "code.qt.io/cgit/qt/qtbase.git": "https://code.qt.io/qt/qtbase.git",
    "git.gnu.org.ua/gdbm.git": "https://git.gnu.org.ua/gdbm.git",
}


def remote(url: str):
    url = url.strip()
    m = re.search(r"[0-9a-f]{40}", url)
    if not m or re.match(r"^[0-9a-f]{40}$", url) or re.search(r"\bhg\.|heptapod|/svn", url):
        return None, None
    sha = m.group(0)
    base = re.sub(r"^\w+://", "", url[: m.start()])
    for k, v in MIRRORS.items():
        if base.startswith(k):
            return v, sha
    scheme = "git://" if url.startswith("git://") else "https://"
    gh = re.match(r"github\.com/([^/]+/[^/]+)/commit/$", base)
    if gh:
        return f"https://github.com/{gh.group(1)}.git", sha
    for pat in (r"^(.*?)/-/commit/$", r"^(.*?)/commit/(\?id=)?$", r"^(.*?)/\+/$"):
        mm = re.match(pat, base)
        if mm:
            return scheme + mm.group(1).rstrip("/"), sha
    mm = re.match(r"^(.*?);a=commitdiff;h=$", base)
    if mm and "?p=" in mm.group(1):
        host, repo = mm.group(1).split("/?p=")
        return f"{scheme}{host}/{repo}", sha
    base = re.sub(r"\s*->\s*$", "", base)
    if base and not base.endswith("/"):
        return scheme + base, sha  # "<remote><sha>" concatenations
    return None, None


if __name__ == "__main__":
    r, s = remote(sys.argv[1])
    if r:
        print(r, s)
