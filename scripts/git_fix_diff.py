#!/usr/bin/env python3
"""Fallback for fix diffs the forge's web endpoints will not serve: map the fix URL to a git
remote and commit, fetch the commit and its parent shallowly (blobs on demand), and print the diff.
Mercurial and Subversion URLs have no git commit and are left unfetched.

Usage: git_fix_diff.py <fix url> <out file>
"""
import re
import subprocess
import sys
import tempfile

RULES = [
    (r"https://github\.com/bminor/binutils-gdb/commit/([0-9a-f]{40})", "https://sourceware.org/git/binutils-gdb.git"),
    (r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{40})", None),
    (r"https://w1\.fi/cgit/hostap/commit/\?id=([0-9a-f]{40})", "https://w1.fi/hostap.git"),
    (r"https://git\.libssh\.org/projects/libssh\.git([0-9a-f]{40})", "https://git.libssh.org/projects/libssh.git"),
    (r"https://sourceware\.org/git/\?p=([\w.-]+\.git);a=commitdiff;h=([0-9a-f]{40})", None),
    (r"https://git\.torproject\.org/tor\.git([0-9a-f]{40})", "https://gitlab.torproject.org/tpo/core/tor.git"),
    (r"https://git\.qemu\.org/git/qemu\.git([0-9a-f]{40})", "https://gitlab.com/qemu-project/qemu.git"),
    (r"https://git\.gnu\.org\.ua/gdbm\.git/commit/\?id=([0-9a-f]{40})", "https://git.gnu.org.ua/gdbm.git"),
    (r"https://code\.qt\.io/cgit/qt/qtbase\.git/commit/\?id=([0-9a-f]{40})", "https://code.qt.io/qt/qtbase.git"),
    (r"https://([\w.-]+\.googlesource\.com/[\w/.-]+?)/\+/([0-9a-f]{40})", None),
]


def remote(url):
    for rx, fixed in RULES:
        m = re.fullmatch(rx, url.strip())
        if not m:
            continue
        if fixed:
            return fixed, m.group(1)
        a, sha = m.group(1), m.group(2)
        if "sourceware" in rx:
            return f"https://sourceware.org/git/{a}", sha
        return f"https://{a}" if "googlesource" in rx else f"https://github.com/{a}.git", sha
    return None, None


def main():
    url, out = sys.argv[1], sys.argv[2]
    repo, sha = remote(url)
    if not repo:
        return 1
    with tempfile.TemporaryDirectory() as d:
        g = ["git", "-C", d]
        subprocess.run(g + ["init", "-q"], check=True)
        r = subprocess.run(g + ["fetch", "-q", "--depth=2", "--filter=blob:none", repo, sha], timeout=900)
        if r.returncode:
            return 1
        diff = subprocess.run(g + ["diff", f"{sha}^", sha], capture_output=True, text=True).stdout
    if not diff.strip():
        return 1
    open(out, "w").write(diff)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
