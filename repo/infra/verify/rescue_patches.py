"""Last attempt at the 77 release-blocking patch URLs, then demote whatever remains.

R5 says a patch URL is not a patch, so these records do not meet the GOLD contract as they
stand. Some of the URLs are also simply malformed - heptapod links concatenate the repo and
the sha with no /-/commit/ between them - so a share of the failures were never a fetch
problem at all.
"""

import base64
import collections
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import clip_patch  # noqa: E402

SHA = re.compile(r"([0-9a-f]{12,40})")


def variants(u):
    out = []
    p = u.rstrip("/")
    host = re.sub(r"^https?://([^/]+).*", r"\1", p)
    sha = SHA.search(p)
    s = sha.group(1) if sha else None
    if "googlesource.com" in host:
        base = p.split("%5E")[0].split("^")[0].rstrip("/")
        out.append(("b64", base + "%5E%21/?format=TEXT"))
    elif "heptapod" in host and s:
        # repo and sha are concatenated with no separator
        repo = p[: p.index(s)].rstrip("/")
        out.append(("txt", f"{repo}/-/commit/{s}.diff"))
        out.append(("txt", f"{repo}/-/commit/{s}.patch"))
    elif "hg." in host and s:
        out.append(("txt", re.sub(r"/rev/.*", "", p) + f"/raw-rev/{s}"))
    elif "cgit" in host or "git.ffmpeg" in host or "gnu.org.ua" in host:
        if s:
            out.append(("txt", re.sub(r"/(commit|diff)/.*", "", p) + f"/patch/?id={s}"))
        out.append(("txt", p.replace("/commit/", "/patch/")))
    elif "gitlab" in host or "videolan" in host or "freedesktop" in host or "qt.io" in host:
        out += [("txt", p + ".diff"), ("txt", p + ".patch")]
    elif "svn." in host:
        out.append(("txt", p + "?view=patch"))
    if "/commit/" in p or "/-/commit/" in p:
        out += [("txt", p + ".diff"), ("txt", p + ".patch")]
    return out


def get(u):
    r = urllib.request.Request(u, headers={"User-Agent": "chainforge/0.1"})
    with urllib.request.urlopen(r, timeout=25) as resp:
        return resp.read(300_000)


def main() -> None:
    t = json.load(open("/tmp/blocking.json"))
    out, st = {}, collections.Counter()
    for i, (rid, url) in enumerate(t.items(), 1):
        got = None
        for kind, v in variants(url):
            try:
                b = get(v)
            except Exception:
                continue
            if kind == "b64":
                try:
                    b = base64.b64decode(b)
                except Exception:
                    pass
            txt = b.decode("utf-8", "replace")
            if "diff --git" in txt or txt.startswith("From ") or re.search(r"^--- ", txt, re.M):
                got = clip_patch(txt, 200_000)
                break
            time.sleep(0.2)
        if got:
            out[rid] = got
            st["rescued"] += 1
        else:
            st["still unfetchable"] += 1
        time.sleep(0.3)
    json.dump(out, open("/tmp/rescued.json", "w"))
    print(dict(st))


if __name__ == "__main__":
    main()
