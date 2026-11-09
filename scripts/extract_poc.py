#!/usr/bin/env python3
"""Copy the crashing input (/tmp/poc) out of public ARVO images without pulling them.

For each `<arvo id>\t<image digest>` line of the case list that falls in this shard: fetch the
vulnerable image's manifest by digest, stream its layers from the top down through tar until
/tmp/poc appears, and save it with its sha256. Docker Hub allows a limited number of manifest
requests per IP an hour, so they are paced. Writes out/files/<id>/poc and out/index.jsonl.

Usage: extract_poc.py <case list> <shard> <shards>
"""

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REG = "https://registry-1.docker.io/v2/n132/arvo"
ACCEPT = "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
PACE = float(os.environ.get("PACE", "37"))
_tok = {"t": None, "at": 0.0}


def token():
    if time.time() - _tok["at"] > 200:
        cmd = ["curl", "-sS", "-m", "30"]
        if os.environ.get("DOCKERHUB_TOKEN"):
            cmd += ["-u", f"{os.environ['DOCKERHUB_USER']}:{os.environ['DOCKERHUB_TOKEN']}"]
        cmd.append("https://auth.docker.io/token?service=registry.docker.io&scope=repository:n132/arvo:pull")
        _tok["t"] = json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)["token"]
        _tok["at"] = time.time()
    return _tok["t"]


def manifest(digest):
    p = subprocess.run(["curl", "-sS", "-m", "60", "-D", "/dev/stderr", "-H", f"Authorization: Bearer {token()}",
                        "-H", f"Accept: {ACCEPT}", f"{REG}/manifests/{digest}"], capture_output=True, text=True)
    status, remaining = "?", ""
    for ln in p.stderr.splitlines():
        if ln.startswith("HTTP/"):
            status = ln.split(" ", 2)[1]
        if ln.lower().startswith("ratelimit-remaining:"):
            remaining = ln.split(":", 1)[1].strip()
    return status, remaining, (json.loads(p.stdout) if status == "200" else None)


def poc_from_layer(digest):
    proc = subprocess.Popen(["curl", "-sSL", "-m", "1800", "-H", f"Authorization: Bearer {token()}",
                             f"{REG}/blobs/{digest}"], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|*") as tf:
            for m in tf:
                if m.name in ("tmp/poc", "./tmp/poc") and m.isfile():
                    return tf.extractfile(m).read()
    except (tarfile.TarError, EOFError, OSError):
        return None
    finally:
        proc.kill()
        proc.wait()
    return None


def main():
    cases, shard, shards = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    lines = [ln.split("\t") for ln in Path(cases).read_text().splitlines() if ln.strip()]
    mine = [x for i, x in enumerate(lines) if i % shards == shard]
    out = Path("out")
    (out / "files").mkdir(parents=True, exist_ok=True)
    idx = open(out / "index.jsonl", "a")
    last = 0.0
    for aid, digest in mine:
        rec = {"arvo": aid, "digest": digest}
        for attempt in range(4):
            wait = PACE - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            last = time.time()
            status, remaining, man = manifest(digest)
            if status == "429":
                time.sleep(600)  # the hour's allowance is spent; wait and retry
                continue
            break
        if man is None:
            rec |= {"status": "error", "error": f"manifest HTTP {status}"}
        else:
            layers = man.get("layers") or []
            data, where = None, None
            for i in range(len(layers) - 1, max(-1, len(layers) - 5), -1):
                data = poc_from_layer(layers[i]["digest"])
                if data is not None:
                    where = i
                    break
            if data is None:
                rec |= {"status": "not-found", "layers": len(layers)}
            else:
                d = out / "files" / aid
                d.mkdir(parents=True, exist_ok=True)
                (d / "poc").write_bytes(data)
                rec |= {"status": "ok", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                        "layer": where, "layers": len(layers), "ratelimit_remaining": remaining}
        idx.write(json.dumps(rec) + "\n")
        idx.flush()
        print(aid, rec["status"], rec.get("bytes", ""), rec.get("ratelimit_remaining", ""), flush=True)


if __name__ == "__main__":
    main()
