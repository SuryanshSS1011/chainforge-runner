#!/usr/bin/env python3
"""Concurrency census through an OpenAI-compatible completions endpoint (stdlib only).
The target request is sent alone and next to k concurrent companions; returned logprobs are fingerprinted."""
import collections, hashlib, json, sys, threading, time, urllib.request

from common import prompts

BASE, MODEL, OUT, LABEL = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]


def post(path, payload, timeout=600):
    req = urllib.request.Request(BASE + path, json.dumps(payload).encode(), {"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def metric(name):
    try:
        txt = urllib.request.urlopen(BASE + "/metrics", timeout=10).read().decode()
        vals = [float(l.rsplit(" ", 1)[1]) for l in txt.splitlines() if l.startswith(name)]
        return sum(vals)
    except Exception:
        return None


def hj(x):
    return hashlib.blake2b(json.dumps(x, sort_keys=True).encode(), digest_size=8).hexdigest()


def fp(resp):
    c = resp["choices"][0]
    lp = c.get("logprobs") or {}
    top = lp.get("top_logprobs") or []
    return {"text": c["text"], "top20_full": hj(top), "token_logprobs": hj(lp.get("token_logprobs")),
            "top20_4dp": hj([{k: round(v, 4) for k, v in (d or {}).items()} for d in top]),
            "top20_2dp": hj([{k: round(v, 2) for k, v in (d or {}).items()} for d in top]),
            "first_step_full": hj(top[:1])}


P = [p for p in prompts() if len(p) < 60]
probes = P[:6]
comps = P[20:60]
res = {"label": LABEL, "model": MODEL, "conditions": {}, "per_probe": []}
t0 = time.time()
for pi, pr in enumerate(probes):
    obs = collections.defaultdict(list)
    for rep in range(2):
        for k in (0, 1, 7, 31):
            th = []
            for j in range(k):
                body = dict(model=MODEL, prompt=comps[(pi * 7 + j) % len(comps)], max_tokens=24, temperature=0)
                t = threading.Thread(target=lambda b=body: post("/v1/completions", b))
                t.start(); th.append(t)
            if k:
                time.sleep(0.4)
            running = metric("vllm:num_requests_running")
            r = post("/v1/completions", dict(model=MODEL, prompt=pr, max_tokens=8, temperature=0, logprobs=20, seed=0))
            for t in th:
                t.join()
            f = fp(r); f["running_seen"] = running
            obs[k].append(f)
    row = {"probe": pi}
    for key in ("text", "top20_full", "top20_4dp", "top20_2dp", "first_step_full", "token_logprobs"):
        allv = [o[key] for k in obs for o in obs[k]]
        row[f"distinct_{key}"] = len(set(allv))
        row[f"alone_stable_{key}"] = len({o[key] for o in obs[0]}) == 1
        row[f"by_k_{key}"] = {str(k): sorted({allv.index(o[key]) for o in obs[k]}) for k in obs}
    row["running_seen"] = {str(k): [o["running_seen"] for o in obs[k]] for k in obs}
    res["per_probe"].append(row)
    print(json.dumps(row), flush=True)
res["elapsed_s"] = round(time.time() - t0, 1)
json.dump(res, open(f"{OUT}/{LABEL}.json", "w"), indent=1)
