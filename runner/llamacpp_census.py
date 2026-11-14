#!/usr/bin/env python3
"""CPU numerics census for llama.cpp through the low-level llama-cpp-python batch API.

One llama_batch can hold tokens of several sequences, so the batch composition around a target
sequence is controlled exactly. The target's raw next-token logits are fingerprinted per schedule.
"""
import argparse, collections, ctypes, hashlib, json, math, os, re, sys, time, traceback
import numpy as np
import llama_cpp as lc

from common import prompts, cpu_info


def hnp(a):
    return hashlib.blake2b(np.ascontiguousarray(a).tobytes(), digest_size=8).hexdigest()


def expo(l):
    l = l.astype(np.float32)
    m = l.max()
    lp = l - (m + np.log(np.exp(l - m).sum(dtype=np.float32)))
    idx = np.argsort(-lp, kind="stable")[:20]
    top = lp[idx].astype(np.float64)
    e = {"raw": hnp(l), "top20_full": hnp(idx) + hnp(lp[idx])}
    for d in (6, 4, 3, 2):
        e[f"top20_{d}dp"] = hnp(idx) + hnp(np.round(top, d))
    e["token"] = str(int(idx[0]))
    return e


EXPOS = ["raw", "top20_full", "top20_6dp", "top20_4dp", "top20_3dp", "top20_2dp", "token"]


def pick(*names):
    for n in names:
        if hasattr(lc, n):
            return getattr(lc, n)
    raise AttributeError(str(names))


class Engine:
    def __init__(self, path, n_threads=4, n_ubatch=2048, n_seq_max=64, n_ctx=16384):
        self.model = None
        mp = lc.llama_model_default_params()
        self.model = pick("llama_model_load_from_file", "llama_load_model_from_file")(path.encode(), mp)
        assert self.model, "model load failed"
        self.vocab = lc.llama_model_get_vocab(self.model) if hasattr(lc, "llama_model_get_vocab") else self.model
        self.nv = (lc.llama_vocab_n_tokens(self.vocab) if hasattr(lc, "llama_vocab_n_tokens") else lc.llama_n_vocab(self.model))
        self.ctx = None
        self.open(n_threads, n_ubatch, n_seq_max, n_ctx)

    def open(self, n_threads, n_ubatch, n_seq_max=64, n_ctx=16384):
        if self.ctx:
            lc.llama_free(self.ctx)
        cp = lc.llama_context_default_params()
        cp.n_ctx = n_ctx
        cp.n_batch = 4096
        cp.n_ubatch = n_ubatch
        cp.n_threads = n_threads
        cp.n_threads_batch = n_threads
        if hasattr(cp, "n_seq_max"):
            cp.n_seq_max = n_seq_max
        if hasattr(cp, "kv_unified"):
            cp.kv_unified = True
        self.ctx = pick("llama_init_from_model", "llama_new_context_with_model")(self.model, cp)
        assert self.ctx, "context creation failed"
        self.n_seq_max = n_seq_max

    def clear(self):
        if hasattr(lc, "llama_get_memory") and hasattr(lc, "llama_memory_clear"):
            lc.llama_memory_clear(lc.llama_get_memory(self.ctx), True)
        elif hasattr(lc, "llama_kv_self_clear"):
            lc.llama_kv_self_clear(self.ctx)
        else:
            lc.llama_kv_cache_clear(self.ctx)

    def tokenize(self, text):
        b = text.encode()
        buf = (lc.llama_token * (len(b) + 16))()
        n = lc.llama_tokenize(self.vocab, b, len(b), buf, len(buf), True, False)
        return [int(buf[i]) for i in range(max(n, 0))]

    def decode(self, segments, target_seq=0):
        """segments: list of (seq_id, tokens, start_pos) in batch order. Returns logits of the target's last token."""
        n = sum(len(s[1]) for s in segments)
        batch = lc.llama_batch_init(n, 0, 1)
        i = 0
        tidx = None
        for seq, toks, pos0 in segments:
            for j, t in enumerate(toks):
                batch.token[i] = t
                batch.pos[i] = pos0 + j
                batch.n_seq_id[i] = 1
                batch.seq_id[i][0] = seq
                last = j == len(toks) - 1
                batch.logits[i] = 1 if last else 0
                if last and seq == target_seq:
                    tidx = i
                i += 1
        batch.n_tokens = n
        rc = lc.llama_decode(self.ctx, batch)
        if rc != 0:
            lc.llama_batch_free(batch)
            raise RuntimeError(f"llama_decode rc={rc}")
        out = None
        if tidx is not None:
            p = lc.llama_get_logits_ith(self.ctx, tidx)
            out = np.ctypeslib.as_array(p, shape=(self.nv,)).copy()
        lc.llama_batch_free(batch)
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gguf", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--budget", type=float, default=40.0)
    ap.add_argument("--out", default="out")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    t_start = time.time()
    lc.llama_backend_init()
    res = {"gguf": os.path.basename(args.gguf), "label": args.label, "llama_cpp_python": getattr(lc, "__version__", "?"),
           "cpu": cpu_info(), "tests": {}, "errors": {}}
    try:
        res["system_info"] = lc.llama_print_system_info().decode()
    except Exception:
        pass
    outpath = os.path.join(args.out, args.label + ".json")

    def save():
        res["elapsed_s"] = round(time.time() - t_start, 1)
        json.dump(res, open(outpath, "w"), indent=1)

    E = Engine(args.gguf)
    res["n_vocab"] = E.nv
    toks = [E.tokenize(p) for p in prompts()]
    toks = [t for t in toks if 6 <= len(t) <= 120]
    short = [t for t in toks if len(t) <= 24]
    res["n_prompts"] = len(toks)
    rng = np.random.default_rng(5)

    def rnd(n):
        return [int(x) for x in rng.integers(100, min(E.nv, 30000) - 1, n)]

    def run_sched(t, steps):
        """steps: list of (n_target_tokens, n_before, n_after, n_single_before, n_single_after)."""
        E.clear()
        pos = 0
        out = None
        seq = 1
        for (c, nb, na, sb, sa) in steps:
            segs = []
            if nb:
                segs.append((seq, rnd(nb), 0)); seq += 1
            for _ in range(sb):
                segs.append((seq, rnd(1), 0)); seq += 1
            segs.append((0, t[pos:pos + c], pos))
            for _ in range(sa):
                segs.append((seq, rnd(1), 0)); seq += 1
            if na:
                segs.append((seq, rnd(na), 0)); seq += 1
            assert seq <= E.n_seq_max
            out = E.decode(segs)
            pos += c
        assert pos == len(t)
        return out

    def run(tname, fn):
        t0 = time.time()
        try:
            res["tests"][tname] = fn(t0 + args.budget)
            res["tests"][tname]["seconds"] = round(time.time() - t0, 1)
        except Exception:
            res["errors"][tname] = traceback.format_exc()[-1500:]
            print("ERROR in", tname, res["errors"][tname], flush=True)
        save()
        print(f"[{time.time()-t_start:6.1f}s] {tname}: {json.dumps(res['tests'].get(tname, {}))[:700]}", flush=True)

    def share(c, n):
        return round(c / max(n, 1), 4)

    def census(deadline, pool, make_conditions):
        n = 0
        cls = {k: [] for k in EXPOS}
        parts = []
        unstable = content = failed = 0
        names = None
        differs = collections.Counter()
        seen = collections.Counter()

        def attempt(t, steps):
            try:
                return expo(run_sched(t, steps))
            except Exception as ex:
                return None
        for t in pool:
            if time.time() > deadline and n >= 5:
                break
            conds = make_conditions(t)
            names = [c[0] for c in conds]
            es = [attempt(t, c[1]) for c in conds]
            if es[0] is None:
                failed += 1
                continue
            again = attempt(t, conds[0][1])
            unstable += again is not None and again["raw"] != es[0]["raw"]
            last = attempt(t, conds[-1][1])
            content += last is not None and es[-1] is not None and last["raw"] != es[-1]["raw"]
            n += 1
            ok = [e for e in es if e is not None]
            failed += len(es) - len(ok)
            m = {}
            parts.append([(-1 if e is None else m.setdefault(e["raw"], len(m))) for e in es])
            for k in EXPOS:
                cls[k].append(len(set(e[k] for e in ok)))
            for j in range(1, len(es)):
                if es[j] is not None:
                    seen[names[j]] += 1
                    differs[names[j]] += es[j]["raw"] != es[0]["raw"]
        return {"probes": n, "conditions": names, "partitions": parts[:60], "rerun_unstable": int(unstable),
                "last_condition_differs_with_new_companion_content": int(content), "failed_runs": int(failed),
                "mean_classes": {k: round(float(np.mean(v)), 3) for k, v in cls.items() if v},
                "max_classes": {k: int(max(v)) for k, v in cls.items() if v},
                "share_probes_with_channel": {k: share(sum(x > 1 for x in v), len(v)) for k, v in cls.items() if v},
                "share_differs_vs_first_condition": {k: share(differs[k], seen[k]) for k in seen}}

    def ref(deadline):
        return {"hashes": {str(i): hnp(run_sched(t, [(len(t), 0, 0, 0, 0)])) for i, t in enumerate(toks[:60])}}
    run("ref", ref)

    geo = [(0, 0), (1, 0), (0, 1), (8, 0), (0, 8), (31, 0), (32, 0), (33, 0), (0, 64), (100, 0), (0, 100), (256, 256), (700, 0)]
    run("prefill_batch_geometry", lambda d: census(d, toks, lambda t: [(f"nb{a}_na{b}", [(len(t), a, b, 0, 0)]) for a, b in geo]))
    run("prefill_vs_decode_vs_chunked", lambda d: census(d, toks, lambda t: [("full", [(len(t), 0, 0, 0, 0)]),
        ("decode_last", [(len(t) - 1, 0, 0, 0, 0), (1, 0, 0, 0, 0)])] +
        [(f"chunk{c}", [(min(c, len(t) - s), 0, 0, 0, 0) for s in range(0, len(t), c)]) for c in (1, 2, 4, 8, 16) if c < len(t)]))
    dec = [0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 48, 60]
    run("decode_census", lambda d: census(d, short, lambda t: [(f"single{k}", [(len(t) - 1, 0, 0, 0, 0), (1, 0, 0, k // 2, k - k // 2)]) for k in dec]))
    run("decode_with_cotenant_prefill", lambda d: census(d, short, lambda t: [(f"prefill{k}", [(len(t) - 1, 0, 0, 0, 0), (1, 0, k, 0, 0)]) for k in (0, 1, 16, 64, 256, 1024)]))

    # physical micro-batch boundary: co-tenant tokens ahead of the target move it across the n_ubatch cut
    def ub(deadline):
        E.open(4, 32)
        try:
            return census(deadline, short, lambda t: [(f"nb{a}", [(len(t), a, 0, 0, 0)]) for a in (0, 4, 8, 16, 20, 28, 31, 32, 40, 64)])
        finally:
            E.open(4, 2048)
    run("ubatch32_boundary", ub)

    def threads(deadline):
        base = {i: hnp(run_sched(t, [(len(t), 0, 0, 0, 0)])) for i, t in enumerate(toks[:30])}
        out = {}
        for nt in (1, 2):
            E.open(nt, 2048)
            out[f"share_differs_{nt}_vs_4_threads"] = share(sum(hnp(run_sched(t, [(len(t), 0, 0, 0, 0)])) != base[i] for i, t in enumerate(toks[:30])), 30)
        E.open(4, 2048)
        return out
    run("threads", threads)
    save()
    print("wrote", outpath, "errors", list(res["errors"]))


if __name__ == "__main__":
    main()
