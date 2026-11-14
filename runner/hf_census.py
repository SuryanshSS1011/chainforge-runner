#!/usr/bin/env python3
"""CPU numerics census for causal LMs (PyTorch + Transformers).

Compares the next-token logits of one target prompt under different execution schedules and
records bit fingerprints. Modes: fp32, bf16 (native), bf16emu (fp32 kernels, bf16-rounded outputs).
"""
import argparse, collections, hashlib, json, math, os, platform, sys, time, traceback
import numpy as np
import torch

from common import prompts, cpu_info


def hb(t):
    t = t.detach().contiguous().cpu()
    if t.dtype == torch.bfloat16:
        t = t.view(torch.int16)
    return hashlib.blake2b(t.numpy().tobytes(), digest_size=8).hexdigest()


def hnp(a):
    return hashlib.blake2b(np.ascontiguousarray(a).tobytes(), digest_size=8).hexdigest()


def expo(l):
    """Fingerprints of one logit row under several exposure levels."""
    lp = torch.log_softmax(l.detach().float().reshape(-1), -1)
    top = torch.topk(lp, 20)
    ids = top.indices.numpy()
    vals = top.values.double().numpy()
    e = {"raw": hb(l), "top20_full": hnp(ids) + hb(top.values)}
    for d in (6, 4, 3, 2):
        e[f"top20_{d}dp"] = hnp(ids) + hnp(np.round(vals, d))
    e["top1_4dp"] = str(int(ids[0])) + hnp(np.round(vals[:1], 4))
    e["token"] = str(int(ids[0]))
    return e


EXPOS = ["raw", "top20_full", "top20_6dp", "top20_4dp", "top20_3dp", "top20_2dp", "top1_4dp", "token"]


def cache_layers(c):
    if hasattr(c, "self_attention_cache"):
        c = c.self_attention_cache
    if hasattr(c, "layers"):
        return [(l.keys, l.values) for l in c.layers]
    if hasattr(c, "key_cache"):
        return list(zip(c.key_cache, c.value_cache))
    return [(x[0], x[1]) for x in c]


def make_cache(layers):
    from transformers import DynamicCache
    c = DynamicCache()
    for i, (k, v) in enumerate(layers):
        c.update(k.clone(), v.clone(), i)
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--mode", default="fp32", choices=["fp32", "bf16", "bf16emu"])
    ap.add_argument("--budget", type=float, default=50.0, help="seconds per test")
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--tests", default="all")
    ap.add_argument("--out", default="out")
    ap.add_argument("--tag", default="")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    if args.threads:
        torch.set_num_threads(args.threads)
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import transformers

    t_start = time.time()
    res = {"model": args.model, "mode": args.mode, "tag": args.tag, "torch": torch.__version__,
           "transformers": transformers.__version__, "threads": torch.get_num_threads(), "cpu": cpu_info(),
           "mkldnn": bool(torch.backends.mkldnn.is_available()), "mkl": bool(torch.backends.mkl.is_available()),
           "tests": {}, "errors": {}}
    name = (args.model.replace("/", "__") + "." + args.mode + (("." + args.tag) if args.tag else ""))
    outpath = os.path.join(args.out, name + ".json")

    def save():
        res["elapsed_s"] = round(time.time() - t_start, 1)
        with open(outpath, "w") as f:
            json.dump(res, f, indent=1)

    tok = AutoTokenizer.from_pretrained(args.model)
    dt = torch.bfloat16 if args.mode == "bf16" else torch.float32
    model = AutoModelForCausalLM.from_pretrained(args.model, torch_dtype=dt)
    model.eval()
    nparams = sum(p.numel() for p in model.parameters())
    res["params_M"] = round(nparams / 1e6, 1)
    res["layers"] = getattr(model.config, "num_hidden_layers", getattr(model.config, "n_layer", None))
    res["hidden"] = getattr(model.config, "hidden_size", getattr(model.config, "n_embd", None))
    if args.mode == "bf16emu":
        with torch.no_grad():
            for p in model.parameters():
                p.copy_(p.to(torch.bfloat16).to(torch.float32))
        nh = 0

        def rnd(m, i, o):
            return o.to(torch.bfloat16).to(torch.float32) if torch.is_tensor(o) else o
        for m in model.modules():
            cn = type(m).__name__
            if isinstance(m, (torch.nn.Linear, torch.nn.Embedding)) or cn.endswith("Norm") or cn == "Conv1D":
                m.register_forward_hook(rnd)
                nh += 1
        res["bf16emu_hooks"] = nh
    V = model.config.vocab_size
    pad_id = tok.pad_token_id if tok.pad_token_id is not None else (tok.eos_token_id or 0)
    enc = [tok(p, return_tensors="pt").input_ids for p in prompts()]
    enc = [e for e in enc if 4 <= e.shape[1] <= 120]
    res["n_prompts"] = len(enc)
    res["prompt_len_min_max"] = [min(e.shape[1] for e in enc), max(e.shape[1] for e in enc)]
    short = [i for i, e in enumerate(enc) if e.shape[1] <= 24]
    big = nparams > 4e8

    def rand_ids(n, T, seed):
        gg = torch.Generator().manual_seed(1000 + seed)
        return torch.randint(10, min(V, 30000), (n, T), generator=gg)

    @torch.inference_mode()
    def fwd(ids, past=None, attn=None):
        o = model(input_ids=ids, past_key_values=past, attention_mask=attn, use_cache=True)
        return o.logits, o.past_key_values

    def ref_row(i):
        return fwd(enc[i])[0][0, -1]

    def batch_row(i, B, row, seed=0):
        T = enc[i].shape[1]
        ids = rand_ids(B, T, seed + 17 * i)
        ids[row] = enc[i][0]
        return fwd(ids)[0][row, -1]

    want = None if args.tests == "all" else set(args.tests.split(","))

    def run(tname, fn):
        if want is not None and tname not in want:
            return
        t0 = time.time()
        try:
            res["tests"][tname] = fn(t0 + args.budget)
            res["tests"][tname]["seconds"] = round(time.time() - t0, 1)
        except Exception:
            res["errors"][tname] = traceback.format_exc()[-1500:]
            print("ERROR in", tname, res["errors"][tname], flush=True)
        save()
        print(f"[{time.time()-t_start:6.1f}s] {tname}: {json.dumps(res['tests'].get(tname, {}))[:600]}", flush=True)

    def share(c, n):
        return round(c / max(n, 1), 4)

    # ---- reference fingerprints (cross-runner and cross-process comparison)
    def t_ref(deadline):
        hs = {}
        for i in range(min(60, len(enc))):
            hs[str(i)] = hb(ref_row(i))
        return {"hashes": hs}
    run("ref", t_ref)

    # ---- T1: batch composition at prefill, same-length companions, plus controls
    def t_batch(deadline):
        n = 0
        c = collections.Counter()
        ex = collections.Counter()
        per_B = collections.Counter()
        nB = collections.Counter()
        Bs = [2, 4, 8, 16] + ([] if big else [32])
        for i in range(len(enc)):
            if time.time() > deadline and n >= 5:
                break
            r = ref_row(i)
            er = expo(r)
            o = batch_row(i, 8, 0)
            eo = expo(o)
            n += 1
            for k in EXPOS:
                ex[k] += er[k] != eo[k]
            c["rerun_unstable"] += hb(batch_row(i, 8, 0)) != eo["raw"]
            c["content_dependent"] += hb(batch_row(i, 8, 0, seed=999)) != eo["raw"]
            c["row_dependent"] += hb(batch_row(i, 8, 7)) != eo["raw"]
            c["argmax_flip"] += er["token"] != eo["token"]
            if n <= 40:
                for B in Bs:
                    if B == 8:
                        continue
                    nB[B] += 1
                    per_B[B] += hb(batch_row(i, B, 0)) != er["raw"]
                nB[8] += 1
                per_B[8] += er["raw"] != eo["raw"]
        return {"probes": n, "share_differs_B1_vs_B8": {k: share(ex[k], n) for k in EXPOS},
                "controls": {k: int(v) for k, v in c.items()},
                "share_differs_vs_B1_by_B": {str(B): share(per_B[B], nB[B]) for B in sorted(nB)}}
    run("batch_prefill", t_batch)

    # ---- T3/T4: prefill vs decode, chunked prefill (B=1)
    def t_pd(deadline):
        n = 0
        ex = collections.Counter()
        ch = collections.Counter()
        nch = collections.Counter()
        flips = 0
        for i in range(len(enc)):
            if time.time() > deadline and n >= 5:
                break
            ids = enc[i]
            T = ids.shape[1]
            er = expo(ref_row(i))
            _, pk = fwd(ids[:, :-1])
            l2, _ = fwd(ids[:, -1:], past=pk)
            eo = expo(l2[0, -1])
            n += 1
            for k in EXPOS:
                ex[k] += er[k] != eo[k]
            flips += er["token"] != eo["token"]
            if n <= 30:
                for cs in (1, 2, 4, 8, 16):
                    if cs >= T:
                        continue
                    past = None
                    lg = None
                    for s in range(0, T, cs):
                        lg, past = fwd(ids[:, s:s + cs], past=past)
                    nch[cs] += 1
                    ch[cs] += hb(lg[0, -1]) != er["raw"]
        return {"probes": n, "share_differs_prefill_vs_decode": {k: share(ex[k], n) for k in EXPOS},
                "argmax_flips": int(flips),
                "share_differs_chunked_vs_full_by_chunk": {str(k): share(ch[k], nch[k]) for k in sorted(nch)}}
    run("prefill_decode_chunk", t_pd)

    # ---- T5: decode-step batch census with the target's KV state held bit-identical
    def t_census(deadline):
        Bs = [1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 24, 32] + ([] if big else [33, 48, 64])
        n = 0
        parts = []
        cls = {k: [] for k in EXPOS}
        match_ref1 = match_ref2 = match_ref8 = tot = 0
        for i in short:
            if time.time() > deadline and n >= 5:
                break
            ids = enc[i]
            T = ids.shape[1]
            _, pk = fwd(ids[:, :-1])
            tl = cache_layers(pk)
            _, ck = fwd(rand_ids(1, T - 1, 5000 + i))
            cl = cache_layers(ck)
            ctok = rand_ids(1, 1, 7000 + i)
            es = []
            for B in Bs:
                layers = [(torch.cat([tk] + [ckk] * (B - 1), 0), torch.cat([tv] + [cvv] * (B - 1), 0))
                          for (tk, tv), (ckk, cvv) in zip(tl, cl)]
                step = torch.cat([ids[:, -1:]] + [ctok] * (B - 1), 0)
                lg, _ = fwd(step, past=make_cache(layers))
                es.append(expo(lg[0, -1]))
            n += 1
            raw = [e["raw"] for e in es]
            ids_map = {}
            parts.append([ids_map.setdefault(h_, len(ids_map)) for h_ in raw])
            for k in EXPOS:
                cls[k].append(len(set(e[k] for e in es)))
            for j in range(len(Bs)):
                tot += 1
                match_ref1 += raw[j] == raw[0]
                match_ref2 += raw[j] == raw[1]
                match_ref8 += raw[j] == raw[5]
        return {"probes": n, "B_values": Bs, "partitions": parts,
                "mean_classes": {k: round(float(np.mean(v)), 3) for k, v in cls.items() if v},
                "max_classes": {k: int(max(v)) for k, v in cls.items() if v},
                "share_probes_with_channel": {k: share(sum(x > 1 for x in v), len(v)) for k, v in cls.items() if v},
                "mean_bits": {k: round(float(np.mean([math.log2(x) for x in v])), 3) for k, v in cls.items() if v},
                "match_rate_vs_reference": {"B1": share(match_ref1, tot), "B2": share(match_ref2, tot), "B8": share(match_ref8, tot)}}
    run("decode_census", t_census)

    # ---- T2: ragged batches. Right padding keeps positions fixed. Left padding shifts them.
    def t_pad(deadline):
        n = 0
        c = collections.Counter()
        for i in short:
            if time.time() > deadline and n >= 5:
                break
            ids = enc[i]
            T = ids.shape[1]
            same = torch.cat([ids, rand_ids(1, T, 9000 + i)], 0)
            base = fwd(same, attn=torch.ones_like(same))[0][0, -1]
            n += 1
            c["mask_ones_vs_no_mask"] += hb(fwd(same)[0][0, -1]) != hb(base)
            for d in (1, 8, 64):
                comp = rand_ids(1, T + d, 9500 + i)
                rp = torch.cat([torch.cat([ids, torch.full((1, d), pad_id)], 1), comp], 0)
                am = torch.ones_like(rp)
                am[0, T:] = 0
                c[f"right_pad_{d}"] += hb(fwd(rp, attn=am)[0][0, T - 1]) != hb(base)
                if "gpt2" not in args.model:
                    lp = torch.cat([torch.cat([torch.full((1, d), pad_id), ids], 1), comp], 0)
                    am2 = torch.ones_like(lp)
                    am2[0, :d] = 0
                    c[f"left_pad_{d}"] += hb(fwd(lp, attn=am2)[0][0, -1]) != hb(base)
        return {"probes": n, "share_differs_vs_same_length_batch": {k: share(v, n) for k, v in sorted(c.items())}}
    run("padding", t_pad)

    # ---- T6: text-only channel under greedy decoding at constant batch size
    def t_text(deadline):
        Bs = [1, 2, 8] + ([] if big else [32])
        n = 0
        diff = collections.Counter()
        first = collections.defaultdict(list)
        new = 40
        for i in short:
            if time.time() > deadline and n >= 4:
                break
            ids = enc[i]
            T = ids.shape[1]
            seqs = {}
            for B in Bs:
                x = rand_ids(B, T, 11000 + i)
                x[0] = ids[0]
                lg, past = fwd(x)
                toks = []
                for _ in range(new):
                    nxt = lg[:, -1].float().argmax(-1, keepdim=True)
                    toks.append(int(nxt[0, 0]))
                    lg, past = fwd(nxt, past=past)
                seqs[B] = toks
            n += 1
            for B in Bs[1:]:
                if seqs[B] != seqs[1]:
                    diff[B] += 1
                    first[B].append(next(j for j in range(new) if seqs[B][j] != seqs[1][j]))
            diff["any"] += len({tuple(v) for v in seqs.values()}) > 1
        return {"probes": n, "new_tokens": new, "share_text_differs_vs_B1": {str(B): share(diff[B], n) for B in Bs[1:]},
                "share_any_difference": share(diff["any"], n),
                "median_first_divergent_token": {str(B): (float(np.median(v)) if v else None) for B, v in first.items()}}
    run("text_only", t_text)

    # ---- T7: thread count as a deployment feature
    def t_threads(deadline):
        base = torch.get_num_threads()
        out = {}
        refs = {i: hb(ref_row(i)) for i in range(min(30, len(enc)))}
        for nt in (1, 2):
            if nt == base:
                continue
            torch.set_num_threads(nt)
            d = sum(hb(ref_row(i)) != refs[i] for i in refs)
            out[f"share_differs_{nt}_vs_{base}_threads"] = share(d, len(refs))
        torch.set_num_threads(base)
        return out
    run("threads", t_threads)
    save()
    print("wrote", outpath, "elapsed", res["elapsed_s"], "errors", list(res["errors"]))


if __name__ == "__main__":
    main()
