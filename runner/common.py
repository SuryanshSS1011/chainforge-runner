"""Shared prompt set and host description. No heavy imports."""
import os, platform

SUBJ = ["France", "Japan", "Brazil", "Kenya", "Canada", "Egypt", "India", "Norway", "Peru", "Vietnam",
        "Turkey", "Chile", "Ghana", "Spain", "Poland", "Mexico", "Nepal", "Greece", "Cuba", "Iran"]
TEMPL = ["The capital of {} is", "Q: Name one famous river in {}.\nA:", "Write a short poem about {}:\n",
         "def area_code_{}(x):\n    return", "In {}, the most popular sport is", "Translate to French: I love {}.\n",
         "{} is located on the continent of", "A list of three cities in {}: 1.", "The history of {} began when",
         "Review: my trip to {} was"]
PASSAGE = ("The committee met on Tuesday to review the proposal. After two hours of discussion the members agreed "
           "that the budget should be revised, that the schedule was too optimistic, and that a second review "
           "would be needed before any contract could be signed. ")


def prompts():
    out = []
    for i, s in enumerate(SUBJ):
        for j, t in enumerate(TEMPL):
            p = t.format(s)
            if (i + j) % 4 == 3:
                p = PASSAGE + p
            out.append(p)
    return out


def cpu_info():
    info = {"machine": platform.machine(), "cores": os.cpu_count()}
    try:
        txt = open("/proc/cpuinfo").read()
        info["model_name"] = next(l.split(":", 1)[1].strip() for l in txt.splitlines() if l.startswith("model name"))
        flags = next(l.split(":", 1)[1].split() for l in txt.splitlines() if l.startswith("flags"))
        info["flags"] = [f for f in ("avx2", "fma", "avx512f", "avx512_bf16", "avx512_vnni", "amx_bf16", "amx_tile") if f in flags]
    except Exception as ex:
        info["error"] = repr(ex)
    return info
