#!/usr/bin/env python3
import os, re, sys
from huggingface_hub import hf_hub_download, list_repo_files

repo, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
files = [f for f in list_repo_files(repo) if f.lower().endswith(".gguf")]
print("available:", files)
for pat in (r"(?i)(f16|fp16)\.gguf$", r"(?i)q8_0\.gguf$", r"(?i)q4_k_m\.gguf$"):
    m = [f for f in files if re.search(pat, f)]
    if m:
        hf_hub_download(repo, m[0], local_dir=out)
        print("fetched", m[0])
