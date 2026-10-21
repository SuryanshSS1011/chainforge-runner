#!/usr/bin/env bash
# Inspect one ARVO vulnerable image: its arvo driver, the fuzz target and any seed corpus the
# build produces. Prints only image metadata (no dataset records). Usage: probe_arvo.sh <id>
set -uo pipefail
ID="$1"; FIX="${2:-}"
docker pull -q "n132/arvo:${ID}-vul" >/dev/null 2>&1 || { echo "pull failed $ID"; exit 0; }
timeout 3600 docker run --rm -e FIX="$FIX" "n132/arvo:${ID}-vul" bash -c '
  echo "== arvo driver"; cat "$(command -v arvo)" | head -60
  echo "== env"; env | grep -E "^(FUZZ|SANITIZER|FUZZING|ARCH|SRC|OUT|WORK|PROJECT)" | sort
  arvo compile >/tmp/b.log 2>&1; echo "compile rc=$?"
  echo "== /out"; ls -la /out | head -40
  for z in /out/*_seed_corpus.zip; do [ -f "$z" ] && echo "corpus $z $(unzip -l "$z" 2>/dev/null | tail -1)"; done
  ls /out/*.options /out/*.dict 2>/dev/null | head
  echo "== git history (leakage check)"
  for d in /src/*/; do
    [ -d "$d/.git" ] || continue
    h=$(git -C "$d" rev-parse HEAD 2>/dev/null)
    all=$(git -C "$d" rev-list --all 2>/dev/null | wc -l)
    ahead=$(git -C "$d" rev-list --all --not HEAD 2>/dev/null | wc -l)
    echo "repo $d head=$h commits_all=$all commits_not_reachable_from_head=$ahead"
    [ -n "$FIX" ] && { git -C "$d" cat-file -e "$FIX^{commit}" 2>/dev/null && echo "FIX_COMMIT_PRESENT $FIX in $d" || echo "fix commit absent in $d"; }
  done
  echo "== network"; (timeout 10 curl -sI https://github.com >/dev/null 2>&1 && echo "network reachable from container") || echo "no network"
'
docker rmi -f "n132/arvo:${ID}-vul" >/dev/null 2>&1
