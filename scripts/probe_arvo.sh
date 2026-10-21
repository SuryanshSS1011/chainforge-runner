#!/usr/bin/env bash
# Inspect one ARVO vulnerable image: its arvo driver, the fuzz target and any seed corpus the
# build produces. Prints only image metadata (no dataset records). Usage: probe_arvo.sh <id>
set -uo pipefail
ID="$1"
docker pull -q "n132/arvo:${ID}-vul" >/dev/null 2>&1 || { echo "pull failed $ID"; exit 0; }
timeout 3600 docker run --rm "n132/arvo:${ID}-vul" bash -c '
  echo "== arvo driver"; cat "$(command -v arvo)" | head -60
  echo "== env"; env | grep -E "^(FUZZ|SANITIZER|FUZZING|ARCH|SRC|OUT|WORK|PROJECT)" | sort
  arvo compile >/tmp/b.log 2>&1; echo "compile rc=$?"
  echo "== /out"; ls -la /out | head -40
  for z in /out/*_seed_corpus.zip; do [ -f "$z" ] && echo "corpus $z $(unzip -l "$z" 2>/dev/null | tail -1)"; done
  ls /out/*.options /out/*.dict 2>/dev/null | head
'
docker rmi -f "n132/arvo:${ID}-vul" >/dev/null 2>&1
