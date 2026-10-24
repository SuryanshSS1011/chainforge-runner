#!/usr/bin/env bash
# For one vulnerable image: print the reported source line of each UBSan index site and decide
# READ or WRITE with access_direction.py. Usage: access_direction.sh <arvo id> <specs.tsv>
# specs.tsv: <key>\t<path>\t<line>\t<col> per site. Prints one JSON line per key.
set -uo pipefail
ID="$1"; SPECS="$2"; HERE="$(cd "$(dirname "$0")" && pwd)"
IMG="n132/arvo:${ID}-vul"
pulled=0
for t in 1 2 3; do docker pull -q "$IMG" >/dev/null 2>&1 && { pulled=1; break; }
  docker pull -q "mirror.gcr.io/$IMG" >/dev/null 2>&1 && docker tag "mirror.gcr.io/$IMG" "$IMG" && { pulled=1; break; }; sleep 20; done
while IFS=$'\t' read -r key path line col; do
  [ -z "$key" ] && continue
  if [ $pulled = 0 ]; then echo "{\"key\":\"$key\",\"status\":\"pull_failed\"}"; continue; fi
  src=$(docker run --rm --network none --entrypoint sh "$IMG" -c \
    "f='$path'; [ -f \"\$f\" ] || f=\$(find /src -path '*/$(basename "$path")' 2>/dev/null | head -1); [ -n \"\$f\" ] && sed -n '${line}p' \"\$f\"" 2>/dev/null)
  if [ -z "$src" ]; then echo "{\"key\":\"$key\",\"status\":\"line_unreadable\"}"; continue; fi
  v=$(printf '%s\n' "$src" | python3 "$HERE/access_direction.py" "$col")
  echo "{\"key\":\"$key\",\"status\":\"ok\",\"access\":\"$v\"}"
done < "$SPECS"
docker rmi -f "$IMG" >/dev/null 2>&1
