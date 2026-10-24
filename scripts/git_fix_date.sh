#!/usr/bin/env bash
# Author date of a fix commit, read from the commit itself (shallow fetch, no blobs).
# Usage: git_fix_date.sh <arvo id> <fix url>  -> one JSON line.
set -uo pipefail
ID="$1"; URL="$2"; HERE="$(cd "$(dirname "$0")" && pwd)"
read -r REMOTE SHA < <(python3 "$HERE/fix_remote.py" "$URL")
if [ -z "${REMOTE:-}" ]; then echo "{\"arvo_id\":\"$ID\",\"status\":\"no_git_remote\"}"; exit 0; fi
d=$(mktemp -d); git -C "$d" init -q
if timeout 600 git -C "$d" fetch -q --depth=1 --filter=blob:none "$REMOTE" "$SHA" 2>/dev/null; then
  date=$(git -C "$d" show -s --format=%aI "$SHA" 2>/dev/null)
  echo "{\"arvo_id\":\"$ID\",\"status\":\"ok\",\"sha\":\"$SHA\",\"author_date\":\"$date\"}"
else
  echo "{\"arvo_id\":\"$ID\",\"status\":\"fetch_failed\",\"sha\":\"$SHA\"}"
fi
rm -rf "$d"
