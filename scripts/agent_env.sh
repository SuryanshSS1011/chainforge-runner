#!/usr/bin/env bash
# Start a repair-agent environment for one ARVO-backed record without leaking its fix.
#
# ARVO's vulnerable images keep each project's full git history, and in every image we probed
# the developer's fix commit is reachable (`git show <fix>` prints the answer). This script starts
# the vulnerable image with networking disabled and rewrites every repository under /src to a
# single commit holding the vulnerable tree: the working tree and `.git` stay (build scripts that
# call git keep working), but no later commit, tag, reflog entry or packed object survives.
#
#   agent_env.sh <arvo_id> [name]   -> prints the container name; `docker exec -it <name> bash`
#   agent_env.sh --check <arvo_id> <fix sha>
#       starts, sanitizes, asserts the fix commit is unreachable, then rebuilds with
#       `arvo compile` to show the image still builds; prints a JSON verdict and removes it.
#
# Scoring stays with score_patch.sh, which applies a patch to a fresh image; this script only
# prepares the environment an agent explores.
set -uo pipefail
CHECK=0
[ "${1:-}" = "--check" ] && { CHECK=1; shift; }
ID="${1:?usage: agent_env.sh [--check] <arvo_id> [name|fix sha]}"
IMG="n132/arvo:${ID}-vul"
NAME="cf-agent-${ID}-$$"
[ "$CHECK" = 0 ] && NAME="${2:-$NAME}"
FIX="${2:-}"

docker image inspect "$IMG" >/dev/null 2>&1 || docker pull -q "$IMG" >/dev/null || exit 1
docker run -d --name "$NAME" --network none "$IMG" sleep infinity >/dev/null || exit 1
docker exec "$NAME" bash -c '
  # The repositories belong to the image build user; without this every git call below fails
  # with "dubious ownership" and the history would silently stay.
  git config --global --add safe.directory "*"
  for d in $(find /src -maxdepth 3 -name .git -prune 2>/dev/null); do
    r=$(dirname "$d")
    git -C "$r" -c user.name=cf -c user.email=cf@localhost checkout -q --orphan cf-vulnerable 2>/dev/null || continue
    git -C "$r" -c user.name=cf -c user.email=cf@localhost commit -q --allow-empty -m "vulnerable revision" >/dev/null 2>&1
    git -C "$r" for-each-ref --format="%(refname)" | grep -v "^refs/heads/cf-vulnerable$" \
      | xargs -r -n1 git -C "$r" update-ref -d
    git -C "$r" remote 2>/dev/null | xargs -r -n1 git -C "$r" remote remove
    rm -f "$d/packed-refs" "$d/ORIG_HEAD" "$d/FETCH_HEAD"
    rm -f "$d"/shallow "$d"/objects/info/alternates "$d"/objects/pack/*.keep
    git -C "$r" reflog expire --expire=now --all
    git -C "$r" gc -q --prune=now --aggressive 2>/dev/null || git -C "$r" gc -q --prune=now
  done'

if [ "$CHECK" = 0 ]; then echo "$NAME"; exit 0; fi

LEAK=$(docker exec -e FIX="$FIX" "$NAME" bash -c '
  git config --global --add safe.directory "*"
  n=0; for d in $(find /src -maxdepth 3 -name .git -prune 2>/dev/null); do
    git -C "$(dirname "$d")" cat-file -e "$FIX^{commit}" 2>/dev/null && n=$((n+1))
  done; echo $n')
NET=$(docker exec "$NAME" bash -c 'timeout 5 bash -c "</dev/tcp/1.1.1.1/443" 2>/dev/null && echo up || echo down')
docker exec "$NAME" bash -c 'arvo compile >/tmp/b.log 2>&1'; BUILD=$?
TAIL=""
[ "$BUILD" = 0 ] || TAIL=$(docker exec "$NAME" bash -c 'tail -c 600 /tmp/b.log' | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')
docker rm -f "$NAME" >/dev/null 2>&1
printf '{"arvo_id":"%s","fix_reachable_in_repos":%s,"network":"%s","build_rc":%s,"build_tail":%s}\n' \
  "$ID" "${LEAK:-null}" "$NET" "$BUILD" "${TAIL:-null}"
