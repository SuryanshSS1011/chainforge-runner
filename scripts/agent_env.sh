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
  # Replace every repository under /src with a fresh one holding a single commit of the
  # vulnerable tree. Rewriting history in place proved unreliable (dangling symrefs and packed
  # objects kept the fix reachable), so the old .git is removed outright. Deepest repositories
  # first, so a submodule is replaced before the repository that contains it.
  git config --global --add safe.directory "*"
  git config --global user.name cf; git config --global user.email cf@localhost
  find /src -maxdepth 4 -name .git 2>/dev/null | awk -F/ "{print NF\" \"\$0}" | sort -rn | cut -d" " -f2- |
  while read -r d; do
    r=$(dirname "$d")
    # Builds that read their version from git (x265 via `git describe`) need the newest tag the
    # vulnerable revision already had. It names the past, so it is kept on the new commit.
    t=$(git -C "$r" describe --tags --abbrev=0 2>/dev/null)
    rm -rf "$d"
    git -C "$r" init -q && git -C "$r" add -A >/dev/null 2>&1 \
      && git -C "$r" commit -q -m "vulnerable revision" >/dev/null 2>&1 \
      && { [ -z "$t" ] || git -C "$r" tag "$t" >/dev/null 2>&1; }
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
# If the offline build failed, tell the rewrite from the network apart: rebuild the unmodified
# image with the network on.
ONLINE=null; OFFLINE=null
if [ "$BUILD" != 0 ]; then
  # Which change broke it: the network (unmodified image, offline) or the rewrite (online)?
  docker run --rm --network none "$IMG" bash -c 'arvo compile >/dev/null 2>&1'; OFFLINE=$?
  docker run --rm "$IMG" bash -c 'arvo compile >/dev/null 2>&1'; ONLINE=$?
fi
printf '{"arvo_id":"%s","fix_reachable_in_repos":%s,"network":"%s","build_rc":%s,"plain_offline_build_rc":%s,"plain_online_build_rc":%s,"build_tail":%s}\n' \
  "$ID" "${LEAK:-null}" "$NET" "$BUILD" "$OFFLINE" "$ONLINE" "${TAIL:-null}"
