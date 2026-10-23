#!/usr/bin/env bash
# How far ARVO's two images sit from the recorded fix commit. GOLD runs ARVO's fixed image; the
# scorer applies the fix commit's own diff to the vulnerable image. They agree only if the
# vulnerable image is at the fix's parent and the fixed image at the fix, with every other
# repository under /src unchanged. Prints one JSON line of counts and booleans.
# Usage: fix_distance.sh <arvo id> <fix sha>
set -uo pipefail
ID="$1"; FIX="$2"
probe() {  # image -> "path head" for every git repo under /src
  docker run --rm --network none --entrypoint sh "$1" -c '
    for g in $(find /src -maxdepth 3 -name .git -prune 2>/dev/null); do
      d=$(dirname "$g"); h=$(git -C "$d" rev-parse HEAD 2>/dev/null) && echo "$d $h"
    done' 2>/dev/null
}
pull() { for t in 1 2 3; do docker pull -q "$1" >/dev/null 2>&1 && return 0; docker pull -q "mirror.gcr.io/$1" >/dev/null 2>&1 && docker tag "mirror.gcr.io/$1" "$1" && return 0; sleep 20; done; return 1; }
V="n132/arvo:${ID}-vul"; F="n132/arvo:${ID}-fix"
pull "$V" || { echo "{\"arvo_id\":\"$ID\",\"status\":\"pull_failed\"}"; exit 0; }
VR=$(probe "$V")
# The project repository is the one that holds the fix commit.
REPO=$(docker run --rm --network none --entrypoint sh "$V" -c "
  for g in \$(find /src -maxdepth 3 -name .git -prune 2>/dev/null); do
    d=\$(dirname \$g); git -C \$d cat-file -e '$FIX^{commit}' 2>/dev/null && { echo \$d; break; }
  done" 2>/dev/null)
STATS=$(docker run --rm --network none --entrypoint sh "$V" -c "
  d='$REPO'; [ -n \"\$d\" ] || { echo none; exit; }
  h=\$(git -C \$d rev-parse HEAD); p=\$(git -C \$d rev-parse '$FIX^' 2>/dev/null)
  a=\$(git -C \$d merge-base --is-ancestor \$h \$p 2>/dev/null && echo 1 || echo 0)
  n=\$( [ \$a = 1 ] && git -C \$d rev-list --count \$h..\$p || echo -1)
  f=\$( [ \$a = 1 ] && git -C \$d diff --name-only \$h \$p | wc -l || echo -1)
  echo \"\$([ \$h = \$p ] && echo 1 || echo 0) \$a \$n \$f\"" 2>/dev/null)
docker rmi -f "$V" >/dev/null 2>&1
pull "$F" || { echo "{\"arvo_id\":\"$ID\",\"status\":\"fix_pull_failed\",\"vul\":\"$STATS\"}"; exit 0; }
FR=$(probe "$F")
FH=$(echo "$FR" | awk -v d="$REPO" '$1==d{print $2}')
docker rmi -f "$F" >/dev/null 2>&1
python3 - "$ID" "$FIX" "$REPO" "$STATS" "$FH" <<PY
import json, sys
aid, fix, repo, stats, fh = sys.argv[1:6]
vr = dict(l.split() for l in """$VR""".splitlines() if len(l.split()) == 2)
fr = dict(l.split() for l in """$FR""".splitlines() if len(l.split()) == 2)
s = stats.split() if stats and stats != "none" else []
out = {"arvo_id": aid, "status": "ok" if repo else "fix_not_in_image",
       "vul_at_fix_parent": s[0] == "1" if s else None,
       "vul_before_fix_parent": s[1] == "1" if s else None,
       "commits_vul_to_fix_parent": int(s[2]) if s else None,
       "files_vul_to_fix_parent": int(s[3]) if s else None,
       "fix_image_at_fix": (fh == fix) if fh else None,
       "other_repos": len(set(vr) - {repo}),
       "other_repos_differing": sum(1 for d in set(vr) & set(fr) if d != repo and vr[d] != fr[d])}
print(json.dumps(out))
PY
