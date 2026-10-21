#!/usr/bin/env bash
# PR-14: is the root site on the crashing path? Runs the vulnerable image's prebuilt libFuzzer
# target on the record's input under gdb, with breakpoints at the root site (file:line), the
# root function, and the sink function (control). Prints ONE JSON line of hit counts; no site,
# file or function name ever reaches the log or the artifact in clear (sites are labels, and
# this repository is public); raw gdb output is kept only encrypted with CF_KEY.
# Usage: path_probe.sh <arvo_id> <target> <root_file_base> <root_line> <root_fn> <sink_fn>
set -uo pipefail
ID="$1"; T="$2"; RF="$3"; RL="$4"; RFN="$5"; SFN="$6"
IMG="n132/arvo:${ID}-vul"
for w in 60 300 0; do docker pull -q "$IMG" >/dev/null 2>&1 && break; sleep $w; done
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "{\"arvo_id\":\"$ID\",\"status\":\"pull_failed\"}"; exit 0; }
W=$(mktemp -d); chmod 777 "$W"
timeout 1500 docker run --rm -v "$W:/pp" -e T="$T" -e RF="$RF" -e RL="$RL" -e RFN="$RFN" -e SFN="$SFN" "$IMG" bash -c '
  (command -v gdb || (apt-get update -qq && apt-get install -y -qq gdb)) >/dev/null 2>&1
  command -v gdb >/dev/null || { echo no_gdb > /pp/status; exit 0; }
  B="/out/$T"
  # The case list names the target from the record; ARVO images name it in their arvo script.
  if [ ! -x "$B" ]; then
    t=$(grep -o "/out/[A-Za-z0-9_.+-]*" "$(command -v arvo)" 2>/dev/null | head -1); [ -x "$t" ] && B="$t"
  fi
  [ -x "$B" ] || { echo no_target > /pp/status; exit 0; }
  cat > /pp/g.gdb <<G
set pagination off
set confirm off
set breakpoint pending on
G
  n=0; : > /pp/ids
  add() { n=$((n+1)); printf "break %s\ncommands %d\nsilent\ncontinue\nend\n" "$1" "$n" >> /pp/g.gdb; echo "$2 $n" >> /pp/ids; }
  [ -n "$RL" ] && [ "$RL" != "None" ] && add "$RF:$RL" line
  [ -n "$RFN" ] && [ "$RFN" != "None" ] && add "$RFN" func
  [ -n "$SFN" ] && [ "$SFN" != "None" ] && add "$SFN" sink
  printf "run\ninfo breakpoints\nquit\n" >> /pp/g.gdb
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout 900 gdb -nx -batch -x /pp/g.gdb --args "$B" -runs=1 /tmp/poc > /pp/g.out 2>&1
  echo ran > /pp/status
' >/dev/null 2>&1
# Parsed on the host: some images have no python3. Counts only reach the artifact.
python3 - "$W" "$ID" <<'P'
import json, re, sys
from pathlib import Path
w, aid = Path(sys.argv[1]), sys.argv[2]
st = (w / "status").read_text().strip() if (w / "status").is_file() else "no_output"
res = {"arvo_id": aid, "status": st}
if st == "ran":
    out = (w / "g.out").read_text(errors="replace")
    res = {"arvo_id": aid, "status": "ok",
           "crashed": bool(re.search(r"Sanitizer|runtime error|deadly signal", out))}
    for line in (w / "ids").read_text().splitlines():
        kind, num = line.split()
        m = re.search(rf"^{num}\s+breakpoint\s+keep\s+y\s+(\S+).*?(?=^\d+\s+breakpoint|\Z)", out, re.M | re.S)
        if not m or "<PENDING>" in m.group(0):
            res[kind] = "unresolved"; continue
        h = re.search(r"already hit (\d+) time", m.group(0))
        res[kind] = int(h.group(1)) if h else 0
print(json.dumps(res))
P
# Raw gdb output names sites, so it leaves the runner only encrypted (for debugging the probe).
if [ -n "${CF_KEY:-}" ] && [ -f "$W/g.out" ]; then
  mkdir -p out/raw
  tar -C "$W" -czf - g.out ids g.gdb 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -pass env:CF_KEY -out "out/raw/$ID.enc"
fi
rm -rf "$W"
docker rmi -f "$IMG" >/dev/null 2>&1
