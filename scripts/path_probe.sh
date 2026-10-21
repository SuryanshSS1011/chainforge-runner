#!/usr/bin/env bash
# PR-14: is the root site on the crashing path? Runs the vulnerable image's prebuilt libFuzzer
# target on the record's input under gdb, with breakpoints at the root site (file:line), the
# root function, and the sink function (control). Prints ONE JSON line of hit counts; no site,
# file or function name ever reaches the log or the artifact (sites are labels, and this
# repository is public).
# Usage: path_probe.sh <arvo_id> <target> <root_file_base> <root_line> <root_fn> <sink_fn>
set -uo pipefail
ID="$1"; T="$2"; RF="$3"; RL="$4"; RFN="$5"; SFN="$6"
IMG="n132/arvo:${ID}-vul"
for w in 60 300 0; do docker pull -q "$IMG" >/dev/null 2>&1 && break; sleep $w; done
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "{\"arvo_id\":\"$ID\",\"status\":\"pull_failed\"}"; exit 0; }
timeout 1500 docker run --rm -e T="$T" -e RF="$RF" -e RL="$RL" -e RFN="$RFN" -e SFN="$SFN" "$IMG" bash -c '
  (command -v gdb || (apt-get update -qq && apt-get install -y -qq gdb)) >/dev/null 2>&1
  command -v gdb >/dev/null || { echo "{\"status\":\"no_gdb\"}"; exit 0; }
  B="/out/$T"; [ -x "$B" ] || { echo "{\"status\":\"no_target\"}"; exit 0; }
  cat > /tmp/g.gdb <<G
set pagination off
set confirm off
set breakpoint pending on
G
  n=0
  add() { [ -n "$1" ] || return; n=$((n+1)); printf "break %s\ncommands %d\nsilent\ncontinue\nend\n" "$1" "$n" >> /tmp/g.gdb; echo "$2 $n" >> /tmp/ids; }
  : > /tmp/ids
  [ -n "$RL" ] && [ "$RL" != "None" ] && add "$RF:$RL" line
  [ -n "$RFN" ] && [ "$RFN" != "None" ] && add "$RFN" func
  [ -n "$SFN" ] && [ "$SFN" != "None" ] && add "$SFN" sink
  printf "run\ninfo breakpoints\nquit\n" >> /tmp/g.gdb
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout 900 gdb -nx -batch -x /tmp/g.gdb --args "$B" -runs=1 /tmp/poc > /tmp/g.out 2>&1
  python3 - <<P 2>/dev/null || echo "{\"status\":\"parse_failed\"}"
import json, re
out = open("/tmp/g.out", errors="replace").read()
ids = dict(l.split()[::-1] for l in open("/tmp/ids") if l.strip())   # number -> kind
res = {"status": "ok", "crashed": bool(re.search(r"Sanitizer|runtime error|deadly signal", out))}
for num, kind in ids.items():
    m = re.search(rf"^{num}\s+breakpoint\s+keep\s+y\s+(\S+).*?(?=^\d+\s+breakpoint|\Z)", out, re.M | re.S)
    if not m:
        res[kind] = "unresolved"; continue
    block = m.group(0)
    if "<PENDING>" in block:
        res[kind] = "unresolved"; continue
    h = re.search(r"already hit (\d+) time", block)
    res[kind] = int(h.group(1)) if h else 0
print(json.dumps(res))
P
' 2>/dev/null | tail -1 | python3 -c "import json,sys; d=json.loads(sys.stdin.read() or '{\"status\":\"no_output\"}'); d['arvo_id']='$ID'; print(json.dumps(d))"
docker rmi -f "$IMG" >/dev/null 2>&1
