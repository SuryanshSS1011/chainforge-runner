#!/usr/bin/env bash
# PR-14: is the root site on the crashing path? Runs the vulnerable image's prebuilt libFuzzer
# target on the record's input under gdb, with breakpoints at the root site (file:line), the
# root function, and the sink function (control). Prints ONE JSON line of hit counts; no site,
# file or function name ever reaches the log or the artifact in clear (sites are labels, and
# this repository is public); raw gdb output is kept only encrypted with CF_KEY.
#
# The images ship gdb 7.x, which does not match `break foo` against `ns::Class::foo`, and an
# unqualified name can resolve into libc. Functions are therefore set with `rbreak FILE:REGEX`,
# matching the name as the last component of a qualified name, restricted to the site's file.
#
# Usage: path_probe.sh <arvo_id> <target> <root_file_base> <root_line> <root_fn> <sink_fn> [sink_file_base]
set -uo pipefail
ID="$1"; T="$2"; RF="$3"; RL="$4"; RFN="$5"; SFN="$6"; SF="${7:-}"
IMG="n132/arvo:${ID}-vul"
for w in 60 300 0; do docker pull -q "$IMG" >/dev/null 2>&1 && break; sleep $w; done
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "{\"arvo_id\":\"$ID\",\"status\":\"pull_failed\"}"; exit 0; }
W=$(mktemp -d); chmod 777 "$W"
timeout 1500 docker run --rm -v "$W:/pp" -e T="$T" -e RF="$RF" -e RL="$RL" -e RFN="$RFN" -e SFN="$SFN" -e SF="$SF" "$IMG" bash -c '
  (command -v gdb || (apt-get update -qq && apt-get install -y -qq gdb)) >/dev/null 2>&1
  command -v gdb >/dev/null || { echo no_gdb > /pp/status; exit 0; }
  B="/out/$T"
  # The case list names the target from the record; ARVO images name it in their arvo script.
  if [ ! -x "$B" ]; then
    t=$(grep -o "/out/[A-Za-z0-9_.+-]*" "$(command -v arvo)" 2>/dev/null | head -1); [ -x "$t" ] && B="$t"
  fi
  [ -x "$B" ] || { echo no_target > /pp/status; exit 0; }
  ok() { [ -n "$1" ] && [ "$1" != "None" ]; }
  # Candidate commands for one function. `break FILE:NAME` finds a C symbol in a binary with
  # line tables only; rbreak finds C++ names (gdb 7 does not match `foo` against `ns::C::foo`),
  # with three basic regexes for a C symbol, a free C++ function and a qualified one (rbreak
  # splits FILE:REGEX at the first colon, so none contains one). Restricted to the file of the site;
  # unrestricted only when no restricted command resolves, since an unqualified name can land in
  # libc. Only commands that resolve in a dry pass are kept.
  cands() {
    local pre=""; [ -n "$2" ] && pre="$2:"
    printf "break %s%s\n" "$pre" "$1"
    for p in "^$1\$" "^$1(" "[^A-Za-z0-9_]$1("; do printf "rbreak %s%s\n" "$pre" "$p"; done
  }
  resolves() { gdb -nx -batch -ex "set breakpoint pending off" -ex "$1" "$B" </dev/null 2>/dev/null | grep -q "^Breakpoint [0-9]"; }
  fn() {
    local kept=""
    if ok "$2"; then kept=$(cands "$1" "$2" | while read -r c; do resolves "$c" && echo "$c"; done); fi
    [ -n "$kept" ] || kept=$(cands "$1" "" | while read -r c; do resolves "$c" && echo "$c"; done)
    [ -n "$kept" ] && printf "%s\n" "$kept"
    return 0
  }
  {
    printf "set pagination off\nset confirm off\nset breakpoint pending on\n"
    ok "$RL" && printf "echo @@line\\\\n\nbreak %s:%s\n" "$RF" "$RL"
    ok "$RFN" && { printf "echo @@func\\\\n\n"; fn "$RFN" "$RF"; }
    ok "$SFN" && { printf "echo @@sink\\\\n\n"; fn "$SFN" "$SF"; }
    printf "echo @@end\\\\n\n"
    printf "commands 1-\$bpnum\nsilent\ncontinue\nend\n"
    printf "run\ninfo breakpoints\nquit\n"
  } > /pp/g.gdb
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout 900 gdb -nx -batch -x /pp/g.gdb --args "$B" -runs=1 /tmp/poc > /pp/g.out 2>&1
  echo ran > /pp/status
' >/dev/null 2>&1
# Parsed on the host: some images have no python3. Counts and booleans only reach the artifact.
python3 - "$W" "$ID" "$RFN" <<'P'
import json, re, sys
from pathlib import Path
w, aid, rfn = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
st = (w / "status").read_text().strip() if (w / "status").is_file() else "no_output"
res = {"arvo_id": aid, "status": st}
if st == "ran":
    out = (w / "g.out").read_text(errors="replace")
    res = {"arvo_id": aid, "status": "ok",
           "crashed": bool(re.search(r"Sanitizer|runtime error|deadly signal", out))}
    # Breakpoint numbers each request created, from the text between its marker and the next.
    made, kind = {}, None
    for ln in out.splitlines():
        m = re.match(r"@@(\w+)$", ln.strip())
        if m:
            kind = None if m.group(1) == "end" else m.group(1)
            if kind:
                made[kind] = []
            continue
        b = re.match(r"(?:Breakpoint|Temporary breakpoint) (\d+) (?:at|\()", ln)
        if b and kind:
            made[kind].append(b.group(1))
    info = out[out.rfind("Num     Type"):] if "Num     Type" in out else ""
    def block(num):
        m = re.search(rf"^{num}\s+breakpoint\s+keep\s+y\s+.*?(?=^\d+\s+breakpoint|\Z)", info, re.M | re.S)
        return m.group(0) if m else ""
    for k, nums in made.items():
        blocks = [block(n) for n in nums]
        live = [b for b in blocks if b and "<PENDING>" not in b]
        if not live:
            res[k] = "unresolved"
            continue
        # Patterns can match one function twice; count each address once.
        hits = {}
        for b in live:
            a = re.match(r"(\d+)\s+breakpoint\s+keep\s+y\s+(\S+)", b)
            key = a.group(2) if a and a.group(2).startswith("0x") else (a.group(1) if a else b)
            h = re.search(r"already hit (\d+) time", b)
            hits[key] = int(h.group(1)) if h else 0
        res[k] = sum(hits.values())
        if k == "line":
            # Does the line's enclosing function, as the debug info names it, match the label?
            f = re.search(r"\bin (\S+?)(?:\(.*?\))? at \S+:\d+", live[0])
            res["line_info"] = bool(f)
            if f and rfn and rfn != "None":
                res["line_fn_matches_label"] = f.group(1).split("::")[-1] == rfn
    res["breakpoints"] = {k: len(v) for k, v in made.items()}
print(json.dumps(res))
P
# Raw gdb output names sites, so it leaves the runner only encrypted (for debugging the probe).
if [ -n "${CF_KEY:-}" ] && [ -f "$W/g.out" ]; then
  mkdir -p out/raw
  tar -C "$W" -czf - g.out g.gdb 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -pass env:CF_KEY -out "out/raw/$ID.enc"
fi
rm -rf "$W"
docker rmi -f "$IMG" >/dev/null 2>&1
