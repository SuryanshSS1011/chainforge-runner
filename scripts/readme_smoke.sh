#!/usr/bin/env bash
# Follow the public RootSink README on a clean machine, one command at a time, and time each step.
#
# Usage: readme_smoke.sh <arvo|kernel|digests> <out dir>
#
# Each step runs the README's command as written, in a fresh shell, against a fresh clone of
# github.com/SuryanshSS1011/RootSink. Where the README leaves a placeholder (<arvo_id>, my.patch),
# the step uses the README's own example record, CHAINFORGE-0042476579 (OSS-Fuzz 42476579,
# wireshark), and its developer fix from `patch_diff`. The kernel part runs the README's kernel
# setup block verbatim, then its re-run and scoring commands on CHAINFORGE-0800011.
# Writes <out>/steps.jsonl (one line per step: rc, seconds, command, last log lines), one log per
# step, and a table in the job summary. Nothing here is RootSink data: it only reads the clone.
set -u
PART="$1"
OUT="$(realpath -m "$2")"
mkdir -p "$OUT"
LOG="$OUT/steps.jsonl"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
R="$HOME/RootSink"
export PATH="$HOME/.local/bin:$PATH"

ARVO=42476579
PROJECT=wireshark
BUNDLE=infra/repro/bundles/CHAINFORGE-0042476579.json
VUL_DIGEST=sha256:43059d7be70ad9ae55afe579836183430cb80c938de0dd98f16e68a1a17813f3
EXTID=87badbb9094e008e0685            # CHAINFORGE-0800011, the first Reproduced-tier kernel record
FIXSHA=035c25007c9e698bef3826070ee34bb6d778020c

printf '| step | result | time |\n|---|---|---|\n' >>"$SUMMARY"

step() { # step <name> <command string>
  local name="$1" cmd="$2" t0 rc dt
  t0=$(date +%s)
  bash -c "$cmd" >"$OUT/$name.log" 2>&1
  rc=$?
  dt=$(($(date +%s) - t0))
  python3 - "$name" "$rc" "$dt" "$OUT/$name.log" "$cmd" >>"$LOG" <<'PY'
import json, sys
name, rc, dt, log, cmd = sys.argv[1:]
tail = open(log, errors="replace").read().splitlines()[-20:]
print(json.dumps({"step": name, "rc": int(rc), "seconds": int(dt), "cmd": cmd, "tail": tail}))
PY
  printf '| %s | %s | %ss |\n' "$name" "$([ "$rc" -eq 0 ] && echo ok || echo "exit $rc")" "$dt" >>"$SUMMARY"
  return "$rc"
}

verdict() { # verdict <name> <result.json>: record the scorer's outcome as its own line
  python3 - "$1" "$2" >>"$LOG" <<'PY'
import json, sys
name, path = sys.argv[1:]
try:
    v = json.load(open(path))
except Exception as e:  # no result file is itself the finding
    v = {"error": str(e)}
print(json.dumps({"step": name, "result": v}))
PY
}

common() {
  step install_uv 'curl -LsSf https://astral.sh/uv/install.sh | sh'
  step clone 'cd "$HOME" && git clone https://github.com/SuryanshSS1011/RootSink'
}

case "$PART" in
arvo)
  common
  step uv_sync "cd '$R' && uv sync --extra dev"
  step pytest "cd '$R' && uv run pytest -q"
  # The README's first Python block, verbatim.
  python3 - "$R/README.md" >"$OUT/quickstart.py" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
print(re.search(r"```python\n(.*?)```", t[t.index("## Quick start"):], re.S).group(1))
PY
  step quickstart_python "cd '$R' && uv run python '$OUT/quickstart.py'"
  step docker_pull "docker pull 'n132/arvo@$VUL_DIGEST'"
  step verify_record "cd '$R' && bash infra/repro/verify.sh $BUNDLE"
  python3 - "$R/data/release/dataset.jsonl" >"$OUT/my.patch" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r["id"] == "CHAINFORGE-0042476579":
        print(r["patch_diff"], end="")
PY
  step score_devfix "cd '$R' && bash infra/repro/score_patch.sh $ARVO $PROJECT '$OUT/my.patch' '$OUT/score_devfix'"
  verdict score_devfix_result "$OUT/score_devfix/result.json"
  step score_nopatch "cd '$R' && bash infra/repro/score_patch.sh $ARVO $PROJECT - '$OUT/score_nopatch'"
  verdict score_nopatch_result "$OUT/score_nopatch/result.json"
  step agent_env "cd '$R' && n=\$(bash infra/repro/agent_env.sh $ARVO) && echo \"container \$n\" && docker exec \"\$n\" sh -c 'for d in /src/*/; do [ -d \"\$d/.git\" ] && git -C \"\$d\" rev-list --count HEAD; done' ; docker rm -f \"\$n\" >/dev/null 2>&1; true"
  ;;
digests)
  common
  step uv_sync "cd '$R' && uv sync --extra dev"
  step check_image_digests "cd '$R' && uv run python infra/verify/check_image_digests.py --raw '$OUT/heads.jsonl' --out '$OUT/image_availability.json'"
  ;;
kernel)
  common
  # The README's kernel setup block, verbatim, from the repository root (sudo apt-get needs an
  # index first on a fresh runner).
  python3 - "$R/README.md" >"$OUT/kernel_setup.sh" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
s = t[t.index("### Linux kernel bugs (syzbot)"):]
print(re.search(r"```bash\n(.*?)```", s, re.S).group(1))
PY
  ENV_LINE=$(grep -m1 '^export CF_BASE' "$OUT/kernel_setup.sh")
  step kernel_setup_readme "sudo apt-get update -qq && cd '$R' && bash -e '$OUT/kernel_setup.sh'"
  # The README's commands, with the record's extid and fix sha for the placeholders.
  step kdiff_readme "cd '$R' && $ENV_LINE && bash \"\$CF_BASE/kdiff_kvm.sh\" $EXTID $FIXSHA </dev/null"
  eval "$ENV_LINE"
  verdict kdiff_readme_result "$CF_BASE/out/$EXTID/differential.json"
  step kscore_devfix "cd '$R' && $ENV_LINE && bash \"\$CF_BASE/kablate_kvm.sh\" $EXTID $FIXSHA devfix </dev/null"
  verdict kscore_devfix_result "$CF_BASE/ablate/$EXTID/result.json"
  ;;
*)
  echo "usage: readme_smoke.sh <arvo|kernel|digests> <out dir>" >&2
  exit 2
  ;;
esac
exit 0
