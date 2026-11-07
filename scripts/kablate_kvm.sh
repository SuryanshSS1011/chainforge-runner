#!/usr/bin/env bash
# kablate_kvm.sh — guard ablation for a kernel record: does ONE hunk of the fix, applied alone to
# fix^, stop the syzbot bug? Same proof as infra/verify/ablate.sh for ARVO, on the KVM box.
#
# Control first: fix^ must reproduce the syzbot bug (same KASAN class + function), or nothing
# below means anything. Then each source hunk (harness/test/doc paths excluded by the shared rule)
# is applied alone, the kernel rebuilt incrementally, and the reproducer booted twice: a hunk is
# the proven guard only if the bug fires on neither boot and both boots demonstrably ran.
#
# Kernel patch scorer: a third argument names a candidate patch, `devfix` (the fix's own diff) or a
# file. After the same control, the candidate is applied whole to fix^ as the only variant and
# booted twice; result.json gets "mode": "score" and "outcome": pass | crash | apply_failed |
# buildfail (PREREGISTRATION, release 1.0.4 supply, item 2).
#
# Since release 1.0.5 (supply, item 1) the build and boot environment is the record's
# differential's (kdiff_kvm.sh): era compiler, compatibility retry, config, PR-6 matching, and the
# symmetric repeated-boot retry (CF_VUL_BOOTS).
#
# Usage: kablate_kvm.sh <extid> <fix_sha> [candidate]   Output: $BASE/ablate/<extid>/result.json
set -uo pipefail
EXTID="${1:?usage: kablate_kvm.sh <extid> <fix_sha> [candidate]}"
FIX="${2:?missing fix_sha}"
CAND="${3:-}"
BASE="${CF_BASE:-/scratch/sss6371/cfk}"
OUT="$BASE/ablate/$EXTID"
WORK="$BASE/awork/$EXTID"
QEMU="${CF_QEMU:-/usr/libexec/qemu-kvm}"
BOOT_T="${CF_BOOT_TIMEOUT:-600}"
SYZ="https://syzkaller.appspot.com"
mkdir -p "$OUT/hunks" "$WORK"
rm -f "$OUT/result.json"
log() { echo "[kablate $EXTID] $(date +%T) $*" >&2; }
emit() {  # status, then the per-hunk results file
  python3 - "$OUT/result.json" "$EXTID" "$FIX" "$1" "${2:-}" "$WORK/hunks.tsv" "$CAND" \
    "${CTRIES:-0}" "${HB:-2}" "${GCCV:-}" "${COMPAT:-0}" "${CTRL:-}" <<'PY'
import json, os, sys
out, extid, fix, status, detail, tsv, cand = sys.argv[1:8]
tries, hb, gccv, compat, ctrl = sys.argv[8:13]
hunks = []
if os.path.exists(tsv):
    for line in open(tsv):
        h, f, add, outcome = line.rstrip("\n").split("\t")
        hunks.append({"hunk": h, "file": f, "added": int(add), "outcome": outcome})
guard = next((h for h in hunks if h["outcome"] == "clean"), None)
res = {"extid": extid, "fix_commit": fix, "status": status, "detail": detail,
       "control": "crashed" if status in ("ok", "no_single_hunk", "hunks_inconclusive") else None,
       "control_boots": int(tries) or None, "control_match": ctrl or None,
       "boots_required": int(hb), "compiler": gccv or None, "build_compat": compat == "1"}
if cand:  # scorer mode: one candidate, no hunk proof
    o = hunks[0]["outcome"] if hunks else None
    res |= {"mode": "score", "candidate": cand, "results": hunks,
            "outcome": None if o is None else "pass" if o == "clean"
            else o if o in ("apply_failed", "buildfail")
            else "crash" if "fired_match" in o else "inconclusive"}  # R10: no verdict
else:
    res |= {"results": hunks, "guard_hunk": guard, "source_causally_proven": bool(guard)}
json.dump(res, open(out, "w"), indent=1)
PY
  log "-> $1 ${2:-}"
  [[ "${CF_KEEP:-0}" != "1" ]] && rm -rf "$WORK"
  exit 0
}

# Artifacts and the fix's tree, exactly as kdiff_kvm.sh.
curl -sSf "$SYZ/bug?extid=$EXTID&json=1" -o "$WORK/bug.json" || emit no_artifacts "bug.json"
read -r CRE CFG FIXREPO SIG < <(python3 - "$WORK/bug.json" "$FIX" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1])); fix = sys.argv[2]
c = next((x for x in d.get("crashes") or [] if x.get("c-reproducer")), None)
fc = d.get("fix-commits") or []
f = next((x for x in fc if (x.get("hash") or "").startswith(fix[:12])), fc[0] if fc else {})
m = re.search(r"KASAN: ([\w-]+) (?:\w+ )?in (\w+)", d.get("title") or "")
print(c.get("c-reproducer") if c else "-", (c or {}).get("kernel-config") or "-",
      (f.get("repo") or "-").replace("git://", "https://"), f"{m.group(1)}:{m.group(2)}" if m else "-")
PY
)
[[ "$CRE" == "-" ]] && emit no_crepro ""
curl -sSf "$SYZ$CRE" -o "$WORK/repro.c" && curl -sSf "$SYZ$CFG" -o "$WORK/kernel.config" || emit no_artifacts "download"
KSRC="$WORK/linux"; mkdir -p "$KSRC"; git -C "$KSRC" init -q
git -C "$KSRC" remote add origin "$FIXREPO"
git -C "$KSRC" fetch -q --depth 2 origin "$FIX" 2>/dev/null || {
  git -C "$KSRC" remote add mirror https://github.com/torvalds/linux
  git -C "$KSRC" fetch -q --depth 2 mirror "$FIX" 2>/dev/null || emit fetch_failed ""
}
git -C "$KSRC" diff "$FIX^" "$FIX" > "$OUT/fix.diff"
if [[ -n "$CAND" ]]; then  # scorer mode: the candidate, whole, is the only variant
  if [[ "$CAND" == devfix ]]; then cp "$OUT/fix.diff" "$OUT/hunks/candidate.patch"
  else cp "$CAND" "$OUT/hunks/candidate.patch" 2>/dev/null || emit candidate_missing "$CAND"; fi
  ADDED=$(grep -c '^+[^+]' "$OUT/hunks/candidate.patch" || true)
  python3 -c "import json;json.dump({'written':1,'hunks':[{'name':'candidate.patch','file':'(candidate)','added':${ADDED:-0}}]},open('$OUT/hunks/index.json','w'))"
else
  "${CF_PY:-python3.12}" "$BASE/repo/infra/verify/split_hunks.py" "$OUT/fix.diff" "$OUT/hunks" > "$WORK/split.log" 2>&1 || emit hunk_split_failed ""
fi
N=$(python3 -c "import json;print(json.load(open('$OUT/hunks/index.json'))['written'])" 2>/dev/null || echo 0)
(( N > 0 )) || emit no_code_hunks ""
git -C "$KSRC" checkout -q "$FIX^"

VER=$(awk -F'= *' '/^VERSION/{print $2;exit}' "$KSRC/Makefile"); PL=$(awk -F'= *' '/^PATCHLEVEL/{print $2;exit}' "$KSRC/Makefile")
# Build environment: the record's differential's, exactly as kdiff_kvm.sh (release 1.0.5 supply,
# item 1). Kernel.org crosstool by era; for kernels before 5.16, the era gcc image syzbot used, with
# its own binutils and host libraries; a host-toolchain compatibility retry after a failed build.
if (( VER < 5 || (VER == 5 && PL < 15) )); then GCC=10.5.0
elif (( VER == 5 || (VER == 6 && PL < 6) )); then GCC=12.3.0
else GCC=13.2.0; fi
GCC="${CF_GCC:-$GCC}"; GCCV="$GCC"
HOSTCC="${CF_HOSTCC:-}"  # see kdiff_kvm.sh: era-appropriate host gcc for pre-6.x objtool
if [[ -z "$HOSTCC" ]] && (( VER < 6 )) && command -v gcc-11 >/dev/null; then HOSTCC=gcc-11; fi
MK=(make -C "$KSRC" -j"${CF_JOBS:-6}" CROSS_COMPILE="$BASE/tools/gcc-$GCC-nolibc/x86_64-linux/bin/x86_64-linux-" KCFLAGS=-g0 HOSTCFLAGS="-g0 -O2"
    ${HOSTCC:+HOSTCC=$HOSTCC} ${HOSTCC:+HOSTCXX=${HOSTCC/gcc/g++}})
KIMG="${CF_KIMG:-}"
if [[ -z "$KIMG" && -z "${CF_GCC:-}" ]]; then
  if (( VER < 4 || (VER == 4 && PL < 19) )); then KIMG=7
  elif (( VER < 5 )); then KIMG=8; elif (( VER == 5 && PL < 8 )); then KIMG=9
  elif (( VER == 5 && PL < 16 )); then KIMG=10; fi
fi
if [[ -n "$KIMG" ]] && command -v docker >/dev/null; then
  if ! docker image inspect "cf-kbuild:$KIMG" >/dev/null 2>&1; then
    mkdir -p "$WORK/kimg"
    printf '%s\n' "FROM gcc:$KIMG" 'COPY apt.sh /apt.sh' 'RUN sh /apt.sh' >"$WORK/kimg/Dockerfile"
    cp "$(dirname "$0")/kimg_apt.sh" "$WORK/kimg/apt.sh"
    for t in 1 2 3; do docker build -t "cf-kbuild:$KIMG" "$WORK/kimg" >"$WORK/kimg.log" 2>&1 && break; sleep 60; done
    docker image inspect "cf-kbuild:$KIMG" >/dev/null 2>&1 || tail -40 "$WORK/kimg.log" >"$OUT/kimg.log"
    docker image inspect "cf-kbuild:$KIMG" >/dev/null 2>&1 || emit toolchain_missing "gcc:$KIMG image"
  fi
fi
if [[ -n "$KIMG" ]]; then
  GCCV="gcc:$KIMG container"
  MK=(docker run --rm -u "$(id -u):$(id -g)" -v "$KSRC:$KSRC" -w "$KSRC" "cf-kbuild:$KIMG"
      make -C "$KSRC" -j"${CF_JOBS:-6}" KCFLAGS=-g0 HOSTCFLAGS="-g0 -O2")
fi
cp "$WORK/kernel.config" "$KSRC/.config"
cat >> "$KSRC/.config" <<'CFG'
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KCOV=n
CONFIG_DEBUG_INFO=n
CONFIG_DEBUG_INFO_NONE=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_EXT4_FS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
CFG
COMPAT=0
enable_compat() {  # as kdiff_kvm.sh: host-side tools only; once on, it holds for every variant
  COMPAT=1
  printf 'CONFIG_WERROR=n\nCONFIG_SECURITY_SELINUX=n\nCONFIG_MODULE_SIG=n\nCONFIG_BPFILTER=n\nCONFIG_DRM_PANEL_ILITEK_ILI9882T=n\n' >> "$KSRC/.config"
  MK+=(WERROR=0 KCFLAGS="-g0 -Wno-error" HOSTCFLAGS="-g0 -O2 -Wno-error -Wno-deprecated-declarations")
}
build_once() { rm -f "$KSRC/arch/x86/boot/bzImage"; nice -n 10 "${MK[@]}" olddefconfig >/dev/null 2>&1
               nice -n 10 "${MK[@]}" bzImage >"$WORK/build.log" 2>&1; [[ -f "$KSRC/arch/x86/boot/bzImage" ]]; }
build() {  # label; on failure the log's errors and tail are kept
  build_once && return 0
  if [[ $COMPAT == 0 ]]; then log "build failed; retrying with host-toolchain compatibility"; enable_compat; build_once && return 0; fi
  grep -nE "error|Error [0-9]" "$WORK/build.log" | head -20 > "$OUT/build.$1.errors.log"
  tail -80 "$WORK/build.log" > "$OUT/build.$1.tail.log"; return 1
}
gcc -O1 -static -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>/dev/null || gcc -O1 -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>/dev/null || emit repro_cc_failed ""
bash "$BASE/build_rootfs.sh" "$WORK/repro" "$WORK/rootfs.ext4" >/dev/null 2>&1 || emit rootfs_failed ""
boot() {  # label -> fired_match | fired_match_pr6 | fired_other | crashed_other | clean | not_run | no_boot
  local con="$WORK/$1.console.log" rc
  cp "$WORK/rootfs.ext4" "$WORK/r.ext4"
  timeout "$BOOT_T" nice -n 5 "$QEMU" -enable-kvm -cpu host -M pc -smp 4 -m 4G -no-reboot -nographic \
    -kernel "$KSRC/arch/x86/boot/bzImage" -drive file="$WORK/r.ext4",format=raw,if=virtio \
    -append "console=ttyS0 root=/dev/vda rw panic=1 kasan_multi_shot=1 init=/init" >"$con" 2>&1
  rc=$?; rm -f "$WORK/r.ext4"
  # The differential's classifier (kdiff_kvm.sh), PR-6 matching included.
  python3 - "$con" "$SIG" "$rc" <<'PY'
import re, sys
t = open(sys.argv[1], errors="replace").read(); sig, rc = sys.argv[2], sys.argv[3]
typ, fn = sig.split(":") if ":" in sig else ("", "")
blocks = re.split(r"(?=BUG: KASAN: )", t)[1:]
reports = []
for b in blocks:
    m = re.match(r"BUG: KASAN: ([\w-]+) (?:\w+ )?in (\w+)", b)
    if m:
        frames = re.findall(r"\s(\w+)(?:\.[\w.]+)?\+0x[0-9a-f]+/0x", b.split("=" * 20)[0])
        reports.append((m.group(1), m.group(2), frames[:12]))
same_class = [r for r in reports if typ and (typ.endswith(r[0]) or r[0].endswith(typ))]
if any(fn and r[1] == fn for r in same_class):
    print("fired_match")
elif any(fn and fn in r[2] for r in same_class):
    print("fired_match_pr6")
elif reports:
    print("fired_other")
elif "environment up" not in t:
    print("no_boot")
elif re.search(r"Kernel panic|BUG: |general protection fault", t):
    print("crashed_other")
elif rc == "124" or "REPRO_FINISHED" in t:
    print("clean")
else:
    print("not_run")
PY
}

# Races fire intermittently: the control may boot fix^ up to CF_VUL_BOOTS times, stopping at the
# first matching report, and then every variant must run clean on as many boots, never fewer than
# two (the symmetric retry of PREREGISTRATION 2026-10-20, applied to hunk tests in 1.0.5).
VB="${CF_VUL_BOOTS:-1}"; HB=$(( VB > 2 ? VB : 2 ))
log "control: fix^ (linux $VER.$PL, $GCCV)"
build control || emit control_build_failed "$(grep -m1 -iE 'error' "$OUT/build.control.tail.log" 2>/dev/null)"
CTRL=""; CTRIES=0
for i in $(seq 1 "$VB"); do
  CTRIES=$i; CTRL=$(boot control); log "fix^ boot $i: $CTRL"
  [[ "$CTRL" == fired_match* ]] && break
done
[[ "$CTRL" == fired_match* ]] || emit control_did_not_crash "fix^ does not reproduce $SIG in $VB boot(s) ($CTRL)"
cp "$WORK/control.console.log" "$OUT/control.log"  # PR-4 addendum: the proof stands on its logs
: > "$WORK/hunks.tsv"
for H in $(python3 -c "import json;print(' '.join(h['name'] for h in json.load(open('$OUT/hunks/index.json'))['hunks']))"); do
  git -C "$KSRC" checkout -q -- . 2>/dev/null
  meta=$(python3 -c "import json;h=next(x for x in json.load(open('$OUT/hunks/index.json'))['hunks'] if x['name']=='$H');print(h['file'],h['added'])")
  if ! git -C "$KSRC" apply "$OUT/hunks/$H" 2>/dev/null; then echo -e "$H\t${meta% *}\t${meta#* }\tapply_failed" >> "$WORK/hunks.tsv"; continue; fi
  if ! build "$H"; then echo -e "$H\t${meta% *}\t${meta#* }\tbuildfail" >> "$WORK/hunks.tsv"; continue; fi
  rs=""; for b in $(seq 1 "$HB"); do r=$(boot "$H.$b"); rs="${rs:+$rs,}$r"; [[ "$r" == clean ]] || break; done
  outcome=$([[ "$rs" =~ ^(clean,)*clean$ && $(tr -cd , <<<"$rs" | wc -c) -eq $((HB-1)) ]] && echo clean || echo "$rs")
  echo -e "$H\t${meta% *}\t${meta#* }\t$outcome" >> "$WORK/hunks.tsv"
  cp "$WORK/$H.1.console.log" "$OUT/$H.log" 2>/dev/null
  for b in $(seq 2 "$HB"); do cp "$WORK/$H.$b.console.log" "$OUT/$H.boot$b.log" 2>/dev/null; done
  log "$H (${meta% *}) -> $outcome"
  [[ "$outcome" == clean ]] && break
done
git -C "$KSRC" checkout -q -- .
grep -q $'\tclean$' "$WORK/hunks.tsv" && emit ok ""
# R10: a hunk whose boot never ran (not_run, no_boot) gave no verdict, so "no single hunk" needs a
# verdict for every hunk; otherwise the case has none.
awk -F'\t' '$4 !~ /^(apply_failed|buildfail)$/ && $4 !~ /fired_|crashed_other/' "$WORK/hunks.tsv" | grep -q . \
  && emit hunks_inconclusive "a hunk run gave no verdict" || emit no_single_hunk ""
