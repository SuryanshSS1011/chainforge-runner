#!/usr/bin/env bash
# kdiff_kvm.sh — two-sided kernel witness on the KVM box: the syzbot C reproducer must trip the
# SAME KASAN bug at fix^ and run clean at fix, both built from the fix commit's own tree.
#
# Why fix^ and not syzbot's crash commit: the crash commit is often on another tree (linux-next,
# net-next) and hundreds of commits from the fix, so "clean at fix" would not isolate the fix.
# fix^ -> fix differs by exactly one commit, and the second build is incremental.
#
# Three guards keep an infrastructure failure from being read as evidence (SPECIFICATION R10):
#   - vulnerable side counts only if the KASAN report matches the syzbot bug (type + function);
#   - patched side counts as clean only if the environment came up AND the reproducer ran;
#   - patched side is booted CF_FIX_BOOTS times (default 2), since races fire intermittently.
#
# Usage: kdiff_kvm.sh <extid> <fix_sha>      Output: $BASE/out/<extid>/differential.json + logs
set -uo pipefail

EXTID="${1:?usage: kdiff_kvm.sh <extid> <fix_sha>}"
FIX="${2:?missing fix_sha}"
BASE="${CF_BASE:-/scratch/sss6371/cfk}"
OUT="$BASE/out/$EXTID"
WORK="$BASE/work/$EXTID"
QEMU="${CF_QEMU:-/usr/libexec/qemu-kvm}"
JOBS="${CF_JOBS:-9}"
BOOT_T="${CF_BOOT_TIMEOUT:-600}"
SYZ="https://syzkaller.appspot.com"
mkdir -p "$OUT" "$WORK"
rm -f "$OUT/differential.json"

log() { echo "[kdiff $EXTID] $(date +%T) $*" >&2; }
emit() {  # status detail
  python3 - "$OUT/differential.json" "$EXTID" "$FIX" "${PARENT:-}" "$1" "$2" \
    "${VUL:-}" "${FIXR:-}" "${SIG:-}" "${GCCV:-}" "${CRASH_COMMIT:-}" <<'PY'
import json, sys
out, extid, fix, parent, status, detail, vul, fixr, sig, gccv, crash = sys.argv[1:12]
json.dump({"extid": extid, "fix_commit": fix, "vulnerable_commit": parent or None,
           "syzbot_crash_commit": crash or None, "status": status, "detail": detail,
           "vulnerable": vul or None, "patched": fixr or None, "expected_signature": sig,
           "compiler": gccv or None,
           "match_rule": "PR-6" if vul == "fired_match_pr6" else ("strict" if vul == "fired_match" else None),
           "differential_complete": status == "differential"},
          open(out, "w"), indent=1)
PY
  log "-> $1 ($2)"
  [[ "${CF_KEEP:-0}" != "1" ]] && rm -rf "$WORK"
  exit 0
}

# 1. syzbot artifacts.
curl -sSf "$SYZ/bug?extid=$EXTID&json=1" -o "$WORK/bug.json" 2>/dev/null || emit no_artifacts "bug.json fetch failed"
read -r CRE CFG CRASH_COMMIT FIXREPO SIG < <(python3 - "$WORK/bug.json" "$FIX" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1])); fix = sys.argv[2]
c = next((x for x in d.get("crashes") or [] if x.get("c-reproducer")), None)
fc = d.get("fix-commits") or []
f = next((x for x in fc if (x.get("hash") or "").startswith(fix[:12])), fc[0] if fc else {})
repo = (f.get("repo") or "-").replace("git://", "https://")
# Expected KASAN signature from the bug title: "KASAN: <type> <Read|Write> in <func>".
m = re.search(r"KASAN: ([\w-]+) (?:\w+ )?in (\w+)", d.get("title") or "")
sig = f"{m.group(1)}:{m.group(2)}" if m else "-"
if not c:
    print("- - - -", repo, sig); sys.exit()
print(c.get("c-reproducer"), c.get("kernel-config") or "-", c.get("kernel-source-commit") or "-",
      repo, sig)
PY
)
[[ "$CRE" == "-" ]] && emit no_crepro "no C reproducer on syzbot"
[[ "$FIXREPO" == "-" ]] && emit no_fix_repo "syzbot names no repo for the fix"
curl -sSf "$SYZ$CRE" -o "$WORK/repro.c" || emit no_crepro "repro download failed"
curl -sSf "$SYZ$CFG" -o "$WORK/kernel.config" || emit no_config "config download failed"
cp "$WORK/repro.c" "$WORK/kernel.config" "$OUT/"

# 2. Fix and its parent from the fix's own tree.
KSRC="$WORK/linux"
mkdir -p "$KSRC"; git -C "$KSRC" init -q; git -C "$KSRC" remote add origin "$FIXREPO"
log "fetching $FIX (depth 2) from $FIXREPO"
# kernel.org refuses connections after a few hundred fetches from one host; fixes in subsystem
# trees land in mainline, so the GitHub mirror of torvalds/linux serves the same commit by SHA.
if ! git -C "$KSRC" fetch -q --depth 2 origin "$FIX" 2>"$WORK/fetch.log"; then
  log "fix repo refused ($(tail -1 "$WORK/fetch.log")); trying the GitHub mainline mirror"
  git -C "$KSRC" remote add mirror https://github.com/torvalds/linux
  git -C "$KSRC" fetch -q --depth 2 mirror "$FIX" 2>>"$WORK/fetch.log" \
    || emit fetch_failed "$(tail -1 "$WORK/fetch.log")"
fi
PARENT=$(git -C "$KSRC" rev-parse "$FIX^" 2>/dev/null) || emit fetch_failed "no parent of $FIX"

# 3. Compiler by kernel era (kernel.org crosstool, no sudo): the host gcc 8.5 cannot build
#    recent kernels, which was ~98 deterministic build failures in the last batch.
git -C "$KSRC" checkout -q "$PARENT" || emit checkout_failed "$PARENT"
VER=$(awk -F'= *' '/^VERSION/{print $2;exit}' "$KSRC/Makefile"); PL=$(awk -F'= *' '/^PATCHLEVEL/{print $2;exit}' "$KSRC/Makefile")
if   (( VER < 5 ));                    then GCC=10.5.0
elif (( VER == 5 && PL < 15 ));        then GCC=10.5.0
elif (( VER == 5 || (VER == 6 && PL < 6) )); then GCC=12.3.0
else GCC=13.2.0; fi
GCC="${CF_GCC:-$GCC}"  # a retry may force another compiler after a build failure
CROSS="$BASE/tools/gcc-$GCC-nolibc/x86_64-linux/bin/x86_64-linux-"
[[ -x "${CROSS}gcc" ]] || emit toolchain_missing "$GCC"
GCCV="$GCC"
MK=(make -C "$KSRC" -j"$JOBS" CROSS_COMPILE="$CROSS" KCFLAGS=-g0 HOSTCFLAGS="-g0 -O2")

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

build() {  # label
  rm -f "$KSRC/arch/x86/boot/bzImage"
  nice -n 10 "${MK[@]}" olddefconfig >/dev/null 2>&1
  nice -n 10 "${MK[@]}" bzImage >"$WORK/build.$1.log" 2>&1
  if [[ -f "$KSRC/arch/x86/boot/bzImage" ]]; then cp "$KSRC/arch/x86/boot/bzImage" "$WORK/bzImage.$1"; return 0; fi
  tail -30 "$WORK/build.$1.log" > "$OUT/build.$1.tail.log"; return 1
}

# 4. Reproducer + rootfs, identical for both revisions so the kernel is the only variable.
gcc -O1 -static -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>"$WORK/cc.log" \
  || gcc -O1 -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>>"$WORK/cc.log" \
  || emit repro_cc_failed "reproducer did not compile"
bash "$BASE/build_rootfs.sh" "$WORK/repro" "$WORK/rootfs.ext4" >"$WORK/rootfs.log" 2>&1 \
  || emit rootfs_failed "$(tail -1 "$WORK/rootfs.log")"

boot() {  # label -> echoes fired_match | fired_other | crashed_other | clean | not_run | no_boot
  local con="$OUT/$1.console.log" rc
  cp "$WORK/rootfs.ext4" "$WORK/rootfs.$1.ext4"
  timeout "$BOOT_T" nice -n 5 "$QEMU" -enable-kvm -cpu host -M pc -smp 4 -m 4G -no-reboot -nographic \
    -kernel "$WORK/bzImage.${1%%[0-9]*}" -drive file="$WORK/rootfs.$1.ext4",format=raw,if=virtio \
    -append "console=ttyS0 root=/dev/vda rw panic=1 kasan_multi_shot=1 init=/init" \
    >"$con" 2>&1
  rc=$?
  rm -f "$WORK/rootfs.$1.ext4"
  # syzbot C reproducers loop silently, so "it ran" means the env came up and the run lasted the
  # whole window (timeout, rc 124) or the reproducer exited on its own (REPRO_FINISHED).
  python3 - "$con" "$SIG" "$rc" <<'PY'
import re, sys
t = open(sys.argv[1], errors="replace").read(); sig, rc = sys.argv[2], sys.argv[3]
typ, fn = sig.split(":") if ":" in sig else ("", "")
# Each KASAN report with its own call trace (PR-6 looks at the first 12 frames).
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
    print("fired_match_pr6")  # PR-6: syzbot's function is in this report's own call trace
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

log "build fix^ ${PARENT:0:12} (linux $VER.$PL, gcc $GCC)"
build vul || emit vul_build_failed "$(grep -m1 -iE 'error' "$OUT/build.vul.tail.log")"
# Races fire intermittently: a retry may boot fix^ up to CF_VUL_BOOTS times, stopping at the
# first matching crash. The patched side still has to stay clean on every one of its boots.
for i in $(seq 1 "${CF_VUL_BOOTS:-1}"); do
  VUL=$(boot vul)
  log "fix^ boot $i: $VUL"
  [[ "$VUL" == fired_match* ]] && break
done
case "$VUL" in
  fired_match|fired_match_pr6) ;;
  fired_other) emit vul_other_bug "KASAN fired but not the syzbot bug ($SIG)" ;;
  *)           emit vul_no_repro "reproducer did not trip the bug at fix^ ($VUL)" ;;
esac

log "build fix ${FIX:0:12} (incremental)"
git -C "$KSRC" checkout -q "$FIX" || emit checkout_failed "$FIX"
build fix || emit fix_build_failed "$(grep -m1 -iE 'error' "$OUT/build.fix.tail.log")"
FIXR=""
for i in $(seq 1 "${CF_FIX_BOOTS:-2}"); do
  r=$(boot "fix$i"); FIXR="${FIXR:+$FIXR,}$r"
  log "fix boot $i: $r"
  [[ "$r" == fired_match* ]] && emit fix_still_crashes "same KASAN bug at fix ($FIXR)"
  [[ "$r" != clean && "$r" != fired_other ]] && emit fix_untestable "patched kernel run not usable ($FIXR)"
done
emit differential "fix^ fired $SIG; fix clean on ${CF_FIX_BOOTS:-2} boots ($FIXR)"
