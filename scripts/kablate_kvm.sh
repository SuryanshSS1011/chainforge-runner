#!/usr/bin/env bash
# kablate_kvm.sh — guard ablation for a kernel record: does ONE hunk of the fix, applied alone to
# fix^, stop the syzbot bug? Same proof as infra/verify/ablate.sh for ARVO, on the KVM box.
#
# Control first: fix^ must reproduce the syzbot bug (same KASAN class + function), or nothing
# below means anything. Then each source hunk (harness/test/doc paths excluded by the shared rule)
# is applied alone, the kernel rebuilt incrementally, and the reproducer booted twice: a hunk is
# the proven guard only if the bug fires on neither boot and both boots demonstrably ran.
#
# Usage: kablate_kvm.sh <extid> <fix_sha>     Output: $BASE/ablate/<extid>/result.json + hunks/
set -uo pipefail
EXTID="${1:?usage: kablate_kvm.sh <extid> <fix_sha>}"
FIX="${2:?missing fix_sha}"
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
  python3 - "$OUT/result.json" "$EXTID" "$FIX" "$1" "${2:-}" "$WORK/hunks.tsv" <<'PY'
import json, os, sys
out, extid, fix, status, detail, tsv = sys.argv[1:7]
hunks = []
if os.path.exists(tsv):
    for line in open(tsv):
        h, f, add, outcome = line.rstrip("\n").split("\t")
        hunks.append({"hunk": h, "file": f, "added": int(add), "outcome": outcome})
guard = next((h for h in hunks if h["outcome"] == "clean"), None)
json.dump({"extid": extid, "fix_commit": fix, "status": status, "detail": detail,
           "control": "crashed" if status in ("ok", "no_single_hunk") else None,
           "results": hunks, "guard_hunk": guard, "source_causally_proven": bool(guard)},
          open(out, "w"), indent=1)
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
"${CF_PY:-python3.12}" "$BASE/repo/infra/verify/split_hunks.py" "$OUT/fix.diff" "$OUT/hunks" > "$WORK/split.log" 2>&1 || emit hunk_split_failed ""
N=$(python3 -c "import json;print(json.load(open('$OUT/hunks/index.json'))['written'])" 2>/dev/null || echo 0)
(( N > 0 )) || emit no_code_hunks ""
git -C "$KSRC" checkout -q "$FIX^"

VER=$(awk -F'= *' '/^VERSION/{print $2;exit}' "$KSRC/Makefile"); PL=$(awk -F'= *' '/^PATCHLEVEL/{print $2;exit}' "$KSRC/Makefile")
if (( VER < 5 || (VER == 5 && PL < 15) )); then GCC=10.5.0
elif (( VER == 5 || (VER == 6 && PL < 6) )); then GCC=12.3.0
else GCC=13.2.0; fi
HOSTCC="${CF_HOSTCC:-}"  # see kdiff_kvm.sh: era-appropriate host gcc for pre-6.x objtool
if [[ -z "$HOSTCC" ]] && (( VER < 6 )) && command -v gcc-11 >/dev/null; then HOSTCC=gcc-11; fi
MK=(make -C "$KSRC" -j"${CF_JOBS:-6}" CROSS_COMPILE="$BASE/tools/gcc-$GCC-nolibc/x86_64-linux/bin/x86_64-linux-" KCFLAGS=-g0 HOSTCFLAGS="-g0 -O2"
    ${HOSTCC:+HOSTCC=$HOSTCC} ${HOSTCC:+HOSTCXX=${HOSTCC/gcc/g++}})
cp "$WORK/kernel.config" "$KSRC/.config"
printf 'CONFIG_KASAN=y\nCONFIG_KASAN_GENERIC=y\nCONFIG_KCOV=n\nCONFIG_DEBUG_INFO_NONE=y\nCONFIG_VIRTIO=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_BLK=y\nCONFIG_EXT4_FS=y\nCONFIG_DEVTMPFS=y\nCONFIG_DEVTMPFS_MOUNT=y\nCONFIG_BLK_DEV_LOOP=y\n' >> "$KSRC/.config"
build() { rm -f "$KSRC/arch/x86/boot/bzImage"; nice -n 10 "${MK[@]}" olddefconfig >/dev/null 2>&1
          nice -n 10 "${MK[@]}" bzImage >"$WORK/build.log" 2>&1; [[ -f "$KSRC/arch/x86/boot/bzImage" ]]; }
gcc -O1 -static -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>/dev/null || gcc -O1 -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>/dev/null || emit repro_cc_failed ""
bash "$BASE/build_rootfs.sh" "$WORK/repro" "$WORK/rootfs.ext4" >/dev/null 2>&1 || emit rootfs_failed ""
boot() {  # label -> fired_match | other | clean
  local con="$WORK/$1.console.log" rc
  cp "$WORK/rootfs.ext4" "$WORK/r.ext4"
  timeout "$BOOT_T" nice -n 5 "$QEMU" -enable-kvm -cpu host -M pc -smp 4 -m 4G -no-reboot -nographic \
    -kernel "$KSRC/arch/x86/boot/bzImage" -drive file="$WORK/r.ext4",format=raw,if=virtio \
    -append "console=ttyS0 root=/dev/vda rw panic=1 kasan_multi_shot=1 init=/init" >"$con" 2>&1
  rc=$?; rm -f "$WORK/r.ext4"
  python3 - "$con" "$SIG" "$rc" <<'PY'
import re, sys
t = open(sys.argv[1], errors="replace").read(); typ, _, fn = sys.argv[2].partition(":"); rc = sys.argv[3]
hits = re.findall(r"KASAN: ([\w-]+) (?:\w+ )?in (\w+)", t)
if any(h[1] == fn and (typ.endswith(h[0]) or h[0].endswith(typ)) for h in hits):
    print("fired_match")
elif "environment up" in t and (rc == "124" or "REPRO_FINISHED" in t) and not re.search(r"Kernel panic|BUG: ", t):
    print("clean")
else:
    print("other")
PY
}

log "control: fix^ (linux $VER.$PL, gcc $GCC)"
build || emit control_build_failed ""
[[ "$(boot control)" == fired_match ]] || emit control_did_not_crash "fix^ does not reproduce $SIG"
cp "$WORK/control.console.log" "$OUT/control.log"  # PR-4 addendum: the proof stands on its logs
: > "$WORK/hunks.tsv"
for H in $(python3 -c "import json;print(' '.join(h['name'] for h in json.load(open('$OUT/hunks/index.json'))['hunks']))"); do
  git -C "$KSRC" checkout -q -- . 2>/dev/null
  meta=$(python3 -c "import json;h=next(x for x in json.load(open('$OUT/hunks/index.json'))['hunks'] if x['name']=='$H');print(h['file'],h['added'])")
  if ! git -C "$KSRC" apply "$OUT/hunks/$H" 2>/dev/null; then echo -e "$H\t${meta% *}\t${meta#* }\tapply_failed" >> "$WORK/hunks.tsv"; continue; fi
  if ! build; then echo -e "$H\t${meta% *}\t${meta#* }\tbuildfail" >> "$WORK/hunks.tsv"; continue; fi
  r1=$(boot "$H.1"); r2=clean; [[ "$r1" == clean ]] && r2=$(boot "$H.2")
  outcome=$([[ "$r1" == clean && "$r2" == clean ]] && echo clean || echo "$r1,$r2")
  echo -e "$H\t${meta% *}\t${meta#* }\t$outcome" >> "$WORK/hunks.tsv"
  cp "$WORK/$H.1.console.log" "$OUT/$H.log" 2>/dev/null
  log "$H (${meta% *}) -> $outcome"
  [[ "$outcome" == clean ]] && break
done
git -C "$KSRC" checkout -q -- .
grep -q $'\tclean$' "$WORK/hunks.tsv" && emit ok "" || emit no_single_hunk ""
