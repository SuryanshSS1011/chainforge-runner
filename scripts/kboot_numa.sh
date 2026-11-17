#!/usr/bin/env bash
# Does the guest's NUMA layout decide whether a Linux 7.0 syzbot kernel boots?
#
# Usage: kboot_numa.sh <out dir>
#
# Follows the public RootSink README's kernel setup block verbatim, then applies
# scripts/numa1.patch (one NUMA node in the VM's firmware tables) to the clone's kernel scripts and
# runs the re-run on CHAINFORGE-0800011 (fix^ is Linux 7.0). The vulnerable kernel and rootfs are
# kept, and each is booted again under five CPU and NUMA settings, so the vendor the guest sees is
# the only thing that changes between boots that share a NUMA setting:
#   host_old, host_numa1       the runner's own CPU, without and with the patch's NUMA node
#   intel_old, intel_numa1     qemu64 with vendor GenuineIntel, without and with it
#   amd_old                    qemu64 with vendor AuthenticAMD, without it
# Writes <out>/boots.jsonl (one line per boot), <out>/host.txt, the re-run's differential.json and
# the tail of each boot's console. Nothing here is RootSink data.
set -u
OUT="$(realpath -m "$1")"
mkdir -p "$OUT/console"
HERE="$(cd "$(dirname "$0")" && pwd)"
R="$HOME/RootSink"
EXTID=87badbb9094e008e0685
FIXSHA=035c25007c9e698bef3826070ee34bb6d778020c
SIG_FN=le_read_features_complete

{ lscpu | grep -E "Model name|Vendor ID|^CPU\(s\)"; uname -r; } >"$OUT/host.txt" 2>&1
cd "$HOME" && git clone -q https://github.com/SuryanshSS1011/RootSink && cd "$R" || exit 1
git log -1 --format='RootSink %H' >>"$OUT/host.txt"

python3 - "$R/README.md" >"$OUT/kernel_setup.sh" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
s = t[t.index("### Linux kernel bugs (syzbot)"):]
print(re.search(r"```bash\n(.*?)```", s, re.S).group(1))
PY
sudo apt-get update -qq
bash -e "$OUT/kernel_setup.sh" >"$OUT/kernel_setup.log" 2>&1 || { echo "README setup failed" >&2; exit 1; }
eval "$(grep -m1 '^export CF_BASE' "$OUT/kernel_setup.sh")"

git apply "$HERE/numa1.patch" || { echo "numa1.patch does not apply" >&2; exit 1; }
cp infra/cse-kvm/github/{kdiff_kvm.sh,kablate_kvm.sh} "$CF_BASE"/
CF_KEEP=1 bash "$CF_BASE/kdiff_kvm.sh" "$EXTID" "$FIXSHA" </dev/null >"$OUT/kdiff.log" 2>&1
cp "$CF_BASE/out/$EXTID/differential.json" "$OUT/" 2>/dev/null
W="$CF_BASE/work/$EXTID"
[ -f "$W/bzImage.vul" ] && [ -f "$W/rootfs.ext4" ] || { echo "no kept bzImage.vul or rootfs" >&2; exit 0; }

NUMA1=(-object memory-backend-ram,id=ram0,size=4G -numa node,nodeid=0,cpus=0-3,memdev=ram0)
boot() { # name, then the -cpu value, then "old" or "numa1"
  local name="$1" cpu="$2" numa=() con="$OUT/console/$1.log" rc t0
  [ "$3" = numa1 ] && numa=("${NUMA1[@]}")
  cp "$W/rootfs.ext4" "$W/r.ext4"
  t0=$(date +%s)
  timeout "${CF_BOOT_TIMEOUT:-300}" "$CF_QEMU" -enable-kvm -cpu "$cpu" -M pc -smp 4 -m 4G "${numa[@]}" \
    -no-reboot -nographic -kernel "$W/bzImage.vul" -drive file="$W/r.ext4",format=raw,if=virtio \
    -append "console=ttyS0 root=/dev/vda rw panic=1 kasan_multi_shot=1 init=/init" >"$con.full" 2>&1
  rc=$?
  rm -f "$W/r.ext4"
  python3 - "$name" "$cpu" "$3" "$rc" "$(($(date +%s) - t0))" "$con.full" "$SIG_FN" >>"$OUT/boots.jsonl" <<'PY'
import json, re, sys
name, cpu, numa, rc, secs, con, fn = sys.argv[1:]
t = open(con, errors="replace").read()
first = lambda p: (re.search(p, t) or [None])[0]
print(json.dumps({
    "boot": name, "cpu": cpu, "numa": numa, "rc": int(rc), "seconds": int(secs),
    "guest_cpu0": first(r"smpboot: CPU0: [^\n]*"),
    "secondary_nodes": re.findall(r"\.\.\.\. node  #(\d+), CPUs", t),
    "smpboot_warn": first(r"WARNING: arch/x86/kernel/smpboot\.c:\d+[^\n]*"),
    "environment_up": "environment up" in t,
    "kasan_match": bool(re.search(r"BUG: KASAN: [\w-]+ (?:\w+ )?in " + fn, t)),
    "first_kasan": first(r"BUG: KASAN: [^\n]*"),
}))
PY
  tail -150 "$con.full" >"$con"; rm -f "$con.full"
}
boot host_old host old
boot host_numa1 host numa1
boot intel_old qemu64,vendor=GenuineIntel old
boot intel_numa1 qemu64,vendor=GenuineIntel numa1
boot amd_old qemu64,vendor=AuthenticAMD old
cat "$OUT/boots.jsonl"
