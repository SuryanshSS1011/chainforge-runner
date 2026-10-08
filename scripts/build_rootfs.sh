#!/usr/bin/env bash
# Build a busybox-based ext4 rootfs disk image for syzbot reproducer replay — ROOT-FREE.
# syzbot reproducers need a real environment (proc/sys/dev, loop devices, a shell, networking
# brought up) to set up their preconditions; a bare initramfs+rdinit=/repro is too minimal, so
# most reproducers loop without ever reaching the bug. This builds a proper rootfs using
# `mke2fs -d` (populates ext4 from a directory, NO mount/chroot/root needed).
#
# Usage: build_rootfs.sh <repro-binary> <out-image.ext4> [extra-lib-dir]
# The reproducer is copied to /repro and run by /init after the environment is up.
set -euo pipefail
REPRO="${1:?usage: build_rootfs.sh <repro> <out.ext4>}"
OUT="${2:?missing out image}"
BB="${CF_BASE:-/scratch/sss6371/chainforge}/imgbuild/busybox"
R="$(mktemp -d "${CF_BASE:-/scratch/sss6371/chainforge}/imgbuild/rootfs.XXXXXX")"
trap 'rm -rf "$R"' EXIT

mkdir -p "$R"/{bin,sbin,proc,sys,dev,tmp,root,etc,usr/bin,usr/sbin}
cp "$BB" "$R/bin/busybox"; chmod +x "$R/bin/busybox"
# symlink common applets so the init script + reproducer's shell-outs work
for a in sh mount umount mkdir mknod ip ifconfig ls cat sleep insmod modprobe dmesg poweroff \
         chmod echo sync mdev switch_root df grep; do ln -sf busybox "$R/bin/$a"; done

# The reproducer (may be dynamic — bundle its libs).
cp "$REPRO" "$R/repro"; chmod +x "$R/repro"
for lib in $(ldd "$REPRO" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
  d="$R${lib}"; mkdir -p "$(dirname "$d")"; cp -L "$lib" "$d" 2>/dev/null || true
done

# init: bring up the FULL environment syzbot reproducers expect, then run the reproducer.
cat > "$R/init" <<'INIT'
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
/bin/mount -t proc none /proc
/bin/mount -t sysfs none /sys
/bin/mount -t devtmpfs none /dev 2>/dev/null || /bin/mount -t tmpfs none /dev
/bin/mount -t tmpfs none /tmp
# device manager so loop/block nodes appear (syz_mount_image needs /dev/loop*)
echo /bin/mdev > /proc/sys/kernel/hotplug 2>/dev/null
/bin/mdev -s 2>/dev/null
# bring up loopback (many reproducers touch the network stack)
/bin/ip link set lo up 2>/dev/null || /bin/ifconfig lo up 2>/dev/null
echo "[init] environment up, running reproducer"
/repro
echo "REPRO_FINISHED"
/bin/sleep 3
/bin/poweroff -f
INIT
chmod +x "$R/init"

# Size: reproducer + libs + busybox are small; give 256MB headroom for the reproducer's own
# scratch (it writes FS images to /tmp/root etc.).
mke2fs -q -F -t ext4 -d "$R" "$OUT" 256M
echo "[rootfs] built $OUT ($(du -h "$OUT" | cut -f1))"
