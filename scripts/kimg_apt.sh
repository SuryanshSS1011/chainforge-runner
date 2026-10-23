#!/bin/sh
# Install kernel build dependencies in an era gcc image (Debian buster or bullseye). Releases that
# left deb.debian.org are read from archive.debian.org; their signatures are still checked.
set -e
pkgs="flex bison bc libelf-dev libssl-dev cpio kmod"
if apt-get update && apt-get install -y $pkgs; then exit 0; fi
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
  [ -f "$f" ] || continue
  sed -i -e 's|deb.debian.org/debian-security|archive.debian.org/debian-security|g' \
         -e 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' \
         -e 's|security.debian.org|archive.debian.org/debian-security|g' \
         -e 's|deb.debian.org|archive.debian.org|g' -e '/-updates/d' "$f"
done
apt-get -o Acquire::Check-Valid-Until=false update
apt-get install -y $pkgs
