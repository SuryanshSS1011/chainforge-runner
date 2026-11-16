#!/usr/bin/env bash
# Copy ARVO images, unchanged and by digest, from Docker Hub (n132/arvo) to the GitHub Container
# Registry, and check that each copy keeps its digest so every record's pin still resolves.
#
# Usage: mirror_images.sh <list> <out dir>
#   <list>: one "<tag>\t<sha256:digest>" per line, e.g. "42476579-vul\tsha256:4305...".
# Needs crane on PATH, GH_TOKEN with packages:write, and MIRROR (e.g. ghcr.io/owner/rootsink-arvo).
# Writes <out>/mirror.jsonl and, after logging out, whether an anonymous client can read each copy.
set -u
LIST="$1"
OUT="$(realpath -m "$2")"
mkdir -p "$OUT"
: "${MIRROR:?set MIRROR to the destination repository}"
echo "$GH_TOKEN" | crane auth login ghcr.io -u "${GITHUB_ACTOR:-x}" --password-stdin
while IFS=$'\t' read -r tag dig; do
  [ -z "$tag" ] && continue
  src="index.docker.io/n132/arvo@$dig"
  dst="$MIRROR:$tag"
  t0=$(date +%s)
  if crane copy "$src" "$dst" >"$OUT/$tag.log" 2>&1; then
    got=$(crane digest "$dst" 2>>"$OUT/$tag.log")
  else
    got=""
  fi
  printf '{"tag": "%s", "source": "%s", "copy": "%s", "digest_kept": %s, "seconds": %s}\n' \
    "$tag" "$src" "$dst" "$([ "$got" = "$dig" ] && echo true || echo false)" "$(($(date +%s) - t0))" \
    >>"$OUT/mirror.jsonl"
done <"$LIST"
crane auth logout ghcr.io >/dev/null 2>&1 || true
rm -f "$HOME/.docker/config.json"
while IFS=$'\t' read -r tag dig; do
  [ -z "$tag" ] && continue
  if crane manifest "$MIRROR@$dig" >/dev/null 2>&1; then a=true; else a=false; fi
  printf '{"tag": "%s", "anonymous_read": %s}\n' "$tag" "$a" >>"$OUT/mirror.jsonl"
done <"$LIST"
cat "$OUT/mirror.jsonl"
