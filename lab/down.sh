#!/usr/bin/env bash
# 랩 컨테이너와 네트워크를 지운다. 이미지는 남긴다.
set -uo pipefail
cd "$(dirname "$0")"
source ./topology.env
PODMAN=${PODMAN:-sudo podman}

containers=(fw)
while IFS= read -r line; do
  [[ -n "$line" ]] && containers+=("${line%%:*}")
done <<<"$HOSTS"

$PODMAN rm -f "${containers[@]}" 2>/dev/null
for n in $NETWORKS; do
  $PODMAN network rm "net-${n%%:*}" 2>/dev/null
done
echo "lab down."
