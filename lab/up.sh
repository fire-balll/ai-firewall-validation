#!/usr/bin/env bash
# 격리 랩을 띄운다. 모든 네트워크는 --internal 이라 외부로 나가는 경로가 없다.
#   ISOLATE=1 ./lab/up.sh   네트워크 간 호스트 라우팅을 막는 isolate 옵션 추가
set -euo pipefail
cd "$(dirname "$0")"
source ./topology.env
PODMAN=${PODMAN:-sudo podman}

$PODMAN build -t "$IMAGE" .

opts=(--internal)
[[ "${ISOLATE:-0}" == 1 ]] && opts+=(--opt isolate=true)

fw_nets=()
for n in $NETWORKS; do
  name=${n%%:*}; prefix=${n#*:}
  $PODMAN network exists "net-$name" || \
    $PODMAN network create "${opts[@]}" --subnet "$prefix.0/24" "net-$name"
  fw_nets+=(--network "net-$name:ip=$prefix.$FW_HOST")
done

$PODMAN run -d --name fw --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 "${fw_nets[@]}" "$IMAGE" sleep infinity

# 초기 상태: forward 전부 차단
$PODMAN exec -i fw nft -f - <<'EOF'
flush ruleset
table inet fwlab {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
  }
}
EOF

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  IFS=: read -r host net num cmd <<<"$line"
  prefix=""
  for n in $NETWORKS; do [[ ${n%%:*} == "$net" ]] && prefix=${n#*:}; done
  $PODMAN run -d --name "$host" --cap-add NET_ADMIN --cap-add NET_RAW \
    --network "net-$net:ip=$prefix.$num" "$IMAGE" sh -c "$cmd"
  $PODMAN exec "$host" ip route replace default via "$prefix.$FW_HOST"
done <<<"$HOSTS"

echo "lab up. 다음으로 ./lab/check-path.sh 로 경로를 검수할 것."
