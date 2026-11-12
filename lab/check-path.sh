#!/usr/bin/env bash
# 네트워크 사이 트래픽이 실제로 fw 를 거치는지 검수한다.
# 이 검수가 실패하면 이후 실험 결과는 전부 무효다.
set -uo pipefail
PODMAN=${PODMAN:-sudo podman}
fail=0

reset_fw() {
  $PODMAN exec -i fw nft -f - <<EOF
flush ruleset
table inet fwlab {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    $1
  }
}
EOF
}

echo "[1] forward 전부 차단 상태에서 pc -> server:80"
reset_fw ""
if $PODMAN exec pc curl -s -m 3 -o /dev/null http://10.10.30.10/; then
  echo "  FAIL: 차단했는데 통과함. 호스트가 직접 라우팅하고 있다. ISOLATE=1 로 다시 띄워 볼 것."
  fail=1
else
  echo "  OK: 차단됨"
fi

echo "[2] lan -> svc:80 만 허용한 상태에서 pc -> server:80"
reset_fw 'ip saddr 10.10.20.0/24 tcp dport 80 counter accept comment "check"'
if $PODMAN exec pc curl -s -m 3 -o /dev/null http://10.10.30.10/; then
  echo "  OK: 통과함"
else
  echo "  FAIL: 허용했는데 막힘. fw 의 ip_forward 와 호스트 기본 경로를 확인할 것."
  fail=1
fi

echo "[3] fw 카운터 확인"
if $PODMAN exec fw nft list ruleset | grep -E 'counter packets [1-9]' >/dev/null; then
  echo "  OK: 허용 룰 카운터가 증가함"
else
  echo "  FAIL: 카운터가 0. 트래픽이 fw 를 거치지 않았다."
  fail=1
fi

echo "[4] UDP: 차단 상태에서 응답 없음, lan -> svc:53/udp 허용하면 server 의 udp-echo 가 응답"
reset_fw ""
blocked=$($PODMAN exec pc sh -c 'echo fwlab-udp | nc -u -w 2 10.10.30.10 53' 2>/dev/null)
reset_fw 'ip saddr 10.10.20.0/24 udp dport 53 accept'
allowed=$($PODMAN exec pc sh -c 'echo fwlab-udp | nc -u -w 2 10.10.30.10 53' 2>/dev/null)
if [[ -z "$blocked" && "$allowed" == fwlab-udp ]]; then
  echo "  OK: 차단 시 응답 없음, 허용 시 응답 받음"
else
  echo "  FAIL: 차단 시 '$blocked', 허용 시 '$allowed'. server 의 udp-echo 가 떠 있는지 확인할 것 (lab 이미지 다시 빌드)"
  fail=1
fi

echo "[5] fw 에서 각 호스트로 직접 TCP 응답 (프로브가 block 전에 쓰는 확인, #62·#64)"
# fw 자신이 보내는 패킷은 forward 체인을 지나지 않으므로 후보 룰과 상관없이 닿아야 한다.
# 닿지 않으면 호스트(VM) 쪽에서 실험실 브리지 트래픽을 걸러내는 것이다(예: br_netfilter 를 켜는 k3s·docker).
# 이 상태로 배치를 돌리면 block 판정이 모두 실행 실패가 된다. 닫힌 포트 1 의 RST 도 응답으로 친다
source "$(dirname "$0")/topology.env"
dead=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  IFS=: read -r host net num _ <<<"$line"
  prefix=""
  for n in $NETWORKS; do [[ ${n%%:*} == "$net" ]] && prefix=${n#*:}; done
  out=$($PODMAN exec fw nc -vz -w 2 "$prefix.$num" 1 2>&1)
  [[ "$out" == *succeeded* || "$out" == *refused* ]] || dead+=("$host($prefix.$num)")
done <<<"$HOSTS"
if [[ ${#dead[@]} -eq 0 ]]; then
  echo "  OK: 모든 호스트가 fw 에 직접 응답함"
else
  echo "  FAIL: fw 에서 응답 없음: ${dead[*]}. 호스트의 br_netfilter·방화벽 규칙을 확인할 것 (sysctl net.bridge.bridge-nf-call-iptables)"
  fail=1
fi

reset_fw ""
exit $fail
