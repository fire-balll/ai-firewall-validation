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

reset_fw ""
exit $fail
