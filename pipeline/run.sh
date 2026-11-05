#!/usr/bin/env bash
# 최소 파이프라인: 생성 -> 정적 검증 -> 위험도 판정 -> (승인) -> 적용·감시·롤백 -> 기록
#   ./pipeline/run.sh scenarios/req-001.json
#   WATCH=30 GENERATOR=mock ./pipeline/run.sh scenarios/req-001.json
#   CANDIDATE=mutations/req-001-port-01.json ./pipeline/run.sh scenarios/req-001.json
#     생성기를 건너뛰고 주어진 룰셋 파일을 후보로 쓴다 (오류 주입 실험용)
#   APPROVE=yes|no   고위험 룰 승인 여부를 묻지 않고 정한다 (배치 실행용, 기본 ask)
#   OUT_DIR=경로      산출물 디렉터리 (기본 out/<시나리오>-<시각>)
#
# 종료 코드: 0 적용 완료, 3 검증 실패로 반려, 4 승인 거부, 1 실행 실패(기록 안 함)
set -Eeuo pipefail
# 예상하지 못한 하위 명령 실패는 그 종료 코드(3·4 일 수도 있음)가 아니라 항상 1(실행 실패)로 끝낸다.
# -E 가 있어야 함수(record 등) 안의 실패에도 trap 이 걸린다
trap 'exit 1' ERR
cd "$(dirname "$0")/.."

SCENARIO=${1:?시나리오 파일을 지정할 것}
CANDIDATE=${CANDIDATE:-}
WATCH=${WATCH:-60}
APPROVE=${APPROVE:-ask}
NAME=$(basename "$SCENARIO" .json)
OUT=${OUT_DIR:-out/$NAME-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"

if [[ -n "$CANDIDATE" ]]; then
  [[ -f "$CANDIDATE" ]] || { echo "CANDIDATE 파일이 없음: $CANDIDATE" >&2; exit 1; }
  # 복사 전에 원본 이름의 모드를 보존한다. 검사와 적용은 같은 값을 소비한다.
  mode=$(python3 -c 'import sys; from common.ir import stateful_for; print("stateful" if stateful_for(sys.argv[1]) else "stateless")' "$CANDIDATE")
  GENERATOR=${GENERATOR:-file:$(basename "$CANDIDATE" .json)}
  cp "$CANDIDATE" "$OUT/candidate.json"
else
  mode=stateful
  GENERATOR=${GENERATOR:-mock}
  gen_args=(--scenario "$SCENARIO")
  [[ "$GENERATOR" == mock ]] && gen_args+=(--mock)
  python3 generator/generate.py "${gen_args[@]}" > "$OUT/candidate.json"
fi

deploy_args=()
compare_args=()
case "${CURRENT_COMPARE:-no}" in
  no) [[ -z "${FW_MANAGED_STORE:-}" ]] || { echo "managed 호스트에서 레거시 적용 금지" >&2; exit 1; } ;;
  yes)
    [[ -n "${FW_MANAGED_STORE:-}" ]] || { echo "FW_MANAGED_STORE 미설정" >&2; exit 1; }
    compare_args+=(--compare-current) ;;
  *) echo "CURRENT_COMPARE는 yes/no만 허용" >&2; exit 1 ;;
esac
case "$mode" in
  stateful) validate_mode=yes ;;
  stateless) validate_mode=no; deploy_args+=(--stateless) ;;
  *) echo "상태 추적 판단 실패: '$mode'" >&2; exit 1 ;;
esac
python3 validator/validate.py "$OUT/candidate.json" --nft-check --stateful "$validate_mode" "${compare_args[@]}" > "$OUT/validation.json"
ok=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ok"])' "$OUT/validation.json")
risk=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["risk"])' "$OUT/validation.json")

record() { python3 eval/evaluate.py --scenario "$NAME" --scenario-file "$SCENARIO" --generator "$GENERATOR" \
             --candidate "$OUT/candidate.json" --validation "$OUT/validation.json" "$@"; }

if [[ "${CURRENT_COMPARE:-no}" == yes && "$ok" == True ]]; then
  # Native Windows python writes CRLF; strip CR before Bash's read/regex checks.
  read -r comparison candidate_sha current_sha policy_changed < <(python3 -c 'import hashlib,json,sys; v=json.load(open(sys.argv[1])); c=v.get("comparison",{}); sha=hashlib.sha256(open(sys.argv[2],"rb").read()).hexdigest(); print(c.get("status",""),v.get("candidate_sha256",""),c.get("baseline_snapshot_token",""),c.get("counts",{}).get("allow_to_block",0)+c.get("counts",{}).get("block_to_allow",0) if sha==v.get("candidate_sha256") else "changed")' "$OUT/validation.json" "$OUT/candidate.json" | tr -d '\r')
  [[ "$comparison" == offline_only ]] || { echo "current 비교 결과 없음" >&2; exit 1; }
  [[ "$candidate_sha" =~ ^[0-9a-f]{64}$ && "$current_sha" =~ ^[0-9a-f]{64}$ && "$policy_changed" =~ ^[0-9]+$ ]] || { echo "current/후보 증거 불완전 또는 후보 변경" >&2; exit 1; }
fi
if [[ "$ok" != True ]]; then
  echo "검증 실패: 적용하지 않음 ($OUT/validation.json)"
  record
  exit 3
fi

# 비교 결과는 적용 승인이 아니다. 아래 deployer가 자체 잠금에서 다시 검증한다.

approved=""
if [[ "$risk" == high ]]; then
  echo "고위험 룰:"; python3 -c 'import json,sys; [print(" -", r) for r in json.load(open(sys.argv[1]))["reasons"]]' "$OUT/validation.json"
  case "$APPROVE" in
    yes) ans=y ;;
    no)  ans=n ;;
    *)   read -r -p "적용을 승인하나? [y/N] " ans ;;
  esac
  if [[ "$ans" != y ]]; then
    echo "승인 거부: 적용하지 않음"
    record --approved no
    exit 4
  fi
  approved=yes
fi

if [[ "${CURRENT_COMPARE:-no}" == yes && "$policy_changed" != 0 ]]; then
  echo "기존 정책 변경 영역 $policy_changed, 후보 SHA $candidate_sha, current SHA $current_sha"
  case "$APPROVE" in
    yes) ans=y ;;
    no) ans=n ;;
    *) read -r -p "위 정책 변경 적용을 승인하나? [y/N] " ans ;;
  esac
  if [[ "$ans" != y ]]; then
    echo "정책 변경 승인 거부: 적용하지 않음" >&2
    exit 4
  fi
  deploy_args+=(--approved-replacement)
fi

# 위에서 보존한 원본 모드로 검사와 동일하게 적용한다.
if [[ "${CURRENT_COMPARE:-no}" == yes ]]; then
  deploy_args+=(--managed-store "$FW_MANAGED_STORE" --expected-sha256 "$candidate_sha" --expected-current "$current_sha")
  [[ "$approved" == yes ]] && deploy_args+=(--approved-high)
fi
if ! python3 deployer/deploy.py "$OUT/candidate.json" --scenario "$SCENARIO" --watch "$WATCH" "${deploy_args[@]+"${deploy_args[@]}"}" > "$OUT/deploy.json"; then
  # 실행 실패는 실험 결과가 아니므로 CSV 에 기록하지 않는다
  echo "적용 중 실행 실패: 상태 미확정, managed intent/복구 확인 필요 ($OUT/deploy.json)" >&2
  exit 1
fi
record --deploy "$OUT/deploy.json" --approved "$approved"
echo "산출물: $OUT"
