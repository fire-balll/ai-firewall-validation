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
  GENERATOR=${GENERATOR:-file:$(basename "$CANDIDATE" .json)}
  cp "$CANDIDATE" "$OUT/candidate.json"
else
  GENERATOR=${GENERATOR:-mock}
  gen_args=(--scenario "$SCENARIO")
  [[ "$GENERATOR" == mock ]] && gen_args+=(--mock)
  python3 generator/generate.py "${gen_args[@]}" > "$OUT/candidate.json"
fi

python3 validator/validate.py "$OUT/candidate.json" --nft-check > "$OUT/validation.json"
ok=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ok"])' "$OUT/validation.json")
risk=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["risk"])' "$OUT/validation.json")

record() { python3 eval/evaluate.py --scenario "$NAME" --generator "$GENERATOR" \
             --validation "$OUT/validation.json" "$@"; }

if [[ "$ok" != True ]]; then
  echo "검증 실패: 적용하지 않음 ($OUT/validation.json)"
  record
  exit 3
fi

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

if ! python3 deployer/deploy.py "$OUT/candidate.json" --scenario "$SCENARIO" --watch "$WATCH" > "$OUT/deploy.json"; then
  # 실행 실패는 실험 결과가 아니므로 CSV 에 기록하지 않는다
  echo "적용 중 실행 실패: 원복 후 중단 ($OUT/deploy.json)" >&2
  exit 1
fi
record --deploy "$OUT/deploy.json" --approved "$approved"
echo "산출물: $OUT"
