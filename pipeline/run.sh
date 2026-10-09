#!/usr/bin/env bash
# 최소 파이프라인: 생성 -> 정적 검증 -> 위험도 판정 -> (승인) -> 적용·감시·롤백 -> 기록
#   ./pipeline/run.sh scenarios/req-001.json
#   WATCH=30 GENERATOR=mock ./pipeline/run.sh scenarios/req-001.json
set -euo pipefail
cd "$(dirname "$0")/.."

SCENARIO=${1:?시나리오 파일을 지정할 것}
GENERATOR=${GENERATOR:-mock}
WATCH=${WATCH:-60}
NAME=$(basename "$SCENARIO" .json)
OUT=out/$NAME-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"

gen_args=(--scenario "$SCENARIO")
[[ "$GENERATOR" == mock ]] && gen_args+=(--mock)
python3 generator/generate.py "${gen_args[@]}" > "$OUT/candidate.json"

python3 validator/validate.py "$OUT/candidate.json" --nft-check > "$OUT/validation.json"
ok=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ok"])' "$OUT/validation.json")
risk=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["risk"])' "$OUT/validation.json")

record() { python3 eval/evaluate.py --scenario "$NAME" --generator "$GENERATOR" \
             --validation "$OUT/validation.json" "$@"; }

if [[ "$ok" != True ]]; then
  echo "검증 실패: 적용하지 않음 ($OUT/validation.json)"
  record
  exit 1
fi

approved=""
if [[ "$risk" == high ]]; then
  echo "고위험 룰:"; python3 -c 'import json,sys; [print(" -", r) for r in json.load(open(sys.argv[1]))["reasons"]]' "$OUT/validation.json"
  read -r -p "적용을 승인하나? [y/N] " ans
  if [[ "$ans" != y ]]; then
    echo "승인 거부: 적용하지 않음"
    record --approved no
    exit 1
  fi
  approved=yes
fi

python3 deployer/deploy.py "$OUT/candidate.json" --scenario "$SCENARIO" --watch "$WATCH" > "$OUT/deploy.json"
record --deploy "$OUT/deploy.json" --approved "$approved"
echo "산출물: $OUT"
