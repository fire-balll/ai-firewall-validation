# 정적 검토 대상 룰 수

`validator/offline_experiment.py`의 기존 후보 파일 건수와 별도로 `review_rule_count`를 출력합니다. #82의 사람 검토 룰 수 형식 문의에 대응하는 **정적 집계**이며, 사람이 실제로 검토했다거나 소요 시간이 줄었다는 측정이 아닙니다. 방화벽·프로버·deployer 동작은 변경하지 않습니다.

## 정의와 재현

이는 weekly-plan 5주차의 룰 수 요구에 대한 정적 보조 집계입니다. `docs/validator-week3-experiment-protocol.md` 2항의 파일 건수 기준선/룰 감소율 미측정 선언은 원 프로토콜 범위이며, 이 추가 배열 항목 집계가 그 프로토콜이나 사람 실측을 소급 변경하지 않습니다.

판정 함수와 pipeline 코드는 바꾸지 않습니다. 다만 이전 하네스가 JSON으로 보고할 수 있던 `rules` 비배열/누락 생성 후보는 이제 룰 수를 계수할 수 없어 전체 집계가 중단됩니다. 기존 지표까지 출력하지 않는 의도적 fail-closed 변경이며, 현행 75개 후보에서는 이 구조 오류가 없어 기존 판정/비교 출력이 같습니다.

- 라운드별로 분리하며, 동일 경로 후보는 한 번만 셉니다. SHA가 같은 서로 다른 생성 시도 파일은 각각 셉니다. 반복 배치 실행 수나 nft가 전개한 행 수가 아닙니다.
- B_files/B_rules: 정적 반려(`ok=false`)를 포함한 생성 후보 전체의 파일 수/IR `rules` 항목 수 합계입니다.
- C_files/C_rules: 같은 집합 중 `ok=true`이고 `risk=high`인 후보의 파일 수/IR 룰 수입니다. high는 실제 정책 오류라는 정답 라벨이 아닙니다.
- `candidate_files=B_files`이며 `rejected_files`는 `ok=false` 수입니다. 반려는 스키마뿐 아니라 포트 값 검사 등에서도 발생합니다. 반려분의 배열 항목도 B에 포함하며, 이는 유효한 nft 규칙 수가 아닙니다. JSON·파일·메타 읽기 실패나 생성 후보의 `rules`가 배열이 아니어서 집계할 수 없으면 전체 실행이 실패하며 결과 JSON을 내지 않습니다. 누락을 0룰로 채우거나 B에서 제외하지 않습니다.
- 룰 감소 비율은 `(B_rules-C_rules)/B_rules`, 분모가 0이면 null입니다. 기존 `review_file_count`의 파일 감소 비율과 혼용하지 않습니다.
- 원파일 `sha256`·`meta_sha256`는 각 record에, `source_commit`·`source_dirty`는 CLI JSON **최상위**에 있습니다. `measure()` 반환값이나 라운드별 객체에는 커밋 필드가 없습니다. dirty 출력의 커밋은 기반 HEAD이므로 패치 식별에는 별도 diff와 SHA도 보존해야 합니다. 배치 결과표와 연결할 때 후보 집합·라운드·실행 커밋을 별도로 맞춰야 합니다. 정적 전체 63개를 일부 시나리오 배치의 값으로 복사하지 않습니다.

```sh
python validator/offline_experiment.py > out/static-review.json
python -m unittest tests.test_review_workload tests.test_validator_offline_experiment
```

## 확인된 원후보 집합

기준 입력 커밋 `6cb95350f56f2d8cc7238ea6105ed68b4f04a1c8`의 후보를 위 정의로 집계한 결과입니다.

| 라운드 | 후보 파일 | 정적 반려 | B 파일→C 파일 | B 룰→C 룰 | 룰 감소 비율 |
|---|---:|---:|---:|---:|---:|
| 1 | 63 | 0 | 63→9 | 216→40 | 81.48% |
| 2 | 12 | 2 | 12→3 | 67→16 | 76.12% |

2라운드 반려 `req-017-qwen2.5-14b-s2-r2.json`·`req-017-qwen2.5-14b-s3-r2.json`의 배열 항목은 각각 6·7개입니다. 이를 뺀 10파일/54항목은 정적 통과 부분집합이지 B 전체가 아닙니다.

1라운드 **파일** 감소 비율 85.71%와 **룰** 감소 비율 81.48%는 서로 다릅니다. 2라운드는 1라운드 분모에 넣지 않습니다. 공격 차단율·위험 룰 탐지율·정상 통과율·MTTR·사람 시간은 이 출력으로 측정하지 않습니다.

## #82에 제안할 연결 형식

별도 `round,B_files,C_files,B_rules,C_rules,rejected_files,source_commit,source_dirty` 표를 제안합니다. JSON의 라운드별 건수와 최상위 provenance를 명시적으로 연결해야 합니다. CLI는 JSON만 출력하며 CSV export/배치 join은 구현하지 않습니다. `final.py`의 배치별 행에 합치려면 manifest에 실제 포함된 후보·라운드만 골라 같은 키로 일치 검증한 뒤 연결해야 합니다. 이 변경은 전체 파일 집계이며 배치별 join 구현은 포함하지 않습니다. `eval/` 담당 강윤서(@yxxunseo)에게 이 구분을 확인받기 전 임의로 `final.py`를 고치거나 CSV 열을 채우지 않습니다.
