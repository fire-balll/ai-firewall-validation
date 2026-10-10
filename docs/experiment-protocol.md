# 검증기 평가 실험 프로토콜 (제안)

> 상태: **제안, 팀 합의 전.** 계획 문서 4장에서 양경찬 담당으로 적힌 "B vs C 및 정적 단독 vs 정적+동적 실험 프로토콜"의 초안이다. 아래 "합의 체크리스트"를 정한 뒤 확정판으로 바꾼다.

## 1. 계획 문서의 비교 정의

계획 문서 5장의 정의를 그대로 옮긴다.

| 비교 | 계획 문서 원문 | 이 프로토콜에서 측정하는 것 |
| --- | --- | --- |
| 정적 단독 vs 정적+동적 (핵심 분석) | "같은 룰셋(LLM 생성분 + 오류 주입분)에 정적 검증 단독과 정적+동적 검증을 각각 돌린다. 동적 검증만 잡아낸 오류의 비율과 유형을 보고한다." | 오류 주입 룰셋별로 정적이 잡았는지, 동적이 잡았는지. 유형별 동적 추가 탐지율 |
| 방식 B vs 방식 C | "B(AI 생성 + 사람 전수 검토)와 C(AI 생성 + 자동 검증, 고위험만 사람 검토)". 지표 표: "사람 검토 룰 수 — B는 전체, C는 고위험 판정 수" | C에서 사람에게 올라가는 수, C가 놓친 오류 수. B는 계획 문서대로 "전체"를 기준값으로 둔다 |

방식 A(사람 직접 작성)는 계획 문서대로 시간이 남을 때만 다룬다.

## 2. 실험 단위와 입력 집합

- **실험 단위:** (시나리오, 후보 룰셋, 반복 번호) 한 번의 `pipeline/run.sh` 실행. `pipeline/batch.py`가 이 단위로 manifest에 한 줄씩 남긴다.
- **입력 집합**

| 집합 | 출처 | 현재 상태 | 역할 |
| --- | --- | --- | --- |
| 정답 룰셋 | `scenarios/req-*.json`의 `gold` | 10개 | 오탐 측정(정답인데 걸리는 경우) |
| 오류 주입 룰셋 | `mutations/<시나리오>-<유형>-<번호>.json` | 16개, 파일당 오류 1개 | 탐지 측정 |
| LLM 생성 룰셋 | `generator/generate.py` | 미구현(`--mock`만 동작) | 생성기 구현 후 추가 |

- **mutation과 정답 판정의 분리:** 오류 주입 룰셋이 "틀렸다"는 근거는 정답 룰셋과 다른 판정을 내는 프로브가 있다는 것이다. 이 판정은 시나리오의 `probes`와 `expect`가 정한다. validator는 정답을 보지 않는다. 오류 유형 목록과 "정적으로 잡히나(가설)" 열은 `mutations/README.md`가 기준이고, `AGENTS.md`에 따라 첫 결과 커밋 뒤에는 바꾸지 않는다.
- **분모에서 빼는 것:** `scenarios/coverage.py`가 `equivalent`(정답과 같은 정책) 또는 `missed`(랩 프로브로 원리상 드러나지 않음)로 분류하는 변형은 동적 추가 탐지율의 분모에서 빼고 따로 보고한다(`AGENTS.md`). 현재 16개 파일은 `mutations/README.md` 기준으로 모두 시뮬레이터에서 실패 프로브가 있다. 랩에서도 그런지는 `pipeline/crosscheck.py`로 확인한다.

## 3. 판정 규칙

"잡힘"의 정의는 `mutations/README.md`를 따른다.

| 조건 | 잡힘으로 보는 결과 | 근거 필드 |
| --- | --- | --- |
| 정적 단독 | `ok=false` 또는 `risk=high` | 실행별 `validation.json`의 `ok`·`risk`. R1(`--approve no`)에서는 manifest `status` = `rejected_validation` / `rejected_approval`과 같다 |
| 동적 | 감시 기간 중 프로브 실패로 롤백 | manifest `status` = `rolled_back` |
| 정적+동적 | 위 둘 중 하나 | |
| 놓침 | 적용되고 롤백 없음 | `status` = `applied` |
| 실행 실패 | 결과로 세지 않음 | `status` = `aborted`. 시나리오·후보별 수를 결과와 함께 보고 |

현재 파이프라인에서 동적 검증은 별도 단계가 아니라 `deployer/deploy.py`의 적용 후 감시 프로브다. 계획 문서 3-1의 순서(정적 → 동적 → 위험도 판정 → 적용)와 다르므로, 감시 프로브를 "동적 검증"으로 볼지 팀이 정해야 한다(체크리스트 3).

## 4. 실행 조건

`pipeline/run.sh`는 검증 결과를 두 단계로 거른다. `ok=false`면 `APPROVE` 값과 관계없이 종료 코드 3(`rejected_validation`)으로 끝나 적용되지 않는다. `ok=true`이고 `risk=high`일 때만 `APPROVE`를 보며, `no`면 종료 코드 4(`rejected_approval`), `yes`면 적용·감시로 넘어간다. validator는 `ok=false`일 때 `risk`를 `null`로 내므로 두 반려는 겹치지 않는다.

그래서 실행 조건별로 동적 결과(적용 후 감시 프로브)가 생기는 범위는 다음과 같다.

| 정적 결과 | R1 (`--approve no`) | R2 (`--approve yes`) |
| --- | --- | --- |
| `ok=false` | 동적 미관측 (`rejected_validation`) | 동적 미관측 (`rejected_validation`) |
| `ok=true`, `risk=high` | 동적 미관측 (`rejected_approval`) | 랩 적용 → `applied` / `rolled_back` |
| `ok=true`, `risk=low` | 랩 적용 → `applied` / `rolled_back` | 랩 적용 (R1과 같은 조건) |

배치를 두 번 돌리는 방식을 제안한다.

| 실행 | 명령 | 얻는 것 |
| --- | --- | --- |
| R1 (방식 C 운영 조건) | `batch.py --candidates all --approve no --reps N --watch W` | C에서 승인 요청이 올라가는 수, `risk=low` 통과분의 동적 결과 → 동적 추가 탐지율 |
| R2 (고위험 후보 랩 승인) | `batch.py --candidates all --approve yes --reps N --watch W` | `ok=true`·`risk=high` 후보의 동적 결과. R1과 합쳐 `ok=true` 후보 안에서 위험도(high/low) × 동적(롤백/적용) 2×2 표 |

- 2×2 표는 `ok=true` 후보로 한정된다. `ok=false` 후보는 두 실행 모두에서 적용되지 않으므로 동적 결과를 "미관측"으로 표기하고 동적 탐지·놓침 어느 쪽에도 세지 않는다. 정적 단독 vs 정적+동적 비교에서 같은 룰셋의 정적·동적 결과를 나란히 볼 수 있는 것도 이 범위뿐이다.
- `batch.py`에는 위험도로 후보를 고르는 옵션이 없어 R2도 같은 후보 전체를 돌린다. R1과 결과가 달라지는 실행은 `ok=true`·`risk=high`뿐이고, `risk=low` 실행은 같은 조건의 반복이 된다. R2의 manifest `status`로는 고위험 실행과 저위험 실행이 구분되지 않으므로 실행별 `validation.json`의 `risk`(또는 CSV `approved=yes`)로 가른다.
- `mutations/README.md` 파일 목록 기록(랩 실측 아님)으로는 16개 모두 `ok=true`이고, `risk=high`는 req-002-port-any-01, req-004-action-01, req-005-widen-01, req-008-proto-01, req-010-extra-01 5개다. R2에서 랩 승인 대상이 되는 오류 주입 룰셋은 이 5개이며, 정답 룰셋도 실행 결과 `risk=high`면 포함된다. 실제 분류는 `run.sh`가 `--nft-check`로 낸 각 실행의 `validation.json`을 기준으로 한다.

R2는 고위험 룰셋을 격리 랩에 실제로 적용한다. `--internal` 네트워크, 10.10.x.x 대상, hping3 속도 제한 규칙은 그대로 지킨다.

**고정할 것:** 실행 커밋(작업 트리 깨끗한 상태, `batch.py`가 확인), `--watch`·프로브 간격, 시나리오·mutation 파일, `mutations/README.md` 유형표. LLM 생성분을 넣을 때는 모델명·temperature·프롬프트 버전도 고정하고 기록한다(계획 문서 5장).

## 5. 측정 지표

| 지표 | 계획 문서 정의 | 지금 파이프라인 | 계산 |
| --- | --- | --- | --- |
| 정상 트래픽 통과율 | 허용돼야 할 통신 중 통과 비율 | **구현됨** (`normal_pass_rate`) | 마지막 프로브 기준 |
| 공격 트래픽 차단율 | 막혀야 할 통신 중 차단 비율 | **구현됨** (`attack_block_rate`) | 마지막 프로브 기준 |
| 롤백 MTTR | 이상 발생부터 원복까지 | **구현됨** (`detect_s`, `mttr_s`) | 롤백된 실행만 |
| 사람 검토 수 | B는 전체, C는 고위험 판정 수 | 룰셋 단위 `risk`만 있음 | 실행별 `validation.json`이 `ok=true`·`risk=high`인 수(= `run.sh`가 승인을 요청하는 수). R1에서는 `rejected_approval` 수와 같아야 하고, 차이가 나면 승인 거부 뒤 기록 단계에서 `aborted`된 실행이다. R2에서는 `rejected_approval`이 0이므로 이 방식으로만 센다. 반복 N회는 룰셋 단위로 묶고, 정답 룰셋 몫(오탐 검토)은 따로 적는다. 룰 단위로 셀지는 체크리스트 4 |
| 위험 룰 탐지율 | 오류 주입 룰 중 검증 전체가 잡은 비율 | manifest `status`로 계산 가능, 집계 코드 없음 | (정적 또는 동적 잡힘) ÷ 분모 |
| 동적 추가 탐지율 | 정적 통과 오류 중 동적만 잡은 비율 | manifest로 계산 가능, `evaluate.py`에는 TODO | R1에서 (`rolled_back`) ÷ (정적 통과 오류) |
| 오탐 | (계획 문서 표에 없음, 제안) | manifest로 계산 가능 | 정답 룰셋 중 고위험·반려·롤백된 수 |
| 의미 일치율 | AI 룰셋과 정답의 allow/drop 일치 비율 | 미구현 (`evaluate.py` TODO) | LLM 생성분이 생긴 뒤 |

검증 시간은 현재 어느 모듈도 기록하지 않으므로 지표에서 뺐다. 필요하면 별도로 추가한다.

## 6. 반복과 기록

- **반복:** 계획 문서는 LLM 출력의 변동 때문에 "시나리오당 최소 3회"를 요구한다. 오류 주입·정답 룰셋은 입력이 고정이라 반복은 랩·프로브의 안정성을 보는 의미다. 같은 횟수로 맞출지 정한다(체크리스트 5).
- **기록 위치:** `eval/results/results.csv`(실행당 한 줄)와 `eval/results/batch-<시각>.json`(커밋 해시, 인자, 실행별 `status`·`error`)을 함께 커밋한다.
- **현재 빈칸:** `batch.py`가 `BATCH_ID`·`REP`·`COMMIT` 환경변수를 넘기지만 `evaluate.py`는 아직 CSV에 쓰지 않는다. 후보는 `generator` 열(`mock` 또는 `file:<파일명>`)로만 구분된다. 모델명·temperature·프롬프트 버전 열도 없다. 집계는 우선 manifest 기준으로 하고, CSV 열 추가는 eval·pipeline 담당과 따로 정한다.
- **보고 형식:** 유형별로 (파일 수, 정적 잡힘(`ok=false` / `risk=high` 구분), 동적 잡힘, 동적만 잡힘, 놓침, 동적 미관측, aborted, 분모 제외)를 한 표로 내고, `mutations/README.md`의 가설 열과 맞음/틀림을 나란히 적는다.

## 7. 구현 상태 구분

| 항목 | 상태 |
| --- | --- |
| 정적 검증(스키마·포트·`nft -c`·범위 기준·이상 4종) | 구현됨 (`validator/`, PR #15 병합 대기) |
| 적용·감시·롤백, MTTR 기록 | 구현됨 (`deployer/`) |
| 배치 실행·manifest·aborted 기록 | 구현됨 (`pipeline/batch.py`) |
| 시뮬레이터 기준 변형 커버리지 | 구현됨 (`scenarios/coverage.py`) |
| 동적 추가 탐지율·위험 룰 탐지율 집계 | 계산 규칙만 이 문서에서 제안 |
| LLM 생성기, 의미 일치율, 기존 룰셋과의 충돌 검사 | 미구현 |
| 고위험 기준, R1/R2 방식, 반복 횟수 | 팀 결정 필요 |

## 8. 합의 체크리스트

1. [ ] **고위험 기준 확정** (계획 문서 2-2 "초안, 양경찬이 확정"): /16 경계(현재 /16은 해당 없음), `1-65535` 같은 거의 전체 포트 범위 처리, 이상 4종의 위험도 배분(shadowing high, correlation은 앞 룰이 accept일 때 high 등).
2. [ ] **"잡힘" 정의**: `risk=high`를 정적 탐지로 셀지(현재 `mutations/README.md` 정의), `ok=false`만 셀지.
3. [ ] **동적 검증의 위치**: 감시 프로브를 동적 검증으로 볼지, 적용 전 별도 동적 단계를 만들지. "정상 트래픽이 하나라도 차단되면 고위험"(2-2) 기준을 어디에 둘지.
4. [ ] **사람 검토 수의 단위**: 계획 문서는 "룰 수", validator 출력은 룰셋 단위 `risk`. 룰 단위로 세려면 `reasons`·`anomalies`에서 룰 id를 뽑는 규칙이 필요하다.
5. [ ] **반복 횟수와 감시 시간**: 오류 주입·정답 룰셋의 반복 수 N, 실험용 `--watch` 값.
6. [ ] **R2(고위험 후보 랩 승인) 실행 여부**: `ok=true`·`risk=high` 룰셋을 격리 랩에 적용하는 데 동의하는지.
7. [ ] **방식 B의 측정 범위**: "사람 검토 수 = 전체"만 쓸지, 팀원이 실제로 검토하는 소규모 비교를 넣을지(계획 문서상 참가자는 팀원뿐).
8. [ ] **state 유형(응답 트래픽 누락)**: 현재 IR로 표현할 수 없다(`mutations/README.md`). 이번 실험 범위에서 뺄지, 변환기 옵션을 만들지.
9. [ ] **데이터 동결 시점**: 시나리오·mutation·유형표를 고정하는 커밋 또는 태그.
10. [ ] **이 문서의 위치와 리뷰어**: `docs/experiment-protocol.md`, 리뷰어 전원.
