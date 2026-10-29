# 3주차 검증기 실험 프로토콜 — 팀 결정 전 제안

기준: `docs/weekly-plan.md`의 양경찬(@SoftwareDevJake) 3주차 세 항목. 이 문서는 실험 설계 초안이며 랩 실측·팀 합의·머지 결과가 아닙니다. 2주차 입력 설계 PR #37과 구분합니다. 변경할 입력과 판단은 첫 실험 결과를 보기 **전에** 동결해야 합니다.

## 질문과 경계

1. 같은 후보에서 정적 단독(`validator/validate.py`: `ok`, `risk`)과 정적+격리 랩 적용/프로브(`pipeline/run.sh`)가 각각 잡는 오류를 분리합니다. `ok=false`는 반려, `ok=true/risk=high`는 승인 요청, 도구 실행 실패는 `aborted`, 실제 정상 차단 또는 공격 통과를 관측한 롤백은 동적 실패입니다. 정적 반려·승인 거부에는 동적 성공/실패를 대입하지 않습니다.
2. B는 같은 동결된 1차 생성 후보 전부를 사람이 검토한다고 가정한 **후보 파일 건수 기준선**, C는 같은 후보를 정적으로 전부 검사한 뒤 유효하고 `risk=high`인 후보 파일 건수입니다. 모든 후보의 정적 결과가 있어야 `(B-C)/B`를 계산하며 B=0이면 N/A입니다. 시간·사람의 판단 정확도·룰 개수 감소율을 측정했다고 쓰지 않습니다. 후속 라운드 후보는 별도 표입니다.
3. 3주차 충돌 검사 완료 기준(`validate.py` TODO 해소)과 이번 `validator/compare.py`의 독립 오프라인 비교는 다릅니다. 후자는 IPv4 TCP/UDP/ICMP **초기 패킷** first-match/default-drop의 허용·차단 영역 셀과 예시만 보여 줍니다. IR에 없는 state 모드는 두 입력 모두 명시해야 하며 원본 후보 파일이면 `common.ir.stateful_for(path)`를 사용합니다. 달라지면 `indeterminate`입니다. 패킷 수·실 트래픽·IPv6/기타 프로토콜·conntrack·현재 적용 룰셋의 증거가 아닙니다. `validate.py`의 `ok/risk`, 배포·승인 경로에는 연결하지 않습니다.

## 입력 동결표(실행 전 작성)

| 필드 | 기록·검증 |
| --- | --- |
| 저장소 | 실행 커밋·깨끗한 작업트리, 시나리오·gold·mutation·generated 상대경로/각 SHA-256·사전 오류/동등/불명확 라벨·예상 실패 프로브 |
| 생성 | 모델·digest·Ollama 버전·프롬프트 버전·temperature·seed·round. generated의 `.meta.json` 존재·형식 검사 |
| 모드 | 원본 후보 경로, `stateful_for(path)` 결과, `deploy.json.stateful` 실제 기록. 이름을 바꿔 `candidate.json`으로 옮긴 파일로 상태를 추론하지 않음 |
| 환경 | VM/Podman/격리 10.10.x.x 경로·프로브/호스트/서비스·watch 시간·승인 정책·기준 룰셋의 복원 책임자 |

`scenarios/req-*.json`의 gold와 `mutations/`의 목록은 main과 열린 PR마다 다르므로 태그/커밋 고정 전에 혼합하지 않습니다. `generated/` 파일은 생성 시도(seed별 파일)와 동일 내용의 중복(SHA-256)을 구분합니다. `mutations/README.md` 가설은 실제 결과를 대체하지 않습니다. 시나리오와 랩 호스트/프로브가 오류를 관측할 수 없는 경우는 별도 목록으로 보존합니다.

## 실행 순서 제안(실행하지 않음)

1. `python -m unittest discover -s tests -t .`, `tests.test_scenarios`, 정적·생성기 mock 검사 후 랩 담당자가 `lab/check-path.sh`와 대상 서비스·정답 프로브·비상 원복을 확인합니다. nft 문법 mock 테스트는 실제 fw 컨테이너 시험이 아닙니다.
2. gold를 후보 종류 `gold`, `--reps 3 --watch 10 --approve no`로 먼저 검증합니다. 각 시나리오 3회 전부 `applied`, `rolled_back=0`, `aborted=0`이어야 후속 비교를 개시합니다. 실패 시 해당 시나리오 결과는 하네스 미확인으로 따로 남깁니다.
3. 같은 고정 mutation은 `--candidates mutations --reps 3`, 생성 후보 seed 1/2/3은 각 서로 다른 파일이므로 `--candidates generated --reps 1`로 **별도 배치**합니다. `batch.py`는 한 호출의 모든 후보에 같은 `--reps`를 적용합니다. `--watch 10`은 실제 10초 종료 보장이 아니며 기본 감시 60초와 동일시하지 않습니다. 이 문서 작성 과정에서 실험용 배치를 실행하지 않았습니다.
4. `--approve no`의 high는 `rejected_approval`이고 동적 평가에 포함하지 않습니다. high를 격리 랩에서 시험할지는 팀 승인·허용 후보 선택·강제 종료 후 수동 복원 계획이 있어야 합니다. `--approve yes`는 배치 **전체** high에 적용되므로 임의로 켜지 않습니다. 운영망/실서비스는 시험하지 않습니다.
5. 각 실행의 manifest `(commit, scenario, candidate, rep, status, out, error, meta)`와 해당 `validation.json`, `deploy.json`, `run.log`, CSV를 연결합니다. `applied/rolled_back/rejected_validation/rejected_approval/aborted`를 섞지 않으며 도구 실패·부분 프로브는 성공/차단으로 보정하지 않습니다. PR #38의 CSV `batch_id`·`rep`·`commit` 열은 main에 반영됐습니다. PR #39는 CSV `stateful` 열을 추가하는 별도 미병합 변경입니다. 후보·메타의 연결은 manifest로 대조합니다.
6. 배치 종료 뒤 승인된 기준 룰셋과 실제 nft snapshot, 경로/서비스를 대조합니다. `flush ruleset`은 직전 후보와 룰을 합치지 않지만 conntrack을 지우지는 않으며, 롤백은 배치 최초 기준 복원과 동일하지 않을 수 있습니다. 복원 실패/시스템 종료 때 자동 안전을 주장하지 않고 실험을 멈춥니다.

## 지표·제외와 빈 표

| 지표 | 분자/분모 및 제외 |
| --- | --- |
| 자동 반려/사람 게이트 | 사전 오류 라벨이 있고 정적 검사 완료된 후보 중 `ok=false` / 그 후보 수; `risk=high`는 별도 승인 게이트 수. 도구 실패는 미판정 |
| 동적 추가 탐지 | 사전 오류·정적 `ok=true`(일반 실험의 low)·gold 게이트 통과·프로브 관측 가능·반복 완결인 후보 중 *예상 오류 대응 프로브 실패가 관측된* 롤백 후보 / 동일 조건에서 시험 완료된 후보. state는 별도 상태 추적 표 |
| B/C 검토량 | 동일 1차 generated 집합 B와 정적 통과 high 집합 C. 도구 실패/불명확 라벨/후속 round는 사유별 별도 기재; 실제 사람 검토 시간 측정 없음 |
| 정상·공격·MTTR | 완료된 해당 프로브의 정상 통과/공격 차단 분모와 성공 롤백의 detect_s·mttr_s만. 정적 반려·승인 거부·aborted에 0%나 0초를 대입하지 않음 |

같은 고정 파일 3회 중 한 번이라도 `aborted`면 불완전, 서로 다른 결과면 불안정으로 표시합니다. 동등(`equivalent`), 프로브 누락·랩 미관측(`uncovered`/`missed`), state 보류 및 승인 거부는 이유별로 기록하되 제외 플래그는 중복 가능하므로 단순 합산하지 않습니다. 결과 표의 실측값은 지금 빈칸이며 분모 0은 N/A입니다.

## 10/26 PR #37 통합 담당 응답과 남은 결정

- @iamtaekjun 님은 PR #37 댓글에서 **replace 전후 비교 범위**와 동시 적용 모드 제외를 수용했습니다. deployer 영역(#29)에서 적용 IR·SHA-256·stateful·커밋을 `current`로 기록하고, 다음 적용 직전 실제 `nft list ruleset` 구조를 `to_nft(current)`와 비교하며 불일치·관리 밖 규칙을 중단시키겠다고 답했습니다. 아직 구현·통합 시험이 확인된 것은 아니므로 이 응답만으로 `validate.py` TODO를 해소하지 않습니다. 실제 구현 시 counter/handle 제외 규칙, 정확한 snapshot 정규화, `current`의 원자적 기록·신뢰 경계, 재조회 시점과 `stale_baseline`/`indeterminate` 전파를 입력 계약과 시험으로 확인해야 합니다.
- 정상 프로브 차단은 승인 가능한 high가 아닌 검증 실패/롤백으로 분류한다는 통합 담당 의견이 확인됐습니다. weekly-plan의 표시·프로브 실패 명세와 B의 사람 전수검토 실제 측정 여부는 팀 반영을 확인합니다.
- high 후보의 선택적 격리 시험·중단/복원 책임, generated round/반복, #39 CSV `stateful` 열의 반영 여부를 기록합니다. 승인 전 VM·Podman·네트워크 실험 없음.

본인 발표 슬라이드: 정적 검사/위험도와 반려 구분 → 오프라인 교체 비교(지원 범위와 state 반례) → B/C·정적/동적 빈 결과표 → 결정/잔여. 실제 결과 수치는 재시험·팀 판단 뒤에만 채웁니다.
