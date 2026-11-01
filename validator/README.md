# validator

정적 검증 + 위험도 판정. (담당: 양경찬)

```
validate.py candidate.json [--nft-check] [--stateful auto|yes|no] [--compare-current]
  -> {"ok": bool, "errors": [...], "risk": "low"|"high"|null, "reasons": [...], "anomalies": [...]}
```

| 단계 | 실패하면 | 비고 |
| --- | --- | --- |
| 0. JSON 읽기 | `ok=false` | JSON 문법·인코딩 오류. 파일이 없으면 결과가 아니라 실행 실패이므로 예외로 멈춘다 |
| 1. 스키마 (`common/ir.py`) | `ok=false` | CIDR 호스트 비트도 검사. 최상위가 배열이거나 `rules` 항목이 객체가 아니어도 `ok=false` |
| 2. 포트 값 | `ok=false` | 스키마 정규식이 통과시키는 `70000`, `9000-8000`, 앞자리 0(`080`)을 막는다 |
| 3. `nft -c` (`--nft-check`) | `ok=false` (nft 종료코드 1) | fw 컨테이너 필요(`PODMAN`, `FW_CONTAINER` 설정은 `common/lab.py` 와 같다). 컨테이너 안에서 `sh -c 'nft -c -f -; echo "__validator_nft_rc=$?"'` 를 실행하고, stdout 마지막 줄의 이 **실행 완료 마커**로 nft 종료코드를 읽는다. 마커가 없거나(sudo·podman 실패, 시간 초과 30초) nft 종료코드가 1 이 아니면(nft 없음 127, 강제 종료 등) **도구 고장**이다: 결과 JSON 없이 종료코드 2. 룰셋은 UTF-8 bytes 로 넘긴다(text 모드면 Windows 에서 줄 끝이 `\r\n` 으로 바뀌어 nft 가 문법 오류로 본다) |
| 4. 범위 기준 (문서 2-2) | `risk=high` | /16 보다 넓은 accept(/16 은 해당 없음), 모든 포트 accept(`any`, `0-65535`), 모든 프로토콜 accept |
| 5. 룰 간 이상 4종 | 유형·방향에 따라 `risk=high` | 아래 표 |

`reasons` 에는 `risk=high` 를 만든 이유만 들어간다(파이프라인이 사람에게 보여 주는 목록). `anomalies` 에는 참고용(`risk: low`)까지 모든 이상이 `{type, rules: [앞, 뒤], risk, detail}` 로 들어간다. `ok=false` 는 **후보 룰셋이 틀렸을 때만** 낸다(JSON·입력 구조·스키마·포트·nft 문법). 검사 도구나 분석기가 고장 나면 후보를 반려한 것처럼 기록하지 않고 결과 없이 비0 종료한다. 검사하지 못한 룰셋은 통과도 반려도 아니며, pipeline 은 하위 명령 실패로 보고 그 실행을 기록하지 않는다(PR #15 리뷰 반영).

| 실패 | 종료 | stdout |
| --- | --- | --- |
| 후보 오류(JSON·구조·스키마·포트·마커의 nft 종료코드 1) | 0 | `ok=false` 결과 |
| 도구 고장(sudo·podman 실패·시간 초과로 마커 없음, 마커의 nft 종료코드 1 이외) | 2 | 없음 (stderr 에 사유) |
| 분석기 내부 예외(4·5단계) | 1 (Python 예외) | 없음 |
| 입력 파일 없음 | 1 (Python 예외) | 없음 |

podman 종료코드만 보지 않는 이유: 기본 `PODMAN="sudo podman"` 에서 sudo 가 비밀번호를 요구하거나 podman 이 일반 오류를 내면 종료코드가 nft 문법 오류와 같은 1 이다. 마커는 컨테이너 안에서 nft 가 끝난 뒤에만 찍히므로, 마커가 있을 때만 nft 의 판정으로 본다. `pipeline/run.sh` 는 `set -e` 라 validate 가 비0 으로 끝나면 `record` 전에 멈추므로, 도구 고장은 CSV 에 기록되지 않는다.

## 룰 간 이상 4종

순서는 `to_nft` 와 같다: priority 오름차순(같으면 id 순), first-match, 기본 정책 drop. "앞"은 먼저 매칭되는 룰이다.

| 유형 | 조건 (앞 X, 뒤 Y) | risk | 이유 |
| --- | --- | --- | --- |
| shadowing | Y ⊆ X, 동작 다름 | high | Y 는 절대 매칭되지 않는다. 가려진 룰이 drop 이면 과허용, accept 이면 과차단. 어느 쪽이든 의도한 룰이 죽어 있다 |
| redundancy | Y ⊆ X, 동작 같음 / 또는 X ⊆ Y, 동작 같음, 사이에 X 와 겹치면서 동작이 다른 룰 없음 | low | 지워도 판정이 같다. 보안 위험은 아니고 정리 대상 |
| correlation | 일부만 겹침(포함 관계 아님), 동작 다름 | 앞이 accept 면 high, 앞이 drop 이면 low | 겹친 부분은 앞 룰을 따른다. accept 가 이기면 막으려던 트래픽이 지나갈 수 있다(과허용). drop 이 이기면 차단 쪽이므로 fail-closed 원칙상 사람 검토까지 올리지 않고, 과차단 여부는 동적 검증에 맡긴다 |
| generalization | X ⊂ Y, 동작 다름 | low | "좁은 예외 → 넓은 기본" 은 정상 패턴이다(예: 침해 기기만 drop 후 IoT 망 accept). 무조건 반려하지 않고 참고로 남긴다. 예외 룰이 accept 인 경우 그 범위는 4단계 기준으로 따로 걸린다 |

예시 (req-004 의 두 룰):

| 순서 | 룰 | 판정 |
| --- | --- | --- |
| 정답 | drop 10.10.10.66/32→any any (100), accept 10.10.10.0/24→10.10.30.10/32 tcp 8080 (110) | correlation, low |
| order 오류 | 위 두 룰의 priority 를 맞바꿈 | correlation, **high** |
| 같은 포트로 좁힌 drop | accept 10.10.10.0/24→서버 tcp 8080 (100), drop 10.10.10.66/32→서버 tcp 8080 (110) | shadowing, **high** |

### 매칭 범위를 비교하는 방법

룰 하나의 매칭 범위를 프로토콜마다 (src 주소 구간) × (dst 주소 구간) × (포트 구간) 상자로 본다.

- `tcp`/`udp`: 해당 프로토콜 하나. `dport` 범위, `any` 는 0-65535.
- `icmp`: icmp 하나. 포트 없음.
- `any`: tcp·udp(전체 포트), icmp, 그 밖의 프로토콜. `to_nft` 가 proto any 에 프로토콜 조건을 붙이지 않으므로 모든 프로토콜이 매칭된다. 그래서 `any` 룰은 `icmp` 룰을 포함하지만, `icmp` 룰이 `any` 룰을 포함하지는 않는다.
- 주소 `any` 는 0.0.0.0/0.

A ⊆ B 는 A 의 모든 프로토콜이 B 에 있고 각 축의 구간이 B 안에 들어갈 때, 겹침은 공통 프로토콜 하나에서 세 축이 모두 겹칠 때다.

### 한계 (정적 검사로 판단하지 않는 것)

- 룰 두 개씩만 비교한다. 앞 룰 여러 개의 합집합이 뒤 룰을 덮는 경우는 shadowing 으로 잡지 않는다.
- 기본 정책 drop 과 겹치는 drop 룰(지워도 결과가 같은 drop)은 redundancy 로 세지 않는다.
- 응답 트래픽(`ct state`)은 IR 밖이라 보지 않는다(`mutations/README.md` 의 state 유형).
- 정답 룰셋과 비교하지 않으므로 port·range·swap·missing·narrow 오류는 여기서 잡히지 않는다. 동적 검증 몫이다.
- 기존(적용 중인) 룰셋 비교는 `validate_with_current` API로 연결한다. `--compare-current`는 `FW_MANAGED_STORE`의 POSIX 전용 보호 디렉터리(소유자·0700, 파일0600, 링크 금지)에서 단일 원자 기록의 IR 원바이트/SHA/state/commit/전체 nft digest를 읽는다. `nft -s list ruleset`을 전체 구조와 대조하고 두 번 조회한다. 임의 JSON verified 플래그나 기존 host 룰을 자동 채택하지 않는다. `deployer/bootstrap_current.py`는 기존 관리기록이 없는 경우에만 운영자가 검토한 IR과 실제 전체 nft 구조 일치 시 명시적으로 등록한다. Windows ACL은 미지원이라 안전 실패한다. 실제 nft 렌더 차이는 지원하지 않으며 실랩 검증 전 운영 적용 금지.
- `CURRENT_COMPARE=yes` pipeline은 후보 바이트 SHA와 current snapshot 토큰을 승인 내용에 묶어 deployer에 전달한다. deployer는 별도 협조 flock 안에서 비교→직전 snapshot 재조회→fsync intent/복구 원본→apply→구조 readback→probe→record fsync/finish 또는 rollback을 수행한다. policy_diff는 정적 high와 별도로 승인한다. 미완료 intent는 이후 적용을 차단하며 `deployer/recover_current.py --store ...`의 명시적 수동 복구 경로가 있다. 이 경로는 **합성 시험 후보**로서 nft 버전별 실제 출력, 같은 권한/외부 nft 작성자의 lock 준수, SIGKILL 뒤 자동 감시·복원, 컨테이너 중단 복구를 입증하지 못했다. 보호된 저장소 자체도 같은 uid의 임의 코드 실행은 막지 못한다. 실환경/운영 안전·3주차 전체 완료 판정이 아니다.
- `1-65535` 처럼 거의 전체인 포트 범위, 같은 id 를 가진 룰 여러 개, 빈 `rules` 는 아직 따로 판정하지 않는다(팀 합의 필요).

## 관리 current의 nft 검사 모드

`--stateful auto`는 원본 파일 경로의 `stateful_for()`를 따른다. `req-001-state-01.json`은 응답 추적 룰 없이 문법 검사한다. 이름을 바꾼 후보와 stdin은 `--stateful yes/no`를 명시한다. `- --nft-check`는 모드를 명시하지 않으면 결과 없이 종료코드 2로 끝난다. `pipeline/run.sh`는 복사 전 원본 CANDIDATE의 모드를 보존하고(생성 후보는 stateful), validator의 `--stateful yes/no`와 deployer의 `--stateless`에 같은 값을 전달한다. pipeline/deployer 수정은 담당 @iamtaekjun의 리뷰 대상이며 POSIX 격리 nft 실증·협조 잠금 운영계약 전까지 운영 적용을 승인하지 않는다.

`tests/test_pipeline_validator_mode.py`는 실제 bash 파이프라인과 validator/deployer CLI를 격리 복사본에서 실행한다. 생성 mock·파일 stateful·state mutation stateless의 nft 변환 일치, nft 실행 파일 부재 시 빈 validation/exit1/기록·적용 중단을 검사한다. nft 성공 응답·랩 snapshot/apply/probe·CSV 기록은 시험 대역이다. 실제 VM/nft·통신·롤백 실측을 대신하지 않는다. Windows checkout의 CRLF는 시험 복사본에서 LF로 정규화한다.

### 적용 중 정책 비교 API

`validate_with_current(candidate, candidate_stateful=bool, provider=...)`는 기존 정적 `ok/risk`와 별도로 `comparison`을 반환한다. provider는 실제 nft 구조·관리 밖 룰·기록 IR 연결을 검증한 `CurrentRules`(원바이트·SHA-256·stateful·commit·snapshot_token)를 읽고, 계산 뒤 다시 확인해야 한다. 검증 플래그 JSON이나 gold 파일은 provider 대신 사용할 수 없다. 없거나 오래된 증거·SHA 불일치·지원 범위/상한 초과는 ToolError로 중단한다. 비교 결과는 초기 패킷 정책 차이이며 배포 승인이나 conntrack 안전성 판정이 아니다. 적용 담당자는 적용 직전 자기 잠금 안에서 재검증해야 한다.

## 테스트

```bash
python3 -m unittest tests.test_validator -v
```

`nft -c` 는 `subprocess.run` 을 mock 으로 바꿔 호출 인자(stdin 이 `\r` 없는 bytes 인지 포함)와 결과 처리(통과, 문법 오류 메시지, 마커 없는 종료코드 1·125 등과 마커의 1 이외 값은 도구 고장 종료코드 2)만 시험한다. 실제 fw 컨테이너에서 마커가 찍히는지와 통과·실패는 랩에서 확인해야 한다.
