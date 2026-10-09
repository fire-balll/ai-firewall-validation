# validator

정적 검증 + 위험도 판정. (담당: 양경찬)

```
validate.py candidate.json [--nft-check]
  -> {"ok": bool, "errors": [...], "risk": "low"|"high"|null, "reasons": [...], "anomalies": [...]}
```

| 단계 | 실패하면 | 비고 |
| --- | --- | --- |
| 0. JSON 읽기 | `ok=false` | JSON 문법·인코딩 오류. 파일이 없으면 결과가 아니라 실행 실패이므로 예외로 멈춘다 |
| 1. 스키마 (`common/ir.py`) | `ok=false` | CIDR 호스트 비트도 검사. 최상위가 배열이거나 `rules` 항목이 객체가 아니어도 `ok=false` |
| 2. 포트 값 | `ok=false` | 스키마 정규식이 통과시키는 `70000`, `9000-8000`, 앞자리 0(`080`)을 막는다 |
| 3. `nft -c` (`--nft-check`) | `ok=false` | fw 컨테이너 필요(`PODMAN`, `FW_CONTAINER` 설정은 `common/lab.py` 와 같다). podman 이 없거나 시간 초과(30초)여도 `ok=false`. 룰셋은 UTF-8 bytes 로 넘긴다(text 모드면 Windows 에서 줄 끝이 `\r\n` 으로 바뀌어 nft 가 문법 오류로 본다) |
| 4. 범위 기준 (문서 2-2) | `risk=high` | /16 보다 넓은 accept(/16 은 해당 없음), 모든 포트 accept(`any`, `0-65535`), 모든 프로토콜 accept |
| 5. 룰 간 이상 4종 | 유형·방향에 따라 `risk=high` | 아래 표 |

`reasons` 에는 `risk=high` 를 만든 이유만 들어간다(파이프라인이 사람에게 보여 주는 목록). `anomalies` 에는 참고용(`risk: low`)까지 모든 이상이 `{type, rules: [앞, 뒤], risk, detail}` 로 들어간다. 입력 구조가 어긋나거나 4·5단계 분석 중 예외가 나면 **fail-closed** 로 `ok=false` 를 낸다. 검사하지 못한 룰셋을 통과로 보지 않는다.

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
- 기존(적용 중인) 룰셋과의 충돌 검사는 아직 TODO.
- `1-65535` 처럼 거의 전체인 포트 범위, 같은 id 를 가진 룰 여러 개, 빈 `rules` 는 아직 따로 판정하지 않는다(팀 합의 필요).

## 테스트

```bash
python3 -m unittest tests.test_validator -v
```

`nft -c` 는 `subprocess.run` 을 mock 으로 바꿔 호출 인자(stdin 이 `\r` 없는 bytes 인지 포함)와 결과 처리(통과, 문법 오류 메시지, 실행 실패 시 반려)만 시험한다. 실제 fw 컨테이너에서의 통과·실패는 랩에서 확인해야 한다.
