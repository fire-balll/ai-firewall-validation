# mutations

정답 룰셋을 일부러 망가뜨린 **오류 주입 룰셋**을 둔다. 생성기 품질과 상관없이 검증기를 평가하기 위한 데이터다. (담당: 서진정)

파일 이름은 `<시나리오>-<유형>-<번호>.json`, 형식은 `schema/rule.schema.json` 과 같다. 스키마에 없는 필드는 거부되므로, 어떤 오류를 넣었는지는 아래 표에 기록한다.

한 파일에는 오류를 **하나만** 넣는다. 여러 오류가 섞이면 어떤 오류를 어느 검증이 잡았는지 가를 수 없다.

## 오류 유형

"결과"는 정답 대비 어느 쪽으로 틀리는지다. 과허용은 막아야 할 트래픽이 통과하는 것(공격 프로브 실패), 과차단은 허용해야 할 트래픽이 막히는 것(정상 프로브 실패)이다.

"잡힘"은 정적 검증이 `ok=false`(반려) 또는 `risk=high`(사람 검토)를 내는 것을 말한다.

| 유형 | 바꾸는 것 | 예시 | 결과 | 정적 검증으로 잡히나 (가설) | 적용할 시나리오 |
| --- | --- | --- | --- | --- | --- |
| order | priority 순서 | 좁은 drop 과 넓은 accept 의 순서를 뒤집음 | 과허용 | 이상 탐지(#15)가 들어가면 잡힘. 앞의 accept 와 뒤의 drop 이 일부만 겹치면 correlation, accept 가 drop 을 모두 포함하면 shadowing 으로 둘 다 고위험. 현재 main 의 validator 로는 안 잡힘 | req-004, req-010 |
| widen | src·dst CIDR 확대 | /32 → /24, /24 → /16, → any | 과허용 | /16 보다 넓거나 any 일 때만 잡힘 (고위험 기준). /32 → /24 는 안 잡힘 | req-003, req-005 |
| port-any | 특정 포트 → any | dport 8080 → any | 과허용 | 잡힘 (모든 포트 accept 고위험 기준) | req-002 |
| port | 포트 번호 오기 | dport 80 → 8080 | 과허용 + 과차단 | 정답 비교 없이는 안 잡힘 | req-001, req-006 |
| range | 포트 범위 경계 | 8000-8100 → 8000-8079 | 과차단 | 정답 비교 없이는 안 잡힘 | req-009 |
| swap | src 와 dst 를 맞바꿈 | server → iot-dev 가 iot-dev → server 로 | 과허용 + 과차단 | 정답 비교 없이는 안 잡힘 | req-007 |
| missing | 필요한 accept 룰 삭제 | 여러 룰 중 하나를 뺌 | 과차단 | 정적으로는 안 잡힘 | req-001, req-006 |
| proto | 프로토콜 변경 | icmp → any, tcp → udp | 과허용 / 과차단 | any 는 잡힘 (모든 프로토콜 accept). tcp → udp 는 안 잡힘 | req-008 |
| action | accept 와 drop 을 뒤집음 | 침해 기기 drop → accept | 과허용 / 과차단 | accept 로 바뀐 룰이 넓으면(any, /16 초과) 잡힘. 좁은 룰이면 안 잡힘 | req-004, req-010 |
| narrow | 범위 축소·다른 호스트 | /24 → 다른 /32 | 과차단 | 안 잡힘 | req-008 |
| extra | 정답에 없는 넓은 accept 추가 | any → any accept | 과허용 | 잡힘 (any-to-any 고위험 기준) | req-010 |

"가설" 열이 실제로 맞는지 확인하는 것이 실험의 핵심 질문이다. 가설은 문서 2-2 의 고위험 기준과 계획된 이상 탐지 4종을 기준으로 적었고, 유형별 예시 하나씩을 현재 `validator/validate.py` 에 넣어 order·action 칸을 고쳤다. 첫 실험 결과를 커밋한 뒤에는 이 표의 유형을 바꾸지 않는다(`AGENTS.md`).

### 지금 IR 로 표현할 수 없는 유형 (팀 논의 필요)

| 유형 | 내용 | 막히는 이유 |
| --- | --- | --- |
| state | 응답 트래픽 누락 (`ct state established,related accept` 가 빠짐) | 변환기(`common/ir.py` 의 `to_nft`)가 상태 추적 룰을 항상 맨 앞에 넣는다. IR 에는 이 룰을 끌 필드가 없다. |

계획서의 "응답 트래픽 누락"이 이 유형이다. 넣으려면 둘 중 하나가 필요하다.

1. 오류 주입 파일을 IR 이 아니라 nft 텍스트로도 둘 수 있게 한다 (deployer·validator 입력 형식 변경).
2. 변환기에 상태 추적 룰을 빼는 옵션을 둔다 (`common/` 담당 정택준, schema 는 그대로).

## 파일 목록

원본은 모두 `scenarios/<시나리오>.json` 의 gold 다. "정적"은 현재 `validator/validate.py` 의 risk(모두 ok=true), "실패 프로브"는 `common/sim.py` 시뮬레이터로 시나리오 프로브를 돌렸을 때 정답과 판정이 달라지는 프로브다. 랩 실측이 아니다.

| 파일 | 원본 | 유형 | 바꾼 내용 | 정적 | 실패 프로브 (시뮬레이터) |
| --- | --- | --- | --- | --- | --- |
| req-001-missing-01.json | req-001 | missing | g-002(PC → IoT 관리 페이지 80) 삭제 | low | n-002 |
| req-001-port-01.json | req-001 | port | g-001 의 dport 80 → 8080 | low | n-001 (#13 이후 a-005 도) |
| req-002-port-any-01.json | req-002 | port-any | g-001 의 dport 8080 → any | high | a-001 |
| req-003-widen-01.json | req-003 | widen | g-001 의 src 10.10.10.10/32 → 10.10.10.0/24 | low | a-001 |
| req-004-action-01.json | req-004 | action | g-001(침해 기기 차단)의 action drop → accept | high | a-001, a-002 |
| req-004-order-01.json | req-004 | order | g-001(drop, 100) 과 g-002(accept, 110) 의 priority 를 맞바꿈 | low | a-001 |
| req-005-widen-01.json | req-005 | widen | g-001 의 src 10.10.20.0/24 → any | high | a-001 |
| req-006-missing-01.json | req-006 | missing | g-002(IoT → 서버 80) 삭제 | low | n-002 |
| req-006-port-01.json | req-006 | port | g-002(IoT → 서버) 의 dport 80 → 8080 | low | n-002, a-001, a-002 |
| req-007-swap-01.json | req-007 | swap | g-001 의 src 와 dst 를 맞바꿈 (서버 → IoT 가 IoT → 서버로) | low | n-001, a-001 |
| req-008-narrow-01.json | req-008 | narrow | g-001 의 dst 10.10.10.0/24 → 10.10.10.20/32 (없는 호스트) | low | n-001 |
| req-008-proto-01.json | req-008 | proto | g-001 의 proto icmp → any | high | a-004 (#13 의 프로브. 그 전에는 안 드러남) |
| req-009-range-01.json | req-009 | range | g-001 의 dport 8000-8100 → 8000-8079 | low | n-001 (#13 이후 n-003 도) |
| req-010-action-01.json | req-010 | action | g-003(PC → IoT 관리 페이지) 의 action accept → drop | low | n-002 |
| req-010-extra-01.json | req-010 | extra | x-001(any → any, proto any, accept, priority 200) 추가 | high | a-003~a-005 (#13 이후 a-006~a-010 도) |
| req-010-order-01.json | req-010 | order | g-001(침해 기기 drop, 100) 과 g-004(IoT → 서버 8080 accept, 130) 의 priority 를 맞바꿈 | low | a-001 |
