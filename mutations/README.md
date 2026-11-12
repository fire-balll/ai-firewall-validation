# mutations

정답 룰셋을 일부러 망가뜨린 **오류 주입 룰셋**을 둔다. 생성기 품질과 상관없이 검증기를 평가하기 위한 데이터다. (담당: 서진정)

파일 이름은 `<시나리오>-<유형>-<번호>.json`, 형식은 `schema/rule.schema.json` 과 같다. 스키마에 없는 필드는 거부되므로, 어떤 오류를 넣었는지는 아래 표에 기록한다.

한 파일에는 오류를 **하나만** 넣는다. 여러 오류가 섞이면 어떤 오류를 어느 검증이 잡았는지 가를 수 없다.

## 오류 유형

"결과"는 정답 대비 어느 쪽으로 틀리는지다. 과허용은 막아야 할 트래픽이 통과하는 것(공격 프로브 실패), 과차단은 허용해야 할 트래픽이 막히는 것(정상 프로브 실패)이다.

"잡힘"은 정적 검증이 `ok=false`(반려) 또는 `risk=high`(사람 검토)를 내는 것을 말한다.

| 유형 | 바꾸는 것 | 예시 | 결과 | 정적 검증으로 잡히나 (가설) | 적용할 시나리오 |
| --- | --- | --- | --- | --- | --- |
| order | priority 순서 | 좁은 drop 과 넓은 accept 의 순서를 뒤집음 | 과허용 | 현재 validator 는 아래 두 order 파일을 correlation/high 로 잡음. 앞의 accept 와 뒤의 drop 이 일부만 겹치면 correlation, accept 가 drop 을 모두 포함하면 shadowing 으로 둘 다 고위험 | req-004, req-010 |
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
| state | 응답 트래픽 누락 (상태 추적 룰을 뺌) | 정답 룰셋 그대로, 파일명(`req-NNN-state-NN.json`)으로 `ct state established,related accept` 없이 적용 | 과차단 (새 연결이 성립하지 않음) | 안 잡힘. IR 이 정답과 같아서 정적 검증과 시뮬레이터로는 원리상 못 잡는다 | 전체 (req-001~010) |

"가설" 열이 실제로 맞는지 확인하는 것이 실험의 핵심 질문이다. 가설은 문서 2-2 의 고위험 기준과 계획된 이상 탐지 4종을 기준으로 적었고, 유형별 예시 하나씩을 현재 `validator/validate.py` 에 넣어 order·action 칸을 고쳤다. 첫 실험 결과를 커밋한 뒤에는 이 표의 유형을 바꾸지 않는다(`AGENTS.md`).

2026-10-19 대조: `45b2ee6`의 validator·시뮬레이터로 기존 비-state 16개를 실행하면 모두 `ok=true`, `high` 7개·`low` 9개다. 아래 order 두 행과 설명은 이 관측에 맞춘 정정이며 오류 유형 목록은 그대로다. 정적 경고와 정답 대비 정책 차이는 구분한다. 범위·state 모드·교체 전후 비교 설계는 `docs/validator-week2-hypothesis-design.md`를 참고한다.

### state 유형

IR 에는 상태 추적 룰을 끌 필드가 없어서, state 후보는 **IR 이 정답과 똑같고 파일명으로만 구분**한다. 변환기(`common/ir.py` 의 `stateful_for`)는 파일명 전체가 `req-<숫자>-state-<숫자>.json` 형식일 때만 상태 추적 룰 없이 nft 로 바꾼다 (#23). 그래서 이 유형의 파일은 이름을 이 형식 그대로 둬야 한다. 이름을 바꾸거나 다른 이름으로 복사하면 정답과 똑같이 적용된다. 반대로 이름 중간에 `-state-` 가 들어간 다른 후보(예: LLM 후보의 모델 태그)는 stateless 로 바뀌지 않는다.

- 시뮬레이터(`common/sim.py`)는 응답 트래픽을 항상 허용으로 가정하므로 정답과 판정이 같다. `scenarios/coverage.py` 는 시뮬레이터로 IR 변형만 만들기 때문에 이 유형을 다루지 않고, `equivalent` 에도 넣지 않는다. 동적 검증만 잡는 오류로 따로 센다.
- stateless 에서 올바른 정책(응답 방향 허용)은 IR 로 쓸 수 없다(출발지 포트 필드가 없음). 그래서 이 유형은 항상 틀린 룰이다.
- 정상 프로브가 모두 timeout 으로 실패해 감지 시간이 다른 유형보다 길다(#23 의 req-001: 23.9초, 다른 유형 8~10초). 감지 시간은 유형별로 나눠 본다.

### union shadow (req-021-range-01)

뒤의 룰 하나가 앞의 룰 **여러 개에 합쳐서** 가려져 한 번도 적용되지 않는 경우다. `validator/anomalies.py` 는 룰을 둘씩만 비교하므로, 앞의 룰 각각이 뒤의 룰과 일부만 겹치면 shadowing(고위험)으로 잡지 못한다. 정답 룰셋에는 적용되지 않는 룰이 있을 수 없어서, 정답에서 오류 하나로 이 모양이 되도록 req-021 을 설계했다.

- 정답: g-001(PC 망 → 서버 8000-8019 drop), g-002(8080-8100 drop), g-003(8000-8100 accept) 순서. g-003 은 8020-8079 에서 적용된다.
- 오류: g-001 의 범위 끝을 8019 → 8079 로 잘못 씀. g-001 과 g-002 가 합쳐서 8000-8100 전체를 덮어 g-003 이 적용되지 않는다.
- validator 는 정답과 같은 경고(g-001·g-002 와 g-003 의 generalization, low)만 내고, 시나리오 프로브 n-001 ~ n-003 이 잡는다.

## 파일 목록

원본은 모두 `scenarios/<시나리오>.json` 의 gold 다. req-011 ~ 021 은 4주차에, req-019 는 UDP 프로브(#62) 머지 뒤에 추가했다. 위 유형 표의 "적용할 시나리오" 열은 req-001 ~ 010 기준이다. "정적"은 현재 `validator/validate.py` 의 risk(모두 ok=true), "실패 프로브"는 `common/sim.py` 시뮬레이터로 시나리오 프로브를 돌렸을 때 정답과 판정이 달라지는 프로브다. 랩 실측이 아니다. state 유형은 시뮬레이터로 드러나지 않으므로 랩 결과(Mac, rootless Podman. req-001 ~ 010 은 #23, req-011 ~ 020 은 #51, req-019·021 은 각 파일을 추가한 PR)를 괄호로 적었다.

| 파일 | 원본 | 유형 | 바꾼 내용 | 정적 | 실패 프로브 (시뮬레이터) |
| --- | --- | --- | --- | --- | --- |
| req-001-missing-01.json | req-001 | missing | g-002(PC → IoT 관리 페이지 80) 삭제 | low | n-002 |
| req-001-port-01.json | req-001 | port | g-001 의 dport 80 → 8080 | low | n-001 (#13 이후 a-005 도) |
| req-001-state-01.json | req-001 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001, n-002) |
| req-002-port-any-01.json | req-002 | port-any | g-001 의 dport 8080 → any | high | a-001 |
| req-002-state-01.json | req-002 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001) |
| req-003-state-01.json | req-003 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001) |
| req-003-widen-01.json | req-003 | widen | g-001 의 src 10.10.10.10/32 → 10.10.10.0/24 | low | a-001 |
| req-004-action-01.json | req-004 | action | g-001(침해 기기 차단)의 action drop → accept | high | a-001, a-002 |
| req-004-order-01.json | req-004 | order | g-001(drop, 100) 과 g-002(accept, 110) 의 priority 를 맞바꿈 | high | a-001 |
| req-004-state-01.json | req-004 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001) |
| req-005-state-01.json | req-005 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001) |
| req-005-widen-01.json | req-005 | widen | g-001 의 src 10.10.20.0/24 → any | high | a-001 |
| req-006-missing-01.json | req-006 | missing | g-002(IoT → 서버 80) 삭제 | low | n-002 |
| req-006-port-01.json | req-006 | port | g-002(IoT → 서버) 의 dport 80 → 8080 | low | n-002, a-001, a-002 |
| req-006-state-01.json | req-006 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-007-state-01.json | req-007 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001) |
| req-007-swap-01.json | req-007 | swap | g-001 의 src 와 dst 를 맞바꿈 (서버 → IoT 가 IoT → 서버로) | low | n-001, a-001 |
| req-008-narrow-01.json | req-008 | narrow | g-001 의 dst 10.10.10.0/24 → 10.10.10.20/32 (없는 호스트) | low | n-001 |
| req-008-proto-01.json | req-008 | proto | g-001 의 proto icmp → any | high | a-004 (#13 의 프로브. 그 전에는 안 드러남) |
| req-008-state-01.json | req-008 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001, n-002) |
| req-009-range-01.json | req-009 | range | g-001 의 dport 8000-8100 → 8000-8079 | low | n-001 (#13 이후 n-003 도) |
| req-009-state-01.json | req-009 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-010-action-01.json | req-010 | action | g-003(PC → IoT 관리 페이지) 의 action accept → drop | low | n-002 |
| req-010-extra-01.json | req-010 | extra | x-001(any → any, proto any, accept, priority 200) 추가 | high | a-003~a-005 (#13 이후 a-006~a-010, #33 이후 a-011 도) |
| req-010-order-01.json | req-010 | order | g-001(침해 기기 drop, 100) 과 g-004(IoT → 서버 8080 accept, 130) 의 priority 를 맞바꿈 | high | a-001 |
| req-010-state-01.json | req-010 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-005) |
| req-011-extra-01.json | req-011 | extra | x-001(10.10.0.0/16 → 서버 8080, accept, priority 200) 추가 | low | a-001 |
| req-011-missing-01.json | req-011 | missing | g-002(IoT → 서버 8080) 삭제 | low | n-002 |
| req-011-state-01.json | req-011 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001, n-002) |
| req-012-action-01.json | req-012 | action | g-002(IoT 망 나가는 통신 차단) 의 action drop → accept | high | a-001~a-004 |
| req-012-order-01.json | req-012 | order | g-001(IoT 기기 → 서버 80 accept, 100) 과 g-002(IoT 망 drop, 110) 의 priority 를 맞바꿈 | high | n-001 |
| req-012-state-01.json | req-012 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001) |
| req-013-port-01.json | req-013 | port | g-002(PC → 서버 SSH) 의 dport 22 → 8080 | low | n-002, a-002 |
| req-013-proto-01.json | req-013 | proto | g-002(PC → 서버 SSH) 의 proto tcp → udp | low | n-002 |
| req-013-state-01.json | req-013 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-014-order-01.json | req-014 | order | g-001(PC → 서버 8080 drop, 100) 과 g-002(PC → 서버 8000-8100 accept, 110) 의 priority 를 맞바꿈 | high | a-001 |
| req-014-range-01.json | req-014 | range | g-002 의 dport 8000-8100 → 8000-8079 | low | n-002 |
| req-014-state-01.json | req-014 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-015-action-01.json | req-015 | action | g-001(침해 기기 차단) 의 action drop → accept | high | a-001 |
| req-015-proto-01.json | req-015 | proto | g-004(IoT → 서버 ping) 의 proto icmp → any | high | a-003 |
| req-015-state-01.json | req-015 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-016-narrow-01.json | req-016 | narrow | g-004(IoT → 서버 망 ping) 의 dst 10.10.30.0/24 → 10.10.30.20/32 (없는 호스트) | low | n-002 |
| req-016-state-01.json | req-016 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-016-widen-01.json | req-016 | widen | g-001(침해 기기 → PC 망 drop) 의 src 10.10.10.66/32 → 10.10.10.0/24 | high | n-001 |
| req-017-missing-01.json | req-017 | missing | g-007(PC 망 → IoT 기기 관리 페이지 80) 삭제 | low | n-006 |
| req-017-port-any-01.json | req-017 | port-any | g-004(IoT 기기 → 서버 8080) 의 dport 8080 → any | high | a-005 |
| req-017-state-01.json | req-017 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-007) |
| req-018-state-01.json | req-018 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-018-swap-01.json | req-018 | swap | g-003 의 src 와 dst 를 맞바꿈 (IoT → PC 9000 이 PC → IoT 9000 으로) | low | n-002 |
| req-018-widen-01.json | req-018 | widen | g-002(IoT → 서버 8080) 의 src 10.10.10.0/24 → any | high | a-008 |
| req-019-port-01.json | req-019 | port | g-001(IoT → 서버 DNS) 의 dport 53 → 5353 | low | n-001 |
| req-019-proto-01.json | req-019 | proto | g-001(IoT → 서버 DNS) 의 proto udp → any (dport any) | high | a-002~a-004 |
| req-019-state-01.json | req-019 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-019-widen-01.json | req-019 | widen | g-002(PC 망 → 서버 DNS) 의 src 10.10.20.0/24 → 10.10.0.0/16. 게스트 망도 DNS 를 쓰게 됨 | low | a-001 (UDP 차단 프로브) |
| req-020-narrow-01.json | req-020 | narrow | g-002(PC 망 → 서버 80) 의 src 10.10.20.0/24 → 10.10.20.10/32 | low | n-002 |
| req-020-state-01.json | req-020 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-003) |
| req-020-widen-01.json | req-020 | widen | g-001(관리자 PC → 서버 8080) 의 src 10.10.20.10/32 → 10.10.20.0/24 | low | a-001 |
| req-021-range-01.json | req-021 | range | g-001(PC 망 → 서버 8000-8019 drop) 의 dport 8000-8019 → 8000-8079. g-001 과 g-002 가 합쳐서 g-003(8000-8100 accept) 을 모두 가림 (union shadow) | low | n-001~n-003 |
| req-021-state-01.json | req-021 | state | 상태 추적 룰을 뺌 (IR 은 정답 그대로) | low | 없음 (랩: n-001~n-004) |
| req-021-widen-01.json | req-021 | widen | g-004(IoT 기기 → 서버 8080) 의 src 10.10.10.10/32 → 10.10.10.0/24 | low | a-007 |
