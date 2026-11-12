# Batfish·Tufin 자료조사와 AI 생성 방화벽 규칙 검증의 연구 방향

## 1. Batfish: 정책 변경 전후의 영향과 규칙 가림 분석

Batfish는 네트워크 구성 스냅샷을 분석해 정책 변경의 영향을 확인하는 도구다. `compareFilters`는 변경 전후 필터가 같은 트래픽을 서로 다르게 허용·차단하는 규칙을 찾고, `differentialReachability`는 두 스냅샷 사이의 도달성 변화를 분석한다.[1]

`filterLineReachability`는 선행 규칙에 가려지거나 조건이 비어 어떤 패킷에도 적용되지 않는 규칙을 찾는다. 결과의 `Blocking_Lines`에는 함께 해당 규칙을 가리는 선행 규칙들이 표시된다.[2]

AI가 생성한 규칙의 문법·스키마 검사에서 나아가, 의도한 트래픽을 허용하는지와 다른 규칙에 가려지는지를 평가할 때 참고할 분석 기준이다. 같은 입력 정책과 질문을 맞춘 비교 실험이 필요하다.

## 2. Tufin: 정책 변경 요청부터 적용 확인까지의 관리

Tufin SecureChange는 접근 요청 접수, 정책 설계, 보안 평가, 승인, 지원 장비 적용, 변경 이력 추적을 연결한다. Designer는 기존 정책 정보를 이용해 필요한 변경을 제안하고, Verifier는 요청한 접근을 허용하는 정책이 구현됐는지 확인한다.[3][4]

Verifier의 결과는 요청 트래픽을 허용하는 정책 존재, 요청 일부 미충족, 검증 실행 불가로 구분된다. 공식 설명의 정책 확인을 우리 팀의 실제 패킷 프로브와 구분해 비교해야 한다.[4]

AI Assistant Access Request는 자연어로 입력한 출발지·목적지·서비스를 구조화된 접근 요청으로 바꾸며, 사용자가 수정하거나 승인할 수 있다. 사용에는 관리자 활성화와 적격 라이선스 등의 조건이 따른다.[5]

AI 입력, 사람 승인, 정책 적용, 사후 확인을 구분해 연구 범위를 설명할 때 참고할 기존 운영 절차다. Tufin의 자연어 접근 요청 작성과 우리 팀의 nftables IR 후보 생성은 출력 단계가 다르므로 단계별로 비교한다.

## 3. 선행연구: 고수준 보안 정책을 방화벽 규칙으로 변환

Kovačević·Štengl·Groš의 2022년 체계적 문헌고찰은 고수준 보안 정책을 방화벽 규칙으로 자동 변환하는 연구들을 정리한다. 초록에서는 전용 언어, 형식 명세, 온톨로지, 그래픽 모델 등을 사용하는 접근을 소개한다.[6]

정책 의도를 규칙으로 바꾸는 기존 연구 흐름을 서론에 연결할 수 있다. 우리 팀은 AI 생성 이후 정적 검사·패킷 관측·실패 피드백에서 무엇을 확인하는지 구체화할 필요가 있다.

## 4. 우리 팀의 실험에서 이어갈 연구 질문

[11월 5일 팀 회의록](meetings/2026-11-05.md)에는 피드백으로 재생성한 `req-006` seed 3 후보가 정적·동적 검증을 모두 통과했지만, 정답 정책과 과허용 1개·과차단 3개 영역 차이를 보인 사례가 기록돼 있다. 이는 지정한 프로브의 통과와 전체 정책 의도 일치를 나누어 평가해야 하는 직접적인 연구 근거다.

현재 자료로 집중할 연구 질문은 다음과 같다.

> **AI가 생성한 방화벽 규칙에 대해 정적 검사와 패킷 프로브는 각각 어떤 오류를 발견하며, 두 검사를 통과한 뒤에도 어떤 정책 오류가 남는가?**

후속 평가에서는 같은 요구·정답 정책·생성 조건을 고정하고, 오류 유형별 정적·동적 발견 결과와 남은 정책 차이를 비교한다. 재생성에 사용한 프로브와 별도의 평가용 프로브를 구분하는 방안도 검토할 수 있다.

Batfish·Tufin과 동일 조건으로 수행한 성능 비교는 아직 없다. 따라서 현 단계의 발표에는 기존 도구의 기능, 우리 팀이 실제로 관측한 오류, 앞으로 측정할 항목을 구분해 제시한다.

## Sources

[1] https://pybatfish.readthedocs.io/en/latest/notebooks/differentialQuestions.html — Batfish differential questions
[2] https://pybatfish.readthedocs.io/en/latest/notebooks/filters.html — Batfish access lists and firewall rules
[3] https://forum.tufin.com/support/kc/latest/Content/Suite/856.htm — Tufin SecureChange overview
[4] https://forum.tufin.com/support/kc/latest/Content/Suite/7445.htm — Tufin verifying access requests
[5] https://forum.tufin.com/support/kc/aurora/Content/ST2/AITools/ai_access_request_assistant_usage.htm — Tufin AI Assistant access request
[6] https://arxiv.org/abs/2212.03645 — Systematic review of automatic translation of high-level security policy into firewall rules
