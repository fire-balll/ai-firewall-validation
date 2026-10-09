# AI 작업 지침 (ai-firewall-validation)

이 저장소에서 코드를 작성·커밋·PR 하는 AI 어시스턴트는 아래 규칙을 따른다. 사람 팀원도 같은 규칙을 따른다.

## 프로젝트 맥락

- AI가 생성한 방화벽 룰을 Podman 격리 랩에서 정적·동적으로 검증하고, 위험도에 따라 선별 적용하며, 이상 시 자동 롤백하는 4인 팀 프로젝트다.
- 저장소: https://github.com/fire-balll/ai-firewall-validation
- 모듈 간 계약은 `schema/rule.schema.json`(IR)이다. 모든 모듈은 **JSON 입력 → JSON 출력 CLI**로 유지한다.

| 디렉터리 | 담당 | GitHub |
| --- | --- | --- |
| `scenarios/`, `mutations/`, `generator/` | 서진정 | @improvv |
| `validator/` | 양경찬 | @SoftwareDevJake |
| `prober/`, `eval/` | 강윤서 | @yxxunseo |
| `lab/`, `deployer/`, `pipeline/`, `common/` | 정택준 | @iamtaekjun |

담당 디렉터리를 건드리는 PR 에는 `.github/CODEOWNERS` 에 따라 담당자가 리뷰어로 자동 지정된다.

## 핵심 원칙: 관측하지 못했으면 결과를 내지 않는다

검증·프로빙·평가 모듈은 **실제로 관측한 것만 결과로 낸다.** 검사를 실행하지 못했으면(컨테이너가 꺼짐, 명령 없음, 타임아웃, 파싱 실패 등) 결과 JSON 을 내지 말고 **원인 메시지와 함께 종료 코드 ≠ 0 으로 실패**한다.

- 실패를 "차단", "반려", "통과" 같은 결과 값으로 바꾸지 않는다. 기본값으로 메우지도 않는다.
- 종료 코드가 0 이 아니라는 것만으로 판정하지 않는다. "관측된 결과"(예: `nc` 의 `timed out`, `nft -c` 의 문법 오류)와 "실행 실패"(예: `podman exec` 의 125·126·127)를 **구분할 근거**를 코드에 적고, 그 근거는 lab 이미지에서 직접 확인한다.
- 실행 실패는 파이프라인에서 `aborted` 로 처리되고 결과 CSV 에 기록되지 않는다 (`pipeline/run.sh` 종료 코드 1). 모듈은 이 흐름에 맡기고 스스로 결과를 꾸며내지 않는다.

**왜:** 실행 실패가 결과로 둔갑하면 실험 데이터가 조용히 오염된다. 이 프로젝트에서 이미 같은 버그가 반복됐다.

| 사례 | 무엇이 둔갑했나 |
| --- | --- |
| #5 prober | attacker 컨테이너가 꺼져 있는데 "공격 차단"으로 기록 → 공격 차단율 거짓 100% |
| #7 리뷰 | `Connection refused`(방화벽은 통과, 포트만 닫힘)를 "차단"으로 판정 |
| #11 validator | fw 컨테이너가 꺼져 있는데 정답 룰셋이 "검증 반려"로 기록 |

**PR 에서 확인할 것:** 외부(컨테이너, 명령, 파일)에 의존하는 코드를 바꿨다면, 그 의존 대상을 멈추거나 없앤 상태에서 실행해 결과 대신 실패가 나는지 확인하고 PR 본문에 적는다.

## 브랜치 전략: GitHub Flow

- `main` 하나만 장기 브랜치다. **`main`에 직접 커밋·push 하지 않는다.** dev 브랜치는 없다.
- 작업은 항상 최신 `main`에서 새 브랜치를 만들어 시작한다.
  ```bash
  git switch main && git pull --ff-only
  git switch -c feat/<모듈>-<짧은-설명>
  ```
- 브랜치 이름: `feat/` 기능, `fix/` 버그, `exp/` 실험, `docs/` 문서, `chore/` 설정. 예: `feat/validator-shadowing`
- 브랜치는 짧게 유지한다. 며칠 안에 PR 로 합친다. 한 PR 에는 한 가지 목적만 담는다.
- PR 전에 최신 `main`을 반영한다.
  ```bash
  git fetch origin && git rebase origin/main
  ```
  충돌은 직접 해결하고, 다른 사람 담당 파일의 충돌은 해결 방향을 사람에게 묻는다.
- force push 는 **자기 작업 브랜치에만**, `git push --force-with-lease` 로 한다. `main` 에는 절대 하지 않는다.

## 커밋

- 메시지 형식: `<type>(<모듈>): <무엇을 했는지>` — type 은 feat, fix, exp, docs, chore, test, refactor
  - 예: `feat(validator): shadowing 탐지 추가`
- 작게, 의미 단위로 커밋한다. 생성 파일·캐시(`out/`, `__pycache__/`, `.venv/`)는 커밋하지 않는다.
- **`.env`, API 키, 토큰, 비밀번호는 절대 커밋하지 않는다.** 커밋됐다면 즉시 사람에게 알리고 키를 폐기하게 한다(히스토리에서 지워도 이미 유출된 것으로 본다).

## PR 생성 전 확인

PR 을 만들기 전에 아래를 실행하고 결과를 PR 본문에 적는다.

```bash
python3 -m py_compile $(git ls-files '*.py')
bash -n lab/*.sh pipeline/*.sh
python3 generator/generate.py --scenario scenarios/req-001.json --mock | python3 validator/validate.py -
python3 -m unittest discover -s tests -t .
```

랩을 쓸 수 있는 환경이면 추가로:

```bash
./lab/up.sh && ./lab/check-path.sh && ./pipeline/run.sh scenarios/req-001.json; ./lab/down.sh
```

실행하지 못한 확인은 "실행하지 않음"이라고 적는다. 통과하지 않은 것을 통과했다고 쓰지 않는다.

## PR 생성

- base 는 항상 `main`. 본문은 `.github/pull_request_template.md` 형식을 따른다.
- gh CLI 가 있으면:
  ```bash
  git push -u origin HEAD
  gh pr create --base main --fill-first
  ```
  없으면 `git push -u origin HEAD` 후 출력되는 링크로 웹에서 PR 을 연다.
- **push 와 PR 생성은 사람에게 확인받은 뒤에 한다.**

## 리뷰와 머지

- 다른 팀원 1명 이상의 승인이 있어야 머지한다. **AI 는 PR 을 머지하지 않는다.** 자기 PR 을 스스로 승인하지 않는다.
- 머지 방식은 **Squash and merge**, 머지 후 브랜치는 삭제한다.
- 리뷰 코멘트에 답할 때는 고친 커밋을 같은 브랜치에 추가로 push 한다.

## 바꾸기 전에 팀 합의가 필요한 것

- `schema/rule.schema.json` (IR 계약) — PR 제목에 `[schema]` 를 붙이고 팀원 전원을 리뷰어로 지정한다.
- 다른 담당자 디렉터리의 동작 변경 — 담당자를 리뷰어로 지정한다.
- 새 의존성 추가 — `requirements.txt` 변경 이유를 PR 에 적는다.
- `mutations/README.md` 의 오류 유형 목록 — 첫 실험 결과 커밋 이후에는 바꾸지 않는다(결과를 보고 유형을 고르지 않기 위해).

## 실험과 보안 규칙

- 공격 트래픽(nmap, hping3)은 **10.10.x.x 랩 네트워크 안에서만** 보낸다. 외부 IP·도메인을 대상으로 하지 않는다. hping3 는 속도 제한을 걸고 `--flood` 는 쓰지 않는다.
- 실험은 태그 또는 특정 커밋에서 실행하고, 결과 CSV(`eval/results/`)를 커밋할 때 실행한 커밋 해시와 모델명·프롬프트 버전을 함께 남긴다.
- 수치는 실측만 기록한다. 추정치나 예시 값을 결과처럼 쓰지 않는다.
