# ai-firewall-validation

AI가 생성한 방화벽 룰을 격리 랩에서 **정적·동적으로 검증**하고, 위험도에 따라 선별 적용하며, 이상 시 자동 롤백하는 파이프라인.

컴퓨터공학 특론 팀 프로젝트 (정택준 · 양경찬 · 서진정 · 강윤서)

## 연구 질문

정적 검증을 통과한 AI 방화벽 룰 중 **동적 검증만 잡아내는 오류**는 얼마나 되고 어떤 유형인가? 위험도 기반 적용으로 사람 검토량을 얼마나 줄이면서 안전성을 유지할 수 있는가?

## 구조

```
schema/      IR 스키마 (팀 계약서. 바꾸려면 팀 합의)
common/      IR 로드·검증·nftables 변환, 랩 실행 헬퍼
lab/         Podman 격리 랩 (Containerfile, up/down, 경로 검수)
scenarios/   자연어 요구사항 + 정답 룰셋 + 프로브 정의        서진정
mutations/   오류 주입 룰셋                                    서진정
generator/   자연어 -> IR (LLM)                                서진정
validator/   정적 검증 + 위험도 판정                           양경찬
prober/      능동 프로빙 (정상·공격 트래픽)                    강윤서
eval/        지표 계산, 결과 CSV                               강윤서
deployer/    적용·감시·자동 롤백                               정택준
pipeline/    전체 실행                                         정택준
```

모든 모듈은 **JSON 입력 → JSON 출력 CLI**다. 앞 모듈이 없어도 예시 JSON 으로 개발할 수 있다.

## 파이프라인

```
scenario ─ generator ─> candidate.json ─ validator ─> validation.json
                                              │ ok=false → 적용 안 함, 기록
                                              │ risk=high → 사람 승인
                                              ▼
                              deployer (적용 → 감시 → 실패 시 롤백) ─> deploy.json
                                              ▼
                                   eval ─> eval/results/results.csv
```

## 시작하기

요구사항: Linux, rootful Podman 4.x 이상, Python 3.10 이상

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # LLM 키는 여기에만. 커밋 금지

./lab/up.sh                     # 랩 기동
./lab/check-path.sh             # 반드시 통과해야 함 (트래픽이 fw 를 거치는지)
./pipeline/run.sh scenarios/req-001.json
./lab/down.sh
```

`sudo` 없이 Podman 을 쓰는 환경이면 `PODMAN=podman` 을 지정한다. 단, fw 컨테이너가 NET_ADMIN 으로 라우팅해야 하므로 rootless 에서는 동작을 보장하지 않는다.

`check-path.sh` 의 1번이 실패하면 호스트가 네트워크 사이를 직접 라우팅하는 것이다. `./lab/down.sh && ISOLATE=1 ./lab/up.sh` 로 다시 띄워 확인한다.

## 실험 실행

```bash
git status                       # 깨끗해야 함 (manifest 에 커밋 해시를 남기므로)
python3 pipeline/batch.py --candidates all --reps 3 --watch 10 --approve no
```

- 후보: `gold`(정답 룰셋), `mutations`(`mutations/<시나리오>-*.json`), `all`
- 결과: `eval/results/results.csv` 에 실행마다 한 줄, `eval/results/batch-<시각>.json` 에 커밋·인자·실행 목록
- 상태: `applied` / `rolled_back` / `rejected_validation` / `rejected_approval` / `aborted`(실행 실패, CSV 에 기록 안 됨, 원인은 manifest 의 `error` 와 `out/.../run.log`)
- 작업 트리에 커밋 안 된 파일이 있으면(새 파일 포함) 실행을 거부한다
- 단건 실행 종료 코드(`pipeline/run.sh`): 0 적용, 3 검증 반려, 4 승인 거부, 1 실행 실패

## 랩 토폴로지

| 컨테이너 | 네트워크 | IP | 역할 |
| --- | --- | --- | --- |
| fw | net-iot, net-lan, net-svc | 10.10.{10,20,30}.254 | nftables 방화벽 (검증 대상) |
| iot-dev | net-iot | 10.10.10.10 | IoT 기기, 관리 페이지 :80 |
| attacker | net-iot | 10.10.10.66 | 침해된 IoT 가정, 공격 프로브 |
| pc | net-lan | 10.10.20.10 | 내부 PC |
| server | net-svc | 10.10.30.10 | 웹 :80, :8080 |

## 규칙

- **공격 트래픽은 10.10.x.x 안에서만.** 외부 IP·도메인을 대상으로 nmap/hping3 를 실행하지 않는다. hping3 는 속도 제한 필수.
- LLM API 키는 `.env` 에만. 커밋되면 즉시 키를 폐기한다.
- main 에는 PR 로만 합치고 다른 팀원 1명이 확인한다.
- 실험 결과(`eval/results/*.csv`)는 커밋한다. 모델명·프롬프트 버전을 함께 남긴다.
- LLM 결과는 매번 다를 수 있으므로 시나리오당 최소 3회 반복한다.
