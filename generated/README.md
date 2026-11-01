# generated

LLM 생성기가 만든 **후보 룰셋**을 둔다. 생성은 각자 PC(Ollama)에서 하고, 결과를 커밋한 뒤 랩(VM)에서 `pipeline/batch.py --candidates generated` 로 실행한다. 생성과 실험을 나누는 이유는 LLM 출력이 같은 seed 에서도 기기·버전에 따라 달라질 수 있어서다. 파일로 남겨야 재현된다.

## 파일 형식

후보 하나당 파일 두 개를 함께 커밋한다.

```
generated/<시나리오>-<모델>-s<seed>.json        IR 룰셋 (schema/rule.schema.json 그대로)
generated/<시나리오>-<모델>-s<seed>.meta.json   생성 조건
```

- `<모델>` 은 파일명에 쓸 수 있게 바꾼다: `qwen2.5:14b` → `qwen2.5-14b`
- 피드백 루프 2라운드부터는 `-s<seed>-r<라운드>` 를 붙인다 (예: `req-001-qwen2.5-14b-s1-r2.json`)
- IR 스키마는 추가 필드를 거부하므로 생성 조건은 반드시 meta 파일에 둔다
- `<후보>.feedback.json` 은 후보가 아니라 재생성 입력이다 (`eval/feedback.py` 가 배치 결과로 만든다, #45)

## meta 필드 (전부 필수)

| 필드 | 예 | 이유 |
| --- | --- | --- |
| `model` | `"qwen2.5:14b"` | 모델 태그 |
| `digest` | `"sha256:7cdf..."` | 태그는 나중에 다른 가중치를 가리킬 수 있다. `ollama list` 의 ID 또는 `/api/show` 의 digest |
| `ollama_version` | `"0.12.3"` | 같은 seed 라도 버전이 다르면 출력이 달라질 수 있다 |
| `temperature` | `0.7` | |
| `seed` | `1` | 반복 회차마다 바꾼다 (아래) |
| `prompt_version` | `"v1"` | 프롬프트를 바꾸면 올린다 |

값이 `null`·빈 문자열이거나 타입이 틀려도(`seed` 는 정수, `temperature` 는 숫자) 누락으로 본다.

선택 필드 `round`: 피드백 루프 라운드(1 이상의 정수, 없으면 1). 파일명의 `-r<라운드>` 와 맞춘다. CSV 에 `|r=라운드` 로 남아 1·2라운드 결과를 CSV 만으로 구분할 수 있다.

temperature 0 은 막지 않고 경고만 낸다(단독 기준 실행으로는 쓸 수 있다). 다만 seed 를 바꿔 반복하는 경우엔 의미가 없다.

추가 필드(생성 시각, 소요 시간, 재시도 횟수 등)는 자유롭게 넣어도 된다. batch 는 위 필드만 확인한다.

## 반복 규칙

temperature 0 에 seed 를 고정하면 몇 번을 돌려도 같은 출력이 나와 반복의 의미가 없다. 생성기의 편차를 재려면 **회차마다 seed 를 바꾸고(seed = 회차 번호) temperature 는 0 보다 크게** 둔다. 즉 "시나리오당 3회 반복" = seed 1·2·3 으로 만든 후보 파일 3개다.

`batch.py --reps` 는 같은 후보 파일을 랩에서 여러 번 실행하는 것(랩 쪽 편차)이라 위 반복과 다르다. generated 후보는 보통 `--reps 1` 로 돌린다.

## 피드백 재생성 (2라운드)

```bash
python3 eval/feedback.py eval/results/batch-<id>.json          # 반려·롤백된 후보마다 generated/<후보>.feedback.json
python3 generator/generate.py --scenario scenarios/req-006.json \
  --feedback generated/req-006-qwen2.5-14b-s2.feedback.json --save   # generated/req-006-qwen2.5-14b-s2-r2.json
```

- LLM 에는 1라운드와 같은 시스템 프롬프트·요구사항 뒤에 **이전 후보와 실패 내용**만 이어 붙인다. 실패 내용은 검증 오류(validation), 고위험 이유(approval), 기대와 다르게 처리된 통신(deploy, 출발지 IP → 목적지 프로토콜 포트) 중 하나다. 정답 룰셋·통과한 프로브·프로브 id·도구는 넘기지 않는다.
- 모델·프롬프트 버전·temperature·seed 는 이전 후보 meta 를 그대로 쓴다. 다르게 주면 멈춘다(라운드 사이에 바뀐 것이 피드백뿐이어야 비교가 된다).
- meta 에 `round`, `parent`(이전 후보 이름), `feedback`(파일·stage·배치 출처), `feedback_version`(피드백 문구 버전) 을 더 남긴다.
- 피드백이 가리키는 후보·meta 가 없거나, 시나리오·라운드가 맞지 않거나, 근거(오류·이유·실패 프로브)가 비어 있으면 생성하지 않고 종료 코드 1.

## 실행

```bash
python3 pipeline/batch.py --candidates generated --reps 1
```

meta 가 없거나 필드가 빠진 후보가 하나라도 있으면 아무것도 실행하지 않고 중단한다(AGENTS.md 핵심 원칙). 결과 CSV 의 generator 열에는 `모델@digest앞12자(sha256: 제외)|t=temperature|seed=seed|p=프롬프트버전|r=라운드` 이 남고, manifest 에는 meta 전체가 남는다.
