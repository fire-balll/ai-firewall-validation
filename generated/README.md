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

## meta 필드 (전부 필수)

| 필드 | 예 | 이유 |
| --- | --- | --- |
| `model` | `"qwen2.5:14b"` | 모델 태그 |
| `digest` | `"sha256:7cdf..."` | 태그는 나중에 다른 가중치를 가리킬 수 있다. `ollama list` 의 ID 또는 `/api/show` 의 digest |
| `ollama_version` | `"0.12.3"` | 같은 seed 라도 버전이 다르면 출력이 달라질 수 있다 |
| `temperature` | `0.7` | |
| `seed` | `1` | 반복 회차마다 바꾼다 (아래) |
| `prompt_version` | `"v1"` | 프롬프트를 바꾸면 올린다 |

추가 필드(생성 시각, 소요 시간, 재시도 횟수 등)는 자유롭게 넣어도 된다. batch 는 위 6개만 확인한다.

## 반복 규칙

temperature 0 에 seed 를 고정하면 몇 번을 돌려도 같은 출력이 나와 반복의 의미가 없다. 생성기의 편차를 재려면 **회차마다 seed 를 바꾸고(seed = 회차 번호) temperature 는 0 보다 크게** 둔다. 즉 "시나리오당 3회 반복" = seed 1·2·3 으로 만든 후보 파일 3개다.

`batch.py --reps` 는 같은 후보 파일을 랩에서 여러 번 실행하는 것(랩 쪽 편차)이라 위 반복과 다르다. generated 후보는 보통 `--reps 1` 로 돌린다.

## 실행

```bash
python3 pipeline/batch.py --candidates generated --reps 1
```

meta 가 없거나 필드가 빠진 후보가 하나라도 있으면 아무것도 실행하지 않고 중단한다(AGENTS.md 핵심 원칙). 결과 CSV 의 generator 열에는 `모델@digest앞12자(sha256: 제외)|t=temperature|seed=seed|p=프롬프트버전` 이 남고, manifest 에는 meta 전체가 남는다.
