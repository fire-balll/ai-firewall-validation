#!/usr/bin/env python3
"""자연어 요구사항 -> IR 룰셋. (담당: 서진정)

현재는 --mock 만 동작한다: 시나리오의 정답 룰셋을 그대로 내보낸다(파이프라인 연결용).
TODO: LLM 호출 + 구조화 출력(schema/rule.schema.json) 구현
TODO: --feedback 으로 받은 검증·프로브 실패 내용을 프롬프트에 넣어 재생성

사용: generate.py --scenario scenarios/req-001.json --mock > out/candidate.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json, schema_errors  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--mock", action="store_true", help="정답 룰셋을 그대로 출력")
    ap.add_argument("--feedback", help="이전 검증/프로브 결과 JSON (재생성용)")
    args = ap.parse_args()

    scenario = load_json(args.scenario)
    if not args.mock:
        sys.exit("LLM 생성은 아직 구현되지 않았다. --mock 을 쓸 것.")

    ruleset = scenario["gold"]
    errors = schema_errors(ruleset)
    if errors:
        sys.exit("정답 룰셋이 스키마를 위반한다:\n" + "\n".join(errors))
    json.dump(ruleset, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
