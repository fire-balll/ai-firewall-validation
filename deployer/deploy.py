#!/usr/bin/env python3
"""적용 + 감시 + 자동 롤백. (담당: 정택준)

OPNsense savepoint 와 같은 구조를 nftables 로 구현한다.
  1. nft list ruleset 으로 현재 상태 저장
  2. 후보 룰셋을 nft -f 로 원자적 적용 (첫 줄 flush ruleset)
  3. 감시 기간 동안 프로브 반복
  4. 실패 시 저장해 둔 상태로 복원하고 시간 기록, 통과 시 확정

출력: {"applied", "rolled_back", "aborted", "error", "t_apply", "t_detect", "t_restored", "detect_s", "mttr_s", "probe"}
  aborted=true 이면 실행 실패(프로브 예외 등)로 원복하고 종료 코드 1
사용: deploy.py out/candidate.json --scenario scenarios/req-001.json --watch 60 > out/deploy.json
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common.ir import load_json, to_nft  # noqa: E402
from common.lab import FW, exec_in, require_lab  # noqa: E402


def nft_apply(text):
    res = exec_in(FW, "nft", "-f", "-", stdin=text)
    if res.returncode != 0:
        raise RuntimeError(f"nft -f 실패: {res.stderr.strip()}")


def snapshot():
    res = exec_in(FW, "nft", "list", "ruleset")
    if res.returncode != 0:
        raise RuntimeError(f"nft list 실패: {res.stderr.strip()}")
    return "flush ruleset\n" + res.stdout


def probe(scenario_path):
    # 프로브 전후로 랩이 온전해야 결과를 믿을 수 있다 (도중에 꺼져도 거짓 block 이 나온다)
    require_lab()
    res = subprocess.run(
        [sys.executable, str(ROOT / "prober" / "probe.py"), scenario_path],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        lines = res.stderr.strip().splitlines()
        raise RuntimeError(f"prober 실패 (exit {res.returncode}): {lines[-1] if lines else ''}")
    require_lab()
    return json.loads(res.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ruleset")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--watch", type=int, default=60, help="감시 기간(초)")
    ap.add_argument("--interval", type=int, default=5, help="프로브 간격(초)")
    args = ap.parse_args()

    out = {"applied": False, "rolled_back": False, "aborted": False, "error": None,
           "t_apply": None, "t_detect": None, "t_restored": None,
           "detect_s": None, "mttr_s": None, "probe": None}

    # 적용 전 실패도 적용 후 실패와 같은 형식으로 남긴다 (후보는 적용되지 않은 상태)
    try:
        require_lab()  # 랩이 온전하지 않으면 후보 룰을 적용조차 하지 않는다
        saved = snapshot()
        nft_apply(to_nft(load_json(args.ruleset)))  # nft -f 는 원자적이라 실패하면 아무것도 바뀌지 않는다
    except Exception as e:
        out["aborted"] = True
        out["error"] = f"{type(e).__name__}: {e}"
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
        print()
        sys.exit(1)
    out["applied"] = True
    out["t_apply"] = time.time()

    # 적용 이후 무엇이 실패하든(프로브 예외, Ctrl-C 포함) 후보 룰을 남겨 두지 않는다.
    # 이 경우는 실험 결과가 아니라 실행 실패이므로 rolled_back/MTTR 대신 aborted 로 표시한다.
    try:
        deadline = out["t_apply"] + args.watch
        while True:
            result = probe(args.scenario)
            out["probe"] = result
            if not all(r["pass"] for r in result["results"]):
                out["t_detect"] = time.time()
                nft_apply(saved)
                out["t_restored"] = time.time()
                out["rolled_back"] = True
                out["detect_s"] = round(out["t_detect"] - out["t_apply"], 3)
                out["mttr_s"] = round(out["t_restored"] - out["t_detect"], 3)
                break
            if time.time() + args.interval > deadline:
                break
            time.sleep(args.interval)
    except BaseException as e:
        out["aborted"] = True
        out["error"] = f"{type(e).__name__}: {e}"
        if not out["rolled_back"]:
            try:
                nft_apply(saved)
                out["t_restored"] = time.time()
            except Exception as restore_err:
                print(f"복원 실패. 수동 복원 필요: nft -f 로 아래 스냅샷 적용\n{saved}",
                      file=sys.stderr)
                out["error"] += f" / 복원 실패: {restore_err}"
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
        print()
        sys.exit(1)

    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
