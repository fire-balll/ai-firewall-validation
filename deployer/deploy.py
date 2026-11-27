#!/usr/bin/env python3
"""적용 + 감시 + 자동 롤백. (담당: 정택준)

OPNsense savepoint 와 같은 구조를 nftables 로 구현한다.
  1. nft list ruleset 으로 현재 상태 저장
  2. 후보 룰셋을 nft -f 로 원자적 적용 (첫 줄 flush ruleset)
  3. 감시 기간 동안 프로브 반복
  4. 실패 시 저장해 둔 상태로 복원하고 시간 기록, 통과 시 확정

deployer 가 강제 종료돼도 후보 룰이 남지 않도록, 적용 전에 fw 안에 데드맨 타이머를 띄운다(deadman.py, #29).
감시 기간 + --deadman-grace 초 안에 해제하지 못하면 fw 가 스스로 스냅샷으로 복원한다.
시작할 때 이전 실행이 남긴 타이머가 있으면 먼저 복원한다(recovered).

출력: {"stateful", "applied", "rolled_back", "aborted", "error", "t_apply", "t_detect", "t_restored", "detect_s",
       "mttr_s", "probe", "deadman", "recovered"}
  aborted=true 이면 실행 실패(관측 불완전·프로브 예외·timeout·예산 부족 등)로 원복하고 종료 코드 1. 이때 detect_s·mttr_s 는 비운다(결과가 아니므로).
    rolled_back 은 "프로브 실패를 보고 되돌렸는가" 그대로 남긴다. 그래서 aborted 와 rolled_back 이 함께 true 일 수 있다
    (롤백 뒤 타이머가 이미 만료돼 있던 경우). 복구 시간을 모을 때는 aborted 를 먼저 거른다
  감시 도중 타이머가 먼저 만료되면 그 뒤 프로브는 원래 룰셋을 본 것이므로 결과로 내지 않고 aborted
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
from common.ir import load_json, stateful_for, to_nft  # noqa: E402
from common.lab import FW, exec_in, require_lab  # noqa: E402
from deployer import deadman  # noqa: E402


def nft_apply(text):
    res = exec_in(FW, "nft", "-f", "-", stdin=text)
    if res.returncode != 0:
        raise RuntimeError(f"nft -f 실패: {res.stderr.strip()}")


def snapshot():
    res = exec_in(FW, "nft", "list", "ruleset")
    if res.returncode != 0:
        raise RuntimeError(f"nft list 실패: {res.stderr.strip()}")
    return "flush ruleset\n" + res.stdout


# lab 후검사 30s + snapshot 복원 30s + disarm 30s + scheduling 여유 1s.
# 직접 자식의 실행 예산만 제한하며 POSIX 자손 정리를 보장하지 않는다.
PROBE_RESTORE_RESERVE = 91


def probe(scenario_path, *, deadman_deadline=None):
    # 프로브 전후로 랩이 온전해야 결과를 믿을 수 있다 (도중에 꺼져도 거짓 block 이 나온다)
    if deadman_deadline is not None and deadman_deadline - time.monotonic() <= PROBE_RESTORE_RESERVE:
        raise RuntimeError("probe budget exhausted before lab check")
    require_lab()
    timeout = 300
    if deadman_deadline is not None:
        timeout = min(timeout, deadman_deadline - time.monotonic() - PROBE_RESTORE_RESERVE)
        if timeout <= 0:
            raise RuntimeError("probe budget exhausted before child launch")
    res = subprocess.run(
        [sys.executable, str(ROOT / "prober" / "probe.py"), scenario_path],
        capture_output=True, text=True, timeout=timeout,
    )
    if res.returncode != 0:
        lines = res.stderr.strip().splitlines()
        raise RuntimeError(f"prober 실패 (exit {res.returncode}): {lines[-1] if lines else ''}")
    require_lab()
    return json.loads(res.stdout)


def complete_probe(result, expected):
    """Require one consistent observation per scenario probe before committing."""
    if not isinstance(result, dict) or not isinstance(result.get('results'), list):
        raise RuntimeError('incomplete probe observation')
    rows = result['results']
    if len(rows) != len(expected):
        raise RuntimeError('incomplete probe observation')
    seen = set()
    required = {'id', 'kind', 'expect', 'observed', 'pass'}
    for row in rows:
        if (not isinstance(row, dict) or not required.issubset(row) or
                not set(row).issubset(required | {'evidence', 'set'}) or
                ('evidence' in row and not isinstance(row['evidence'], str))):
            raise RuntimeError('incomplete probe observation')
        ident = row['id']
        if not isinstance(ident, str) or ident not in expected or ident in seen:
            raise RuntimeError('incomplete probe observation')
        seen.add(ident)
        reference = expected[ident]
        if (row['kind'] != reference['kind'] or row['expect'] != reference['expect'] or
                row.get('set', 'v1') not in ('v1', 'v2') or
                row.get('set', 'v1') != reference.get('set', 'v1') or
                row['observed'] not in ('allow', 'block') or
                type(row['pass']) is not bool or
                row['pass'] != (row['observed'] == row['expect'])):
            raise RuntimeError('incomplete probe observation')
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ruleset")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--watch", type=int, default=60, help="감시 기간(초)")
    ap.add_argument("--interval", type=int, default=5, help="프로브 간격(초)")
    ap.add_argument("--stateless", action="store_true",
                    help="상태 추적 룰 없이 적용 (오류 주입 state 유형). 생략 시 후보 파일명으로 판단")
    ap.add_argument("--deadman-grace", type=int, default=300,
                    help="데드맨 타이머 = 감시 기간 + 이 값(초). 마지막 프로브·복원이 끝날 시간보다 길어야 한다")
    args = ap.parse_args()

    stateful = not args.stateless and stateful_for(args.ruleset)
    out = {"stateful": stateful, "applied": False, "rolled_back": False, "aborted": False, "error": None,
           "t_apply": None, "t_detect": None, "t_restored": None,
           "detect_s": None, "mttr_s": None, "probe": None, "deadman": None, "recovered": []}

    # 적용 전 실패도 적용 후 실패와 같은 형식으로 남긴다 (후보는 적용되지 않은 상태)
    try:
        scenario = load_json(args.scenario)
        probes = scenario.get('probes')
        if (not isinstance(probes, list) or not probes or
                any(not isinstance(p, dict) or not isinstance(p.get('id'), str) or
                    not isinstance(p.get('kind'), str) or p.get('expect') not in ('allow', 'block')
                    for p in probes)):
            raise RuntimeError('invalid scenario probes')
        expected = {p['id']: p for p in probes}
        if len(expected) != len(probes):
            raise RuntimeError('duplicate scenario probe IDs')
        require_lab()  # 랩이 온전하지 않으면 후보 룰을 적용조차 하지 않는다
        out["recovered"] = deadman.recover()  # 남은 타이머가 이번 실행 도중 만료되지 않게 먼저 처리한다
        saved = snapshot()
        # arm 호출 자체와 후보 적용에 걸린 시간도 잔여 예산에서 차감한다.
        deadman_deadline = time.monotonic() + args.watch + args.deadman_grace
        token = deadman.arm(saved, args.watch + args.deadman_grace)
        try:
            nft_apply(to_nft(load_json(args.ruleset), stateful=stateful))  # nft -f 는 원자적이라 실패하면 아무것도 바뀌지 않는다
        except Exception:
            deadman.disarm(token)
            raise
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
            result = probe(args.scenario, deadman_deadline=deadman_deadline)
            out["probe"] = result
            rows = complete_probe(result, expected)
            if not all(r["pass"] for r in rows):
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
        out["deadman"] = deadman.disarm(token)
        if out["deadman"] != "disarmed":
            raise RuntimeError(f"데드맨 타이머가 감시 중에 만료됨({out['deadman']}). "
                               "관측 구간에 원래 룰셋이 섞였을 수 있다. --deadman-grace 를 늘릴 것")
    except BaseException as e:
        out["aborted"] = True
        out["error"] = f"{type(e).__name__}: {e}"
        out["detect_s"] = out["mttr_s"] = None  # 실행 실패의 측정값이 복구 시간 집계에 섞이지 않게 한다
        if not out["rolled_back"]:
            try:
                nft_apply(saved)
                out["t_restored"] = time.time()
            except Exception as restore_err:
                print(f"복원 실패. 수동 복원 필요: nft -f 로 아래 스냅샷 적용\n{saved}",
                      file=sys.stderr)
                out["error"] += f" / 복원 실패: {restore_err}"
        if out["deadman"] is None:
            try:
                out["deadman"] = deadman.disarm(token)
            except Exception as disarm_err:  # 해제하지 못해도 타이머는 같은 스냅샷으로 복원할 뿐이다
                out["error"] += f" / 타이머 해제 실패: {disarm_err}"
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
        print()
        sys.exit(1)

    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
