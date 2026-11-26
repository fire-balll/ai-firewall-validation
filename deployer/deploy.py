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
  aborted=true 이면 실행 실패(프로브 예외 등)로 원복하고 종료 코드 1. 이때 detect_s·mttr_s 는 비운다(결과가 아니므로).
    rolled_back 은 "프로브 실패를 보고 되돌렸는가" 그대로 남긴다. 그래서 aborted 와 rolled_back 이 함께 true 일 수 있다
    (롤백 뒤 타이머가 이미 만료돼 있던 경우). 복구 시간을 모을 때는 aborted 를 먼저 거른다
  감시 도중 타이머가 먼저 만료되면 그 뒤 프로브는 원래 룰셋을 본 것이므로 결과로 내지 않고 aborted
사용: deploy.py out/candidate.json --scenario scenarios/req-001.json --watch 60 > out/deploy.json
"""

import argparse
import json
import os
import signal
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


def snapshot(managed=False):
    # Preserve main's legacy rollback format; stable rendering is opt-in only.
    flags = ("-n", "-y", "-s") if managed else ()
    res = exec_in(FW, "nft", *flags, "list", "ruleset")
    if res.returncode != 0:
        raise RuntimeError(f"nft list 실패: {res.stderr.strip()}")
    return "flush ruleset\n" + res.stdout


PROBE_RESTORE_RESERVE = 91


def probe(scenario_path, timeout=None, *, deadman_deadline=None):
    if timeout is not None:
        return _managed_probe(scenario_path, timeout=timeout)
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


def _managed_probe(scenario_path, timeout=None):
    # 프로브 전후로 랩이 온전해야 결과를 믿을 수 있다 (도중에 꺼져도 거짓 block 이 나온다)
    require_lab()
    if timeout is None:
        # Legacy path still bounds its child, independent of managed watch time.
        timeout = 300
    if timeout <= 0:
        raise RuntimeError('probe deadline expired')
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "prober" / "probe.py"), scenario_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=(os.name == 'posix'),
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except BaseException as ex:
        # Timeouts and termination signals both own the direct child and its
        # nested podman process. Reap before the managed rollback begins.
        try:
            if os.name == 'posix':
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        proc.communicate()
        if isinstance(ex, subprocess.TimeoutExpired):
            raise RuntimeError('probe deadline expired') from ex
        raise
    res = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    if res.returncode != 0:
        lines = res.stderr.strip().splitlines()
        raise RuntimeError(f"prober 실패 (exit {res.returncode}): {lines[-1] if lines else ''}")
    require_lab()
    return json.loads(res.stdout)


def complete_probe(result, expected):
    """Require one observed row per scenario probe on legacy and managed paths."""
    if (not isinstance(result, dict) or set(result) != {'results'} or
            not isinstance(result.get('results'), list)):
        raise RuntimeError('incomplete probe observation')
    rows = result['results']
    if len(rows) != len(expected):
        raise RuntimeError('incomplete probe observation')
    seen = set()
    for row in rows:
        # Current prober rows add optional evidence and probe-set identity.
        required = {'id', 'kind', 'expect', 'observed', 'pass'}
        if (not isinstance(row, dict) or
                not required.issubset(row) or
                not set(row).issubset(required | {'evidence', 'set'}) or
                ('evidence' in row and not isinstance(row['evidence'], str)) or
                ('set' in row and row['set'] not in ('v1', 'v2'))):
            raise RuntimeError('incomplete probe observation')
        ident = row['id']
        if not isinstance(ident, str) or ident not in expected or ident in seen:
            raise RuntimeError('incomplete probe observation')
        seen.add(ident)
        reference = expected[ident]
        if (row['kind'] != reference['kind'] or row['expect'] != reference['expect'] or
                row.get('set', 'v1') != reference.get('set', 'v1') or
                row['observed'] not in ('allow', 'block') or
                type(row['pass']) is not bool or
                row['pass'] != (row['observed'] == row['expect'])):
            raise RuntimeError('incomplete probe observation')
    return rows

def restore_managed(store, before, candidate, stateful, saved, observe):
    """Do not erase an uncooperative writer's policy during rollback.

    An atomic nft apply can fail before changing the ruleset, or another writer
    can modify it after our apply. Only the known before/candidate structure may
    be restored automatically; anything else retains the durable intent.
    """
    from deployer.managed import structure
    observed = observe()
    try:
        structure(observed, candidate, stateful)
    except RuntimeError:
        structure(observed, json.loads(before.ir_bytes), before.stateful)
        if observed != observe():
            raise RuntimeError('nft changed during managed restoration')
        store.publish(before.ir_bytes, before.stateful, before.commit, observed)
        store.finish()
        return
    # The cooperative lock is not a kernel fence against external nft writers.
    if observed != observe():
        raise RuntimeError('nft changed during managed restoration')
    nft_apply(saved)
    restored = observe()
    structure(restored, json.loads(before.ir_bytes), before.stateful)
    store.publish(before.ir_bytes, before.stateful, before.commit, restored)
    store.finish()

def validator_check(args, stateful):
    """Cross the validator boundary through its public JSON CLI only."""
    result = subprocess.run(
        [sys.executable, str(ROOT / 'validator/validate.py'), args.ruleset,
         '--nft-check', '--stateful', 'yes' if stateful else 'no', '--compare-current'],
        capture_output=True, text=True, encoding='utf-8', timeout=300,
        env={**os.environ, 'FW_MANAGED_STORE': str(args.managed_store),
             'PYTHONIOENCODING': 'utf-8'},
    )
    if result.returncode:
        raise RuntimeError(f'validator CLI failed (exit {result.returncode}): {result.stderr.strip()}')
    try:
        check = json.loads(result.stdout)
        if (not isinstance(check, dict) or type(check.get('ok')) is not bool or
                check.get('risk') not in ('low', 'high') or
                not isinstance(check.get('reasons'), list)):
            raise ValueError('invalid validator response')
        if check['ok']:
            comparison = check['comparison']
            counts = comparison['counts']
            if (comparison['status'] != 'offline_only' or
                    any(type(counts[key]) is not int or counts[key] < 0
                        for key in ('allow_to_block', 'block_to_allow'))):
                raise ValueError('invalid comparison response')
        return check
    except (ValueError, KeyError, TypeError) as ex:
        raise RuntimeError('invalid validator CLI JSON') from ex


def managed_apply(args, stateful):
    """Opt-in managed path; legacy snapshot/deadman remain, shared probe changes."""
    from deployer.managed import ManagedStore, digest, structure


    out = {"stateful": stateful, "applied": False, "rolled_back": False,
           "aborted": False, "error": None, "t_apply": None, "t_detect": None,
           "t_restored": None, "detect_s": None, "mttr_s": None, "probe": None}
    store = ManagedStore(args.managed_store)
    if (type(args.watch) is not int or args.watch < 0 or
            type(args.interval) is not int or args.interval <= 0):
        raise ValueError('watch must be nonnegative and interval positive')
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
    raw = Path(args.ruleset).read_bytes()
    if not args.expected_sha256 or digest(raw) != args.expected_sha256:
        raise RuntimeError('candidate changed since validation')
    candidate = json.loads(raw)

    commit = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=True).stdout.strip()
    with store.locked():
        before = store.current()  # actual nft + persisted IR structure and digest
        if before.snapshot_token != args.expected_current:
            raise RuntimeError('current changed since validation/approval')
        check = validator_check(args, stateful)
        if not check['ok']:
            raise RuntimeError('candidate validation failed; no managed verdict')
        if check.get('candidate_sha256') != digest(raw):
            raise RuntimeError('candidate changed during validator CLI')
        comparison = check['comparison']
        if comparison.get('baseline_snapshot_token') != before.snapshot_token or store.current() != before:
            raise RuntimeError('current changed during validator CLI')
        if check['risk'] == 'high' and not args.approved_high:
            raise RuntimeError('high-risk candidate requires explicit approval')
        if comparison.get('status') != 'offline_only':
            raise RuntimeError('managed comparison unavailable')
        changed = comparison['counts']['allow_to_block'] + comparison['counts']['block_to_allow']
        if changed and not args.approved_replacement:
            raise RuntimeError('replacement policy change requires explicit approval')
        # Keep a restorable full nft dump, not the stateless digest observation.
        saved = snapshot(managed=True)
        if store.current() != before:
            raise RuntimeError('current changed before managed intent')
        store.intent(before, raw, stateful, saved)
        attempted = False
        watched_signals = (signal.SIGTERM,) + ((signal.SIGHUP,) if hasattr(signal, 'SIGHUP') else ())
        previous_handlers = {}
        def interrupted(signum, _frame):
            # Defer termination to the transaction's rollback handler.
            signal.signal(signum, signal.SIG_IGN)
            raise RuntimeError(f'managed transaction interrupted by signal {signum}')
        try:
            for sig in watched_signals:
                previous_handlers[sig] = signal.signal(sig, interrupted)
            # Recheck under the lock immediately before the only nft write.
            from deployer.managed import live_snapshot as observe
            if digest(observe().encode()) != before.snapshot_token:
                raise RuntimeError('current changed immediately before apply')
            attempted = True
            nft_apply(to_nft(candidate, stateful=stateful))
            structure(observe(), candidate, stateful)
            out['applied'] = True
            out['t_apply'] = time.time()
            deadline = out['t_apply'] + args.watch
            while True:
                result = probe(args.scenario, timeout=max(1, deadline - time.time()))
                out['probe'] = result
                rows = complete_probe(result, expected)
                if args.watch and time.time() > deadline:
                    raise RuntimeError('probe watch deadline expired')
                if not all(r['pass'] for r in rows):
                    out['t_detect'] = time.time()
                    restore_managed(store, before, candidate, stateful, saved, observe)
                    out['t_restored'] = time.time()
                    out['rolled_back'] = True
                    out['detect_s'] = round(out['t_detect'] - out['t_apply'], 3)
                    out['mttr_s'] = round(out['t_restored'] - out['t_detect'], 3)
                    return out
                if time.time() + args.interval > deadline:
                    break
                time.sleep(args.interval)
            observed = observe()
            structure(observed, candidate, stateful)
            store.publish(raw, stateful, commit, observed)
            store.finish()
            return out
        except BaseException:
            # An interrupted apply or failed readback cannot become a success.
            # If restoration/recording fails, intent remains as a recovery fence.
            if attempted:
                restore_managed(store, before, candidate, stateful, saved, observe)
            else:
                store.finish()
            raise
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)


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
    ap.add_argument('--managed-store', help='protected POSIX managed current directory (opt-in)')
    ap.add_argument('--approved-high', action='store_true', help='explicit high risk approval for managed path')
    ap.add_argument('--approved-replacement', action='store_true', help='explicit replacement difference approval')
    ap.add_argument('--expected-sha256', help='validator-observed candidate byte digest')
    ap.add_argument('--expected-current', help='validator-observed baseline nft digest')
    args = ap.parse_args()

    stateful = not args.stateless and stateful_for(args.ruleset)
    if args.managed_store:
        try:
            out = managed_apply(args, stateful)
        except BaseException as ex:
            print(f'managed apply aborted: {type(ex).__name__}: {ex}', file=sys.stderr)
            sys.exit(1)  # no result JSON/CSV on incomplete observation
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return
    if os.environ.get('FW_MANAGED_STORE'):
        print('managed 호스트에서 레거시 적용 금지', file=sys.stderr)
        sys.exit(1)
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
