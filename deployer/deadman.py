"""fw 컨테이너 안의 데드맨 타이머 (#29). (담당: 정택준)

deploy.py 는 자기 프로세스가 복원 주체라, deployer 가 강제 종료(kill -9, OOM)되면 후보 룰이 fw 에 남는다.
OPNsense savepoint 처럼 방화벽 쪽이 스스로 복원하도록, 적용 전에 fw 안에 타이머를 띄운다.

  arm(saved, ttl)  스냅샷을 fw 에 저장하고 "ttl 초 뒤 스냅샷 적용" 프로세스를 띄운다. 토큰을 돌려준다
  disarm(token)    타이머를 해제한다. "disarmed"(해제함) | "fired"(이미 복원됨) | "missing"(흔적 없음)
  recover()        이전 실행(deployer 가 죽음)이 남긴 타이머를 처리한다. 아직 대기 중이면 지금 복원하고,
                   이미 만료돼 복원됐으면 표시만 지운다. 처리한 토큰 목록을 돌려준다

타이머와 해제가 동시에 일어나도 한쪽만 동작하도록, 둘 다 armed.<토큰> 파일을 mv 로 가져간 쪽만 진행한다
(같은 파일시스템 안의 rename 은 원자적이다). 타이머: armed → fired 로 옮긴 뒤 nft -f. 해제: armed → done.
"""

import os
import re
import uuid

from common.lab import FW, exec_detached, exec_in

TOKEN = re.compile(r"^[0-9a-f]{32}$")


def _dir():
    # fw 컨테이너 안의 경로. 테스트에서 바꿀 수 있게 호출할 때 읽는다
    return os.environ.get("FW_DEADMAN_DIR", "/run/fwlab-deadman")


def _sh(script, stdin=None):
    res = exec_in(FW, "sh", "-c", script, stdin=stdin)
    if res.returncode != 0:
        raise RuntimeError(f"데드맨 타이머 명령 실패 (exit {res.returncode}): {res.stderr.strip()}")
    return res.stdout


def arm(saved, ttl):
    if type(ttl) is not int or ttl <= 0:
        raise ValueError(f"ttl 은 양의 정수여야 함: {ttl!r}")
    d, token = _dir(), uuid.uuid4().hex
    # 스냅샷을 먼저 쓰고 armed 표시를 나중에 만든다. armed 가 있으면 스냅샷도 있다
    _sh(f'mkdir -p {d} && cat > {d}/snap.{token} && : > {d}/armed.{token}', stdin=saved)
    timer = (f'sleep {ttl}; mv {d}/armed.{token} {d}/fired.{token} 2>/dev/null'
             f' && nft -f {d}/snap.{token} && rm -f {d}/snap.{token}')
    try:
        exec_detached(FW, "sh", "-c", timer)
    except Exception:
        _sh(f'rm -f {d}/armed.{token} {d}/snap.{token}')
        raise
    return token


def disarm(token):
    if not TOKEN.match(token):
        raise ValueError(f"토큰 형식이 아님: {token!r}")
    d = _dir()
    out = _sh(f'if mv {d}/armed.{token} {d}/done.{token} 2>/dev/null; then'
              f' rm -f {d}/done.{token} {d}/snap.{token}; echo disarmed;'
              f' elif [ -e {d}/fired.{token} ]; then rm -f {d}/fired.{token}; echo fired;'
              f' else echo missing; fi').strip()
    if out not in ("disarmed", "fired", "missing"):
        raise RuntimeError(f"데드맨 타이머 해제 결과를 알 수 없음: {out!r}")
    return out


def recover():
    """이전 deployer 가 죽어 남은 타이머를 처리한다.

    armed: 아직 대기 중. 그대로 두면 이번 실행 도중에 만료돼 룰셋을 바꾸므로 지금 가져와 스냅샷을 적용한다.
    fired: 이미 만료돼 fw 가 복원했다(스냅샷도 지워짐). 표시만 지운다. 스냅샷이 남아 있으면 복원 중이거나
           복원에 실패한 것이라 결과를 믿을 수 없으므로 실패로 끝낸다.
    """
    d = _dir()
    out = _sh(f'mkdir -p {d}; for f in {d}/armed.*; do [ -e "$f" ] || continue; t=${{f##*/armed.}};'
              f' mv "$f" {d}/fired.$t 2>/dev/null || continue;'  # 그 사이 타이머가 먼저 가져갔다
              f' nft -f {d}/snap.$t || exit 1; rm -f {d}/snap.$t {d}/fired.$t; echo $t; done;'
              f' for f in {d}/fired.*; do [ -e "$f" ] || continue; t=${{f##*/fired.}};'
              f' if [ -e {d}/snap.$t ]; then echo "타이머 복원이 끝나지 않음: $t" >&2; exit 1; fi;'
              f' rm -f "$f"; echo $t; done')
    tokens = out.split()
    if any(not TOKEN.match(t) for t in tokens):
        raise RuntimeError(f"데드맨 복구 출력을 알 수 없음: {out!r}")
    return tokens
