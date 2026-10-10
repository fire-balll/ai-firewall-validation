"""랩 컨테이너 실행 헬퍼."""

import os
import shlex
import subprocess

PODMAN = shlex.split(os.environ.get("PODMAN", "sudo podman"))
FW = os.environ.get("FW_CONTAINER", "fw")


def exec_in(container, *cmd, stdin=None, timeout=30):
    """컨테이너 안에서 명령을 실행한다. stdout/stderr 는 str 로 돌려준다.

    stdin 은 UTF-8 bytes 로 그대로 넘긴다. text=True 로 넘기면 Windows 에서 \n 이 \r\n 으로
    바뀌어 nft 가 \r 을 문법 오류로 본다 (#15 에서 발견).
    """
    res = subprocess.run(
        [*PODMAN, "exec", "-i", container, *cmd],
        input=stdin.encode("utf-8") if stdin is not None else None,
        capture_output=True, timeout=timeout,
    )
    return subprocess.CompletedProcess(
        res.args, res.returncode,
        res.stdout.decode("utf-8", errors="replace"),
        res.stderr.decode("utf-8", errors="replace"),
    )


def running_containers():
    res = subprocess.run([*PODMAN, "ps", "--format", "{{.Names}}"],
                         capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        raise RuntimeError(f"podman ps 실패: {res.stderr.strip()}")
    return set(res.stdout.split())


def require_lab():
    """fw 와 토폴로지의 모든 호스트가 실행 중인지 확인한다. 아니면 RuntimeError.

    받는 쪽 호스트가 꺼져 있으면 프로브는 방화벽 drop 과 똑같이 timed out 으로 보이고,
    닫힌 포트 판정(Connection refused = 방화벽 통과)도 성립하지 않는다.
    그래서 프로브 결과를 쓰기 전후로 랩이 온전한지 확인해야 한다. (AGENTS.md 핵심 원칙)
    """
    from common.topology import hosts

    missing = sorted(({FW} | set(hosts())) - running_containers())
    if missing:
        raise RuntimeError(f"랩 컨테이너가 실행 중이 아님: {', '.join(missing)}")
