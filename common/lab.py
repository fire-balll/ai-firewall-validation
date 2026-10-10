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
