"""랩 컨테이너 실행 헬퍼."""

import os
import shlex
import subprocess

PODMAN = shlex.split(os.environ.get("PODMAN", "sudo podman"))
FW = os.environ.get("FW_CONTAINER", "fw")


def exec_in(container, *cmd, stdin=None, timeout=30):
    return subprocess.run(
        [*PODMAN, "exec", "-i", container, *cmd],
        input=stdin, capture_output=True, text=True, timeout=timeout,
    )
