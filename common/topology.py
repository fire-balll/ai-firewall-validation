"""lab/topology.env 를 읽어 호스트 이름 -> IP 와 UDP 에코 서비스 위치를 돌려준다. up.sh 와 같은 파일을 쓴다."""

import re
import shlex

from common.ir import ROOT

TOPOLOGY = ROOT / "lab" / "topology.env"


def _env():
    text = TOPOLOGY.read_text(encoding="utf-8")
    env = {}
    for token in shlex.split(text, comments=True):
        key, sep, value = token.partition("=")
        if sep:
            env[key] = value
    return env


def hosts():
    env = _env()
    prefixes = dict(n.split(":", 1) for n in env["NETWORKS"].split())
    out = {}
    for line in env["HOSTS"].splitlines():
        if not line.strip():
            continue
        name, net, num = line.split(":", 3)[:3]
        out[name] = f"{prefixes[net]}.{num}"
    return out


def udp_echo():
    """UDP 에코 서비스(lab/udp-echo.py)가 떠 있는 (IP, 포트) 집합. 받은 데이터그램에 항상 응답하는 곳이다.

    HOSTS 의 실행 명령에서 "udp-echo <포트>" 를 찾는다. prober 가 UDP "응답 없음" 을 차단으로 볼 수 있는 곳은 여기뿐이다.
    """
    env = _env()
    prefixes = dict(n.split(":", 1) for n in env["NETWORKS"].split())
    out = set()
    for line in env["HOSTS"].splitlines():
        if not line.strip():
            continue
        _, net, num, cmd = line.split(":", 3)
        for port in re.findall(r"\budp-echo\s+(\d+)", cmd):
            out.add((f"{prefixes[net]}.{num}", int(port)))
    return out
