"""lab/topology.env 를 읽어 호스트 이름 -> IP 를 돌려준다. up.sh 와 같은 파일을 쓴다."""

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
