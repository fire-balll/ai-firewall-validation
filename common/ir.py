"""IR 로드, 스키마 검증, nftables 변환."""

import ipaddress
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "schema" / "rule.schema.json").read_text(encoding="utf-8")
)
_validator = Draft202012Validator(SCHEMA)

TABLE = "fwlab"


def load_json(path):
    if path == "-":
        import sys
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def schema_errors(ruleset):
    """스키마 위반 목록. 비어 있으면 통과."""
    errors = []
    for e in _validator.iter_errors(ruleset):
        where = "/".join(str(p) for p in e.absolute_path) or "(root)"
        errors.append(f"{where}: {e.message}")
    for r in ruleset.get("rules", []):
        for field in ("src", "dst"):
            v = r.get(field, "any")
            if v == "any":
                continue
            try:
                ipaddress.ip_network(v, strict=True)
            except ValueError as ex:
                errors.append(f"{r.get('id')}.{field}: {ex}")
    return errors


def _match(rule):
    parts = []
    if rule["src"] != "any":
        parts.append(f"ip saddr {rule['src']}")
    if rule["dst"] != "any":
        parts.append(f"ip daddr {rule['dst']}")
    proto, dport = rule["proto"], rule["dport"]
    if proto in ("tcp", "udp"):
        parts.append(f"{proto} dport {dport}" if dport != "any" else f"meta l4proto {proto}")
    elif proto == "icmp":
        parts.append("ip protocol icmp")
    return " ".join(parts)


def sorted_rules(ruleset):
    return sorted(ruleset["rules"], key=lambda r: (r["priority"], r["id"]))


# 파일명에 이 표시가 있는 후보는 상태 추적 룰 없이 변환한다 (오류 주입 state 유형, mutations/README.md)
STATELESS_MARK = "-state-"


def stateful_for(path):
    """후보 파일명으로 상태 추적 룰을 넣을지 정한다. IR 에는 이 정보를 담을 필드가 없다."""
    return STATELESS_MARK not in Path(path).name


def to_nft(ruleset, stateful=True):
    """IR 룰셋을 nft -f 로 적용할 전체 룰셋 텍스트로 변환한다.

    forward 체인 기본 정책은 drop(default deny)이고, 상태 추적 허용 룰을 맨 앞에 둔다.
    룰은 priority 오름차순으로 배치되며 first-match로 동작한다.

    stateful=False 는 상태 추적 룰을 뺀다. 응답 트래픽이 default deny 에 걸리므로
    연결이 성립하지 않는다. common/sim.py 는 응답을 항상 허용으로 가정하므로
    이 경우 시뮬레이터와 랩의 판정이 갈린다 (동적 검증만 잡는 오류의 대표 사례).
    """
    lines = [
        "flush ruleset",
        f"table inet {TABLE} {{",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
    ]
    if stateful:
        lines.append("    ct state established,related accept")
    for r in sorted_rules(ruleset):
        match = _match(r)
        lines.append(f'    {match + " " if match else ""}counter {r["action"]} comment "{r["id"]}"')
    lines += ["  }", "}", ""]
    return "\n".join(lines)
