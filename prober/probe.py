#!/usr/bin/env python3
"""능동 프로빙. 실제로 연결을 맺어 허용/차단을 관측한다. (담당: 강윤서)

tcpreplay 는 쓰지 않는다: 상태 기반 방화벽에서 handshake 없는 재생은 차단으로 오측정된다.
방화벽 판정을 잰다: 서버의 포트가 닫혀 있어도 방화벽이 통과시켰으면(Connection refused) allow 다.

현재 구현: tcp(nc -vz, 프로브에 "tool": "curl" 이면 HTTP 요청, "tool": "nmap" 이면 포트 스캔,
"tool": "hping3" 이면 SYN 1개), udp(데이터그램 송수신, python3), icmp(ping)
방화벽 drop 으로 확실한 경우(nc·curl 연결 단계 timeout, nmap filtered/no-response, hping3 응답 없음,
UDP 에코 서비스의 응답 없음, ping 응답 없음)만 block 으로 판정한다.
그 외 실패(컨테이너 꺼짐, 명령 없음, 주소 오류, 경로 없음 등)는 실행 실패로 보고
결과를 내지 않고 종료 코드 1 로 끝낸다. 실험 결과에 섞이지 않게 하기 위함.
종료 코드·메시지는 lab/Containerfile 이미지(debian bookworm netcat-openbsd, iputils-ping, curl 7.88,
nmap 7.93, hping3 3.0.0-alpha-2, python3 3.11)에서 확인했다.

결과마다 판정 근거(evidence, 예: "nc: Connection refused (방화벽 통과, 포트 닫힘)")를 남긴다.
실행 실패 메시지는 원인을 분류한다: 컨테이너 없음·꺼짐(125), 명령 실행 권한 없음(126), 명령 없음(127),
podman exec 시간 초과, 판정할 수 없는 출력.

출력: {"results": [{"id", "kind", "expect", "observed", "pass", "evidence"}...]}
사용: probe.py scenarios/req-001.json > out/probe.json
"""

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json  # noqa: E402
from common.lab import FW, exec_in  # noqa: E402
from common.topology import udp_echo  # noqa: E402

TIMEOUT_S = 2

# 공격 도구(nmap)는 랩 네트워크 안에서만 쓴다 (AGENTS.md 실험과 보안 규칙)
LAB_NET = ipaddress.ip_network("10.10.0.0/16")

# nc -v 는 사용 오류(주소·포트 오류)와 경로 없음에도 종료 코드 1 을 내므로 메시지로 구분한다.
#   timed out: 방화벽 drop (IR 의 action 은 accept/drop 뿐이라 reject 는 없다)
#   Connection refused: SYN 이 방화벽을 지나 서버가 RST 로 응답함 = 방화벽은 허용
NC_BLOCKED = "timed out"
NC_PASSED = "Connection refused"

# curl 도 Connection refused 와 경로 없음(Network is unreachable)에 같은 종료 코드 7, 같은 마지막 줄을 내므로
# -v 출력의 단계별 메시지로 구분한다.
#   * Connected to: TCP 연결이 방화벽을 통과함. 이후 응답 없음(28)·끊김(56)이어도 방화벽은 허용
#   * connect to ... failed: Connection refused: 방화벽은 통과했고 포트가 닫힘 (종료 코드 7)
#   Failed to connect ... Timeout was reached: 연결 단계 timeout = 방화벽 drop (종료 코드 28)
CURL_CONNECTED = "* Connected to "
CURL_PASSED = "Connection refused"
CURL_BLOCKED = "Timeout was reached"

# nmap 은 경로 없음·주소 오류에도 종료 코드 0 으로 끝나고 호스트를 하나도 스캔하지 않으므로
# -oX XML 에서 대상 포트의 state 와 reason 을 읽어 판정한다.
#   open/syn-ack, closed/conn-refused: 방화벽은 허용 (closed 는 nc 의 Connection refused 와 같음)
#   filtered/no-response: 방화벽 drop
#   filtered/host-unreach 등 그 밖의 reason: reject·ICMP 오류라 drop 이 아니다 → 실행 실패
#   <host> 없음(경로 없음, 주소 오류), <host timedout="true">, <port> 없음, XML 아님(podman exec 실패 등): 실행 실패
# -sT(connect 스캔)를 쓴다. -sS 는 raw 소켓이 필요해 권한 없는 컨테이너에서 "dnet: Failed to open device" 로 실패한다.
NMAP_ALLOW = {("open", "syn-ack"), ("closed", "conn-refused")}
NMAP_BLOCK = {("filtered", "no-response")}

# hping3 -S -c 1 은 SYN 하나를 보내고 1초 기다린다. 응답 줄(stdout)과 통계(stderr)로 판정한다.
#   flags=SA(열림)·flags=RA(닫힘, RST): 방화벽은 허용. 종료 코드 0
#   "1 packets transmitted, 0 packets received": 방화벽 drop. 종료 코드 1
#   ICMP 오류(경로 없음 "ICMP Network Unreachable from ...")도 "1 packets received", 종료 코드 0 으로 끝나므로
#   종료 코드만 보지 않고 대상 ip·포트의 응답 줄을 찾는다. 없으면 실행 실패
#   이름 해석 실패("Unable to resolve")도 종료 코드 1 이지만 통계 줄이 없어 실행 실패로 남는다
# -p 는 65535 를 넘으면 조용히 다른 포트로 접히므로(99999 → 34463) 포트를 미리 검사한다.
# 공격 도구라 대상은 랩 네트워크만, 패킷은 1개(-c 1)에 간격 10ms(-i u10000)로 제한한다. --flood 는 쓰지 않는다.
HPING_SENT_NONE = "1 packets transmitted, 0 packets received"
HPING_ALLOW_FLAGS = {"SA", "RA"}

# UDP 는 handshake 가 없어 nc -u 로는 "응답 없음" 과 오류를 구분할 수 없다. 랩 이미지의 python3 로
# 연결된(connect) UDP 소켓에 무작위 토큰을 보내고, 받은 것을 한 줄 JSON 으로 낸다 (UDP_SCRIPT).
#   reply(토큰이 같음): 에코 서비스가 응답 = 방화벽 허용. 토큰이 다른 응답은 무시하고 계속 기다린다
#   refused(ECONNREFUSED): 대상이 ICMP port unreachable 로 응답 = 방화벽은 통과, 포트만 닫힘 (nc 의 Connection refused 와 같음)
#     연결된 소켓에는 대상 주소에서 온 ICMP 오류만 전달된다. IR 에는 reject 가 없어 fw 가 이 ICMP 를 만들지 않는다
#   timeout: 대상이 UDP 에코 서비스(common.topology.udp_echo)일 때만 block.
#     그 밖의 대상은 응답 없음이 drop 인지 알 수 없어 실행 실패로 본다. 랩에서 확인한 것:
#     닫힌 포트도 커널의 ICMP 속도 제한으로 10번 중 1번은 응답이 없었고(나머지 refused),
#     없는 호스트(10.10.30.99)·없는 망(10.10.99.5)도 오류 대신 timeout 이었다
#   error(그 밖의 OSError), JSON 이 아님(podman exec 실패 125 등): 실행 실패
#   block 으로 판정하기 전에 fw 컨테이너에서 같은 에코 서비스에 직접 보내 응답을 확인한다(echo_alive).
#     fw 자신이 보내는 패킷은 forward 체인을 지나지 않아 후보 룰과 상관없이 닿는다. 랩에서 server 를 멈췄을 때
#     프로브는 timeout(block)으로 보였으므로, 서비스가 죽어 응답이 없는 것을 차단으로 기록하지 않기 위함이다
# 상태 추적 룰이 없으면(오류 주입 state) 에코 응답이 돌아오지 못해 tcp 와 같이 block 으로 보인다.
# 패킷 손실에 대비해 같은 토큰을 UDP_ATTEMPTS 번까지 보낸다(각 TIMEOUT_S 초 대기).
UDP_ATTEMPTS = 2
UDP_SCRIPT = """
import json, os, socket, sys, time
to, port, wait, attempts = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
token = os.urandom(8).hex().encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
out = {"result": "timeout"}
try:
    s.connect((to, port))
    for _ in range(attempts):
        s.send(token)
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            try:
                if s.recv(65535) == token:
                    out = {"result": "reply"}
                    break
            except socket.timeout:
                break
        if out["result"] != "timeout":
            break
except ConnectionRefusedError:
    out = {"result": "refused"}
except OSError as e:
    out = {"result": "error", "errno": e.errno, "error": str(e)}
print(json.dumps(out))
"""


def udp_result(stdout):
    """UDP_SCRIPT 출력의 result. 한 줄 JSON 이 아니면 None."""
    lines = stdout.strip().splitlines()
    if len(lines) != 1:
        return None
    try:
        out = json.loads(lines[0])
    except ValueError:
        return None
    return out.get("result") if isinstance(out, dict) else None


def hping_flags(stdout, to, port):
    """hping3 출력에서 대상의 응답 TCP 플래그를 찾는다. 응답 줄이 정확히 1개가 아니면 None."""
    pat = re.compile(rf"^len=\d+ ip={re.escape(to)} .*\bsport={port} flags=([A-Z]+) ")
    found = [m.group(1) for m in map(pat.match, stdout.splitlines()) if m]
    return found[0] if len(found) == 1 else None


def nmap_state(stdout, port):
    """nmap -oX 출력에서 대상 포트의 (state, reason) 을 찾는다. 없으면 None."""
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return None
    hosts = root.findall("host")
    if len(hosts) != 1 or hosts[0].get("timedout") == "true":
        return None
    ports = hosts[0].findall(f"ports/port[@protocol='tcp'][@portid='{port}']")
    if len(ports) != 1:
        return None
    state = ports[0].find("state")
    if state is None:
        return None
    return state.get("state"), state.get("reason")


class ProbeError(Exception):
    """프로브를 실행하지 못함. 허용/차단을 관측한 것이 아니다."""


def judge(tool, res, port=None, to=None, echo=None):
    """관측 결과 -> (판정, 근거). 판정할 수 없으면 (None, None). 근거는 결과에 evidence 로 남긴다."""
    if tool == "udp":
        if res.returncode != 0:
            return None, None
        r = udp_result(res.stdout)
        if r == "reply":
            return "allow", "udp: 에코 응답 받음"
        if r == "refused":
            return "allow", "udp: ICMP port unreachable (방화벽 통과, 포트 닫힘)"
        if r == "timeout" and (to, port) in (udp_echo() if echo is None else echo):
            return "block", "udp: 에코 서비스 응답 없음 (drop)"
        return None, None
    if tool == "hping3":
        if res.returncode == 0:
            flags = hping_flags(res.stdout, to, port)
            if flags in HPING_ALLOW_FLAGS:
                return "allow", f"hping3: flags={flags} ({'열림' if flags == 'SA' else '방화벽 통과, 포트 닫힘'})"
            return None, None
        if res.returncode == 1 and HPING_SENT_NONE in res.stderr and "len=" not in res.stdout:
            return "block", "hping3: SYN 응답 없음 (drop)"
        return None, None
    if tool == "nmap":
        if res.returncode != 0:
            return None, None
        st = nmap_state(res.stdout, port)
        if st in NMAP_ALLOW:
            return "allow", f"nmap: {st[0]}/{st[1]}"
        if st in NMAP_BLOCK:
            return "block", f"nmap: {st[0]}/{st[1]} (drop)"
        return None, None
    if res.returncode == 0:
        return "allow", {"nc": "nc: 연결됨", "curl": "curl: HTTP 응답 받음", "ping": "ping: 응답 받음"}.get(tool, tool)
    if tool == "curl":
        if CURL_CONNECTED in res.stderr:
            return "allow", f"curl: TCP 연결됨, 이후 종료 코드 {res.returncode}"
        if res.returncode == 7 and CURL_PASSED in res.stderr:
            return "allow", "curl: Connection refused (방화벽 통과, 포트 닫힘)"
        if res.returncode == 28 and CURL_BLOCKED in res.stderr:
            return "block", "curl: 연결 단계 timeout (drop)"
        return None, None
    if tool == "nc" and res.returncode == 1:
        if NC_PASSED in res.stderr:
            return "allow", "nc: Connection refused (방화벽 통과, 포트 닫힘)"
        if NC_BLOCKED in res.stderr:
            return "block", "nc: timed out (drop)"
    if tool == "ping" and res.returncode == 1:  # ping: 1 응답 없음, 2 오류
        return "block", "ping: 응답 없음 (drop)"
    return None, None


def observe(tool, res, port=None, to=None, echo=None):
    """판정만. allow | block | None(실행 실패)"""
    return judge(tool, res, port, to, echo)[0]


# podman exec 자체가 실패한 종료 코드. lab 이미지에서 확인했다.
#   125: 컨테이너가 없거나 꺼짐 ("no such container", "container state improper")
#   126: 실행 권한 없음 ("exists but it is not executable")
#   127: 명령 없음 ("executable file ... not found in $PATH")
# 126·127 은 마지막 줄이 "read unixpacket ...: connection reset by peer" 라 원인이 가려지므로 "Error:" 줄을 쓴다.
EXEC_FAILURES = {125: "컨테이너 없음·꺼짐", 126: "명령 실행 권한 없음", 127: "명령 없음"}


def failure_reason(tool, res):
    """판정할 수 없었던 실행의 원인 (분류, 근거 줄)."""
    lines = [ln.strip() for ln in res.stderr.splitlines() if ln.strip()]
    errors = [ln for ln in lines if ln.startswith("Error:")]
    if res.returncode in EXEC_FAILURES:
        return EXEC_FAILURES[res.returncode], (errors[0] if errors else (lines[-1] if lines else ""))
    if tool == "udp" and res.returncode == 0:
        return "판정할 수 없는 출력", res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "출력 없음"
    if tool == "nmap" and res.returncode == 0:
        return "판정할 수 없는 출력", "대상 포트의 state/reason 이 없거나 drop 이 아닌 filtered"
    return "판정할 수 없는 출력", lines[-1] if lines else "출력 없음"


def echo_alive(to, port):
    """fw 에서 UDP 에코 서비스에 직접 보내 응답을 받는가. forward 체인(후보 룰)을 지나지 않는다."""
    res = exec_in(FW, "python3", "-c", UDP_SCRIPT, to, str(port), str(TIMEOUT_S), str(UDP_ATTEMPTS),
                  timeout=TIMEOUT_S * UDP_ATTEMPTS + 10)
    return res.returncode == 0 and udp_result(res.stdout) == "reply"


def check_udp_target(p):
    """UDP 프로브는 IP 와 단일 포트만 받는다 (이름 해석 실패가 timeout 으로 보이지 않게). 어기면 ValueError."""
    try:
        ipaddress.ip_address(p["to"])
    except ValueError:
        raise ValueError(f"{p['id']}: udp 대상은 IP 여야 함: {p['to']}") from None
    if type(p.get("port")) is not int or not 0 < p["port"] < 65536:
        raise ValueError(f"{p['id']}: udp 프로브의 port 는 1-65535 정수여야 함: {p.get('port')!r}")


def check_attack_target(p, tool):
    """공격 도구(nmap·hping3) 프로브의 대상과 포트를 검사한다. 어기면 ValueError."""
    try:
        to = ipaddress.ip_address(p["to"])
    except ValueError:
        raise ValueError(f"{p['id']}: {tool} 대상은 IP 여야 함: {p['to']}") from None
    if to not in LAB_NET:
        raise ValueError(f"{p['id']}: {tool} 대상은 랩 네트워크({LAB_NET}) 안이어야 함: {p['to']}")
    # nmap 의 -p 는 "80-90", "80,443" 도 받아 여러 포트를 스캔하고, hping3 의 -p 는 65535 를 넘으면 접히므로
    # 단일 포트만 허용한다
    if type(p["port"]) is not int or not 0 < p["port"] < 65536:
        raise ValueError(f"{p['id']}: {tool} 프로브의 port 는 1-65535 정수여야 함: {p['port']!r}")


def command(p):
    tool = p.get("tool", {"tcp": "nc", "udp": "udp"}.get(p["proto"], "ping"))
    if p["proto"] == "tcp" and tool == "nc":
        return tool, ["nc", "-vz", "-w", str(TIMEOUT_S), p["to"], str(p["port"])]
    if p["proto"] == "tcp" and tool == "curl":
        # --noproxy: 프록시 환경변수가 있으면 프록시에 연결돼 "Connected to" 가 방화벽 통과로 오판정된다
        return tool, ["curl", "-sS", "-v", "-o", "/dev/null", "--noproxy", "*",
                      "--connect-timeout", str(TIMEOUT_S), "-m", str(TIMEOUT_S + 3),
                      f"http://{p['to']}:{p['port']}/"]
    if p["proto"] == "tcp" and tool in ("nmap", "hping3"):
        check_attack_target(p, tool)
    if p["proto"] == "tcp" and tool == "hping3":
        # -S: SYN 만. -n: DNS 조회 안 함. -c 1: 패킷 1개
        return tool, ["hping3", "-S", "-n", "-c", "1", "-i", "u10000", "-p", str(p["port"]), p["to"]]
    if p["proto"] == "tcp" and tool == "nmap":
        # -Pn: 호스트 탐색(ping)도 방화벽에 막히므로 생략. -n: DNS 조회 안 함. 재전송 1회.
        return tool, ["nmap", "-Pn", "-n", "-sT", "-p", str(p["port"]), "--reason",
                      "--max-retries", "1", "--host-timeout", f"{TIMEOUT_S * 5}s",
                      "-oX", "-", p["to"]]
    if p["proto"] == "udp" and tool == "udp":
        check_udp_target(p)
        return tool, ["python3", "-c", UDP_SCRIPT, p["to"], str(p["port"]), str(TIMEOUT_S), str(UDP_ATTEMPTS)]
    if p["proto"] == "icmp" and tool == "ping":
        return tool, ["ping", "-c", "1", "-W", str(TIMEOUT_S), p["to"]]
    raise ValueError(f"{p['id']}: 지원하지 않는 proto/tool {p['proto']}/{tool}")


def run_probe(p):
    tool, cmd = command(p)
    # nmap 은 --host-timeout 이 TIMEOUT_S * 5 초, udp 는 TIMEOUT_S 초씩 UDP_ATTEMPTS 번이라 그보다 길게 기다린다
    wait = {"nmap": TIMEOUT_S * 5, "udp": TIMEOUT_S * UDP_ATTEMPTS}.get(tool, TIMEOUT_S) + 10
    try:
        res = exec_in(p["from"], *cmd, timeout=wait)
    except subprocess.TimeoutExpired:
        raise ProbeError(f"{p['id']}: 프로브 실행 실패 [podman exec 시간 초과] {wait}초 안에 끝나지 않음") from None
    observed, evidence = judge(tool, res, p.get("port"), p["to"])
    if observed is None:
        if tool == "udp" and res.returncode == 0 and udp_result(res.stdout) == "timeout":
            raise ProbeError(f"{p['id']}: udp 응답 없음. {p['to']}:{p['port']} 는 UDP 에코 서비스가 아니라 "
                             "차단으로 판정할 수 없음 (lab/topology.env 의 udp-echo 포트로 프로브할 것)")
        kind, line = failure_reason(tool, res)
        raise ProbeError(f"{p['id']}: 프로브 실행 실패 [{kind}] ({tool}, exit {res.returncode}) {line}".rstrip())
    if tool == "udp" and observed == "block":
        if not echo_alive(p["to"], p["port"]):
            raise ProbeError(f"{p['id']}: udp 응답 없음. fw 에서 보내도 {p['to']}:{p['port']} 의 UDP 에코 서비스가 "
                             "응답하지 않아 차단으로 판정할 수 없음")
        evidence += ", fw 에서는 에코 응답"
    return {
        "id": p["id"], "kind": p["kind"], "expect": p["expect"],
        "observed": observed, "pass": observed == p["expect"], "evidence": evidence,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    args = ap.parse_args()

    scenario = load_json(args.scenario)
    try:
        results = [run_probe(p) for p in scenario["probes"]]
    except ProbeError as e:
        sys.exit(str(e))
    json.dump({"results": results}, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
