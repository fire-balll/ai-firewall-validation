#!/usr/bin/env python3
"""받은 UDP 데이터그램을 보낸 쪽으로 그대로 돌려보낸다. (lab server 의 53/udp, #32)

prober 가 UDP 를 판정하려면 대상 포트가 항상 응답해야 한다. 듣기만 하고 응답하지 않으면
"응답 없음" 이 방화벽 drop 인지 서비스가 조용한 것인지 구분할 수 없다.
사용: udp-echo [포트]  (기본 53)
"""

import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 53
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(data, addr)
