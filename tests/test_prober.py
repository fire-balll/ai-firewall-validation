"""prober/probe.py 테스트. 컨테이너 없이 lab 이미지(nmap 7.93)에서 관측한 출력으로 판정만 확인한다."""

import subprocess
import unittest.mock
import unittest

from prober import probe

# lab 이미지의 nmap -oX - 출력 머리 그대로 (DOCTYPE, xml-stylesheet, 주석 포함)
HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE nmaprun>\n'
        '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'
        '<!-- Nmap 7.93 scan initiated Wed Oct 14 07:13:36 2026 as: nmap -Pn -n -sT -p 80 -&#45;reason '
        '-&#45;max-retries 1 -&#45;host-timeout 10s -oX - 10.10.30.10 -->\n'
        '<nmaprun scanner="nmap" version="7.93" xmloutputversion="1.05">\n'
        '<scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>\n')
TAIL = '<runstats><finished exit="success"/><hosts up="{up}" down="0" total="{up}"/></runstats>\n</nmaprun>\n'


def nmap_xml(port, state, reason):
    return (HEAD
            + '<host><status state="up" reason="user-set" reason_ttl="0"/>\n'
            + f'<ports><port protocol="tcp" portid="{port}"><state state="{state}" reason="{reason}" '
            + 'reason_ttl="0"/></port>\n</ports>\n</host>\n'
            + TAIL.format(up=1))


def done(stdout, returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class NmapObserveTest(unittest.TestCase):
    def test_open_is_allow(self):
        self.assertEqual(probe.observe("nmap", done(nmap_xml(80, "open", "syn-ack")), 80), "allow")

    def test_closed_is_allow_because_firewall_passed(self):
        res = done(nmap_xml(9999, "closed", "conn-refused"))
        self.assertEqual(probe.observe("nmap", res, 9999), "allow")

    def test_filtered_no_response_is_block(self):
        res = done(nmap_xml(8080, "filtered", "no-response"))
        self.assertEqual(probe.observe("nmap", res, 8080), "block")

    def test_filtered_by_icmp_error_is_not_block(self):
        res = done(nmap_xml(8081, "filtered", "host-unreach"))
        self.assertIsNone(probe.observe("nmap", res, 8081))

    def test_no_host_scanned_with_exit_zero_is_failure(self):
        # 경로 없음·주소 오류: nmap 은 종료 코드 0, exit="success" 로 끝나지만 <host> 가 없다
        res = done(HEAD + TAIL.format(up=0), stderr="WARNING: No targets were specified, so 0 hosts scanned.\n")
        self.assertIsNone(probe.observe("nmap", res, 80))

    def test_host_timeout_is_failure(self):
        # --host-timeout 초과: 종료 코드 0, exit="success" 지만 <host timedout="true"> 에 <ports> 가 없다
        res = done(HEAD + '<host timedout="true"><status state="up" reason="user-set" reason_ttl="0"/>\n'
                   + '<address addr="10.10.30.10" addrtype="ipv4"/>\n</host>\n' + TAIL.format(up=1))
        self.assertIsNone(probe.observe("nmap", res, 8080))

    def test_other_port_in_output_is_failure(self):
        self.assertIsNone(probe.observe("nmap", done(nmap_xml(80, "open", "syn-ack")), 8080))

    def test_podman_exec_failure_is_failure(self):
        res = done("", returncode=125, stderr='Error: no container with name or ID "attacker" found')
        self.assertIsNone(probe.observe("nmap", res, 80))

    def test_raw_socket_error_is_failure(self):
        res = done("", returncode=1, stderr="dnet: Failed to open device eth0\nQUITTING!\n")
        self.assertIsNone(probe.observe("nmap", res, 80))

    def test_truncated_xml_is_failure(self):
        self.assertIsNone(probe.observe("nmap", done(HEAD), 80))


class NmapCommandTest(unittest.TestCase):
    def test_command_scans_single_port_without_ping_or_dns(self):
        p = {"id": "a-001", "from": "attacker", "to": "10.10.30.10", "proto": "tcp", "port": 8080,
             "tool": "nmap"}
        tool, cmd = probe.command(p)
        self.assertEqual(tool, "nmap")
        self.assertEqual(cmd[0], "nmap")
        for flag in ("-Pn", "-n", "-sT", "--reason"):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("-p") + 1], "8080")
        self.assertEqual(cmd[cmd.index("-oX") + 1], "-")
        self.assertEqual(cmd[-1], "10.10.30.10")

    def test_target_outside_lab_is_rejected(self):
        for to in ("8.8.8.8", "10.11.0.1", "192.168.0.1"):
            p = {"id": "a-x", "from": "attacker", "to": to, "proto": "tcp", "port": 80, "tool": "nmap"}
            with self.subTest(to=to), self.assertRaises(ValueError):
                probe.command(p)

    def test_target_must_be_ip_with_probe_id_in_message(self):
        p = {"id": "a-x", "from": "attacker", "to": "web", "proto": "tcp", "port": 80, "tool": "nmap"}
        with self.assertRaisesRegex(ValueError, r"^a-x: nmap 대상은 IP 여야 함: web$"):
            probe.command(p)

    def test_port_must_be_single_integer(self):
        for port in ("80", "80-90", "80,443", 0, 65536, True):
            p = {"id": "a-x", "from": "attacker", "to": "10.10.30.10", "proto": "tcp", "port": port,
                 "tool": "nmap"}
            with self.subTest(port=port), self.assertRaises(ValueError):
                probe.command(p)

    def test_nmap_on_icmp_is_rejected(self):
        p = {"id": "a-003", "from": "attacker", "to": "10.10.20.10", "proto": "icmp", "tool": "nmap"}
        with self.assertRaises(ValueError):
            probe.command(p)


if __name__ == "__main__":
    unittest.main()


# lab 이미지의 hping3 -S -n -c 1 -i u10000 출력 그대로. 응답 줄은 stdout, 통계는 stderr 로 나온다
HPING_HEAD = "HPING 10.10.30.10 (eth0 10.10.30.10): S set, 40 headers + 0 data bytes\n"


def hping_stats(received):
    return (f"\n--- 10.10.30.10 hping statistic ---\n1 packets transmitted, {received} packets received, "
            f"{0 if received else 100}% packet loss\nround-trip min/avg/max = 0.0/0.0/0.0 ms\n")


def hping_reply(port, flags):
    return f"len=44 ip=10.10.30.10 ttl=63 DF id=0 sport={port} flags={flags} seq=0 win=65480 rtt=0.8 ms\n"


class HpingObserveTest(unittest.TestCase):
    def observe(self, stdout, returncode, stderr, port=80):
        return probe.observe("hping3", done(stdout, returncode, stderr), port, "10.10.30.10")

    def test_syn_ack_is_allow(self):
        self.assertEqual(self.observe(HPING_HEAD + hping_reply(80, "SA"), 0, hping_stats(1)), "allow")

    def test_rst_is_allow_because_firewall_passed(self):
        self.assertEqual(self.observe(HPING_HEAD + hping_reply(22, "RA"), 0, hping_stats(1), 22), "allow")

    def test_no_reply_is_block(self):
        self.assertEqual(self.observe(HPING_HEAD, 1, hping_stats(0), 8080), "block")

    def test_icmp_unreachable_with_exit_zero_is_failure(self):
        # 경로 없음: ICMP 오류도 "1 packets received" 로 세고 종료 코드 0 이다
        out = "HPING 10.10.50.5 (eth0 10.10.50.5): S set, 40 headers + 0 data bytes\n" \
              "ICMP Network Unreachable from ip=10.10.20.254\n"
        res = done(out, 0, hping_stats(1))
        self.assertIsNone(probe.observe("hping3", res, 80, "10.10.50.5"))

    def test_reply_for_other_port_is_failure(self):
        self.assertIsNone(self.observe(HPING_HEAD + hping_reply(8080, "SA"), 0, hping_stats(1), 80))

    def test_unexpected_flags_are_failure(self):
        self.assertIsNone(self.observe(HPING_HEAD + hping_reply(80, "S"), 0, hping_stats(1)))

    def test_resolve_error_is_failure(self):
        self.assertIsNone(self.observe("", 1, "Unable to resolve 'server'\n"))

    def test_podman_exec_failure_is_failure(self):
        err = "Error: can only create exec sessions on running containers: container state improper\n"
        self.assertIsNone(self.observe("", 125, err))


class HpingCommandTest(unittest.TestCase):
    def probe(self, **kw):
        return dict({"id": "a-x", "from": "attacker", "to": "10.10.30.10", "proto": "tcp", "port": 80,
                     "tool": "hping3"}, **kw)

    def test_command_sends_one_syn_without_dns(self):
        tool, cmd = probe.command(self.probe())
        self.assertEqual(tool, "hping3")
        self.assertEqual(cmd, ["hping3", "-S", "-n", "-c", "1", "-i", "u10000", "-p", "80", "10.10.30.10"])
        self.assertNotIn("--flood", cmd)

    def test_target_outside_lab_is_rejected(self):
        for to in ("8.8.8.8", "10.11.0.1", "server"):
            with self.subTest(to=to), self.assertRaisesRegex(ValueError, "^a-x: hping3 대상"):
                probe.command(self.probe(to=to))

    def test_port_must_be_single_integer(self):
        # hping3 는 99999 를 받아 다른 포트(34463)로 보낸다
        for port in ("80", "80-90", 0, 65536, 99999, True):
            with self.subTest(port=port), self.assertRaises(ValueError):
                probe.command(self.probe(port=port))

    def test_hping3_on_icmp_is_rejected(self):
        with self.assertRaises(ValueError):
            probe.command(self.probe(proto="icmp"))


# lab 이미지(python3 3.11)에서 UDP_SCRIPT 가 낸 출력 그대로
UDP_REPLY = '{"result": "reply"}\n'
UDP_REFUSED = '{"result": "refused"}\n'
UDP_TIMEOUT = '{"result": "timeout"}\n'
UDP_UNREACH = '{"result": "error", "errno": 101, "error": "[Errno 101] Network is unreachable"}\n'
ECHO = {("10.10.30.10", 53)}


class UdpObserveTest(unittest.TestCase):
    def observe(self, stdout, returncode=0, stderr="", to="10.10.30.10", port=53):
        return probe.observe("udp", done(stdout, returncode, stderr), port, to, echo=ECHO)

    def test_echo_reply_is_allow(self):
        self.assertEqual(self.observe(UDP_REPLY), "allow")

    def test_port_unreachable_is_allow_because_firewall_passed(self):
        self.assertEqual(self.observe(UDP_REFUSED, port=54), "allow")

    def test_no_reply_from_echo_service_is_block(self):
        self.assertEqual(self.observe(UDP_TIMEOUT), "block")

    def test_no_reply_from_other_port_is_failure(self):
        # 닫힌 포트도 ICMP 속도 제한으로 응답이 없을 수 있다 (랩: 10번 중 1번)
        self.assertIsNone(self.observe(UDP_TIMEOUT, port=54))
        self.assertIsNone(self.observe(UDP_TIMEOUT, to="10.10.30.99"))

    def test_socket_error_is_failure(self):
        self.assertIsNone(self.observe(UDP_UNREACH))

    def test_podman_exec_failure_is_failure(self):
        err = "Error: can only create exec sessions on running containers: container state improper\n"
        self.assertIsNone(self.observe("", 125, err))

    def test_garbage_output_is_failure(self):
        for out in ("", "not json\n", UDP_REPLY + UDP_REPLY, "[1]\n", '{"result": "other"}\n'):
            with self.subTest(out=out):
                self.assertIsNone(self.observe(out))


class UdpCommandTest(unittest.TestCase):
    def probe(self, **kw):
        return dict({"id": "n-x", "from": "pc", "to": "10.10.30.10", "proto": "udp", "port": 53}, **kw)

    def test_udp_defaults_to_python_datagram_probe(self):
        tool, cmd = probe.command(self.probe())
        self.assertEqual(tool, "udp")
        self.assertEqual(cmd[:2], ["python3", "-c"])
        self.assertEqual(cmd[3:], ["10.10.30.10", "53", str(probe.TIMEOUT_S), str(probe.UDP_ATTEMPTS)])
        compile(cmd[2], "<udp>", "exec")

    def test_target_must_be_ip(self):
        with self.assertRaisesRegex(ValueError, "^n-x: udp 대상은 IP"):
            probe.command(self.probe(to="server"))

    def test_port_must_be_single_integer(self):
        for port in ("53", "53-54", 0, 65536, True, None):
            with self.subTest(port=port), self.assertRaises(ValueError):
                probe.command(self.probe(port=port))


class UdpRunTest(unittest.TestCase):
    """run_probe: block 은 fw 에서 에코 서비스가 살아 있는지 확인한 뒤에만 낸다."""

    def run_with(self, outputs):
        calls = []

        def fake_exec(container, *cmd, timeout=30):
            calls.append(container)
            return done(outputs[len(calls) - 1])

        p = {"id": "a-x", "kind": "attack", "expect": "block", "from": "pc", "to": "10.10.30.10",
             "proto": "udp", "port": 53}
        with unittest.mock.patch.object(probe, "exec_in", fake_exec), \
                unittest.mock.patch.object(probe, "udp_echo", return_value=ECHO):
            return probe.run_probe(p), calls

    def test_block_needs_echo_alive_from_fw(self):
        result, calls = self.run_with([UDP_TIMEOUT, UDP_REPLY])
        self.assertEqual((result["observed"], result["pass"]), ("block", True))
        self.assertEqual(calls, ["pc", probe.FW])

    def test_dead_echo_service_is_failure_not_block(self):
        with self.assertRaisesRegex(probe.ProbeError, "에코 서비스가 응답하지 않아"):
            self.run_with([UDP_TIMEOUT, UDP_TIMEOUT])

    def test_allow_does_not_query_fw(self):
        result, calls = self.run_with([UDP_REPLY])
        self.assertEqual((result["observed"], calls), ("allow", ["pc"]))

    def test_timeout_on_non_echo_port_names_the_reason(self):
        def fake_exec(container, *cmd, timeout=30):
            return done(UDP_TIMEOUT)
        p = {"id": "a-x", "kind": "attack", "expect": "block", "from": "pc", "to": "10.10.30.10",
             "proto": "udp", "port": 54}
        with unittest.mock.patch.object(probe, "exec_in", fake_exec), \
                unittest.mock.patch.object(probe, "udp_echo", return_value=ECHO), \
                self.assertRaisesRegex(probe.ProbeError, "UDP 에코 서비스가 아니라"):
            probe.run_probe(p)


class TopologyUdpEchoTest(unittest.TestCase):
    def test_lab_server_runs_udp_echo_on_53(self):
        from common.topology import udp_echo
        self.assertIn(("10.10.30.10", 53), udp_echo())
