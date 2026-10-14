"""prober/probe.py 테스트. 컨테이너 없이 lab 이미지(nmap 7.93)에서 관측한 출력으로 판정만 확인한다."""

import subprocess
import unittest

from prober import probe

HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n<nmaprun scanner="nmap" version="7.93" xmloutputversion="1.05">\n'
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
