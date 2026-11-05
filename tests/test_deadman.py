"""deployer/deadman.py 테스트.

컨테이너 대신 가짜 podman(명령을 로컬에서 실행, -d 는 백그라운드)과 가짜 nft(룰셋을 파일에 저장)로
타이머가 실제로 만료·해제되는지 확인한다. 실제 fw 컨테이너에서의 동작은 랩에서 확인해야 한다.
"""

import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from common import lab
from deployer import deadman

FAKE_PODMAN = """#!/bin/sh
# podman exec [-i|-d] <컨테이너> 명령... 을 로컬에서 실행한다
[ "$1" = exec ] || exit 125
shift; detach=
while :; do case "$1" in -i) shift;; -d) detach=1; shift;; *) break;; esac; done
shift
if [ -n "$detach" ]; then "$@" >/dev/null 2>&1 & exit 0; fi
exec "$@"
"""

FAKE_NFT = """#!/bin/sh
# nft -f <파일|-> 은 룰셋 파일을 바꾸고, list ruleset 은 그 내용을 출력한다
case "$1" in
  -f) if [ "$2" = - ]; then cat > "$FAKE_NFT_STATE"; else cat "$2" > "$FAKE_NFT_STATE"; fi ;;
  list) cat "$FAKE_NFT_STATE" ;;
  *) exit 1 ;;
esac
"""


class DeadmanTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        for name, body in (("podman", FAKE_PODMAN), ("nft", FAKE_NFT)):
            f = bin_ / name
            f.write_text(body)
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        self.state = self.tmp / "ruleset"
        self.state.write_text("candidate\n")
        self.dir = self.tmp / "deadman"
        env = {"PATH": f"{bin_}{os.pathsep}{os.environ['PATH']}", "FAKE_NFT_STATE": str(self.state),
               "FW_DEADMAN_DIR": str(self.dir)}
        patches = [mock.patch.dict(os.environ, env), mock.patch.object(lab, "PODMAN", [str(bin_ / "podman")])]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def wait_for(self, cond, limit=5):
        end = time.time() + limit
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_timer_restores_snapshot_when_not_disarmed(self):
        # deployer 가 죽은 경우: 아무도 해제하지 않으면 ttl 뒤 fw 가 스스로 복원한다
        token = deadman.arm("flush ruleset\nbaseline\n", 1)
        self.assertTrue(self.wait_for(lambda: self.state.read_text() == "flush ruleset\nbaseline\n"))
        self.assertEqual(deadman.disarm(token), "fired")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [])

    def test_disarm_stops_timer(self):
        token = deadman.arm("flush ruleset\nbaseline\n", 1)
        self.assertEqual(deadman.disarm(token), "disarmed")
        time.sleep(1.5)
        self.assertEqual(self.state.read_text(), "candidate\n")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [])  # 스냅샷·표시 파일이 남지 않는다

    def test_disarm_unknown_token_is_missing(self):
        self.assertEqual(deadman.disarm("0" * 32), "missing")

    def test_disarm_rejects_non_token(self):
        with self.assertRaises(ValueError):
            deadman.disarm("x; rm -rf /")

    def test_recover_applies_leftover_and_prevents_late_fire(self):
        # 이전 deployer 가 죽고 타이머가 아직 만료되지 않은 상태
        token = deadman.arm("flush ruleset\nbaseline\n", 2)
        self.assertEqual(deadman.recover(), [token])
        self.assertEqual(self.state.read_text(), "flush ruleset\nbaseline\n")
        self.state.write_text("next run\n")
        time.sleep(2.5)  # 원래 타이머가 만료돼도 다시 적용하지 않는다
        self.assertEqual(self.state.read_text(), "next run\n")
        self.assertEqual(deadman.recover(), [])

    def test_recover_reports_timer_that_already_fired(self):
        # 이전 deployer 가 죽고 타이머가 이미 복원한 상태: 표시만 지우고 토큰을 보고한다
        token = deadman.arm("flush ruleset\nbaseline\n", 1)
        self.assertTrue(self.wait_for(lambda: not (self.dir / f"snap.{token}").exists()))
        self.assertEqual(deadman.recover(), [token])
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [])
        self.assertEqual(deadman.recover(), [])

    def test_recover_fails_while_fired_snapshot_remains(self):
        self.dir.mkdir()
        (self.dir / ("fired." + "f" * 32)).write_text("")
        (self.dir / ("snap." + "f" * 32)).write_text("x")
        with self.assertRaises(RuntimeError):
            deadman.recover()

    def test_recover_without_leftover(self):
        self.assertEqual(deadman.recover(), [])
        self.assertEqual(self.state.read_text(), "candidate\n")

    def test_recover_fails_when_nft_fails(self):
        deadman.arm("flush ruleset\nbaseline\n", 60)
        with mock.patch.dict(os.environ, {"FAKE_NFT_STATE": str(self.tmp / "없는" / "경로")}):
            with self.assertRaises(RuntimeError):
                deadman.recover()

    def test_arm_rejects_bad_ttl(self):
        for ttl in (0, -1, 1.5, "10"):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                deadman.arm("x", ttl)

    def test_arm_fails_when_timer_cannot_start(self):
        with mock.patch.object(deadman, "exec_detached", side_effect=RuntimeError("podman exec -d 실패")):
            with self.assertRaises(RuntimeError):
                deadman.arm("flush ruleset\nbaseline\n", 60)
        self.assertEqual(deadman.recover(), [])  # 띄우지 못한 타이머의 표시는 지운다


if __name__ == "__main__":
    unittest.main()
