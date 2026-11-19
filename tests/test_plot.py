import re
import unittest

from eval.plot import PlotError, render, timing_rows


def group(scenario, candidate, kind, detect=None, n=0):
    return {"scenario": scenario, "candidate": candidate, "kind": kind,
            "detect_s": {"mean": detect, "std": None, "n": n}, "mttr_s": {"mean": detect and 0.3, "std": None, "n": n}}


SUMMARY = {
    "batches": [{"batch_id": "20261112-165451", "kinds": {
        "gold": {"status": {"applied": 3}},
        "mutation": {"status": {"rolled_back": 4, "rejected_approval": 2}}}}],
    "groups": [group("req-001", "gold", "gold"),
               group("req-001", "req-001-port-01", "mutation", 10.0, 3),
               group("req-001", "req-001-widen-01", "mutation", 20.0, 1),
               group("req-002", "req-002-port-01", "mutation", 30.0, 2)],
}


class PlotTest(unittest.TestCase):
    def test_renders_three_charts_from_summary(self):
        files = render(SUMMARY)
        self.assertEqual(sorted(files), ["detect.svg", "mttr.svg", "status.svg"])
        self.assertIn("오류 주입 · 롤백 4회 (67%)", files["status.svg"])
        self.assertIn("6회", files["status.svg"])

    def test_long_row_labels_stay_inside(self):
        two = {"batches": [{"batch_id": b, "kinds": {"generated": {"status": {"applied": 1}}}}
                           for b in ("20261112-162424", "20261112-170000")], "groups": SUMMARY["groups"]}
        svg = render(two)["status.svg"]
        self.assertIn("AI 후보 20261112-162424", svg)
        # 행 이름은 text-anchor=end 라 x 가 이름 폭(한글 13px·그 외 약 8px)보다 커야 그림 안에 든다
        for x, label in re.findall(r'<text x="([\d.]+)" y="[\d.]+" font-size="13" fill="#0b0b0b" '
                                   r'text-anchor="end">([^<]+)</text>', svg):
            width = sum(13 if ord(c) > 127 else 8 for c in label)
            self.assertGreater(float(x), width, label)

    def test_scenario_mean_is_weighted_by_runs(self):
        self.assertEqual(timing_rows(SUMMARY, "detect_s"), [("req-001", 12.5), ("req-002", 30.0)])

    def test_detection_chart_only_when_given(self):
        det = {"batch_id": "x", "by_type": {"port": {"static": 0, "dynamic": 3, "missed": 1}}}
        self.assertIn("동적 검증만 잡음 3회", render(SUMMARY, det)["detection.svg"])

    def test_missing_input_is_an_error(self):
        with self.assertRaises(PlotError):
            render({"groups": SUMMARY["groups"]})
        with self.assertRaises(PlotError):
            render({"batches": SUMMARY["batches"], "groups": [group("req-001", "gold", "gold")]})
        with self.assertRaises(PlotError):
            render(SUMMARY, {"batch_id": "x"})


if __name__ == "__main__":
    unittest.main()
