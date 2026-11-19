"""eval/final.py 최종 결과 CSV 테스트. 랩 없이 돈다."""

import csv
import tempfile
import unittest
from pathlib import Path

from eval.final import FinalError, build, write_csv


def metric(mean, n):
    return {"mean": mean, "std": None, "n": n}


def kind_summary(runs, status, npr=None, mttr=None, n=0):
    return {"runs": runs, "aborted": status.get("aborted", 0), "status": status,
            "normal_pass_rate": metric(npr, n), "attack_block_rate": metric(npr, n), "detect_s": metric(mttr, n),
            "mttr_s": metric(mttr, n), "semantic_match": metric(npr, n), "policy_diff": 1}


SUMMARY = {"batches": [
    {"batch_id": "20261112-165451", "commit": "672a8a0", "kinds": {
        "gold": kind_summary(3, {"applied": 3}, 1.0, None, 3),
        "mutation": kind_summary(5, {"rolled_back": 4, "rejected_approval": 1}, 0.5, 0.3, 4)}},
    {"batch_id": "20261112-170000", "commit": "672a8a0", "kinds": {
        "generated": kind_summary(2, {"applied": 1, "aborted": 1}, 1.0, None, 1)}}]}

DETECTION = {"batch_id": "20261112-165451", "commit": "672a8a0",
             "rate": {"dynamic": 3, "missed": 1, "denominator": 4, "value": 0.75},
             "rate_without_state": {"dynamic": 1, "missed": 1, "denominator": 2, "value": 0.5},
             "risk_detection_rate": {"static": 3, "dynamic": 3, "missed": 1, "denominator": 7, "value": 0.8571}}


class FinalTest(unittest.TestCase):
    def test_one_row_per_batch_and_kind(self):
        rows = build(SUMMARY, [DETECTION])
        self.assertEqual([(r["batch_id"], r["kind"]) for r in rows],
                         [("20261112-165451", "gold"), ("20261112-165451", "mutation"),
                          ("20261112-170000", "generated")])
        mut = rows[1]
        self.assertEqual((mut["runs"], mut["rolled_back"], mut["rejected_approval"]), (5, 4, 1))
        self.assertEqual((mut["mttr_s_mean"], mut["mttr_s_n"]), (0.3, 4))
        self.assertEqual(rows[2]["aborted"], 1)

    def test_detection_rates_only_on_mutation_row(self):
        rows = build(SUMMARY, [DETECTION])
        self.assertEqual((rows[1]["risk_detection_rate"], rows[1]["risk_detection_n"]), (0.8571, 7))
        self.assertEqual((rows[1]["dynamic_detection_rate"], rows[1]["dynamic_detection_n"]), (0.75, 4))
        self.assertEqual(rows[1]["dynamic_detection_without_state_rate"], 0.5)
        self.assertEqual(rows[0]["risk_detection_rate"], "")

    def test_mutation_without_detection_is_left_blank(self):
        self.assertEqual(build(SUMMARY, [])[1]["risk_detection_rate"], "")

    def test_detection_must_match_summary(self):
        with self.assertRaisesRegex(FinalError, "summary 에 없는 배치"):
            build(SUMMARY, [dict(DETECTION, batch_id="20261113-000000")])
        with self.assertRaisesRegex(FinalError, "commit 이 다름"):
            build(SUMMARY, [dict(DETECTION, commit="910dc8e")])
        with self.assertRaisesRegex(FinalError, "두 번"):
            build(SUMMARY, [DETECTION, DETECTION])
        with self.assertRaisesRegex(FinalError, "오류 주입 실행이 없음"):
            build(SUMMARY, [dict(DETECTION, batch_id="20261112-170000")])

    def test_missing_key_is_an_error(self):
        with self.assertRaisesRegex(FinalError, "batches"):
            build({}, [])
        with self.assertRaisesRegex(FinalError, "risk_detection_rate"):
            build(SUMMARY, [{k: v for k, v in DETECTION.items() if k != "risk_detection_rate"}])

    def test_csv_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "final.csv"
            write_csv(build(SUMMARY, [DETECTION]), path)
            with path.open(encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1]["risk_detection_rate"], "0.8571")
        self.assertEqual(rows[0]["mttr_s_mean"], "")


if __name__ == "__main__":
    unittest.main()
