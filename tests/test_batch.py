"""pipeline/batch.py 의 후보 선택과 generated meta 처리 테스트. 랩 없이 돈다."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from common.ir import ROOT

spec = importlib.util.spec_from_file_location("batch", ROOT / "pipeline" / "batch.py")
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)

META = {"model": "qwen2.5:14b", "digest": "sha256:7cdf5a0187d5c0ffee", "ollama_version": "0.12.3",
        "temperature": 0.7, "seed": 1, "prompt_version": "v1"}


class GeneratedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gen = Path(self.tmp.name)
        patcher = mock.patch.object(batch, "GENERATED", self.gen)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, meta=META):
        (self.gen / f"{name}.json").write_text('{"rules": []}', encoding="utf-8")
        if meta is not None:
            (self.gen / f"{name}.meta.json").write_text(json.dumps(meta), encoding="utf-8")
        return str(self.gen / f"{name}.json")

    def test_generated_candidates_exclude_meta_and_other_scenarios(self):
        a = self.write("req-001-qwen2.5-14b-s1")
        b = self.write("req-001-qwen2.5-14b-s2")
        self.write("req-002-qwen2.5-14b-s1")
        self.assertEqual(batch.candidates_for("scenarios/req-001.json", "generated"), [a, b])

    def test_all_includes_gold_and_generated(self):
        g = self.write("req-001-qwen2.5-14b-s1")
        cands = batch.candidates_for("scenarios/req-001.json", "all")
        self.assertIsNone(cands[0])
        self.assertIn(g, cands)
        self.assertTrue(batch.is_generated(g))
        self.assertFalse(batch.is_generated(None))

    def test_missing_meta_is_an_error(self):
        g = self.write("req-001-qwen2.5-14b-s1", meta=None)
        with self.assertRaisesRegex(ValueError, "meta 없음"):
            batch.load_meta(g)

    def test_missing_meta_field_is_an_error(self):
        g = self.write("req-001-qwen2.5-14b-s1", meta={k: v for k, v in META.items() if k != "digest"})
        with self.assertRaisesRegex(ValueError, "digest"):
            batch.load_meta(g)

    def test_generator_label_has_reproduction_conditions_and_no_comma(self):
        label = batch.generator_label(META)
        self.assertEqual(label, "qwen2.5:14b@7cdf5a0187d5|t=0.7|seed=1|p=v1")
        self.assertNotIn(",", label)


if __name__ == "__main__":
    unittest.main()
