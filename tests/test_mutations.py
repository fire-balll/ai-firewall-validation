"""mutations/ 데이터 검사. 실행: python3 -m unittest discover -s tests -t ."""

import glob
import re
import unittest
from pathlib import Path

from common.ir import ROOT, load_json, schema_errors, stateful_for

MUTATIONS = sorted(glob.glob(str(ROOT / "mutations" / "req-*.json")))
README = (ROOT / "mutations" / "README.md").read_text(encoding="utf-8")
NAME = re.compile(r"^(req-\d{3})-([a-z-]+)-(\d{2})\.json$")


def readme_types():
    """'## 오류 유형' 표의 첫 열."""
    section = README.split("## 오류 유형", 1)[1].split("###", 1)[0]
    return {m.group(1) for m in re.finditer(r"^\| ([a-z-]+) \|", section, re.M)}


class MutationTest(unittest.TestCase):
    def test_passes_schema(self):
        for path in MUTATIONS:
            with self.subTest(file=Path(path).name):
                self.assertEqual(schema_errors(load_json(path)), [])

    def test_name_matches_scenario_and_type(self):
        types = readme_types()
        for path in MUTATIONS:
            name = Path(path).name
            with self.subTest(file=name):
                m = NAME.match(name)
                self.assertIsNotNone(m)
                self.assertEqual(load_json(path)["scenario"], m.group(1))
                self.assertIn(m.group(2), types)

    def test_differs_from_gold(self):
        """state 유형은 IR 이 정답과 같아야 한다. 오류는 파일명으로만 주입한다 (README 의 state 유형)."""
        for path in MUTATIONS:
            mutant = load_json(path)
            with self.subTest(file=Path(path).name):
                gold = load_json(ROOT / "scenarios" / f"{mutant['scenario']}.json")["gold"]
                if NAME.match(Path(path).name).group(2) == "state":
                    self.assertEqual(mutant["rules"], gold["rules"])
                else:
                    self.assertNotEqual(mutant["rules"], gold["rules"])

    def test_only_state_files_are_stateless(self):
        """변환기가 state 파일만 상태 추적 없이 적용하는지. 아니면 state 후보가 정답과 똑같이 적용된다."""
        for path in MUTATIONS:
            name = Path(path).name
            with self.subTest(file=name):
                self.assertEqual(stateful_for(path), NAME.match(name).group(2) != "state")

    def test_listed_in_readme(self):
        for path in MUTATIONS:
            with self.subTest(file=Path(path).name):
                self.assertIn(f"| {Path(path).name} |", README)


if __name__ == "__main__":
    unittest.main()
