"""generator 테스트. Ollama API 는 가짜 client 로 대체한다(모델 없이 돈다)."""

import json
import socket
import tempfile
import unittest
from pathlib import Path

from common.ir import ROOT, load_json
from generator import llm
from generator.generate import NUM_CTX, feedback_message, generate, load_feedback, output_stem, user_message

SCENARIO = load_json(ROOT / "scenarios" / "req-004.json")
GOOD = json.dumps({"rules": [{
    "id": "r-001", "intent": "t", "src": "10.10.10.0/24", "dst": "10.10.30.10/32",
    "proto": "tcp", "dport": "8080", "action": "accept", "priority": 100}]})
BAD = json.dumps({"rules": [{
    "id": "r-001", "intent": "t", "src": "10.10.10.1/24", "dst": "any",
    "proto": "icmp", "dport": "80", "action": "accept", "priority": 100}]})


DIGEST = "sha256:7cdf5a0187d5c0ffee"


class FakeClient:
    """Ollama API 대역. chat 은 준비한 응답을 차례로 돌려준다."""

    def __init__(self, *texts, done_reason="stop", models=None):
        self.replies = list(texts)
        self.done_reason = done_reason
        self.models = [{"name": "fake:7b", "model": "fake:7b", "digest": DIGEST}] if models is None else models
        self.calls = []

    def version(self):
        return {"version": "0.12.3"}

    def tags(self):
        return {"models": self.models}

    def chat(self, body):
        self.calls.append(json.loads(json.dumps(body)))  # 이후 messages 변경과 분리
        return {"message": {"role": "assistant", "content": self.replies.pop(0)},
                "done_reason": self.done_reason, "prompt_eval_count": 10, "eval_count": 20}


class GenerateTest(unittest.TestCase):
    def run_with(self, client, model="fake:7b"):
        out, meta = generate(SCENARIO, model, "v1", 0.7, 3, client)
        return json.loads(out) if out.lstrip().startswith("{") else out, meta

    def test_valid_output_gets_scenario_and_meta(self):
        client = FakeClient(GOOD)
        out, meta = self.run_with(client)
        self.assertEqual(out["scenario"], "req-004")
        self.assertEqual(len(out["rules"]), 1)
        for key in ("model", "digest", "ollama_version", "temperature", "seed", "prompt_version"):
            self.assertIn(key, meta)
        self.assertEqual((meta["digest"], meta["ollama_version"], meta["seed"]), (DIGEST, "0.12.3", 3))
        self.assertEqual(len(meta["attempts"]), 1)
        sent = client.calls[0]
        self.assertEqual(sent["options"], {"temperature": 0.7, "seed": 3, "num_ctx": NUM_CTX})
        self.assertFalse(sent["stream"])
        self.assertEqual(sent["format"], llm.output_schema())

    def test_invalid_output_is_regenerated_once_with_problems(self):
        client = FakeClient(BAD, GOOD)
        out, meta = self.run_with(client)
        self.assertEqual(out["rules"][0]["src"], "10.10.10.0/24")
        self.assertEqual(len(meta["attempts"]), 2)
        self.assertTrue(meta["attempts"][0]["problems"])
        self.assertEqual(meta["attempts"][1]["problems"], [])
        # seed 가 같으므로 같은 입력을 다시 보내지 않고, 이전 출력과 문제를 덧붙인다
        retry = client.calls[1]["messages"]
        self.assertEqual(retry[2], {"role": "assistant", "content": BAD})
        self.assertEqual(retry[3]["role"], "user")
        self.assertIn(meta["attempts"][0]["problems"][0], retry[3]["content"])

    def test_invalid_twice_is_passed_through_for_validator(self):
        out, meta = self.run_with(FakeClient(BAD, BAD))
        self.assertEqual(out["rules"][0]["src"], "10.10.10.1/24")  # 고치지 않고 그대로
        self.assertEqual(len(meta["attempts"]), 2)

    def test_non_json_twice_is_passed_through_raw(self):
        out, meta = self.run_with(FakeClient("not json", "still not json"))
        self.assertEqual(out, "still not json")
        self.assertIn("JSON 파싱 실패", meta["attempts"][1]["problems"][0])

    def test_truncation_is_execution_failure(self):
        for reason in ("length", None):
            with self.subTest(reason=reason), self.assertRaises(llm.GenerationError):
                self.run_with(FakeClient(GOOD, done_reason=reason))

    def test_missing_model_or_digest_is_execution_failure(self):
        for models in ([], [{"name": "fake:7b", "model": "fake:7b"}]):
            client = FakeClient(GOOD, models=models)
            with self.subTest(models=models), self.assertRaises(llm.GenerationError):
                self.run_with(client)
            self.assertEqual(client.calls, [])  # 조건을 모르면 생성하지 않는다

    def test_untagged_model_matches_latest(self):
        client = FakeClient(GOOD, models=[{"name": "fake:latest", "model": "fake:latest", "digest": DIGEST}])
        _, meta = self.run_with(client, model="fake")
        self.assertEqual(meta["digest"], DIGEST)

    def test_gold_and_probes_are_not_sent(self):
        client = FakeClient(GOOD)
        self.run_with(client)
        sent = json.dumps(client.calls[0]["messages"], ensure_ascii=False)
        for r in SCENARIO["requirements"]:
            self.assertIn(r, sent)
        for key in ("gold", "probes", "g-001", "a-001"):
            self.assertNotIn(key, sent)
        self.assertEqual(client.calls[0]["messages"][1]["content"], user_message(SCENARIO))

    def test_output_stem(self):
        self.assertEqual(output_stem("req-001", "qwen2.5:14b", 1), "req-001-qwen2.5-14b-s1")
        self.assertEqual(output_stem("req-001", "hf.co/user/m:Q4", 2), "req-001-hf.co-user-m-Q4-s2")
        self.assertEqual(output_stem("req-001", "qwen2.5:14b", 1, 1), "req-001-qwen2.5-14b-s1")
        self.assertEqual(output_stem("req-001", "qwen2.5:14b", 1, 2), "req-001-qwen2.5-14b-s1-r2")


PREV_META = {"model": "fake:7b", "digest": DIGEST, "ollama_version": "0.12.3", "temperature": 0.7,
             "seed": 3, "prompt_version": "v1"}
DEPLOY_FB = {
    "scenario": "req-004", "candidate": "req-004-fake-7b-s3", "round": 1,
    "source": {"batch_id": "20261101-120000", "rep": 1, "commit": "abc1234"},
    "stage": "deploy",
    "validation": {"ok": True, "risk": "low", "errors": [], "reasons": []},
    "failed_probes": [
        {"id": "a-001", "kind": "attack", "from": "attacker", "from_ip": "10.10.10.66", "to": "10.10.30.10",
         "proto": "tcp", "port": 8080, "expect": "block", "observed": "allow"},
        {"id": "n-009", "kind": "normal", "from": "pc", "from_ip": "10.10.20.10", "to": "10.10.30.10",
         "proto": "icmp", "expect": "allow", "observed": "block"},
    ],
}


class FeedbackTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "req-004-fake-7b-s3.json").write_text(
            json.dumps({"scenario": "req-004", **json.loads(GOOD)}), encoding="utf-8")
        (self.dir / "req-004-fake-7b-s3.meta.json").write_text(json.dumps(PREV_META), encoding="utf-8")

    def write_fb(self, **changes):
        path = self.dir / "req-004-fake-7b-s3.feedback.json"
        path.write_text(json.dumps({**DEPLOY_FB, **changes}), encoding="utf-8")
        return path

    def test_deploy_message_lists_failed_probes_and_allow_meaning(self):
        text = feedback_message(DEPLOY_FB)
        self.assertIn("10.10.10.66 → 10.10.30.10 tcp 8080: 차단되어야 하는데 통과했다", text)
        self.assertIn("10.10.20.10 → 10.10.30.10 icmp: 허용되어야 하는데 차단됐다", text)
        self.assertIn("포트를 열어 두지 않았더라도", text)  # observed allow 의 뜻 (#45)
        for key in ("a-001", "attacker", "nmap"):  # 프로브 id·호스트 이름·도구는 넣지 않는다
            self.assertNotIn(key, text)

    def test_validation_and_approval_messages(self):
        v = feedback_message({**DEPLOY_FB, "stage": "validation", "failed_probes": [],
                              "validation": {"ok": False, "risk": None, "errors": ["rules/0/dst: bad"], "reasons": []}})
        self.assertIn("- rules/0/dst: bad", v)
        a = feedback_message({**DEPLOY_FB, "stage": "approval", "failed_probes": [],
                              "validation": {"ok": True, "risk": "high", "errors": [],
                                             "reasons": ["r-001: accept 범위가 /16 보다 넓음"]}})
        self.assertIn("고위험", a)
        self.assertIn("- r-001: accept 범위가 /16 보다 넓음", a)

    def test_empty_evidence_or_unknown_stage_is_refused(self):
        for fb in ({**DEPLOY_FB, "failed_probes": []}, {**DEPLOY_FB, "stage": "approval"},
                   {**DEPLOY_FB, "stage": "applied"}):
            with self.subTest(stage=fb["stage"]), self.assertRaises(ValueError):
                feedback_message(fb)

    def test_load_feedback_checks_scenario_round_and_files(self):
        fb, text, meta = load_feedback(self.write_fb(), "req-004")
        self.assertNotIn("scenario", json.loads(text))  # LLM 이 낸 형식으로 되돌린다
        self.assertEqual(meta["seed"], 3)
        with self.assertRaisesRegex(ValueError, "시나리오"):
            load_feedback(self.write_fb(), "req-001")
        with self.assertRaisesRegex(ValueError, "round"):
            load_feedback(self.write_fb(round=2), "req-004")
        with self.assertRaisesRegex(ValueError, "후보 파일 없음"):
            load_feedback(self.write_fb(candidate="req-004-fake-7b-s9"), "req-004")

    def test_round_two_conversation_and_meta(self):
        path = self.write_fb()
        fb, text, prev_meta = load_feedback(path, "req-004")
        client = FakeClient(GOOD)
        out, meta = generate(SCENARIO, "fake:7b", "v1", 0.7, 3, client, feedback=(fb, text, prev_meta, path))
        sent = client.calls[0]["messages"]
        self.assertEqual([m["role"] for m in sent], ["system", "user", "assistant", "user"])
        self.assertEqual(sent[2]["content"], text)
        self.assertEqual(sent[3]["content"], feedback_message(fb))
        self.assertEqual((meta["round"], meta["parent"], meta["feedback"]["stage"]), (2, "req-004-fake-7b-s3", "deploy"))
        self.assertEqual(meta["feedback"]["source"], DEPLOY_FB["source"])
        for key in ("gold", "probes", "g-001"):
            self.assertNotIn(key, json.dumps(sent, ensure_ascii=False))


class ClientTest(unittest.TestCase):
    def test_connection_refused_is_execution_failure(self):
        # 아무도 듣지 않는 포트. 결과 대신 GenerationError 가 나야 한다
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        with self.assertRaisesRegex(llm.GenerationError, "연결하지 못함"):
            llm.Client(f"127.0.0.1:{port}").version()


class OutputSchemaTest(unittest.TestCase):
    def test_unsupported_keywords_removed(self):
        text = json.dumps(llm.output_schema())
        for key in ("pattern", "allOf", "minLength", "minimum", "$schema"):
            self.assertNotIn(f'"{key}"', text)
        self.assertIn('"$defs"', text)


if __name__ == "__main__":
    unittest.main()
