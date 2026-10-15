"""Ollama API 호출. (담당: 서진정)

Ollama HTTP API(/api/chat, /api/tags, /api/version)를 표준 라이브러리로 부른다. 추가 의존성 없음.
호스트는 OLLAMA_HOST (기본 http://localhost:11434).
"""

import json
import os
import urllib.error
import urllib.request

from common.ir import ROOT

SCHEMA = ROOT / "schema" / "rule.schema.json"
# 구조화 출력(format)에 넘기지 않는 키워드. 전체 스키마 검사는 생성 후와 validator 에서 한다
UNSUPPORTED = {"$schema", "$id", "title", "description", "pattern", "allOf", "minLength", "minimum"}
DEFAULT_HOST = "http://localhost:11434"
TIMEOUT_S = 600  # 14B 모델을 CPU 로 돌리면 몇 분 걸릴 수 있다


class GenerationError(RuntimeError):
    """정상 출력을 관측하지 못함(연결 실패, 모델 없음, 출력 잘림). 반려가 아니라 실행 실패로 처리한다."""


def _strip(node):
    if isinstance(node, dict):
        return {k: _strip(v) for k, v in node.items() if k not in UNSUPPORTED}
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def output_schema():
    """LLM 출력 형식: {"rules": [...]}. scenario 는 생성기가 붙인다."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return _strip({
        "type": "object",
        "properties": {"rules": schema["properties"]["rules"]},
        "required": ["rules"],
        "additionalProperties": False,
        "$defs": schema["$defs"],
    })


class Client:
    """Ollama HTTP 클라이언트. 테스트에서는 같은 메서드를 가진 가짜로 바꾼다."""

    def __init__(self, host=None):
        self.host = (host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")
        if "://" not in self.host:
            self.host = "http://" + self.host

    def _request(self, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.host + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as res:
                return json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as ex:
            detail = ex.read().decode("utf-8", "replace").strip()
            raise GenerationError(f"Ollama {path} HTTP {ex.code}: {detail}") from ex
        except (urllib.error.URLError, OSError) as ex:  # 연결 거부, 타임아웃
            raise GenerationError(f"Ollama 에 연결하지 못함 ({self.host}{path}): {ex}") from ex
        except ValueError as ex:
            raise GenerationError(f"Ollama {path} 응답이 JSON 이 아님: {ex}") from ex

    def version(self):
        return self._request("/api/version")

    def tags(self):
        return self._request("/api/tags")

    def chat(self, body):
        return self._request("/api/chat", body)


def environment(model, client):
    """재현 조건: (모델 digest, Ollama 버전). 확인하지 못하면 GenerationError."""
    version = client.version().get("version")
    if not version:
        raise GenerationError("Ollama 버전을 확인하지 못함")
    # 태그를 생략하면 Ollama 는 :latest 로 찾는다
    names = {model, model if ":" in model else model + ":latest"}
    for m in client.tags().get("models", []):
        if m.get("name") in names or m.get("model") in names:
            if not m.get("digest"):
                break
            return m["digest"], version
    raise GenerationError(f"모델이 없거나 digest 를 확인하지 못함: {model} (ollama pull {model})")


def chat(messages, model, options, client):
    """한 번 호출해서 (응답 텍스트, 호출 정보) 를 돌려준다. 출력이 잘리면 GenerationError."""
    res = client.chat({
        "model": model,
        "messages": messages,
        "format": output_schema(),
        "options": options,
        "stream": False,
    })
    info = {
        "done_reason": res.get("done_reason"),
        "prompt_eval_count": res.get("prompt_eval_count"),
        "eval_count": res.get("eval_count"),
        "total_duration_ns": res.get("total_duration"),
    }
    if res.get("done_reason") != "stop":
        raise GenerationError(f"정상 출력 없음: done_reason={res.get('done_reason')}")
    text = (res.get("message") or {}).get("content")
    if text is None:
        raise GenerationError("응답에 message.content 가 없음")
    return text, info
