"""Pure tests for the AgentDojo adapter — no `agentdojo`/`openai` needed.

The adapter's value is that the heavy benchmark deps are lazy-imported inside
functions, so the module loads (and CI runs) without the `[bench]` extra. These
tests guard that contract plus the pure ASR/utility math. The full benchmark
itself needs `[bench,llm]` + a live LLM key and is run manually, not in CI.
"""
import importlib


def test_module_imports_without_bench_extra():
    m = importlib.import_module("tracewall.eval.adapters.agentdojo")
    assert hasattr(m, "run") and hasattr(m, "main") and hasattr(m, "_rate")


def test_rate_math():
    from tracewall.eval.adapters.agentdojo import _rate

    assert _rate({}) == 0.0
    assert _rate({"a": True}) == 1.0
    assert _rate({"a": False}) == 0.0
    assert _rate({"a": True, "b": False}) == 0.5


def test_argparser_defaults_to_all_tasks():
    """Absent --user-tasks/--injection-tasks must be None (= run all), not []."""
    from tracewall.eval.adapters import agentdojo

    ap = __import__("argparse").ArgumentParser()
    ap.add_argument("--user-tasks", nargs="*", default=None)
    ap.add_argument("--injection-tasks", nargs="*", default=None)
    ns = ap.parse_args([])
    assert ns.user_tasks is None and ns.injection_tasks is None
