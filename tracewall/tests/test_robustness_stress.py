"""Cross-domain robustness stress (no LLM)."""
import pytest

from tracewall.eval.robustness_stress import run_matrix, scenarios


@pytest.mark.asyncio
async def test_robustness_matrix_all_pass():
    rows = await run_matrix()
    failed = [r for r in rows if not r["pass"]]
    assert not failed, failed
    domains = {c["domain"] for c in scenarios()}
    assert {"workspace", "contagion", "host", "identity", "banking"} <= domains


def test_scenarios_include_limits():
    kinds = {c["kind"] for c in scenarios()}
    assert "success" in kinds and "expected_limit" in kinds
