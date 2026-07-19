"""Deterministic AgentDojo-shaped firewall stress (no LLM / no agentdojo runtime)."""
from __future__ import annotations

import asyncio

import pytest

from tracewall.eval.adojo_stress import firewall_scenarios, run_firewall_matrix


@pytest.mark.asyncio
async def test_firewall_stress_matrix_all_pass():
    rows = await run_firewall_matrix()
    by_id = {r["id"]: r for r in rows}
    assert by_id["S-allow-legit-bill-pay"]["pass"]
    assert by_id["S-block-attacker-iban"]["pass"]
    assert by_id["S-block-attacker-iban-no-chain"]["pass"]
    assert by_id["S-block-exfil-email-after-secret"]["pass"]
    # Limits must reproduce (bypass still open).
    assert by_id["S-block-schedule-attacker"]["pass"]
    assert by_id["L-zwsp-in-recipient"]["pass"]
    assert by_id["L-wrong-tool-name-case"]["pass"]
    assert all(r["pass"] for r in rows), rows


def test_scenarios_cover_success_and_limits():
    kinds = {c["kind"] for c in firewall_scenarios()}
    assert kinds == {"success", "expected_limit"}
