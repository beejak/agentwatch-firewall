"""
tracewall test fixtures — pure, zero infra.

No redis/clickhouse/postgres/neo4j. The only state is a function-scoped SQLite
Ledger on a tmp path (fresh per test), plus an injectable frozen clock so
time-decay is deterministic. The semantic backend is forced deterministic so the
suite is key-free and reproducible.
"""
from __future__ import annotations

import pytest

from tracewall.audit.sink import NullAuditSink
from tracewall.core.firewall import Firewall
from tracewall.policy.engine import PolicyEngine
from tracewall.semantic.judge import SemanticJudge
from tracewall.taint.ledger import Ledger

FROZEN_NOW = 1_700_000_000.0  # fixed unix ts for deterministic decay


@pytest.fixture(autouse=True)
def _force_deterministic(monkeypatch):
    """Every test runs the deterministic semantic backend (no key, reproducible)."""
    monkeypatch.setenv("TRACEWALL_SEMANTIC_LLM", "0")


@pytest.fixture
def ledger(tmp_path):
    """Fresh SQLite ledger per test (real wall clock)."""
    return Ledger(str(tmp_path / "tw.db"))


@pytest.fixture
def make_ledger(tmp_path):
    """Factory for a ledger with a fixed clock — deterministic time-decay."""
    counter = {"n": 0}

    def _make(now: float = FROZEN_NOW):
        counter["n"] += 1
        return Ledger(str(tmp_path / f"tw_frozen_{counter['n']}.db"), now=lambda: now)

    return _make


@pytest.fixture
async def policy():
    p = PolicyEngine()
    await p.load_policies()   # packaged tracewall/policy/rules/
    return p


@pytest.fixture
async def firewall(ledger, policy):
    """A fully-wired firewall with a no-op audit sink."""
    return Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=NullAuditSink())
