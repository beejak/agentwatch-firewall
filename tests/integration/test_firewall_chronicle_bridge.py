"""Integration seam: firewall enforcement verdict → watchtower chronicle (L8).

Proves the two subsystems compose: a FirewallVerdict becomes an observability
Signal and lands in the append-only Chronicle, queryable as one audit trail.
"""
import asyncio
import uuid

import pytest

from firewall.core.signal import FirewallVerdict, HookEvent, Verdict
from firewall.integration.chronicle_bridge import verdict_to_signal, write_verdict


def _verdict(action=Verdict.BLOCK, tool="memory_write", agent="agent-x", **kw):
    return FirewallVerdict(
        event_id=str(uuid.uuid4()),
        agent_id=agent,
        tool=tool,
        action=action,
        score=kw.get("score", 0.1),
        source=kw.get("source", "deterministic"),
        reason=kw.get("reason", "matched minja_memory rule"),
        latency_ms=kw.get("latency_ms", 0.5),
    )


def test_verdict_to_signal_block_maps_status():
    v = _verdict(action=Verdict.BLOCK)
    s = verdict_to_signal(v)
    assert s.status == "blocked"
    assert s.policy_checked is True
    assert s.span_id == v.event_id
    assert s.action == "memory_write"
    assert s.memory_op == "write"
    assert "verdict=block" in s.summary and "source=deterministic" in s.summary


def test_verdict_to_signal_allow_and_hold():
    assert verdict_to_signal(_verdict(action=Verdict.ALLOW)).status == "ok"
    assert verdict_to_signal(_verdict(action=Verdict.HOLD)).status == "held"


def test_verdict_to_signal_uses_session_and_caller_chain():
    ev = HookEvent(
        agent_id="agent-x", tool="memory_write", args={}, session_id="sess-1",
        caller_chain=["orchestrator", "parent", "agent-x"],
    )
    s = verdict_to_signal(_verdict(), ev)
    assert s.trace_id == "sess-1"
    assert s.caller_agent_id == "parent"


def test_verdict_to_signal_falls_back_to_event_id_for_trace():
    v = _verdict()
    s = verdict_to_signal(v)  # no HookEvent → trace_id falls back to event_id
    assert s.trace_id == v.event_id


async def test_write_verdict_appends_to_chronicle(clickhouse_client):
    from watchtower.chronicle.writer import ChronicleWriter
    from watchtower.chronicle.reader import ChronicleReader

    writer = ChronicleWriter(client=clickhouse_client)
    await writer.start()
    reader = ChronicleReader(client=clickhouse_client)
    try:
        trace = f"sess-{uuid.uuid4()}"
        ev = HookEvent(agent_id="agent-x", tool="memory_write", args={}, session_id=trace)
        await write_verdict(writer, _verdict(action=Verdict.BLOCK), ev)
        await writer.flush()
        await asyncio.sleep(0.5)

        spans = await reader.get_trace(trace)
        assert len(spans) >= 1, "verdict not written to chronicle"
        row = spans[0]
        assert row["trace_id"] == trace
        assert row["status"] == "blocked"
        # the full verdict round-trips via the chronicle summary field
        assert "verdict=block" in row["summary"]
        assert "source=deterministic" in row["summary"]
    finally:
        await writer.stop()
