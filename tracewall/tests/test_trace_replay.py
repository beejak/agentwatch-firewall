"""
Frozen trace-fixture replay.

Realistic agent-trace shapes (tool + args + caller_chain) are captured once as a
static JSONL fixture and replayed through the firewall. This gives the suite
realistic event shapes WITHOUT any external/observability dependency — the
fixture is data, nothing is imported from any trace source. Regenerating the
fixture is a deliberate, reviewed act.
"""
import json
from pathlib import Path

import pytest

from tracewall.core.signal import HookEvent
from tracewall.transports.python_guard import GuardBlocked, guard

FIXTURE = Path(__file__).parent / "fixtures" / "agent_traces.jsonl"


def _load():
    return [json.loads(l) for l in FIXTURE.read_text().splitlines() if l.strip()]


def test_fixture_present_and_shaped():
    rows = _load()
    assert rows, "trace fixture is empty"
    for r in rows:
        assert {"agent_id", "tool", "args", "expect"} <= set(r)


@pytest.mark.parametrize("row", _load(), ids=lambda r: r["note"])
async def test_replay_trace(firewall, row):
    ctx = {"agent_id": row["agent_id"], "caller_chain": row.get("caller_chain", []),
           "session_id": row.get("session_id", "")}
    if row["expect"] == "BLOCK":
        with pytest.raises(GuardBlocked):
            await guard(firewall, row["tool"], row["args"], ctx)
    else:
        v = await guard(firewall, row["tool"], row["args"], ctx)
        assert v.action.value == "allow"
