"""
firewall/integration/chronicle_bridge.py — the watchtower↔firewall seam.

The firewall (enforcement) and watchtower (observability) were designed as one
layered system but were never wired together. This module is the bridge: it maps
a firewall enforcement decision (FirewallVerdict) onto a watchtower observability
span (Signal) and writes it to the append-only Chronicle — the paper's L8 audit
layer. This gives the integrated system a single, queryable audit trail covering
both what was observed and what was enforced.

Direction implemented here: firewall verdict → watchtower chronicle.
(The reverse — watchtower context enriching a firewall decision — is a separate
step; see EnrichedEvent / behavioral baseline integration.)

firewall/ is permitted to depend on watchtower/ (firewall/core/signal.py declares
it "extends watchtower/core/signal.py"); watchtower/ never imports firewall/.
"""
from __future__ import annotations

from typing import Optional

from watchtower.core.signal import Signal
from firewall.core.signal import FirewallVerdict, HookEvent, Verdict


# Firewall verdict action → observability span status.
_VERDICT_STATUS = {
    Verdict.ALLOW: "ok",
    Verdict.BLOCK: "blocked",
    Verdict.HOLD: "held",
}


def _infer_memory_op(tool: str) -> Optional[str]:
    """Best-effort memory operation tag from the tool name (for chronicle queries)."""
    t = tool.lower()
    if "memory" not in t and "mem_" not in t:
        return None
    if "write" in t or "store" in t or "put" in t or "save" in t:
        return "write"
    if "read" in t or "get" in t or "query" in t or "search" in t:
        return "read"
    return "access"


def verdict_to_signal(
    verdict: FirewallVerdict,
    event: Optional[HookEvent] = None,
) -> Signal:
    """
    Map a firewall enforcement decision onto a watchtower observability span.

    The Signal is the canonical chronicle record (watchtower/core/signal.py); we
    populate it so a verdict is fully reconstructable from the audit trail:
      - trace_id groups a session's spans (session_id, falling back to event_id)
      - status carries the enforcement outcome (ok | blocked | held)
      - policy_checked marks that the firewall evaluated this call
      - summary preserves verdict|source|score|reason for forensic queries
    """
    session = (event.session_id if event and event.session_id else "") or verdict.event_id
    caller = None
    if event and len(event.caller_chain) >= 2:
        caller = event.caller_chain[-2]

    status = _VERDICT_STATUS.get(verdict.action, "ok")

    return Signal(
        trace_id=session,
        span_id=verdict.event_id,
        parent_span_id=None,
        agent_id=verdict.agent_id,
        action=verdict.tool,
        status=status,
        timestamp=verdict.ts,
        duration_ms=verdict.latency_ms,
        caller_agent_id=caller,
        memory_op=_infer_memory_op(verdict.tool),
        policy_checked=True,
        summary=f"verdict={verdict.action.value} source={verdict.source} "
                f"score={verdict.score:.3f} reason={verdict.reason}",
    )


async def write_verdict(writer, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> Signal:
    """
    Convert a firewall verdict to a Signal and append it to the Chronicle via a
    watchtower ChronicleWriter. Returns the Signal that was written.

    `writer` is a watchtower.chronicle.writer.ChronicleWriter (already started).
    Append-only: this only ever writes; it never updates or deletes (invariant V).
    """
    signal = verdict_to_signal(verdict, event)
    await writer.write_signal(signal)
    return signal
