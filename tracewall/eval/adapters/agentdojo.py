"""
tracewall/eval/adapters/agentdojo.py — run tracewall as an AgentDojo defense.

Transport #2 *evaluation* wrapper: intercepts the tool calls an AgentDojo agent
makes and runs them through the firewall, so we can report attack-success-rate
(ASR) with vs. without tracewall, and with vs. without call-tree context (via the
verdict's `context_completeness`).

Isolated on purpose: `agentdojo` is an optional `[bench]` dependency and is
imported lazily inside functions, so this module — and the rest of tracewall —
imports fine without it. A benchmark version bump never touches the core.

Install: `pip install -e .[bench]`.
"""
from __future__ import annotations

import tempfile
from typing import Any, Optional

from tracewall.core.firewall import Firewall
from tracewall.core.signal import FirewallVerdict, Verdict
from tracewall.transports.python_guard import GuardBlocked, guard


def build_default_firewall(db_path: Optional[str] = None) -> Firewall:
    """Construct a Firewall with the standalone defaults (deterministic, key-free)."""
    from tracewall.audit.sink import NullAuditSink
    from tracewall.policy.engine import PolicyEngine
    from tracewall.semantic.judge import SemanticJudge
    from tracewall.taint.ledger import Ledger

    if db_path is None:
        db_path = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
    ledger = Ledger(db_path)
    policy = PolicyEngine()
    judge = SemanticJudge()
    fw = Firewall(ledger=ledger, policy=policy, judge=judge, audit=NullAuditSink())
    # PolicyEngine.load_policies is async; the caller loads it before first use.
    fw._policy_loaded = False  # type: ignore[attr-defined]
    return fw


class TracewallDefense:
    """A thin AgentDojo-side hook: check each tool call, block on BLOCK.

    Usage is intentionally framework-shaped without importing agentdojo at module
    load. Wire `check_tool_call` into AgentDojo's pipeline (e.g. a PipelineElement
    that runs before tool execution); on a BLOCK it raises so the harness records
    the attack as prevented.
    """

    def __init__(self, firewall: Firewall, agent_id: str = "agentdojo-agent",
                 fail_closed: bool = True) -> None:
        self._fw = firewall
        self._agent_id = agent_id
        self._fail_closed = fail_closed

    async def ensure_loaded(self) -> None:
        if not getattr(self._fw, "_policy_loaded", False):
            await self._fw._policy.load_policies()  # type: ignore[attr-defined]
            self._fw._policy_loaded = True  # type: ignore[attr-defined]

    async def check_tool_call(
        self,
        tool: str,
        args: dict,
        caller_chain: Optional[list[str]] = None,
        session_id: str = "",
    ) -> FirewallVerdict:
        """Returns the verdict on ALLOW; raises GuardBlocked on BLOCK."""
        await self.ensure_loaded()
        ctx = {
            "agent_id": self._agent_id,
            "caller_chain": list(caller_chain or []),
            "session_id": session_id,
        }
        return await guard(self._fw, tool, args, ctx, fail_closed=self._fail_closed)


def was_blocked(exc: Any) -> bool:
    """Helper for the harness: True if an exception is a tracewall BLOCK."""
    return isinstance(exc, GuardBlocked) and exc.verdict.action == Verdict.BLOCK
