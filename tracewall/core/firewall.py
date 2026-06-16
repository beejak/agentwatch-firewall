"""
tracewall/core/firewall.py — the enforcement facade.

One stable seam for every transport, benchmark, and test:

    verdict = await firewall.check(event)

Pipeline (deterministic tiers are the fast path; only ESCALATE/NARROW awaits the
semantic judge):

    L0 identity   — token expiry, delegation depth, capability set
    enrich        — attach optional call-tree context
    tier-0 content— surface-form injection screen (noisy prior; never blocks alone)
    tier-1 policy — deterministic policy DSL  → BLOCK
    trust/taint   — gate routes ALLOW / ESCALATE / NARROW
    tier-2 semantic (await) on ESCALATE/NARROW (or when tier-0 flagged)
    audit         — append the verdict (always)

Fail-safe: any internal error → BLOCK (source="fail_safe").

The HOLD verdict and an async hold/barrier are reserved for *networked* transports
(MCP proxy / sidecar), which cannot await the judge inline; the in-process guard
resolves ESCALATE here by awaiting the judge directly.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Callable, Optional

from tracewall.audit.sink import AuditSink, LocalAuditSink
from tracewall.content.filter import flagged as content_flagged
from tracewall.core.signal import (
    EnrichedEvent,
    FirewallVerdict,
    HookEvent,
    IdentityCtx,
    Verdict,
)

logger = logging.getLogger(__name__)

MAX_DELEGATION_DEPTH = 8


class Firewall:
    """Transport-agnostic enforcement core.

    Parameters
    ----------
    ledger:         trust/taint/identity store (tracewall.taint.ledger.Ledger).
    policy:         deterministic policy DSL (tracewall.policy.engine.PolicyEngine).
    judge:          semantic tier (tracewall.semantic.judge.SemanticJudge).
    content_filter: callable(str)->bool tier-0 screen (defaults to content.filter.flagged).
    audit:          AuditSink; defaults to a local append-only JSONL sink.
    """

    def __init__(
        self,
        ledger,
        policy,
        judge,
        content_filter: Callable[[str], bool] = content_flagged,
        audit: Optional[AuditSink] = None,
    ) -> None:
        self._ledger = ledger
        self._policy = policy
        self._judge = judge
        self._content_filter = content_filter
        self._audit = audit if audit is not None else LocalAuditSink()

    async def check(self, event: HookEvent) -> FirewallVerdict:
        t0 = time.perf_counter()
        completeness: dict[str, bool] = {"identity": False, "call_tree": False, "ledger": False}
        try:
            verdict = await self._check(event, completeness)
        except Exception as e:  # any internal failure → fail-safe BLOCK
            logger.error("tracewall: check exception — fail-safe BLOCK: %s", e)
            verdict = self._verdict(event, Verdict.BLOCK, 0.0, "fail_safe",
                                    f"internal error: {e}", completeness)
        verdict.latency_ms = (time.perf_counter() - t0) * 1000
        try:
            await self._audit.write(verdict, event)
        except Exception as e:
            logger.error("tracewall: audit write failed: %s", e)
        return verdict

    # ── Pipeline ─────────────────────────────────────────────────────────────

    async def _check(self, event: HookEvent, completeness: dict[str, bool]) -> FirewallVerdict:
        aid = event.agent_id

        # L0 — identity: token valid, caps include this tool, depth OK
        identity = await self._ledger.get_identity(aid)
        completeness["identity"] = identity is not None
        if identity:
            id_block = _check_identity(identity, event)
            if id_block:
                return self._verdict(event, Verdict.BLOCK, 0.0, "identity", id_block, completeness)

        # enrich (optional call-tree context)
        enriched = EnrichedEvent(event=event, call_tree=list(event.caller_chain or []))
        completeness["call_tree"] = bool(enriched.call_tree)

        # tier-0 content — surface-form injection screen (noisy; never blocks alone)
        content_flag = bool(self._content_filter(_content(event)))

        # tier-1 deterministic policy match
        rule_match = await self._policy.evaluate(enriched)
        if rule_match and rule_match.verdict == "BLOCK":
            return self._verdict(event, Verdict.BLOCK, 0.0, "deterministic",
                                 rule_match.reason, completeness)

        # trust/taint gate (routes, never hard-blocks alone)
        trust, taint = await self._get_trust_taint(aid, completeness)
        route = _route(trust, taint)

        if route == "ALLOW" and not content_flag:
            return self._verdict(event, Verdict.ALLOW, trust, "trust_gate", "clean", completeness)

        # ESCALATE / NARROW (or tier-0 flagged) — await the semantic judge inline
        result = await self._judge.analyze(event, enriched, trust, taint)
        action = Verdict.BLOCK if result.action == "BLOCK" else Verdict.ALLOW
        trigger = f"route={route}" + (", content_flag" if content_flag else "")
        return self._verdict(event, action, result.score, "semantic",
                             f"{trigger}: {result.reason}", completeness)

    async def _get_trust_taint(self, aid: str, completeness: dict[str, bool]) -> tuple[float, float]:
        trust = 0.5
        taint = 0.0
        try:
            trust = await self._ledger.get_trust(aid)
            t = await self._ledger.get_taint(aid)
            taint = t.level if t else 0.0
            completeness["ledger"] = True
        except Exception as e:
            logger.warning("tracewall: ledger read failed (%s) — defaults", e)
        return trust, taint

    def _verdict(
        self,
        event: HookEvent,
        action: Verdict,
        score: float,
        source: str,
        reason: str,
        completeness: dict[str, bool],
    ) -> FirewallVerdict:
        return FirewallVerdict(
            event_id=event.event_id,
            agent_id=event.agent_id,
            tool=event.tool,
            action=action,
            score=score,
            source=source,
            reason=reason,
            context_completeness=dict(completeness),
        )


# ── Pure helpers (ported verbatim from the original enforcement path) ─────────

def _route(trust: float, taint: float) -> str:
    if taint >= 0.7:   return "ESCALATE"   # quarantine threshold
    if trust > 0.7:    return "ALLOW"
    if trust >= 0.3:   return "ESCALATE"
    return "NARROW"                         # NARROW caps + ESCALATE


def _check_identity(identity: IdentityCtx, event: HookEvent) -> Optional[str]:
    if identity.token_exp and time.time() > identity.token_exp:
        return "token expired"
    if identity.delegation_depth > MAX_DELEGATION_DEPTH:
        return f"delegation depth {identity.delegation_depth} exceeds MAX_DEPTH={MAX_DELEGATION_DEPTH}"
    if identity.caps and event.tool not in identity.caps:
        return f"tool '{event.tool}' not in agent capabilities"
    return None


def _content(event: HookEvent) -> str:
    a = event.args or {}
    return a.get("content") or a.get("body") or a.get("command") or json.dumps(a)
