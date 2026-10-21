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
    ledger write  — on_clean_call (ALLOW) / on_taint_event (BLOCK from policy|semantic)

Fail-safe: any internal error → BLOCK (source="fail_safe").

`require_identity=True` fail-closes when no identity is registered for the agent
(default False so MCP/context-starved transports still degrade gracefully).

`require_caps=True` fail-closes when identity has an empty capability set or the
tool is absent from caps (ZTA default-deny on capabilities).

`deny_unknown_tools=True` (zta/paranoid) fail-closes when the tool is not in
``caps ∪ declared_tools`` (declared = tools named in the loaded YAML pack).
Lab ``balanced`` keeps this off so pack-only regression stays honest.

`session_ratchet` (E4, optional): after any BLOCK, elevate the session key; later
egress-sensitive tools BLOCK with ``rule_id=session_ratchet``. Off when the
handle is ``None`` (lab default).

Verdict.score is always **0.0 bad … 1.0 clean** (semantic malicious scores are
inverted at this facade).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import TYPE_CHECKING, Callable, Iterable, Optional

from tracewall.audit.sink import AuditSink, LocalAuditSink
from tracewall.content.filter import flagged as content_flagged
from tracewall.core.signal import (
    EnrichedEvent,
    FirewallVerdict,
    HookEvent,
    IdentityCtx,
    Verdict,
)
from tracewall.ops.metrics import Metrics
from tracewall.policy.normalize import canonical_tool_name

if TYPE_CHECKING:
    from tracewall.transports.session_ratchet import SessionRatchet

logger = logging.getLogger(__name__)

MAX_DELEGATION_DEPTH = 8


def args_hash(args: dict | None) -> str:
    raw = json.dumps(args or {}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class Firewall:
    """Transport-agnostic enforcement core."""

    def __init__(
        self,
        ledger,
        policy,
        judge,
        content_filter: Callable[[str], bool] = content_flagged,
        audit: Optional[AuditSink] = None,
        require_identity: bool = False,
        require_caps: bool = False,
        deny_unknown_tools: bool = False,
        declared_tools: Iterable[str] | None = None,
        metrics: Metrics | None = None,
        session_ratchet: Optional["SessionRatchet"] = None,
    ) -> None:
        self._ledger = ledger
        self._policy = policy
        self._judge = judge
        self._content_filter = content_filter
        self._audit = audit if audit is not None else LocalAuditSink()
        self._require_identity = require_identity
        self._require_caps = require_caps
        self._deny_unknown_tools = deny_unknown_tools
        if declared_tools is not None:
            self._declared_tools = frozenset(canonical_tool_name(t) for t in declared_tools)
        elif deny_unknown_tools and hasattr(policy, "declared_tools"):
            self._declared_tools = frozenset(policy.declared_tools())
        else:
            self._declared_tools = frozenset()
        self.metrics = metrics
        self._session_ratchet = session_ratchet

    async def check(self, event: HookEvent) -> FirewallVerdict:
        t0 = time.perf_counter()
        completeness: dict[str, bool] = {
            "identity": False,
            "call_tree": False,
            "ledger": False,
            "session_chain": False,
        }
        try:
            verdict = await self._check(event, completeness)
        except Exception as e:  # any internal failure → fail-safe BLOCK
            logger.error("tracewall: check exception — fail-safe BLOCK: %s", e)
            verdict = self._verdict(
                event, Verdict.BLOCK, 0.0, "fail_safe",
                f"internal error: {e}", completeness,
            )
        if verdict.action == Verdict.BLOCK and self._session_ratchet is not None:
            try:
                self._session_ratchet.note_block(event.session_id, event.agent_id)
            except Exception as e:
                logger.warning("tracewall: session_ratchet note_block failed: %s", e)
        verdict.latency_ms = (time.perf_counter() - t0) * 1000
        if self.metrics is not None:
            try:
                self.metrics.record(
                    action=verdict.action.value,
                    latency_ms=verdict.latency_ms,
                    call_tree_empty=not bool(event.caller_chain),
                )
            except Exception as e:
                logger.warning("tracewall: metrics record failed: %s", e)
        try:
            await self._audit.write(verdict, event)
        except Exception as e:
            logger.error("tracewall: audit write failed: %s", e)
        return verdict

    async def _check(self, event: HookEvent, completeness: dict[str, bool]) -> FirewallVerdict:
        aid = event.agent_id

        identity = await self._ledger.get_identity(aid)
        completeness["identity"] = identity is not None
        if identity is None and self._require_identity:
            return self._verdict(
                event, Verdict.BLOCK, 0.0, "identity",
                "identity required but not registered", completeness,
            )
        if identity:
            id_block = _check_identity(identity, event, require_caps=self._require_caps)
            if id_block:
                return self._verdict(
                    event, Verdict.BLOCK, 0.0, "identity", id_block, completeness,
                )
        elif self._require_caps:
            return self._verdict(
                event, Verdict.BLOCK, 0.0, "identity",
                "capabilities required but no identity registered", completeness,
            )

        if self._deny_unknown_tools:
            unknown = _check_unknown_tool(
                event, identity=identity, declared=self._declared_tools,
            )
            if unknown:
                return self._verdict(
                    event, Verdict.BLOCK, 0.0, "unknown_tool", unknown, completeness,
                    rule_id="deny_unknown_tools",
                )

        enriched = EnrichedEvent(event=event, call_tree=list(event.caller_chain or []))
        completeness["call_tree"] = bool(enriched.call_tree)
        completeness["session_chain"] = bool(event.session_id)

        if self._session_ratchet is not None and self._session_ratchet.should_contain(
            event.tool, event.session_id, aid,
        ):
            await self._ledger_feedback(aid, Verdict.BLOCK, severity=0.8)
            return self._verdict(
                event, Verdict.BLOCK, 0.0, "session_ratchet",
                (
                    f"session elevated after prior BLOCK; "
                    f"egress tool '{event.tool}' contained (session_ratchet)"
                ),
                completeness,
                rule_id="session_ratchet",
            )

        content_flag = bool(self._content_filter(_content(event)))

        rule_match = await self._policy.evaluate(enriched)
        if rule_match and rule_match.verdict == "BLOCK":
            await self._ledger_feedback(aid, Verdict.BLOCK, severity=rule_match.severity)
            return self._verdict(
                event, Verdict.BLOCK, 0.0, "deterministic",
                rule_match.reason, completeness, rule_id=rule_match.rule_id,
            )

        trust, taint = await self._get_trust_taint(aid, completeness)
        route = _route(trust, taint)

        if route == "ALLOW" and not content_flag:
            await self._ledger_feedback(aid, Verdict.ALLOW)
            return self._verdict(
                event, Verdict.ALLOW, trust, "trust_gate", "clean", completeness,
            )

        result = await self._judge.analyze(event, enriched, trust, taint)
        action = Verdict.BLOCK if result.action == "BLOCK" else Verdict.ALLOW
        clean_score = max(0.0, min(1.0, 1.0 - float(result.score)))
        trigger = f"route={route}" + (", content_flag" if content_flag else "")
        await self._ledger_feedback(aid, action, severity=float(result.score))
        return self._verdict(
            event, action, clean_score, "semantic",
            f"{trigger}: {result.reason}", completeness,
        )

    async def _ledger_feedback(self, aid: str, action: Verdict, severity: float = 0.5) -> None:
        try:
            if action == Verdict.ALLOW:
                await self._ledger.on_clean_call(aid, "")
            elif action == Verdict.BLOCK:
                await self._ledger.on_taint_event(aid, max(0.0, min(1.0, severity)))
        except Exception as e:
            logger.warning("tracewall: ledger feedback failed: %s", e)

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
        rule_id: str = "",
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
            rule_id=rule_id,
            args_hash=args_hash(event.args),
        )


def _route(trust: float, taint: float) -> str:
    if taint >= 0.7:
        return "ESCALATE"
    if trust > 0.7:
        return "ALLOW"
    if trust >= 0.3:
        return "ESCALATE"
    return "NARROW"


def _check_identity(
    identity: IdentityCtx,
    event: HookEvent,
    *,
    require_caps: bool = False,
) -> Optional[str]:
    if identity.token_exp and time.time() > identity.token_exp:
        return "token expired"
    if identity.delegation_depth > MAX_DELEGATION_DEPTH:
        return (
            f"delegation depth {identity.delegation_depth} "
            f"exceeds MAX_DEPTH={MAX_DELEGATION_DEPTH}"
        )
    if require_caps and not identity.caps:
        return "capabilities required but identity.caps is empty"
    if identity.caps:
        allowed = {canonical_tool_name(c) for c in identity.caps}
        if canonical_tool_name(event.tool) not in allowed:
            return f"tool '{event.tool}' not in agent capabilities"
    return None


def _check_unknown_tool(
    event: HookEvent,
    *,
    identity: Optional[IdentityCtx],
    declared: frozenset[str],
) -> Optional[str]:
    """Default-deny tools absent from caps ∪ declared YAML tool names."""
    tool = canonical_tool_name(event.tool)
    if not tool:
        return (
            "unknown tool '' denied (deny_unknown_tools); "
            "register caps or add a YAML rule naming the tool"
        )
    allowed = set(declared)
    if identity and identity.caps:
        allowed |= {canonical_tool_name(c) for c in identity.caps}
    if tool in allowed:
        return None
    return (
        f"unknown tool '{event.tool}' denied (deny_unknown_tools); "
        "register caps or add a YAML rule naming the tool"
    )


def _content(event: HookEvent) -> str:
    a = event.args or {}
    return a.get("content") or a.get("body") or a.get("command") or json.dumps(a)
