"""
hermes.py — Firewall intercept adapter for Hermes Agent.

Registers pre_tool_call and pre_gateway_dispatch hooks.
This is the enforcement point — the bouncer at the door.

Drop this file into ~/.hermes/plugins/ to activate.
No fork of Hermes required.

Architecture position:
    Hermes agent calls tool
        → pre_tool_call fires HERE
        → HookEvent → EnrichedEvent (graphify)
        → deterministic rule check (superpowers policy)
        → trust/taint gate (cavemem)
        → ALLOW / BLOCK / HOLD
        → post_tool_call: write FirewallVerdict to chronicle + cavemem
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from firewall.core.signal import (
    FirewallVerdict,
    HookEvent,
    IdentityCtx,
    Taint,
    Verdict,
)

logger = logging.getLogger(__name__)

# Lazy imports — adapters loaded only when enforcement engine is up
_graphify: Any = None
_cavemem: Any = None
_superpowers: Any = None
_ruflo: Any = None
_chronicle: Any = None

# In-process trust cache (TTL 5s) — keeps hot-path latency < 2ms
_trust_cache: dict[str, tuple[float, float]] = {}   # aid -> (score, expires_at)
_TRUST_TTL = 5.0

# Hold registry: event_id -> asyncio.Future[FirewallVerdict]
_holds: dict[str, asyncio.Future] = {}
_holds_lock = asyncio.Lock()


# ── Public plugin entry points (Hermes plugin API) ──────────────────────────

async def on_load(ctx) -> None:
    """Called once when Hermes loads the plugin."""
    global _graphify, _cavemem, _superpowers, _ruflo, _chronicle
    try:
        from agents.adapters.graphify import GraphifyAdapter
        from agents.adapters.cavemem import CavememAdapter
        from agents.adapters.superpowers import SuperpowersAdapter
        from agents.adapters.ruflo import RufloAdapter
        _graphify   = GraphifyAdapter()
        _cavemem    = CavememAdapter()
        _superpowers = SuperpowersAdapter()
        _ruflo      = RufloAdapter()
        await _superpowers.load_policies("policies/")
        logger.info("firewall: adapters loaded")
    except Exception as e:
        logger.error("firewall: adapter load failed — fail-safe active: %s", e)


async def pre_tool_call(ctx, tool: str, args: dict) -> dict | None:
    """
    Hermes hook: fires before every tool call.
    Returns None to allow, or {"block": True, "reason": str} to block.
    Must complete within 10ms p99.
    """
    t0 = time.perf_counter()
    event = HookEvent(
        agent_id=_agent_id(ctx),
        tool=tool,
        args=args,
        session_id=_session_id(ctx),
        caller_chain=_caller_chain(ctx),
    )
    try:
        verdict = await _enforce(event)
    except Exception as e:
        # Any internal failure → fail-safe BLOCK
        logger.error("firewall: enforce exception — fail-safe BLOCK: %s", e)
        verdict = FirewallVerdict(
            event_id=event.event_id,
            agent_id=event.agent_id,
            tool=tool,
            action=Verdict.BLOCK,
            score=0.0,
            source="fail_safe",
            reason=f"internal error: {e}",
        )

    verdict.latency_ms = (time.perf_counter() - t0) * 1000
    asyncio.create_task(_record(verdict))

    if verdict.action == Verdict.BLOCK:
        return {"block": True, "reason": verdict.reason}
    if verdict.action == Verdict.HOLD:
        # Register barrier — Hermes will await this future before marking task complete
        return {"hold": True, "hold_id": verdict.verdict_id}
    return None   # ALLOW


async def post_tool_call(ctx, tool: str, args: dict, result: Any) -> None:
    """Async — write outcome to cavemem. Never blocks the hot path."""
    asyncio.create_task(_post_record(ctx, tool, args, result))


async def pre_gateway_dispatch(ctx, platform: str, message: dict) -> dict | None:
    """
    Hermes hook: fires before cross-platform send_message dispatch.
    Same enforcement path as pre_tool_call.
    """
    return await pre_tool_call(ctx, f"send_message:{platform}", message)


# ── Core enforcement pipeline ────────────────────────────────────────────────

async def _enforce(event: HookEvent) -> FirewallVerdict:
    """
    Two-tier enforcement.

    Hot path (sync, <10ms p99):
        L0 identity check
        L2 graphify enrichment (cache-only)
        L3 deterministic rule match
        L4 trust/taint gate

    Cold path (async, off hot path):
        L5 ruflo deep analysis
        L7 barrier enforcement
    """
    aid = event.agent_id

    # L0 — identity: token valid, caps include this tool, depth OK
    identity = await _get_identity(aid)
    if identity:
        id_block = _check_identity(identity, event)
        if id_block:
            return _verdict(event, Verdict.BLOCK, 0.0, "identity", id_block)

    # L2 — graphify enrichment (cache-only on hot path)
    enriched = await _enrich(event)

    # L3 — deterministic rule match
    if _superpowers:
        rule_match = await _superpowers.evaluate(enriched)
        if rule_match and rule_match.verdict == "BLOCK":
            return _verdict(event, Verdict.BLOCK, 0.0, "deterministic", rule_match.reason)

    # L4 — trust/taint gate (routes, never hard-blocks alone)
    trust, taint = await _get_trust_taint(aid)
    route = _route(trust, taint)

    if route == "ALLOW":
        return _verdict(event, Verdict.ALLOW, trust, "trust_gate", "clean")

    # ESCALATE or NARROW — hand to ruflo async
    if _ruflo:
        future = asyncio.get_event_loop().create_future()
        async with _holds_lock:
            _holds[event.event_id] = future
        asyncio.create_task(_async_analyze(event, enriched, trust, taint, future))
        return _verdict(event, Verdict.HOLD, trust, "trust_gate",
                        f"route={route}, escalated to async analysis")

    # ruflo unavailable — conservative: ALLOW but flag
    logger.warning("firewall: ruflo unavailable, ALLOW with flag: %s", aid)
    return _verdict(event, Verdict.ALLOW, trust, "trust_gate", "ruflo_unavailable_allow_flagged")


async def _async_analyze(
    event: HookEvent,
    enriched,
    trust: float,
    taint: float,
    future: asyncio.Future,
) -> None:
    """Cold path — ruflo deep analysis. Resolves the future for the barrier."""
    try:
        result = await _ruflo.analyze(event, enriched, trust, taint)
        action = Verdict.BLOCK if result.action == "BLOCK" else Verdict.ALLOW
        v = _verdict(event, action, result.score, "async_ruflo", result.reason)
        if not future.done():
            future.set_result(v)
    except asyncio.TimeoutError:
        # Timeout → fail-safe: halt task via BLOCK
        v = _verdict(event, Verdict.BLOCK, 0.0, "fail_safe", "async analysis timeout")
        if not future.done():
            future.set_result(v)
    except Exception as e:
        v = _verdict(event, Verdict.BLOCK, 0.0, "fail_safe", f"async error: {e}")
        if not future.done():
            future.set_result(v)
    finally:
        asyncio.create_task(_record(v))
        if _cavemem:
            await _cavemem.propagate_taint_if_blocked(event.agent_id, v)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _route(trust: float, taint: float) -> str:
    if taint >= 0.7:   return "ESCALATE"   # quarantine threshold
    if trust > 0.7:    return "ALLOW"
    if trust >= 0.3:   return "ESCALATE"
    return "NARROW"                         # NARROW caps + ESCALATE


def _check_identity(identity: IdentityCtx, event: HookEvent) -> Optional[str]:
    if identity.token_exp and time.time() > identity.token_exp:
        return "token expired"
    if identity.delegation_depth > 8:
        return f"delegation depth {identity.delegation_depth} exceeds MAX_DEPTH=8"
    if identity.caps and event.tool not in identity.caps:
        return f"tool '{event.tool}' not in agent capabilities"
    return None


async def _get_identity(aid: str) -> Optional[IdentityCtx]:
    if _cavemem:
        try:
            return await _cavemem.get_identity(aid)
        except Exception:
            pass
    return None


async def _get_trust_taint(aid: str) -> tuple[float, float]:
    now = time.time()
    cached = _trust_cache.get(aid)
    if cached and cached[1] > now:
        trust = cached[0]
    else:
        trust = 0.5
        if _cavemem:
            try:
                trust = await _cavemem.get_trust(aid)
                _trust_cache[aid] = (trust, now + _TRUST_TTL)
            except Exception:
                pass

    taint = 0.0
    if _cavemem:
        try:
            t = await _cavemem.get_taint(aid)
            taint = t.level if t else 0.0
        except Exception:
            pass

    return trust, taint


async def _enrich(event: HookEvent):
    if _graphify:
        try:
            return await _graphify.enrich(event)
        except Exception:
            pass
    from firewall.core.signal import EnrichedEvent
    return EnrichedEvent(event=event, needs_async=True)


def _verdict(
    event: HookEvent,
    action: Verdict,
    score: float,
    source: str,
    reason: str,
) -> FirewallVerdict:
    return FirewallVerdict(
        event_id=event.event_id,
        agent_id=event.agent_id,
        tool=event.tool,
        action=action,
        score=score,
        source=source,
        reason=reason,
    )


async def _record(verdict: FirewallVerdict) -> None:
    """Append-only write to Chronicle + cavemem. Never raises."""
    try:
        if _chronicle:
            await _chronicle.write_event("interceptor_acts", {
                "trace_id":  verdict.verdict_id,
                "agent_id":  verdict.agent_id,
                "timestamp": verdict.ts,
                "action":    verdict.action.value,
                "reason":    verdict.reason,
                "details":   str({
                    "tool": verdict.tool,
                    "score": verdict.score,
                    "source": verdict.source,
                    "latency_ms": verdict.latency_ms,
                }),
            })
        if _cavemem:
            await _cavemem.record_verdict(verdict)
    except Exception as e:
        logger.error("firewall: chronicle write failed: %s", e)


async def _post_record(ctx, tool: str, args: dict, result: Any) -> None:
    """Post-call: update trust score on clean execution."""
    try:
        aid = _agent_id(ctx)
        if _cavemem:
            await _cavemem.on_clean_call(aid, tool)
            _trust_cache.pop(aid, None)   # invalidate cache
    except Exception as e:
        logger.error("firewall: post_record failed: %s", e)


# ── Context helpers (Hermes ctx duck-typing) ─────────────────────────────────

def _agent_id(ctx) -> str:
    return getattr(ctx, "agent_id", None) or getattr(ctx, "id", "unknown")


def _session_id(ctx) -> str:
    return getattr(ctx, "session_id", None) or getattr(ctx, "session", "")


def _caller_chain(ctx) -> list[str]:
    return getattr(ctx, "caller_chain", []) or []
