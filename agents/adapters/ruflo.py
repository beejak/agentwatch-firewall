"""
ruflo.py — Async deep-analysis swarm adapter.
Wraps ruvnet/ruflo BFT consensus swarm for ambiguous tool-call verdicts.
Operates off the hot path — invoked only when trust gate routes to ESCALATE.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Optional

from firewall.core.signal import EnrichedEvent, FirewallVerdict, Verdict

logger = logging.getLogger(__name__)

# Swarm verdict timeout — task-completion barrier blocks until this expires.
SWARM_TIMEOUT_S = 5.0

# Minimum swarm quorum for BLOCK verdict (BFT: 2f+1 of 3f+1)
QUORUM_THRESHOLD = 0.67


async def submit_for_analysis(
    event: EnrichedEvent,
    hold_future: asyncio.Future,
) -> None:
    """
    Submit event to ruflo swarm for async deep analysis.
    Resolves hold_future with FirewallVerdict when quorum reached or timeout.
    Called from hermes.py off the hot path — never awaited inline.
    """
    asyncio.ensure_future(_run_swarm(event, hold_future))


async def _run_swarm(event: EnrichedEvent, hold_future: asyncio.Future) -> None:
    try:
        verdict = await asyncio.wait_for(_swarm_consensus(event), timeout=SWARM_TIMEOUT_S)
    except asyncio.TimeoutError:
        logger.warning("ruflo: swarm timeout for event %s — defaulting ALLOW", event.event.event_id)
        verdict = FirewallVerdict(
            event_id=event.event.event_id,
            agent_id=event.event.agent_id,
            tool=event.event.tool,
            action=Verdict.ALLOW,
            score=0.5,
            source="ruflo_timeout",
            reason="swarm timeout — escalation inconclusive",
        )
    except Exception as e:
        logger.error("ruflo: swarm error: %s — defaulting BLOCK (fail-safe)", e)
        verdict = FirewallVerdict(
            event_id=event.event.event_id,
            agent_id=event.event.agent_id,
            tool=event.event.tool,
            action=Verdict.BLOCK,
            score=1.0,
            source="fail_safe",
            reason=f"ruflo swarm error: {e}",
        )

    if not hold_future.done():
        hold_future.set_result(verdict)


async def _swarm_consensus(event: EnrichedEvent) -> FirewallVerdict:
    """
    Run 3-agent BFT consensus. Production: dispatch to ruflo swarm via MCP.
    Stub: local heuristic scoring simulating swarm quorum.
    """
    agents = await asyncio.gather(
        _agent_vote(event, "semantic"),
        _agent_vote(event, "contagion"),
        _agent_vote(event, "intent"),
    )
    block_votes = sum(1 for v in agents if v >= 0.7)
    score = sum(agents) / len(agents)
    quorum_block = block_votes / len(agents) >= QUORUM_THRESHOLD

    action = Verdict.BLOCK if quorum_block else Verdict.ALLOW
    return FirewallVerdict(
        event_id=event.event.event_id,
        agent_id=event.event.agent_id,
        tool=event.event.tool,
        action=action,
        score=score,
        source="ruflo_swarm",
        reason=f"swarm consensus: {block_votes}/{len(agents)} block votes, score={score:.2f}",
    )


async def _agent_vote(event: EnrichedEvent, role: str) -> float:
    """Single swarm agent vote. Returns suspicion score 0.0-1.0."""
    await asyncio.sleep(0)  # yield to event loop
    tool = event.event.tool
    args = event.event.args

    # Heuristic stubs — production replaces with LLM semantic analysis
    if role == "semantic":
        dangerous = {"bash", "exec", "eval", "delete_file", "drop_table"}
        return 0.8 if tool in dangerous else 0.1
    if role == "contagion":
        taint = getattr(event, "taint_level", 0.0) or 0.0
        return min(1.0, taint * 1.2)
    if role == "intent":
        # Check for exfil patterns in args
        body = str(args)
        if any(kw in body.lower() for kw in ("attacker", "evil.com", "exfil", "credentials")):
            return 0.9
        return 0.1
    return 0.0
