"""
tracewall/transports/python_guard.py — the v1 reference transport.

An in-process Python guard: the simplest way to plug tracewall into an agent
loop, and the interception point the eval/benchmark drives. It builds a
``HookEvent`` from a tool call, awaits ``firewall.check(event)``, and turns the
verdict into control flow — BLOCK raises ``GuardBlocked``, ALLOW returns the
verdict.

Because it runs in-process, the full context (``caller_chain``, ``session_id``,
``call_site``) is available when the caller supplies it, so the taint and
semantic tiers keep their inputs. ``agent_id`` is the one mandatory field
(cross-session taint needs a stable id).

Latency: in-process, the deterministic path targets p99 < 10ms. Networked
transports (MCP proxy, sidecar) added later cannot promise this — they use the
HOLD / async-barrier path instead.

Fail policy: ``firewall.check`` is itself fail-safe (any internal error →
BLOCK), so the guard rarely sees an exception from it. The remaining failure
mode is *the transport cannot form a valid request* (e.g. no ``agent_id``).
``fail_closed=True`` (default) turns that into a BLOCK; ``fail_closed=False``
lets the call through (fail-open) for non-critical deployments.
"""
from __future__ import annotations

import functools
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal, Optional, Union

from tracewall.core.firewall import Firewall
from tracewall.core.signal import FirewallVerdict, HookEvent, Verdict

logger = logging.getLogger(__name__)

# ctx may be a plain dict or any object exposing the same attributes.
Ctx = Union[dict, Any, None]


class GuardBlocked(Exception):
    """Raised when the firewall returns BLOCK for a guarded tool call.

    The full :class:`FirewallVerdict` is attached as ``.verdict`` for the caller
    (audit, retry policy, user messaging)."""

    def __init__(self, verdict: FirewallVerdict) -> None:
        self.verdict = verdict
        super().__init__(f"tracewall BLOCK [{verdict.source}]: {verdict.reason}")


@dataclass
class SoftBlockResult:
    """Product soft-block: do not execute the tool; return this to the agent loop.

    ``message`` is the stable error string to surface as a tool error.
    """

    verdict: FirewallVerdict

    @property
    def message(self) -> str:
        rid = f" rule_id={self.verdict.rule_id}" if self.verdict.rule_id else ""
        return f"tracewall BLOCK [{self.verdict.source}]: {self.verdict.reason}{rid}"

    @property
    def blocked(self) -> bool:
        return True


def _ctx_get(ctx: Ctx, key: str, default=None):
    if ctx is None:
        return default
    if isinstance(ctx, dict):
        return ctx.get(key, default)
    return getattr(ctx, key, default)


def _build_event(tool: str, args: Optional[dict], ctx: Ctx) -> HookEvent:
    agent_id = _ctx_get(ctx, "agent_id")
    if not agent_id:
        raise ValueError("guard: ctx must supply a stable 'agent_id'")
    return HookEvent(
        agent_id=str(agent_id),
        tool=tool,
        args=dict(args or {}),
        caller_chain=list(_ctx_get(ctx, "caller_chain", []) or []),
        session_id=str(_ctx_get(ctx, "session_id", "") or ""),
        call_site=_ctx_get(ctx, "call_site"),
    )


def _synthetic_block(tool: str, agent_id: str, reason: str) -> FirewallVerdict:
    return FirewallVerdict(
        event_id="", agent_id=agent_id or "unknown", tool=tool,
        action=Verdict.BLOCK, score=0.0, source="transport",
        reason=reason, context_completeness={"identity": False, "call_tree": False, "ledger": False},
    )


async def guard(
    firewall: Firewall,
    tool: str,
    args: Optional[dict] = None,
    ctx: Ctx = None,
    *,
    fail_closed: bool = True,
    on_block: Literal["raise", "soft"] = "raise",
) -> FirewallVerdict | SoftBlockResult:
    """Check a single tool call.

    On ALLOW: returns :class:`FirewallVerdict`.
    On BLOCK:
      - ``on_block="raise"`` (default) → raises :class:`GuardBlocked`
      - ``on_block="soft"`` → returns :class:`SoftBlockResult` (do not execute tool)
    """
    try:
        event = _build_event(tool, args, ctx)
    except Exception as e:
        agent_id = str(_ctx_get(ctx, "agent_id", "") or "")
        if fail_closed:
            verdict = _synthetic_block(tool, agent_id, f"transport could not reach firewall: {e}")
            if on_block == "soft":
                return SoftBlockResult(verdict)
            raise GuardBlocked(verdict) from e
        logger.warning("guard: fail-open on transport error: %s", e)
        return FirewallVerdict(
            event_id="", agent_id=agent_id or "unknown", tool=tool,
            action=Verdict.ALLOW, score=0.5, source="transport",
            reason=f"fail-open: {e}",
        )

    verdict = await firewall.check(event)
    if verdict.action == Verdict.BLOCK:
        if on_block == "soft":
            return SoftBlockResult(verdict)
        raise GuardBlocked(verdict)
    return verdict


def guarded(
    firewall: Firewall,
    *,
    tool: Optional[str] = None,
    ctx: Ctx = None,
    fail_closed: bool = True,
) -> Callable[[Callable], Callable]:
    """Decorator that guards a tool callable.

    The wrapped call's **keyword arguments** are inspected as the tool args
    (the common shape for tool-calling frameworks). Agent context comes from
    the ``ctx`` given here, or a per-call ``ctx=`` keyword if present. Works on
    sync or async tools; the returned wrapper is always async.

        fw = Firewall(...)

        @guarded(fw, tool="send_email")
        async def send_email(*, to, body, ctx): ...
    """
    def deco(fn: Callable) -> Callable:
        name = tool or getattr(fn, "__name__", "tool")

        @functools.wraps(fn)
        async def wrapper(*a, **kw) -> Any:
            call_ctx = kw.get("ctx", ctx)
            await guard(firewall, name, dict(kw), call_ctx, fail_closed=fail_closed)
            result = fn(*a, **kw)
            if inspect.isawaitable(result):
                result = await result
            return result

        return wrapper

    return deco
