"""
LangGraph-style tool-node wrapper (no LangGraph dependency).

Wraps a mapping of tool_name → callable so every invocation goes through
``guard`` / ``Firewall.check`` before the tool runs. Drop into a LangGraph
``ToolNode``-shaped loop, or any agent framework that dispatches named tools.

    from tracewall.transports.tool_node import GuardedToolNode

    node = GuardedToolNode(fw, {"read_file": read_file, "send_email": send_email})
    result = await node.ainvoke(
        {"name": "send_email", "args": {"to": "x@evil.com", "body": "hi"}},
        ctx={"agent_id": "agent-1"},
    )
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping

from tracewall.core.firewall import Firewall
from tracewall.core.signal import FirewallVerdict
from tracewall.transports.python_guard import (
    Ctx,
    GuardBlocked,
    SoftBlockResult,
    guard,
)

ToolFn = Callable[..., Any]
ToolMap = Mapping[str, ToolFn]


@dataclass
class ToolInvokeResult:
    """Outcome of a guarded tool invoke."""

    name: str
    allowed: bool
    result: Any = None
    soft_block: SoftBlockResult | None = None
    verdict: FirewallVerdict | None = None
    error: str | None = None


class GuardedToolNode:
    """Thin tool dispatcher with Tracewall as the PEP.

    Compatible with LangGraph's common message shape:
    ``{"name": "<tool>", "args": {...}}`` (or ``"arguments"``).
    """

    def __init__(
        self,
        firewall: Firewall,
        tools: ToolMap,
        *,
        fail_closed: bool = True,
        on_block: Literal["raise", "soft"] = "soft",
        default_ctx: Ctx = None,
    ) -> None:
        self._fw = firewall
        self._tools = dict(tools)
        self._fail_closed = fail_closed
        self._on_block = on_block
        self._default_ctx = default_ctx

    def register(self, name: str, fn: ToolFn) -> None:
        self._tools[name] = fn

    async def ainvoke(
        self,
        call: Mapping[str, Any],
        *,
        ctx: Ctx = None,
    ) -> ToolInvokeResult:
        name = str(call.get("name") or call.get("tool") or "")
        args = call.get("args")
        if args is None:
            args = call.get("arguments")
        if not isinstance(args, dict):
            args = dict(args or {}) if args else {}
        call_ctx = ctx if ctx is not None else self._default_ctx

        if name not in self._tools:
            if self._fail_closed:
                from tracewall.transports.python_guard import _synthetic_block

                agent_id = ""
                if isinstance(call_ctx, dict):
                    agent_id = str(call_ctx.get("agent_id") or "")
                v = _synthetic_block(name, agent_id, f"unknown tool: {name}")
                if self._on_block == "soft":
                    return ToolInvokeResult(
                        name=name, allowed=False, soft_block=SoftBlockResult(v), verdict=v,
                        error=SoftBlockResult(v).message,
                    )
                raise GuardBlocked(v)
            return ToolInvokeResult(name=name, allowed=False, error=f"unknown tool: {name}")

        screened = await guard(
            self._fw,
            name,
            args,
            call_ctx,
            fail_closed=self._fail_closed,
            on_block=self._on_block,
        )
        if isinstance(screened, SoftBlockResult):
            return ToolInvokeResult(
                name=name,
                allowed=False,
                soft_block=screened,
                verdict=screened.verdict,
                error=screened.message,
            )

        fn = self._tools[name]
        try:
            out = fn(**args)
        except TypeError:
            out = fn(args)
        if hasattr(out, "__await__"):
            out = await out  # type: ignore[misc]
        return ToolInvokeResult(name=name, allowed=True, result=out, verdict=screened)

    async def __call__(self, call: Mapping[str, Any], *, ctx: Ctx = None) -> ToolInvokeResult:
        return await self.ainvoke(call, ctx=ctx)
