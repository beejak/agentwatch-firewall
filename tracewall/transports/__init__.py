"""tracewall transports — ways to plug the firewall into an agent pipeline.

Ships: in-process Python guard, MCP stdio gateway proxy, and a LangGraph-style
``GuardedToolNode`` (no LangGraph dependency). HTTP sidecar remains optional.
"""
from __future__ import annotations

from tracewall.transports.mcp_proxy import (
    McpStdioProxy,
    ProxyConfig,
    build_event_from_mcp,
    screen_tool_call,
)
from tracewall.transports.profiles import (
    PROFILE_NAMES,
    Profile,
    build_firewall_for_profile,
    get_profile,
)
from tracewall.transports.python_guard import GuardBlocked, SoftBlockResult, guard, guarded
from tracewall.transports.tool_node import GuardedToolNode, ToolInvokeResult

__all__ = [
    "guard",
    "guarded",
    "GuardBlocked",
    "SoftBlockResult",
    "GuardedToolNode",
    "ToolInvokeResult",
    "screen_tool_call",
    "McpStdioProxy",
    "ProxyConfig",
    "build_event_from_mcp",
    "PROFILE_NAMES",
    "Profile",
    "get_profile",
    "build_firewall_for_profile",
]
