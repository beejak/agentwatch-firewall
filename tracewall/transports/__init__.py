"""tracewall transports — ways to plug the firewall into an agent pipeline.

v1 ships the in-process Python guard and an MCP stdio gateway proxy. Framework
callback adapters and an HTTP sidecar are designed-for but out of scope for v1.
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
from tracewall.transports.python_guard import GuardBlocked, guard, guarded

__all__ = [
    "guard",
    "guarded",
    "GuardBlocked",
    "screen_tool_call",
    "McpStdioProxy",
    "ProxyConfig",
    "build_event_from_mcp",
    "PROFILE_NAMES",
    "Profile",
    "get_profile",
    "build_firewall_for_profile",
]
