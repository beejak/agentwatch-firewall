"""tracewall transports — ways to plug the firewall into an agent pipeline.

v1 ships the in-process Python guard. MCP proxy / framework adapters / HTTP
sidecar are designed-for but out of scope for v1.
"""
from __future__ import annotations

from tracewall.transports.python_guard import GuardBlocked, guard, guarded

__all__ = ["guard", "guarded", "GuardBlocked"]
