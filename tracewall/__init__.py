"""tracewall — a standalone, pluggable agent firewall.

Transport-agnostic enforcement core behind a stable async seam:

    from tracewall import Firewall
    verdict = await firewall.check(event)

Cross-session multi-hop taint propagation, a deterministic policy DSL, a
content pre-filter, and an optional semantic judge — all key-free and
infra-free by default.
"""
from __future__ import annotations

from tracewall.core.firewall import Firewall
from tracewall.core.signal import (
    EnrichedEvent,
    FirewallVerdict,
    HookEvent,
    IdentityCtx,
    Taint,
    Verdict,
)

__all__ = [
    "Firewall",
    "HookEvent",
    "EnrichedEvent",
    "IdentityCtx",
    "Taint",
    "Verdict",
    "FirewallVerdict",
]
