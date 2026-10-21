"""
Session progressive containment (E4) — in-memory posture ratchet.

Not a sandbox. Not a chat scanner. After a screened tool is BLOCKed, the
session (or agent fallback key) is marked elevated. Subsequent calls whose
tools are in the egress-sensitive set are BLOCKed with ``rule_id=session_ratchet``
even if deterministic policy would otherwise ALLOW.

Expected behavior (honest):
  - New ``session_id`` → clean posture (no sticky cross-session elevation).
  - Empty session_id falls back to ``agent:{agent_id}`` (same keying as
    :class:`~tracewall.transports.session_chain.SessionCallTree`).
  - Soft-block / hard-block transports still decide control flow; this only
    changes *which* later calls the PEP blocks.
  - Off by default on lab ``balanced``; on for ``zta`` / ``paranoid``.
"""
from __future__ import annotations

from threading import Lock
from typing import Iterable, Optional

from tracewall.policy.normalize import canonical_tool_name
from tracewall.transports.session_chain import SessionCallTree

# High-risk egress / side-effect tools. Read-only / lookup tools are intentionally
# absent so soft-block utility paths can still complete after a BLOCK.
DEFAULT_EGRESS_TOOLS: frozenset[str] = frozenset(
    canonical_tool_name(t)
    for t in (
        "send_money",
        "send_email",
        "send_message",
        "schedule_transaction",
        "http_post",
        "http_request",
        "upload",
        "bash",
        "execute",
        "run_shell",
        "write_file",
        "transfer",
        "wire_transfer",
    )
)


class SessionRatchet:
    """Per-session elevation after BLOCK; ephemeral egress tighten on subsequent calls."""

    def __init__(
        self,
        egress_tools: Optional[Iterable[str]] = None,
    ) -> None:
        self._elevated: dict[str, int] = {}
        self._lock = Lock()
        tools = egress_tools if egress_tools is not None else DEFAULT_EGRESS_TOOLS
        self._egress = frozenset(canonical_tool_name(t) for t in tools if t)

    @staticmethod
    def key(session_id: str, agent_id: str = "") -> str:
        return SessionCallTree.key(session_id, agent_id)

    def is_elevated(self, session_id: str = "", agent_id: str = "") -> bool:
        k = self.key(session_id, agent_id)
        with self._lock:
            return self._elevated.get(k, 0) > 0

    def block_count(self, session_id: str = "", agent_id: str = "") -> int:
        k = self.key(session_id, agent_id)
        with self._lock:
            return int(self._elevated.get(k, 0))

    def note_block(self, session_id: str = "", agent_id: str = "") -> None:
        """Mark session elevated after a BLOCK verdict."""
        k = self.key(session_id, agent_id)
        with self._lock:
            self._elevated[k] = self._elevated.get(k, 0) + 1

    def should_contain(self, tool: str, session_id: str = "", agent_id: str = "") -> bool:
        """True when elevated and ``tool`` is egress-sensitive."""
        if not self.is_elevated(session_id, agent_id):
            return False
        return canonical_tool_name(tool) in self._egress

    def clear(self, session_id: str = "", agent_id: str = "") -> None:
        with self._lock:
            if session_id or agent_id:
                self._elevated.pop(self.key(session_id, agent_id), None)
            else:
                self._elevated.clear()
