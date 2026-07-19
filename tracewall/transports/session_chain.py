"""
Proxy-owned session call trees (anti-forge).

Client-supplied ``caller_chain`` in ``_meta`` is honor-system. For ZTA-style
deployments the PEP (MCP proxy) records tools it actually screened, keyed by
``session_id`` (fallback: ``agent_id``). Policy sees that chain only.
"""
from __future__ import annotations

from threading import Lock


class SessionCallTree:
    """In-memory per-session tool history owned by the transport PEP."""

    def __init__(self, max_len: int = 64) -> None:
        self._max = max(1, int(max_len))
        self._chains: dict[str, list[str]] = {}
        self._lock = Lock()

    @staticmethod
    def key(session_id: str, agent_id: str) -> str:
        sid = (session_id or "").strip()
        return sid if sid else f"agent:{agent_id}"

    def chain(self, session_id: str, agent_id: str = "") -> list[str]:
        k = self.key(session_id, agent_id)
        with self._lock:
            return list(self._chains.get(k, []))

    def record(self, session_id: str, tool: str, agent_id: str = "") -> None:
        if not tool:
            return
        k = self.key(session_id, agent_id)
        with self._lock:
            ch = self._chains.setdefault(k, [])
            ch.append(str(tool))
            overflow = len(ch) - self._max
            if overflow > 0:
                del ch[0:overflow]

    def clear(self, session_id: str = "", agent_id: str = "") -> None:
        with self._lock:
            if session_id or agent_id:
                self._chains.pop(self.key(session_id, agent_id), None)
            else:
                self._chains.clear()
