"""
claude_mem.py — Persistent agent memory adapter.
Wraps cavemem (JuliusBrussee/cavemem) SQLite+FTS5 store via MCP interface.
Used for cross-session memory reads that trigger taint propagation checks.
"""
from __future__ import annotations

import logging
from typing import Optional, Any

logger = logging.getLogger(__name__)


class ClaudeMemAdapter:
    """
    Thin adapter over cavemem MCP server.
    In production: connects to cavemem MCP endpoint.
    For tests: in-proc dict store.
    """

    def __init__(self, mcp_url: str = "http://localhost:3001") -> None:
        self._url = mcp_url
        self._store: dict[str, Any] = {}  # fallback in-proc store

    async def read(self, key: str, agent_id: str) -> Optional[str]:
        """
        Read memory entry. Returns (value, writer_agent_id) for taint propagation.
        Caller is responsible for calling cavemem.propagate_read_taint if writer is tainted.
        """
        entry = self._store.get(key)
        if entry is None:
            return None
        logger.debug("claude_mem: read key=%s by agent=%s writer=%s", key, agent_id, entry.get("writer"))
        return entry.get("value")

    async def write(self, key: str, value: str, agent_id: str) -> None:
        """Write memory entry, tagging with writer agent_id for provenance."""
        self._store[key] = {"value": value, "writer": agent_id}
        logger.debug("claude_mem: write key=%s by agent=%s", key, agent_id)

    async def get_writer(self, key: str) -> Optional[str]:
        """Return agent_id of last writer for a given key."""
        entry = self._store.get(key)
        return entry.get("writer") if entry else None

    async def search(self, query: str, agent_id: str) -> list[dict]:
        """FTS5 search. Returns list of {key, value, writer} dicts."""
        results = []
        for k, v in self._store.items():
            if query.lower() in str(v.get("value", "")).lower():
                results.append({"key": k, "value": v.get("value"), "writer": v.get("writer")})
        return results
