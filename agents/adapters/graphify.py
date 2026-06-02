"""
graphify.py — AST call-context enrichment adapter.
Wraps graphify-ts (Howell5/graphify-ts) tree-sitter WASM bridge.
Returns cached AST path for a call site. Cache hit target: >90%.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_cache: dict[str, Optional[str]] = {}
_cache_lock = asyncio.Lock()

# Cold-path window: if graphify WASM unavailable, return None (not block).
_graphify_available: Optional[bool] = None


async def get_ast_path(call_site: Optional[str], source_lang: str = "python") -> tuple[Optional[str], bool]:
    """
    Resolve AST path for call_site. Returns (ast_path, cache_hit).
    Cache miss → needs_async=True, never inline BLOCK.
    """
    if not call_site:
        return None, False

    key = hashlib.sha1(f"{source_lang}:{call_site}".encode()).hexdigest()

    async with _cache_lock:
        if key in _cache:
            return _cache[key], True

    path = await _resolve_ast(call_site, source_lang)

    async with _cache_lock:
        _cache[key] = path

    return path, False  # freshly computed, not a cache hit


async def _resolve_ast(call_site: str, lang: str) -> Optional[str]:
    """
    Invoke graphify-ts via subprocess bridge. Falls back gracefully.
    Real implementation would call: node graphify_bridge.js --lang python --site <call_site>
    """
    global _graphify_available
    if _graphify_available is False:
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            "node", "--version",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=1.0)
        _graphify_available = True
    except (FileNotFoundError, asyncio.TimeoutError):
        _graphify_available = False
        logger.debug("graphify: node not available, skipping AST enrichment")
        return None

    # Stub: return a synthetic path representing the call site
    # Production: invoke graphify-ts WASM bridge and parse JSON output
    return f"{lang}::{call_site}"


def invalidate_cache() -> None:
    _cache.clear()
