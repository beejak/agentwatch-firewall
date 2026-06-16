"""
tracewall/audit/sink.py — the audit trail.

Every verdict is appended to an audit sink (always, on every call). The default
sink is a local append-only JSONL file: it only ever writes, never updates or
deletes. Swap in a different AuditSink to forward verdicts elsewhere (a remote
collector, a SIEM, etc.) without touching the core.
"""
from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from tracewall.core.signal import FirewallVerdict, HookEvent

logger = logging.getLogger(__name__)


class AuditSink(ABC):
    """Append-only audit destination. Implementations must never block the caller
    on failure — swallow and log, so auditing can never break enforcement."""

    @abstractmethod
    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        ...


class LocalAuditSink(AuditSink):
    """Append-only JSONL file sink (the default). One JSON object per verdict."""

    def __init__(self, path: str = "tracewall_audit.jsonl") -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()

    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        record = verdict.model_dump(mode="json")
        if event is not None:
            record["event"] = event.model_dump(mode="json")
        line = json.dumps(record, sort_keys=True) + "\n"
        try:
            async with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception as e:  # auditing must never break enforcement
            logger.error("audit: write failed: %s", e)


class NullAuditSink(AuditSink):
    """Discards everything — for tests / benchmarks that don't care about the trail."""

    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        return None
