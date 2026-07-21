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


class StdoutAuditSink(AuditSink):
    """Write one JSON object per line to stdout (SIEM / container friendly)."""

    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        record = verdict.model_dump(mode="json")
        if event is not None:
            record["event"] = {
                "agent_id": event.agent_id,
                "tool": event.tool,
                "session_id": event.session_id,
                "args_hash": verdict.args_hash,
            }
        print(json.dumps(record, sort_keys=True), flush=True)


class TeeAuditSink(AuditSink):
    """Fan-out to multiple sinks."""

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = sinks

    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        for s in self._sinks:
            try:
                await s.write(verdict, event)
            except Exception as e:
                logger.error("audit: tee sink failed: %s", e)


class NullAuditSink(AuditSink):
    """Discards everything — for tests / benchmarks that don't care about the trail."""

    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        return None


def _otel_log_record(verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> dict:
    """OTel-compatible JSON log record (filelog / OTLP JSON shape, not gRPC).

    Honest limits: this is structured JSONL shaped for OpenTelemetry collectors
    (filelog receiver → transform) or any SIEM. It is **not** a full OTLP/gRPC
    exporter — no batching, retries, or resource detectors beyond static attrs.
    """
    attrs = {
        "tracewall.action": verdict.action.value,
        "tracewall.source": verdict.source,
        "tracewall.reason": verdict.reason,
        "tracewall.rule_id": verdict.rule_id or "",
        "tracewall.args_hash": verdict.args_hash or "",
        "tracewall.score": verdict.score,
        "tracewall.latency_ms": verdict.latency_ms,
        "tracewall.agent_id": verdict.agent_id,
        "tracewall.tool": verdict.tool,
    }
    for k, v in (verdict.context_completeness or {}).items():
        attrs[f"tracewall.context.{k}"] = bool(v)
    if event is not None:
        attrs["tracewall.session_id"] = event.session_id or ""
    return {
        "body": f"tracewall {verdict.action.value} {verdict.tool}",
        "severityText": "INFO" if verdict.action.value == "allow" else "WARN",
        "severityNumber": 9 if verdict.action.value == "allow" else 13,
        "attributes": attrs,
        "resource": {
            "service.name": "tracewall",
            "service.version": "0.2.0",
        },
        "instrumentationScope": {"name": "tracewall.audit", "version": "0.2.0"},
    }


class OTelJsonlAuditSink(AuditSink):
    """Append OTel-shaped JSON log records (one line each) for collector ingest."""

    def __init__(self, path: str = "tracewall_otel_audit.jsonl") -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()

    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        line = json.dumps(_otel_log_record(verdict, event), sort_keys=True) + "\n"
        try:
            async with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception as e:
            logger.error("audit: otel jsonl write failed: %s", e)


class OTelStdoutAuditSink(AuditSink):
    """Print OTel-shaped JSON log records to stdout (container / pipe friendly)."""

    async def write(self, verdict: FirewallVerdict, event: Optional[HookEvent] = None) -> None:
        print(json.dumps(_otel_log_record(verdict, event), sort_keys=True), flush=True)
