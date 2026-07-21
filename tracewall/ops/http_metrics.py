"""HTTP scrape endpoint for Tracewall metrics (stdlib only).

    python -m tracewall.ops.http_metrics --port 9100 --profile zta

Exposes:
  GET /metrics  — Prometheus text (block rate, starve rate, p50/p95/p99)
  GET /health   — liveness JSON (rules_loaded)
  GET /         — short help

Limits (honest): in-process counters only; no cluster aggregation; p99 is over
a sliding sample window (default 2048). Pair with Firewall.metrics on the same
process — this CLI holds its own demo Firewall unless --attach is used later.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from tracewall.ops.metrics import Metrics


class _State:
    metrics: Metrics = Metrics()
    profile: str = "balanced"
    rules_loaded: int = 0
    job: str = "tracewall"


STATE = _State()


class MetricsHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # quieter than default
        return

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/metrics", "/metrics/"):
            text = STATE.metrics.prometheus_text(job=STATE.job)
            self._send(200, text.encode("utf-8"), "text/plain; version=0.0.4; charset=utf-8")
            return
        if path in ("/health", "/healthz"):
            payload = {
                "ok": STATE.rules_loaded > 0,
                "profile": STATE.profile,
                "rules_loaded": STATE.rules_loaded,
                "n_check": STATE.metrics.n_check,
            }
            raw = json.dumps(payload).encode("utf-8")
            self._send(200 if payload["ok"] else 503, raw, "application/json")
            return
        if path in ("/", ""):
            help_txt = (
                "Tracewall metrics\n"
                "  GET /metrics  Prometheus text\n"
                "  GET /health   liveness JSON\n"
            )
            self._send(200, help_txt.encode("utf-8"), "text/plain; charset=utf-8")
            return
        self._send(404, b"not found\n", "text/plain; charset=utf-8")


def serve_metrics(
    metrics: Metrics,
    *,
    host: str = "127.0.0.1",
    port: int = 9100,
    profile: str = "balanced",
    rules_loaded: int = 0,
    job: str = "tracewall",
) -> ThreadingHTTPServer:
    """Start a background ThreadingHTTPServer; returns the server (caller may shut down)."""
    STATE.metrics = metrics
    STATE.profile = profile
    STATE.rules_loaded = rules_loaded
    STATE.job = job
    httpd = ThreadingHTTPServer((host, port), MetricsHandler)
    t = threading.Thread(target=httpd.serve_forever, name="tracewall-metrics", daemon=True)
    t.start()
    return httpd


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Tracewall HTTP /metrics scrape server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--job", default="tracewall")
    args = ap.parse_args(argv)

    from tracewall.audit.sink import NullAuditSink
    from tracewall.ops.config import load_config
    from tracewall.transports.profiles import build_firewall_for_profile

    cfg = load_config()
    profile = args.profile or cfg.profile

    async def _boot() -> Metrics:
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            m = Metrics()
            fw, prof = await build_firewall_for_profile(
                profile, db_path=db, audit=NullAuditSink(),
            )
            fw.metrics = m
            STATE.rules_loaded = len(fw._policy._rules)
            STATE.profile = prof.name
            # Smoke one check so scrapers see non-zero samples in demos
            from tracewall.core.signal import HookEvent

            await fw.check(HookEvent(agent_id="metrics-health", tool="read_file", args={"path": "/"}))
            return m
        finally:
            Path(db).unlink(missing_ok=True)

    metrics = asyncio.run(_boot())
    httpd = serve_metrics(
        metrics, host=args.host, port=args.port,
        profile=STATE.profile, rules_loaded=STATE.rules_loaded, job=args.job,
    )
    print(f"tracewall metrics listening on http://{args.host}:{args.port}/metrics "
          f"(profile={STATE.profile} rules={STATE.rules_loaded})", flush=True)
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        httpd.shutdown()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
