"""
Latency microbenchmark for Firewall.check (deterministic path).

Writes bootstrap summary to eval/results/latency_check.json.
Does NOT claim competitor comparisons — only our measured numbers.

Usage:
  python -m tracewall.eval.latency
  python -m tracewall.eval.latency --n 500 --warmup 50
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from tracewall.audit.sink import NullAuditSink
from tracewall.core.firewall import Firewall
from tracewall.core.signal import HookEvent
from tracewall.policy.engine import PolicyEngine
from tracewall.semantic.judge import SemanticJudge
from tracewall.taint.ledger import Ledger


async def _build_fw() -> Firewall:
    os.environ["TRACEWALL_SEMANTIC_LLM"] = "0"
    policy = PolicyEngine()
    await policy.load_policies()
    fd, dbpath = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return Firewall(
        ledger=Ledger(dbpath),
        policy=policy,
        judge=SemanticJudge(),
        audit=NullAuditSink(),
    )


def _percentile(sorted_ms: list[float], p: float) -> float:
    if not sorted_ms:
        return 0.0
    k = (len(sorted_ms) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_ms) - 1)
    if f == c:
        return sorted_ms[f]
    return sorted_ms[f] + (sorted_ms[c] - sorted_ms[f]) * (k - f)


async def measure(n: int = 400, warmup: int = 40) -> dict:
    fw = await _build_fw()
    # Mix: benign allow + known-block attacker IBAN (policy hot path).
    cases = [
        HookEvent(
            agent_id="lat-agent",
            tool="send_money",
            args={
                "recipient": "UK12345678901234567890",
                "amount": 98.70,
                "subject": "Car Rental",
                "date": "2022-01-01",
            },
            caller_chain=["read_file"],
        ),
        HookEvent(
            agent_id="lat-agent",
            tool="send_money",
            args={
                "recipient": "US133000000121212121212",
                "amount": 9.99,
                "subject": "Spotify",
                "date": "2024-01-01",
            },
            caller_chain=["read_file"],
        ),
        HookEvent(
            agent_id="lat-agent",
            tool="read_file",
            args={"file_path": "bill-december-2023.txt"},
            caller_chain=[],
        ),
    ]

    for i in range(warmup):
        await fw.check(cases[i % len(cases)])

    samples_ms: list[float] = []
    for i in range(n):
        ev = cases[i % len(cases)]
        t0 = time.perf_counter()
        await fw.check(ev)
        samples_ms.append((time.perf_counter() - t0) * 1000.0)

    s = sorted(samples_ms)
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "n": n,
        "warmup": warmup,
        "semantic_backend": "deterministic",
        "unit": "ms",
        "mean": round(statistics.fmean(samples_ms), 4),
        "stdev": round(statistics.pstdev(samples_ms), 4) if len(samples_ms) > 1 else 0.0,
        "p50": round(_percentile(s, 50), 4),
        "p95": round(_percentile(s, 95), 4),
        "p99": round(_percentile(s, 99), 4),
        "min": round(s[0], 4),
        "max": round(s[-1], 4),
        "note": (
            "Full Firewall.check on mixed allow/block HookEvents; "
            "not comparable to GPU sentinel e2e without matched methodology."
        ),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--warmup", type=int, default=40)
    ap.add_argument("--out", default="tracewall/eval/results/latency_check.json")
    args = ap.parse_args(argv)
    result = asyncio.run(measure(args.n, args.warmup))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
