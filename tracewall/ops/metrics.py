"""In-process enforcement metrics (block rate, starve rate, latency)."""
from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class MetricsSnapshot:
    n_check: int
    n_allow: int
    n_block: int
    starve_call_tree: int
    block_rate: float
    starve_rate: float
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float

    def to_prometheus(self, *, job: str = "tracewall") -> str:
        """Prometheus text exposition (scrapeable by Prom / Grafana Agent / OTel)."""
        labels = f'job="{job}"'
        lines = [
            "# HELP tracewall_checks_total Total Firewall.check calls",
            "# TYPE tracewall_checks_total counter",
            f"tracewall_checks_total{{{labels}}} {self.n_check}",
            "# HELP tracewall_allows_total ALLOW verdicts",
            "# TYPE tracewall_allows_total counter",
            f"tracewall_allows_total{{{labels}}} {self.n_allow}",
            "# HELP tracewall_blocks_total BLOCK verdicts",
            "# TYPE tracewall_blocks_total counter",
            f"tracewall_blocks_total{{{labels}}} {self.n_block}",
            "# HELP tracewall_starve_call_tree_total Checks with empty caller_chain",
            "# TYPE tracewall_starve_call_tree_total counter",
            f"tracewall_starve_call_tree_total{{{labels}}} {self.starve_call_tree}",
            "# HELP tracewall_block_rate Fraction of checks that blocked (gauge)",
            "# TYPE tracewall_block_rate gauge",
            f"tracewall_block_rate{{{labels}}} {self.block_rate:.6f}",
            "# HELP tracewall_starve_rate Fraction of checks with empty call tree",
            "# TYPE tracewall_starve_rate gauge",
            f"tracewall_starve_rate{{{labels}}} {self.starve_rate:.6f}",
            "# HELP tracewall_check_latency_ms Check latency percentiles (ms)",
            "# TYPE tracewall_check_latency_ms gauge",
            f'tracewall_check_latency_ms{{{labels},quantile="0.5"}} {self.latency_ms_p50:.4f}',
            f'tracewall_check_latency_ms{{{labels},quantile="0.95"}} {self.latency_ms_p95:.4f}',
            f'tracewall_check_latency_ms{{{labels},quantile="0.99"}} {self.latency_ms_p99:.4f}',
            "",
        ]
        return "\n".join(lines)


class Metrics:
    def __init__(self, max_latency_samples: int = 2048) -> None:
        self._lock = threading.Lock()
        self.n_check = 0
        self.n_allow = 0
        self.n_block = 0
        self.starve_call_tree = 0
        self._latencies: list[float] = []
        self._max = max_latency_samples

    def record(self, *, action: str, latency_ms: float, call_tree_empty: bool) -> None:
        with self._lock:
            self.n_check += 1
            if action == "block":
                self.n_block += 1
            else:
                self.n_allow += 1
            if call_tree_empty:
                self.starve_call_tree += 1
            self._latencies.append(float(latency_ms))
            overflow = len(self._latencies) - self._max
            if overflow > 0:
                del self._latencies[0:overflow]

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            n = max(1, self.n_check)
            lats = sorted(self._latencies)

            def pct(p: float) -> float:
                if not lats:
                    return 0.0
                idx = min(len(lats) - 1, max(0, int(round((p / 100.0) * (len(lats) - 1)))))
                return lats[idx]

            return MetricsSnapshot(
                n_check=self.n_check,
                n_allow=self.n_allow,
                n_block=self.n_block,
                starve_call_tree=self.starve_call_tree,
                block_rate=self.n_block / n,
                starve_rate=self.starve_call_tree / n,
                latency_ms_p50=pct(50),
                latency_ms_p95=pct(95),
                latency_ms_p99=pct(99),
            )

    def prometheus_text(self, *, job: str = "tracewall") -> str:
        return self.snapshot().to_prometheus(job=job)
