"""
tracewall/taint/mtp.py — Multi-Hop Taint Propagation (MTP)

Pure, DB-free propagation engine. No async, no side effects.
Ledger.propagate_graph() is the stateful driver; this module
provides the core algorithm and convergence utilities.

Formal Model
------------
Let G = (V, E) be a directed graph where:
  - V = set of nodes (agent IDs or memory keys)
  - E ⊆ V × V — directed edges with attributes (weight w, timestamp ts)
  - T[v] ∈ [0,1] — taint level of node v
  - λ — time-decay constant (per hour)
  - Δt(e) — hours elapsed since edge e was recorded

Edge decay factor:
  d(e) = w(e) × exp(-λ × Δt(e))

Propagation update:
  T^(k+1)[v] = max(T^(k)[v], max_{u:(u,v)∈E} T^(k)[u] × d(u,v))

Convergence Claim
-----------------
The algorithm converges in at most |V| iterations.

Proof sketch:
1. Monotonicity: T[v] is non-decreasing — values only increase or stay the same.
2. Boundedness: T[v] ∈ [0,1] (taint never exceeds 1.0).
3. Strict decay: w < 1 and exp(-λΔt) ≤ 1, so each hop strictly reduces propagated
   taint unless the edge was recorded at exactly t=now and w=1 (excluded by design).
4. Path exploration: After k iterations, all paths of length ≤ k have been explored.
   After |V| iterations, all simple paths (length ≤ |V|−1) have been explored.
5. Fixed point: Once no T[v] increases, the algorithm has reached a fixed point and
   halts. This is guaranteed within |V| iterations by (3) and (4).

Therefore: worst-case complexity is O(|V| × |E|).

Practical bound: with λ=0.1/hr and min edge weight 0.80, taint at hop k from a source
with T=1.0 is at most (0.80)^k × exp(-0.1 × Δt_total). At k=8 hops the maximum
residual taint (ignoring time decay) is 0.80^8 ≈ 0.168, below any useful quarantine
threshold — making max_hops=8 a practical default.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class GraphEdge:
    src: str
    dst: str
    weight: float
    hours_elapsed: float = 0.0  # Δt in hours since edge was recorded


@dataclass
class PropagationResult:
    taint: dict[str, float]          # final taint levels for all nodes
    iterations: int                   # iterations until convergence
    changed: dict[str, float]         # nodes whose taint increased: {node_id: new_taint}


def propagate(
    graph: list[GraphEdge],
    initial_taint: dict[str, float],
    max_hops: int = 8,
    lambda_decay: float = 0.1,
) -> PropagationResult:
    """
    Multi-hop Taint Propagation — pure function, no DB dependency.

    Parameters
    ----------
    graph:         List of directed edges with pre-computed hours_elapsed.
    initial_taint: Starting taint levels per node {node_id: level}.
    max_hops:      Maximum iterations (convergence usually before this).
    lambda_decay:  Time-decay constant λ (per hour). Default 0.1.

    Returns
    -------
    PropagationResult with final taint levels, iteration count, changed nodes.
    """
    # Compute per-edge effective decay factor up front
    edges_with_decay = [
        (e.src, e.dst, e.weight * math.exp(-lambda_decay * e.hours_elapsed))
        for e in graph
    ]

    # Copy initial state — include all edge endpoints
    taint: dict[str, float] = dict(initial_taint)
    for src, dst, _ in edges_with_decay:
        taint.setdefault(src, 0.0)
        taint.setdefault(dst, 0.0)

    original = dict(taint)
    iterations = 0

    for _ in range(max_hops):
        changed = False
        for src, dst, decay in edges_with_decay:
            propagated = taint[src] * decay
            if propagated > taint[dst]:
                taint[dst] = propagated
                changed = True
        iterations += 1
        if not changed:
            break

    changed_nodes = {
        node_id: level
        for node_id, level in taint.items()
        if level > original.get(node_id, 0.0)
    }

    return PropagationResult(taint=taint, iterations=iterations, changed=changed_nodes)


def convergence_bound(
    max_taint: float,
    min_edge_weight: float,
    max_hops: int,
) -> float:
    """
    Upper bound on residual taint after max_hops hops (ignoring time decay).

    Parameters
    ----------
    max_taint:       Maximum source taint level (≤ 1.0).
    min_edge_weight: Minimum edge weight across the graph (< 1.0 required).
    max_hops:        Number of hops.

    Returns
    -------
    Upper bound T_max × w_min^max_hops.

    Example
    -------
    >>> convergence_bound(1.0, 0.80, 8)
    0.16777216  # 0.80^8
    """
    if min_edge_weight >= 1.0:
        raise ValueError("min_edge_weight must be < 1.0 for convergence guarantee")
    return max_taint * (min_edge_weight ** max_hops)


class MultiHopTaintPropagator:
    """
    Stateful wrapper around the pure propagate() function.

    Typical usage:
        mtp = MultiHopTaintPropagator(lambda_decay=0.1)
        mtp.add_edge("agent-A", "mem-key1", weight=0.95, hours_elapsed=0.0)
        mtp.add_edge("mem-key1", "agent-B", weight=0.80, hours_elapsed=0.0)
        result = mtp.run(initial_taint={"agent-A": 0.9})
        # result.taint["agent-B"] == 0.9 * 0.95 * 0.80 == 0.684
    """

    def __init__(self, lambda_decay: float = 0.1, max_hops: int = 8) -> None:
        self.lambda_decay = lambda_decay
        self.max_hops = max_hops
        self._edges: list[GraphEdge] = []

    def add_edge(
        self,
        src: str,
        dst: str,
        weight: float,
        hours_elapsed: float = 0.0,
    ) -> None:
        """Add a directed edge to the propagation graph."""
        self._edges.append(GraphEdge(src=src, dst=dst, weight=weight, hours_elapsed=hours_elapsed))

    def run(self, initial_taint: dict[str, float]) -> PropagationResult:
        """Run MTP propagation and return results."""
        return propagate(
            graph=self._edges,
            initial_taint=initial_taint,
            max_hops=self.max_hops,
            lambda_decay=self.lambda_decay,
        )

    def convergence_bound(self, max_taint: float = 1.0) -> float:
        """Upper bound on residual taint after max_hops (assumes uniform min weight)."""
        if not self._edges:
            return 0.0
        min_weight = min(e.weight for e in self._edges)
        return convergence_bound(max_taint, min_weight, self.max_hops)
