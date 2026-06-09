"""Multi-hop taint propagation (firewall/taint/mtp.py) — moved from watchtower.

Covers the paper's KB17 chain and the convergence bound.
"""
from firewall.taint.mtp import propagate, MultiHopTaintPropagator, convergence_bound, GraphEdge


def test_kb17_two_hop_chain():
    # A --write(0.95)--> mem --read(0.80)--> B ; source taint 0.9 → 0.9*0.95*0.80 = 0.684
    mtp = MultiHopTaintPropagator()
    mtp.add_edge("agent-A", "mem-1", weight=0.95)
    mtp.add_edge("mem-1", "agent-B", weight=0.80)
    res = mtp.run(initial_taint={"agent-A": 0.9})
    assert abs(res.taint["agent-B"] - 0.684) < 1e-6


def test_monotonic_and_bounded():
    res = propagate(
        [GraphEdge("x", "y", 0.8), GraphEdge("y", "z", 0.8)],
        initial_taint={"x": 1.0},
    )
    assert 0.0 <= res.taint["z"] <= 1.0
    assert res.taint["z"] == 0.64  # 1.0*0.8*0.8


def test_convergence_terminates():
    # cycle must still converge (strict decay, weights < 1)
    res = propagate(
        [GraphEdge("a", "b", 0.8), GraphEdge("b", "a", 0.8)],
        initial_taint={"a": 1.0},
        max_hops=8,
    )
    assert res.iterations <= 8


def test_convergence_bound():
    assert abs(convergence_bound(1.0, 0.80, 8) - 0.80 ** 8) < 1e-9
