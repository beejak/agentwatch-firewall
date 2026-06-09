"""
Eval harness sanity tests — deterministic, key-free, no external services.

Validates corpus integrity and that the harness produces well-formed metrics.
Does NOT assert specific scores (those are research results that will move as the
corpus grows); asserts structural invariants only.
"""
import json
from pathlib import Path

import pytest

from eval.harness import load_corpus, run_eval

CORPUS = Path("eval/corpus/corpus_v0.1.jsonl")


def test_corpus_integrity():
    recs = [json.loads(l) for l in CORPUS.read_text().splitlines() if l.strip()]
    assert len(recs) >= 30
    ids = [r["id"] for r in recs]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for r in recs:
        assert r["label"] in ("malicious", "benign")
        assert r["surface"] in ("injection", "capability_abuse")
        assert r["split"] in ("dev", "test")
    # held-out test split must be non-trivial and class-balanced enough to be useful
    test = [r for r in recs if r["split"] == "test"]
    assert len(test) >= 15
    assert any(r["label"] == "malicious" for r in test)
    assert any(r["label"] == "benign" for r in test)


async def test_harness_runs_and_reports():
    res = await run_eval(split="test", use_llm=False)
    assert res["n_cases"] == len(load_corpus("test"))
    for name in ("tier0_regex", "tier1_policy", "tier2_semantic", "integrated"):
        e = res["evaluators"][name]
        # confusion counts sum to n
        assert e["tp"] + e["fp"] + e["fn"] + e["tn"] == res["n_cases"]
        for m in ("precision", "recall", "f1", "fpr"):
            assert 0.0 <= e[m] <= 1.0
        assert len(e["recall_ci95"]) == 2


async def test_integrated_recall_dominates_single_tiers():
    """integrated = OR of tiers ⇒ its recall is ≥ every single tier's recall."""
    res = await run_eval(split="test", use_llm=False)
    ev = res["evaluators"]
    integ = ev["integrated"]["recall"]
    for name in ("tier0_regex", "tier1_policy", "tier2_semantic"):
        assert integ >= ev[name]["recall"] - 1e-9
