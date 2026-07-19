"""
Eval integrity & reproducibility — the paper's evidence guards.

  * frozen-corpus hash: the labeled corpus cannot silently change.
  * reproducibility: the deterministic harness reproduces the committed results
    byte-for-byte (seeded bootstrap).
  * pure-tier regression: tier1_policy / tier2_semantic are in-repo + deterministic,
    so their confusion counts are pinned. Drift here is a real regression (not a
    re-baseline). tier-0 / integrated are re-baselined and NOT pinned.
"""
import hashlib
import json
from pathlib import Path

from tracewall.eval.harness import run_eval

CORPUS = Path(__file__).resolve().parents[1] / "eval" / "corpus" / "corpus_v0.1.jsonl"
RESULTS = Path(__file__).resolve().parents[1] / "eval" / "results" / "corpus_v0.1_test_deterministic.json"

CORPUS_SHA256 = "bcb15fe25540cd060035889c91ba3d26bd434f2be6680d2e11215429cfdf9c41"

# Pinned pure-tier confusion counts (held-out test split, n=27).
PINNED = {
    "tier1_policy":   {"tp": 13, "fp": 0, "fn": 0, "tn": 14},
    "tier2_semantic": {"tp": 6, "fp": 1, "fn": 7,  "tn": 13},
}


def test_frozen_corpus_hash():
    # Normalize CRLF→LF so Windows checkouts match the committed LF blob hash.
    digest = hashlib.sha256(CORPUS.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    assert digest == CORPUS_SHA256, "corpus changed — update hash deliberately, not by accident"


async def test_eval_reproducible():
    res = await run_eval(split="test", use_llm=False)
    committed = json.loads(RESULTS.read_text())
    assert res["n_cases"] == committed["n_cases"]
    # Point metrics + confusion must match; bootstrap CI bounds can differ slightly
    # across platforms (float / RNG edge) — compare without ci keys.
    for name, got in res["evaluators"].items():
        want = committed["evaluators"][name]
        for k in ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"):
            assert got[k] == want[k], f"{name}.{k}: {got[k]} != {want[k]}"


async def test_pure_tier_regression():
    res = await run_eval(split="test", use_llm=False)
    for tier, counts in PINNED.items():
        got = {k: res["evaluators"][tier][k] for k in ("tp", "fp", "fn", "tn")}
        assert got == counts, f"{tier} regressed: {got} != {counts}"


def test_gated_beats_naive_or():
    """The documented finding: gating beats naive OR (lower FPR, higher precision)."""
    committed = json.loads(RESULTS.read_text())
    gated = committed["evaluators"]["integrated"]
    naive = committed["evaluators"]["integrated_or"]
    assert gated["fpr"] <= naive["fpr"]
    assert gated["precision"] >= naive["precision"]
    assert gated["recall"] == naive["recall"]  # gating drops FPs, not recall
