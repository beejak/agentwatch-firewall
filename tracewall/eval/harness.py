"""
tracewall/eval/harness.py — deterministic evaluation harness for the frozen corpus.

Runs the detector tiers as ablation baselines against the frozen, human-labeled
corpus and reports precision / recall / F1 / FP-rate with bootstrap 95% CIs on a
held-out split. Results are written to eval/results/ as preserved, reproducible
artifacts for the paper. Key-free and infra-free: the deterministic backend is
the stable, reproducible default.

Evaluators (ablation):
  tier0_content  — standalone content pre-filter (tracewall.content.filter)
  tier1_policy   — deterministic policy DSL (PolicyEngine, incl. call_tree context)
  tier2_semantic — SemanticJudge (deterministic backend by default; --llm for LLM)
  integrated_or  — naive OR of all three tiers (kept for comparison; inherits tier-0 FPR)
  integrated     — GATED: policy OR semantic. tier-0 routes/escalates only, never
                   blocks alone — mirrors Firewall.check and fixes the OR FP inflation.

Usage:
  python -m tracewall.eval.harness                       # test split, deterministic
  python -m tracewall.eval.harness --split all
  python -m tracewall.eval.harness --llm                 # tier2 uses the LLM backend
  python -m tracewall.eval.harness --out eval/results/run.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import time
from pathlib import Path

CORPUS = Path(__file__).parent / "corpus" / "corpus_v0.1.jsonl"
RESULTS_DIR = Path(__file__).parent / "results"
BOOTSTRAP_B = 2000
BOOTSTRAP_SEED = 1729


def load_corpus(split: str = "test") -> list[dict]:
    recs = [json.loads(l) for l in CORPUS.read_text().splitlines() if l.strip()]
    if split != "all":
        recs = [r for r in recs if r["split"] == split]
    return recs


def _content(case: dict) -> str:
    a = case.get("args", {})
    return a.get("content") or a.get("body") or a.get("command") or json.dumps(a)


def _enriched(case: dict):
    from tracewall.core.signal import EnrichedEvent, HookEvent
    he = HookEvent(agent_id="eval", tool=case["tool"], args=case.get("args", {}),
                   caller_chain=list(case.get("call_tree", [])))
    return he, EnrichedEvent(event=he, call_tree=list(case.get("call_tree", [])))


# ── Evaluators (each returns True if it would BLOCK the case) ─────────────────
def _tier0_content(case: dict) -> bool:
    from tracewall.content.filter import flagged
    return bool(flagged(_content(case)))


async def _tier1_policy(case: dict, engine) -> bool:
    _, en = _enriched(case)
    m = await engine.evaluate(en)
    return bool(m and m.verdict == "BLOCK")


async def _tier2_semantic(case: dict, judge) -> bool:
    he, en = _enriched(case)
    r = await judge.analyze(he, en, trust=0.5, taint=float(case.get("taint", 0.0)))
    return r.action == "BLOCK"


# ── Metrics ──────────────────────────────────────────────────────────────────
def _confusion(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for y, p in pairs if y and p)
    fp = sum(1 for y, p in pairs if not y and p)
    fn = sum(1 for y, p in pairs if y and not p)
    tn = sum(1 for y, p in pairs if not y and not p)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _prf(c: dict) -> dict:
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def _bootstrap_ci(pairs: list[tuple[bool, bool]], metric: str) -> list[float]:
    if not pairs:
        return [0.0, 0.0]
    rng = random.Random(BOOTSTRAP_SEED)
    n = len(pairs)
    vals = []
    for _ in range(BOOTSTRAP_B):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        vals.append(_prf(_confusion(sample))[metric])
    vals.sort()
    lo = vals[int(0.025 * BOOTSTRAP_B)]
    hi = vals[int(0.975 * BOOTSTRAP_B)]
    return [round(lo, 3), round(hi, 3)]


async def run_eval(split: str = "test", use_llm: bool = False) -> dict:
    if not use_llm:
        os.environ["TRACEWALL_SEMANTIC_LLM"] = "0"   # force deterministic, reproducible backend
    from tracewall.policy.engine import PolicyEngine
    from tracewall.semantic.judge import SemanticJudge

    cases = load_corpus(split)
    engine = PolicyEngine()
    await engine.load_policies()
    judge = SemanticJudge()

    # Compute each tier's prediction per case once.
    preds: dict[str, list[bool]] = {"tier0_content": [], "tier1_policy": [], "tier2_semantic": []}
    labels: list[bool] = []
    for c in cases:
        labels.append(c["label"] == "malicious")
        preds["tier0_content"].append(_tier0_content(c))
        preds["tier1_policy"].append(await _tier1_policy(c, engine))
        preds["tier2_semantic"].append(await _tier2_semantic(c, judge))

    # Naive OR (kept for comparison) inherits tier-0's false positives.
    preds["integrated_or"] = [a or b or d for a, b, d in zip(
        preds["tier0_content"], preds["tier1_policy"], preds["tier2_semantic"])]
    # Gated: tier-0 routes/escalates only (never blocks alone) — the precise tiers decide.
    # Mirrors Firewall.check, where content_flag forces semantic evaluation but the
    # policy/semantic verdict is authoritative.
    preds["integrated"] = [b or d for b, d in zip(
        preds["tier1_policy"], preds["tier2_semantic"])]

    evaluators: dict[str, dict] = {}
    for name, plist in preds.items():
        pairs = list(zip(labels, plist))
        conf = _confusion(pairs)
        metrics = _prf(conf)
        evaluators[name] = {
            **conf, **{k: round(v, 3) for k, v in metrics.items()},
            "f1_ci95": _bootstrap_ci(pairs, "f1"),
            "recall_ci95": _bootstrap_ci(pairs, "recall"),
        }

    return {
        "corpus": "corpus_v0.1",
        "split": split,
        "n_cases": len(cases),
        "n_malicious": sum(labels),
        "n_benign": len(labels) - sum(labels),
        "semantic_backend": "llm" if use_llm else "deterministic",
        "bootstrap_B": BOOTSTRAP_B,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evaluators": evaluators,
    }


def _print_table(res: dict) -> None:
    print(f"\nCorpus {res['corpus']} | split={res['split']} | n={res['n_cases']} "
          f"(mal={res['n_malicious']}, ben={res['n_benign']}) | semantic={res['semantic_backend']}")
    print(f"{'evaluator':<16}{'prec':>7}{'recall':>8}{'F1':>7}{'FPR':>7}   {'recall 95% CI':>16}")
    print("-" * 70)
    for name, e in res["evaluators"].items():
        ci = e["recall_ci95"]
        print(f"{name:<16}{e['precision']:>7.2f}{e['recall']:>8.2f}{e['f1']:>7.2f}{e['fpr']:>7.2f}"
              f"   [{ci[0]:.2f}, {ci[1]:.2f}]")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test", choices=["test", "dev", "all"])
    ap.add_argument("--llm", action="store_true", help="use the LLM semantic backend (needs LLM_API_KEY)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    res = asyncio.run(run_eval(split=args.split, use_llm=args.llm))
    _print_table(res)

    out = Path(args.out) if args.out else (
        RESULTS_DIR / f"{res['corpus']}_{res['split']}_{res['semantic_backend']}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2))
    print(f"\npreserved → {out}")


if __name__ == "__main__":
    main()
