# WatchTower Evaluation Harness

Reproducible, preserved evaluation of the detector tiers against a **frozen,
human-labeled corpus**. Produces precision / recall / F1 / FP-rate with bootstrap
95% CIs on a **held-out** split, and writes results to `eval/results/` as durable
artifacts for the paper.

## Run
```bash
python -m eval.harness                 # held-out test split, deterministic semantic
python -m eval.harness --split all
python -m eval.harness --llm           # tier-2 uses the LLM backend (needs LLM_API_KEY)
```
Rebuild the corpus from its reviewed source: `python -m eval.corpus._build_v0_1`.

## Corpus (`corpus/corpus_v0.1.jsonl`, 38 cases)
- **Human-curated labels** — authored by a reviewer, **not** assigned by any
  attacker/LLM, so ground truth is independent of the system under test.
- Surfaces: ① injection (22), ② capability-abuse (16). Surface ③ contagion is
  stateful taint propagation — covered by the MTP/taint tests; sequence cases TBD.
- **Split policy:** `dev` (11, KB-like/obvious) is the only set you may tune on;
  `test` (27, novel paraphrases + FP-bait benign business text) is **held-out** —
  all reported numbers come from `test`. Never tune on `test`.

## Evaluators (ablation baselines)
`tier0_regex` (watchtower content/MIM) · `tier1_policy` (superpowers DSL) ·
`tier2_semantic` (SemanticJudge; deterministic or `--llm`) · `integrated` (BLOCK if
ANY tier blocks).

## Results — held-out `test` split (n=27: 13 malicious, 14 benign)

| evaluator | precision | recall | F1 | FPR |
|---|---|---|---|---|
| tier0_regex | 0.17 | 0.08 | 0.10 | 0.36 |
| tier1_policy | 0.50 | 0.08 | 0.13 | 0.07 |
| tier2_semantic (deterministic) | 0.86 | 0.46 | 0.60 | 0.07 |
| tier2_semantic (**LLM**) | 1.00 | 1.00 | 1.00 | 0.00 |
| integrated (OR, deterministic) | 0.54 | 0.54 | 0.54 | 0.43 |
| integrated (OR, LLM) | 0.72 | 1.00 | 0.84 | 0.36 |

What the data shows:
1. **Regex does not generalize** — recall 0.08 on novel paraphrases, FPR 0.36 on
   benign business text. Confirms it belongs at tier-0 (cheap filter), not as the
   detector of record.
2. **The semantic tier carries detection** — LLM backend dominates; the
   deterministic backend (no NLP, structural-only) is the key-free floor.
3. **Naive OR-integration is wrong** — ORing tiers inherits tier-0's false
   positives (integrated FPR 0.36–0.43 vs tier-2-alone 0.00). The verdict should
   be gated, not a blunt OR. *(Concrete architecture fix, surfaced by the data.)*

## ⚠️ Caveats — read before citing any number

- **n=27 is small. The LLM tier's "1.00" is NOT a 100%-detection claim.** The
  bootstrap CI is [1.00,1.00] only because every one of 27 cases happened to be
  correct — a small-sample artifact, not evidence of true 100%. **This is exactly
  the trap the prior "100% on 17 cases" fell into.** Do not put "100%" in the paper
  off this. Scale to hundreds–thousands of independent cases first.
- **Author-curated corpus → possible shared-intuition bias** between the labeler
  and the LLM judge. Needs independently/adversarially sourced cases and
  human inter-annotator agreement before headline claims.
- **LLM backend is non-deterministic and a model snapshot** (deepseek-chat). The
  committed `*_llm.json` is a dated run; the deterministic result is the stable,
  reproducible baseline.
- **No external baselines yet** (LlamaFirewall/PromptGuard, etc.). Head-to-head on
  this corpus is required for comparative claims.

## Next (to make this publication-grade)
Scale the corpus with agent-generated + independently-labeled cases; add surface-③
sequence cases; run external baselines head-to-head; report with CIs across seeds
and ≥2 judge models; keep tuning strictly on `dev`.
