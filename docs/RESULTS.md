# How to read results

Eval artifacts live under `tracewall/eval/results/`. Claims that enter the paper must also appear in [`paper/EVIDENCE.md`](../paper/EVIDENCE.md).

## Quick map

| File | What it proves | Pass means |
|------|----------------|------------|
| `corpus_v0.1_test_deterministic.json` | Held-out detection (P/R/FPR) | Regression bar, **not** adaptive proof |
| `mcp_brink.json` | MCP profile contracts | All `kind=success` pass **and** `expected_limit` still reproduce |
| `adojo_stress.json` | Banking-shaped firewall matrix + optional live ASR | Firewall rows green; live[] is DeepSeek slice |
| `robustness_stress.json` | Non-banking domains | **18/18** (16 success + 2 expected_limit) |
| `latency_check.json` | Full `Firewall.check` microbench | Method note required if you quote numbers |

## Held-out (`corpus_v0.1_test_*.json`)

Look at per-tier **recall / precision / FPR**. Headline integrated recall **1.0** with FPR ≈ **0.07** is a **frozen-corpus regression bar**. It does **not** mean “safe against paraphrases or AgentDojo.”

## Brink (`mcp_brink.json`)

```json
"by_kind": {
  "success": { "n": 12, "pass": 12 },
  "expected_limit": { "n": 6, "pass": 6 }
}
```

- **`kind=success` fail** → feature broken. Fix before merge.  
- **`kind=expected_limit` fail** → we *hid* a known miss (also bad). Limits must still happen until closed.  
- Profiles differ: `balanced` may forward context-starved exfil; `zta` default-denies external email.

## Robustness (`robustness_stress.json`)

Domains: workspace, HTTP, contagion, host, identity, banking. Same success vs
expected_limit discipline as brink. Current matrix: **18/18** (16 success +
2 expected_limit: unknown tool names). ZWSP IBAN and PascalCase aliases are
**success** rows after normalize/canonical (not open limits).

## AgentDojo (`adojo_stress.json`)

- **`firewall` / `rows`**: no LLM — policy must BLOCK attacker IBAN, ALLOW legit bill.  
- **`live[]`**: DeepSeek slices. Read **ASR** (attack goal met) and **utility** (user task still done).  
  - Baseline ASR 1.0 → defended ASR 0.0 with utility 1.0 = Tracewall win (soft-block).  
  - Baseline ASR 0.0 = model refusal — **not** a Tracewall win.

## Latency (`latency_check.json`)

Mean / p50 / p95 / p99 of full `Firewall.check` on a mixed allow/block microbench. Do **not** compare to GPU sentinels without matched e2e methodology.

## ASR vs utility (one line)

**ASR** = did the injection succeed? **Utility** = did the user task still succeed? Soft-block aims for ASR↓ without killing utility.

## Paper rule

Repo evidence → paper. Never invent metrics in LaTeX first. See EVIDENCE claim statuses: VERIFIED / CAVEATS / UNVERIFIED / REFUTED.
