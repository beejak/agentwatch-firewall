# How to read results

Eval artifacts live under `tracewall/eval/results/`. Claims that enter the paper must also appear in [`paper/EVIDENCE.md`](../paper/EVIDENCE.md).

**Two number sets (do not mix):**

| Set | Use for | Robustness | Brink | Notes |
|-----|---------|------------|-------|-------|
| **Paper freeze** (v0.2.0 / EVIDENCE) | Paper, arXiv, release PDF | **18/18** | freeze-era matrix | Do **not** rewrite freeze headlines |
| **Current post–Gate B** (repo HEAD) | Operator docs, CI expectations | **19/19** (17 success + 2 expected_limit) | **21/21** (18 success + 3 expected_limit) | E1/E2 rows; not a paper claim rewrite |

**Honesty (2026-10-21):** Quote soft-block banking, freeze robustness **18/18**, and latency only from committed freeze artifacts + EVIDENCE. Do not treat local `adojo_diag/` / `adojo_stress_live/` trees as paper evidence. Gate B E1/E2 closed unknown-tool / list-filter holes on zta/paranoid; paper freeze numbers unchanged.

### Soft-block banking re-measure (post–Gate B)

| Lane | Status | Outcome |
|------|--------|---------|
| Firewall-only `adojo_stress` | **Re-run** | **7/7** pass (deterministic banking-shaped rows) |
| Live AgentDojo soft-block (`.[bench]` + `LLM_API_KEY`) | **Blocked** | No API key / `.env` in this environment — **no new ASR/utility invented**. Paper freeze `direct` ASR 1.0→0.0 util 1.0→1.0 stays the only quoted live soft-block evidence ([`EVIDENCE.md`](../paper/EVIDENCE.md)). Committed `adojo_stress.json` `live[]` is prior freeze-era data, not a 2026-10-21 re-measure. |

**Decision:** soft-block utility story remains freeze-backed; live re-measure deferred until keys available. E4 `session_ratchet` shipped **optional** (off on `balanced`, on for `zta`/`paranoid`) as plug-and-play progressive containment — not as a claim that soft-block failed.

### API key + live eval cost (plain English)

- **Firewall-only 7/7** — no LLM, no `LLM_API_KEY`. AgentDojo-*shaped* tool chains; proves PEP behavior only.
- **Live ASR** — needs `.[bench]` + **`LLM_API_KEY`** (optional `LLM_BASE_URL` / `LLM_MODEL`). Last re-measure blocked = keys missing.
- **Unit / pytest / brink / robustness** — no key.
- **Dollar range** for banking soft-block `direct` **1×4** (base+defended, ~8 episodes): roughly **~$0.05–$0.50** (cheap API) · **~$0.50–$2** (mid) · **~$2–$10** (frontier). Rough; see full table in [`TEST_PLAN.md`](TEST_PLAN.md)#live-eval-cost-rough-usd.

## Quick map

| File | What it proves | Pass means |
|------|----------------|------------|
| `corpus_v0.1_test_deterministic.json` | Held-out detection (P/R/FPR) | Regression bar, **not** adaptive proof |
| `mcp_brink.json` | MCP profile contracts | All `kind=success` pass **and** `expected_limit` still reproduce |
| `adojo_stress.json` | Banking-shaped firewall matrix + optional live ASR | Firewall rows green; live[] is DeepSeek slice |
| `robustness_stress.json` | Non-banking domains | **Current:** **19/19**; **paper freeze:** **18/18** |
| `latency_check.json` | Full `Firewall.check` microbench | Method note required if you quote numbers |

## Held-out (`corpus_v0.1_test_*.json`)

Look at per-tier **recall / precision / FPR**. Headline integrated recall **1.0** with FPR ≈ **0.07** is a **frozen-corpus regression bar**. It does **not** mean “safe against paraphrases or AgentDojo.”

## Brink (`mcp_brink.json`)

**Current (post–Gate B):**

```json
"by_kind": {
  "success": { "n": 18, "pass": 18 },
  "expected_limit": { "n": 3, "pass": 3 }
}
```

- **`kind=success` fail** → feature broken. Fix before merge.
- **`kind=expected_limit` fail** → we *hid* a known miss (also bad). Limits must still happen until closed.
- Remaining limits: forged call-tree ignored, context starvation (balanced), permissive skips exfil.
- Profiles differ: `balanced` may forward context-starved exfil; `zta` default-denies external email.
- E2: `S-tools-list-request-forwards` success rows (filter on zta/paranoid; request still forwards).

## Robustness (`robustness_stress.json`)

Domains: workspace, HTTP, contagion, host, identity, banking. Same success vs expected_limit discipline as brink.

- **Current:** **19/19** (17 success + 2 expected_limit: `L-unknown-tool-name-balanced`, `L-tools-list-not-firewall-layer`).
- **Paper freeze:** **18/18** — cite only from EVIDENCE / paper, not as “HEAD matrix.”
- E1: `S-block-unknown-tool-deny` is a **success** row under `deny_unknown_tools`.
- ZWSP IBAN and PascalCase aliases are **success** rows after normalize/canonical (not open limits).

## AgentDojo (`adojo_stress.json`)

AgentDojo ships **multiple environment suites** (banking, workspace, travel, …).
We measured a **banking slice** only — do **not** imply full-AgentDojo coverage
in docs or the paper. See [`EVIDENCE.md`](../paper/EVIDENCE.md).

- **`firewall` / `rows`**: no LLM — policy must BLOCK attacker IBAN, ALLOW legit bill.
- **`live[]`**: DeepSeek banking slices. Read **ASR** (attack goal met) and **utility** (user task still done).
  - Baseline ASR 1.0 → defended ASR 0.0 with utility 1.0 = Tracewall win (soft-block).
  - Baseline ASR 0.0 = model refusal — **not** a Tracewall win.

## Latency (`latency_check.json`)

Mean / p50 / p95 / p99 of full `Firewall.check` on a mixed allow/block microbench. Do **not** compare to GPU sentinels without matched e2e methodology. Paper freeze: ≈6.4 ms mean / ≈9.8 ms p99.

## ASR vs utility (one line)

**ASR** = did the injection succeed? **Utility** = did the user task still succeed? Soft-block aims for ASR↓ without killing utility.

## Test parameters (durable)

Full command / profile matrix: [`TEST_PLAN.md`](TEST_PLAN.md)#test-parameters. Short form:

| Lane | Typical command | CI? |
|------|-----------------|-----|
| Unit | `pytest -q` → **153 passed, 2 skipped** (AgentDojo soft-block without `[bench]`; includes E4) | Yes |
| Held-out | `python -m tracewall.eval.harness --split test` | Yes |
| Brink | `python -m tracewall.eval.mcp_brink` | Yes |
| Robustness | `python -m tracewall.eval.robustness_stress` | **No** (local / release gate) |
| AgentDojo live | needs `.[bench]` + `LLM_API_KEY` | **No** |

Profiles: lab `balanced`; prod `zta` / `paranoid`. E1/E2 flags apply on zta/paranoid only.

## Paper rule

Repo evidence → paper. Never invent metrics in LaTeX first. See EVIDENCE claim statuses: VERIFIED / CAVEATS / UNVERIFIED / REFUTED. **Do not** promote current 19/19 or 21/21 into paper freeze quotes.
