# Tracewall paper evidence ledger

Claim status: **VERIFIED** | **CAVEATS** | **UNVERIFIED** | **REFUTED**.  
Only VERIFIED rows may appear as unqualified paper assertions. Update after every eval run.

Sources: [`LESSONS_LEARNED.md`](../LESSONS_LEARNED.md), [`HANDOFF.md`](../HANDOFF.md), `tracewall/eval/results/`, tests.

## Architecture / product

| Claim | Status | Artifact |
|-------|--------|----------|
| Stable `await Firewall.check(event) → FirewallVerdict` | VERIFIED | `tracewall/core/firewall.py`, tests |
| Pipeline: identity → content → policy → trust/taint → semantic → audit | VERIFIED | `docs/FIREWALL.md`, code |
| Fail-safe: internal error → BLOCK | VERIFIED | `firewall.check` except path; KB tests |
| Transports: Python guard + MCP stdio proxy | VERIFIED | `tracewall/transports/` |
| Hermes / graphify AST / ruflo BFT / ClickHouse / SPIFFE CA shipped | REFUTED | Not in `tracewall/` package |
| Brand: WatchTower observation-first OS | REFUTED | Product is **tracewall** enforcement-only ([HANDOFF](../HANDOFF.md)) |

## Metrics (held-out corpus_v0.1 test, n=27)

| Claim | Status | Artifact |
|-------|--------|----------|
| Deterministic integrated recall ≈ 0.462, FPR ≈ 0.143 | VERIFIED | `eval/results/corpus_v0.1_test_deterministic.json` (2026-06-16) |
| Deterministic tier1 policy recall ≈ 0.154 (tp=2 after org-domain + secret-reader + private-key pattern fixes) | VERIFIED | `eval/results/corpus_v0.1_test_deterministic.json` (refreshed 2026-07-19) |
| Deterministic tier1 policy recall ≈ 0.077 | REFUTED | Superseded 2026-07-19 — was pre-G1b baseline |
| Deterministic tier0 content recall = 0.0 | VERIFIED | same |
| LLM semantic integrated recall = 1.0, prec ≈ 0.929, FPR ≈ 0.071 | CAVEATS | `corpus_v0.1_test_llm.json` — dated snapshot; non-gating; refresh before paper |
| “100% detection on 17-case known-bad corpus” as primary result | REFUTED | LESSONS overfitting trap; held-out ≠ 100% without LLM |
| “0.011ms p99 / 9636× vs Sentinel” as current system | REFUTED / UNVERIFIED | No committed measurement of full `Firewall.check` at that number; PB01 is policy mean &lt; 10ms |
| Key-free path is security-complete | REFUTED | HANDOFF: deterministic alone ≈ empty; LLM carries system |

## Taint / MINJA

| Claim | Status | Artifact |
|-------|--------|----------|
| MTP fixed-point + ledger APIs exist | VERIFIED | `taint/mtp.py`, `taint/ledger.py`, KB17–20 |
| Live `Firewall.check` updates ledger trust/taint | CAVEATS | Wired as of G1b; re-verify with tests |
| End-to-end MINJA vs GPT-4 agents reproduced | UNVERIFIED | Synthetic taint tests only |
| Contagion surface in frozen corpus | UNVERIFIED | Deferred in `_build_v0_1.py` |

## AgentDojo

| Claim | Status | Artifact |
|-------|--------|----------|
| Adapter code + pure unit tests | VERIFIED | `eval/adapters/agentdojo.py`, `test_agentdojo_adapter.py` |
| Live ASR/utility base vs defended | UNVERIFIED | HANDOFF 2026-06-23 — needs `[bench,llm]` + key |

## Policy DSL

| Claim | Status | Artifact |
|-------|--------|----------|
| YAML rules load and BLOCK on match | VERIFIED | `policy/engine.py`, rules/*.yaml |
| Working `rate_exceeds` operator | REFUTED | Stub / unsupported |
| `${ORG_DOMAIN}` org allowlist | CAVEATS | Expanded via `TRACEWALL_ORG_DOMAINS` (G1b) |

## Paper process rules (LESSONS)

- Held-out + baselines + CIs, or it doesn’t count  
- Evidence repo → paper, never reverse  
- Empty success (exit 0, zero spans) = failure  
- Render PDF and inspect floats — never trust build exit alone  

Append new rows; never delete REFUTED history without striking through and dating.
