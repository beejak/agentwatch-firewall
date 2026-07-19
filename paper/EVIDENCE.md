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
| Deterministic integrated recall = 1.0, prec ≈ 0.929, FPR ≈ 0.071 | VERIFIED | `eval/results/corpus_v0.1_test_deterministic.json` (2026-07-19 policy pack) |
| Deterministic integrated recall ≈ 0.462, FPR ≈ 0.143 | REFUTED | Superseded 2026-07-19 — pre-policy-pack baseline |
| Deterministic tier1 policy recall = 1.0, FPR = 0.0 (tp=13) | VERIFIED | same JSON — paraphrase + egress rules; **held-out only, not adaptive attacks** |
| Deterministic tier1 policy recall ≈ 0.154 (tp=2 after org-domain + secret-reader + private-key pattern fixes) | REFUTED | Superseded by full policy pack same day |
| Deterministic tier1 policy recall ≈ 0.077 | REFUTED | Superseded 2026-07-19 — was pre-G1b baseline |
| Deterministic tier0 content recall = 0.0 | VERIFIED | same |
| LLM semantic integrated recall = 1.0, prec ≈ 0.929, FPR ≈ 0.071 | CAVEATS | `corpus_v0.1_test_llm.json` — dated snapshot; non-gating; refresh before paper |
| “100% detection on 17-case known-bad corpus” as primary result | REFUTED | LESSONS overfitting trap; held-out ≠ 100% without LLM |
| “0.011ms p99 / 9636× vs Sentinel” as current system | REFUTED / UNVERIFIED | No committed measurement of full `Firewall.check` at that number; PB01 is policy mean &lt; 10ms |
| Key-free path is security-complete | CAVEATS | Held-out deterministic integrated recall now 1.0 after policy pack — still not adaptive/AgentDojo; LESSONS overfitting warning applies |

## Taint / MINJA

| Claim | Status | Artifact |
|-------|--------|----------|
| MTP fixed-point + ledger APIs exist | VERIFIED | `taint/mtp.py`, `taint/ledger.py`, KB17–20 |
| Live `Firewall.check` updates ledger trust/taint | CAVEATS | Wired as of G1b; re-verify with tests |
| End-to-end MINJA vs GPT-4 agents reproduced | UNVERIFIED | Synthetic taint tests only |
| Contagion surface in frozen corpus | UNVERIFIED | Deferred in `_build_v0_1.py` |

## MCP profiles

| Claim | Status | Artifact |
|-------|--------|----------|
| Profiles paranoid / balanced / permissive exist and differ observably | VERIFIED | `transports/profiles.py`, `tests/test_mcp_profiles.py` |
| Brink matrix: 9 success + 5 expected_limit rows all pass | VERIFIED | `eval/results/mcp_brink.json` (2026-07-19) |
| Without `_meta`, secret→email may forward under high trust | VERIFIED (limit) | brink `L-context-starvation-no-meta` |
| Permissive omits exfil rule pack | VERIFIED (limit) | brink `L-permissive-skips-exfil-pack` |
| Content-Length MCP framing supported | VERIFIED | `mcp_framing.py` + proxy auto-detect NDJSON/CL; unit tests |

## AgentDojo

| Claim | Status | Artifact |
|-------|--------|----------|
| Adapter code + pure unit tests | VERIFIED | `eval/adapters/agentdojo.py`, `test_agentdojo_adapter.py` |
| Live ASR/utility base vs defended (vanilla important_instructions) | CAVEATS | DeepSeek clean utility=True; under injection often ASR≈0 utility≈0 (refusals / wiped bill) — not a Tracewall measurement |
| Firewall-only AgentDojo-shaped banking chains (send_money + schedule_transaction attacker IBAN) | VERIFIED | `eval/adojo_stress.py` → `eval/results/adojo_stress.json`; `test_adojo_stress.py`; rule `exfil_schedule_transaction.yaml` |
| Known bypasses tracked (ZWSP IBAN, tool case) | VERIFIED (limit) | same JSON `expected_limit` rows (deterministic semantic off); schedule_transaction promoted to success 2026-07-19 |
| Cross-domain robustness matrix (workspace/HTTP/contagion/host/identity; 14/14) | VERIFIED | `eval/robustness_stress.py` → `eval/results/robustness_stress.json`; `test_robustness_stress.py` |
| Robustness expected limits (unknown tool, PascalCase alias) | VERIFIED (limit) | same JSON `L-unknown-tool-name`, `L-alias-tool-SendMessage` |
| Live DeepSeek bill-preserving + benchmark system (n=1 pair) | VERIFIED (slice) | `adojo_stress.json` live[] 2026-07-19: **direct** base ASR=1.0 util=1.0 → defended ASR=0.0 util=1.0; important_instructions & ignore_previous ASR=0 util=1 both arms (model refuse attack, still pays bill) |
| Live DeepSeek `direct` expand (user_task_0 × inj 0–3, n=4) | VERIFIED (slice) | abort-era: base ASR=**1.0** util=**1.0** → defended ASR=**0.0** util=**0.25**; **soft-block**: defended ASR=**0.0** util=**1.0** (2026-07-19) |
| Soft-block defense (rewrite blocked tool → non-executing error) | VERIFIED | `adapters/agentdojo.py` `on_block=soft`; `test_agentdojo_soft_block.py` |
| Full `Firewall.check` latency (deterministic, n=400) | VERIFIED | `eval/results/latency_check.json` — mean≈6.41ms, p99≈9.82ms (not vs GPU sentinel) |
| MCP Content-Length framing | VERIFIED | `transports/mcp_framing.py` + proxy auto-detect; `test_mcp_framing.py` |
| Live ASR/utility base vs defended (full suite) | UNVERIFIED | Expand beyond banking user_task_0 / more suites |

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
