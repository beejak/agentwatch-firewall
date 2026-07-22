# Tracewall goals (FABLE / measure-first)

Evidence flows **repo → paper**. A goal without a named verification is a wish.

## Product placement

**Tool-call PEP** (library + MCP proxy) that ALLOW/BLOCKs screened tool calls.
Contains screened side effects after prompt compromise — **not** a chat-stream
scanner, OS sandbox, on-disk file scanner, SaaS gateway, HITL approve box, or
CaMeL-style IFC redesign. No SPIFFE-as-shipped. Features **frozen** for paper
submit (v0.2.0, author beejak). Threat model: [`../SECURITY.md`](../SECURITY.md).

| Use site | Status |
|----------|--------|
| Python `Firewall.check` / `guard` | Shipped |
| MCP stdio proxy | Shipped (Content-Length + NDJSON auto-detect) |
| LangGraph-style `GuardedToolNode` | Shipped (no `langgraph` dep) |
| HTTP sidecar PEP | Roadmap |

Wiring guide: [`INTEGRATION.md`](INTEGRATION.md).

## Goals + success / failure

| ID | Goal | Success (observed) | Failure | Verify |
|----|------|--------------------|---------|--------|
| G0 | Tooling | Superpowers + `tracewall-paper` skill; this file exists | Skills missing | Skills load in Cursor |
| G1 | Evidence ledger | [`paper/EVIDENCE.md`](../paper/EVIDENCE.md) rows for load-bearing claims | Abstract claim with no row | Open EVIDENCE |
| G1b | Live-path correctness | P0 bugs fixed + pytest green | Silent no-op security rules | `pytest -q` + tests below |
| G2 | Key-free security | Deterministic integrated recall **> 0.462** on held-out; FPR justified | Still weak tier1 + marketing without numbers | `python -m tracewall.eval.harness --split test` → integrated R=1.0 FPR≈0.07 (2026-07-19); not adaptive/AgentDojo |
| G3 | MCP profiles | All `kind=success` rows in `mcp_brink.json` pass; profiles load; `--fail-closed`/`--fail-open` CLI work | Success-row fails, or profiles only in docs | `pytest tracewall/tests/test_mcp_profiles.py` + `python -m tracewall.eval.mcp_brink` (exit 0) |
| G3-fail | MCP honesty | `expected_limit` rows **pass** (limit reproduced: no `_meta`, permissive skips exfil, tools/list unscanned) | We hide misses or claim profiles fix context starvation | Same brink JSON `by_kind.expected_limit` |
| G3z | ZTA practicality | zta profile: allowlists, own call-tree, require_caps, rate_exceeds tests green | Lab denylist-only story | `pytest …test_zta_practical.py` + brink zta rows |
| G4 | AgentDojo banking slice | ASR base vs defended + utility on **banking**; never imply full AgentDojo | Unrun adapter or “full suite” claim | adapter CLI smoke + EVIDENCE |
| G4b | Firewall stress (no LLM) | `adojo_stress` success rows pass; limits reproduced | Claim AgentDojo blocked without send_money rules | `python -m tracewall.eval.adojo_stress` / `pytest …test_adojo_stress` |
| G4c | DeepSeek follow-through | Live **banking** probes with `--system benchmark` + bill-preserving raise ASR above vanilla 0/0 when model complies | Treat refusal-as-defense as Tracewall win; imply workspace/travel measured | `python -m tracewall.eval.adojo_stress --live` |
| G4d | Cross-domain robustness | `robustness_stress` success rows pass; limits reproduced | Banking-only story | `python -m tracewall.eval.robustness_stress` / pytest |
| G5 | Paper honesty | Tracewall draft matches EVIDENCE | WatchTower 17/17 / 0.011ms | Diff abstract vs EVIDENCE |
| G6 | Venue | G4+G5 done; PDF floats verified | Submit on stale PDF | tectonic + page inspect |

**Status snapshot (2026-07-22, v0.2.0, features frozen):** G0–G3 (+G3-fail, G3z) met; G4b/G4c/G4d met (robustness **18/18**; AgentDojo = banking slice); G5 paper draft + PDF aligned with EVIDENCE (PEP ≠ chat scanner). ZWSP/NFKC + canonical tool names closed. Remaining (post-submit): signed identity, HTTP sidecar PEP, SBOM, OTLP/gRPC, venue polish, unknown-tool / `tools/list` limits — not OS sandbox productization.


## P0 correctness (G1b) — named checks

1. `${ORG_DOMAIN}` expands from `TRACEWALL_ORG_DOMAINS` (comma-separated).
2. Exfil policy matches any secret-reader alias in call tree.
3. `require_identity=True` → missing identity BLOCKs (default False for transport degrade).
4. ALLOW → `on_clean_call`; BLOCK (policy/semantic) → `on_taint_event`.
5. `rate_exceeds` — match-level sliding window (`window_s`/`max`/`key`); in-process only.
6. Verdict `score` is **0 bad … 1 clean** (semantic malicious score inverted at facade).
7. ZTA profile: `require_identity` + `require_caps` + `own_call_tree` + `rules/zta/` allowlists.

## Lanes

- **pytest** — scenarios / edges / regressions  
- **harness** — offline P/R/F1 only (not the scenario suite)  
- **AgentDojo** — live ASR/utility  

See [`TEST_PLAN.md`](TEST_PLAN.md).
