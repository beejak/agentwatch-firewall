# Tracewall goals (FABLE / measure-first)

Evidence flows **repo → paper**. A goal without a named verification is a wish.

## Product placement

Library + MCP proxy that ALLOW/BLOCKs tool calls. Not a SaaS gateway, HITL approve box, or CaMeL-style IFC redesign.

| Use site | Status |
|----------|--------|
| Python `Firewall.check` / `guard` | Shipped |
| MCP stdio proxy | Shipped (Content-Length + NDJSON auto-detect) |
| LangGraph / HTTP sidecar | Roadmap |

## Goals + success / failure

| ID | Goal | Success (observed) | Failure | Verify |
|----|------|--------------------|---------|--------|
| G0 | Tooling | Superpowers + `tracewall-paper` skill; this file exists | Skills missing | Skills load in Cursor |
| G1 | Evidence ledger | [`paper/EVIDENCE.md`](../paper/EVIDENCE.md) rows for load-bearing claims | Abstract claim with no row | Open EVIDENCE |
| G1b | Live-path correctness | P0 bugs fixed + pytest green | Silent no-op security rules | `pytest -q` + tests below |
| G2 | Key-free security | Deterministic integrated recall **> 0.462** on held-out; FPR justified | Still weak tier1 + marketing without numbers | `python -m tracewall.eval.harness --split test` → integrated R=1.0 FPR≈0.07 (2026-07-19); not adaptive/AgentDojo |
| G3 | MCP profiles | All `kind=success` rows in `mcp_brink.json` pass; profiles load; `--fail-closed`/`--fail-open` CLI work | Success-row fails, or profiles only in docs | `pytest tracewall/tests/test_mcp_profiles.py` + `python -m tracewall.eval.mcp_brink` (exit 0) |
| G3-fail | MCP honesty | `expected_limit` rows **pass** (limit reproduced: no `_meta`, permissive skips exfil, tools/list unscanned) | We hide misses or claim profiles fix context starvation | Same brink JSON `by_kind.expected_limit` |
| G4 | AgentDojo | ASR base vs defended + utility; non-empty | Unrun adapter as “result” | adapter CLI smoke |
| G4b | Firewall stress (no LLM) | `adojo_stress` success rows pass; limits reproduced | Claim AgentDojo blocked without send_money rules | `python -m tracewall.eval.adojo_stress` / `pytest …test_adojo_stress` |
| G4c | DeepSeek follow-through | Live probes with `--system benchmark` + bill-preserving raise ASR above vanilla 0/0 when model complies | Treat refusal-as-defense as Tracewall win | `python -m tracewall.eval.adojo_stress --live` |
| G4d | Cross-domain robustness | `robustness_stress` success rows pass; limits reproduced | Banking-only story | `python -m tracewall.eval.robustness_stress` / pytest |
| G5 | Paper honesty | Tracewall draft matches EVIDENCE | WatchTower 17/17 / 0.011ms | Diff abstract vs EVIDENCE |
| G6 | Venue | G4+G5 done; PDF floats verified | Submit on stale PDF | tectonic + page inspect |

**Status snapshot (2026-07-19):** G0–G3 (+G3-fail) met; G4b + G4c slice met (`direct` ASR drop); G4d robustness 14/14; G5 PAPER/tex with ELI5+TL;DR. Venue polish + closing expected limits still open.

## P0 correctness (G1b) — named checks

1. `${ORG_DOMAIN}` expands from `TRACEWALL_ORG_DOMAINS` (comma-separated).
2. Exfil policy matches any secret-reader alias in call tree.
3. `require_identity=True` → missing identity BLOCKs (default False for transport degrade).
4. ALLOW → `on_clean_call`; BLOCK (policy/semantic) → `on_taint_event`.
5. `rate_exceeds` unsupported (warns; never silently “works”).
6. Verdict `score` is **0 bad … 1 clean** (semantic malicious score inverted at facade).

## Lanes

- **pytest** — scenarios / edges / regressions  
- **harness** — offline P/R/F1 only (not the scenario suite)  
- **AgentDojo** — live ASR/utility  

See [`TEST_PLAN.md`](TEST_PLAN.md).
