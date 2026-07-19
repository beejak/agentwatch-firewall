# Tracewall goals (FABLE / measure-first)

Evidence flows **repo → paper**. A goal without a named verification is a wish.

## Product placement

Library + MCP proxy that ALLOW/BLOCKs tool calls. Not a SaaS gateway, HITL approve box, or CaMeL-style IFC redesign.

| Use site | Status |
|----------|--------|
| Python `Firewall.check` / `guard` | Shipped |
| MCP stdio proxy | Shipped (NDJSON; framing gaps known) |
| LangGraph / HTTP sidecar | Roadmap |

## Goals + success / failure

| ID | Goal | Success (observed) | Failure | Verify |
|----|------|--------------------|---------|--------|
| G0 | Tooling | Superpowers + `tracewall-paper` skill; this file exists | Skills missing | Skills load in Cursor |
| G1 | Evidence ledger | [`paper/EVIDENCE.md`](../paper/EVIDENCE.md) rows for load-bearing claims | Abstract claim with no row | Open EVIDENCE |
| G1b | Live-path correctness | P0 bugs fixed + pytest green | Silent no-op security rules | `pytest -q` + tests below |
| G2 | Key-free security | Deterministic integrated recall **> 0.462** on held-out; FPR justified | Still ~1/13 tier1 + “secure by default” marketing | `python -m tracewall.eval.harness --split test` |
| G3 | MCP productization | Profiles + fail_closed CLI + tests | Prose-only profiles | pytest + docs |
| G4 | AgentDojo | ASR base vs defended + utility; non-empty | Unrun adapter as “result” | adapter CLI smoke |
| G5 | Paper honesty | Tracewall draft matches EVIDENCE | WatchTower 17/17 / 0.011ms | Diff abstract vs EVIDENCE |
| G6 | Venue | G4+G5 done; PDF floats verified | Submit on stale PDF | tectonic + page inspect |

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
