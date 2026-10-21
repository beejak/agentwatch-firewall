# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-10-21** (v0.3.0: Gate B E1/E2 + E4).

## Track

- **Product features (v0.2.0 paper claim set): FROZEN** — arXiv numbers stay evidence-backed; no claim inflation.
- **Gate B P0: DONE** — E1 unknown-tool deny + E2 `tools/list` filter on `zta`/`paranoid`.
- **E4: SHIPPED (optional)** — `session_ratchet` on `zta`/`paranoid`, off on `balanced`. Soft-block live re-measure **blocked** (no API key); firewall-only adojo **7/7**. See [`docs/RESULTS.md`](docs/RESULTS.md).
- **Release:** [v0.3.0](https://github.com/beejak/agentwatch-firewall/releases/tag/v0.3.0). Paper PDF still the freeze asset ([v0.2.0 PDF](https://github.com/beejak/agentwatch-firewall/releases/download/v0.2.0/tracewall.pdf) also uploaded on v0.3.0 if present).
- Evidence only from [`paper/EVIDENCE.md`](paper/EVIDENCE.md) + committed `tracewall/eval/results/` (not local `adojo_diag/` / `adojo_stress_live/` dumps). Do **not** upload stale [`paper/watchtower.tex`](paper/watchtower.tex).

## Decision log (2026-10-21)

| Item | Locked |
|------|--------|
| Premises P1–P5 | ACCEPTED |
| Gate | **B** with Karpathy overrides |
| P0 | **E1** + **E2** shipped |
| Soft-block re-measure | Firewall-only **7/7**; live **blocked** (no `LLM_API_KEY`) — no invented ASR |
| E4 | **Shipped optional** (prod on / lab off) — not claimed as “soft-block failed” |
| E5 / E6 | DEMOTED |
| Paper | FROZEN |

## Product truth (non-negotiable)

Tracewall is a **tool-call PEP**: `await Firewall.check(event) → FirewallVerdict` (ALLOW/BLOCK). Companion to agentwatch observability.

| Is | Is not |
|----|--------|
| Gate screened tool calls (`guard` / `mcp_proxy` / `GuardedToolNode`) | Chat-stream prompt scanner / jailbreak neutralizer |
| Soft-block can preserve utility while blocking attack tools | OS/kernel sandbox or on-disk FS scanner |
| Lab = `balanced`; prod = `zta` / `paranoid` | Full NIST ZTA / SPIFFE-as-shipped |
| AgentDojo evidence = **banking slice** only | Full AgentDojo (workspace/travel/…) |
| Robustness **18/18** + latency ≈6.4 ms / p99 ≈9.8 ms *(paper freeze)*; HEAD matrix **19/19** / brink **21/21** (not paper) | WatchTower 17/17 or 0.011 ms-vs-Sentinel claims |

## Where things stand (2026-10-21)

- Tracewall **0.3.0**: enforcement core + MCP proxy + profiles + E1/E2/E4.
- **CI green:** AgentDojo soft-block test uses `importorskip` when `[bench]` absent ([`320ee56`](https://github.com/beejak/agentwatch-firewall/commit/320ee56)). CI runs `pytest` + harness + `mcp_brink` only — **not** `robustness_stress` / AgentDojo live.
- **Current** verify: pytest **153**+2 skip; brink **21/21**; robustness **19/19**. Paper freeze quotes stay **18/18** — see [`docs/RESULTS.md`](docs/RESULTS.md), [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)#test-parameters.
- DevSecOps: [`docs/DEVSECOPS.md`](docs/DEVSECOPS.md) — build blocker = policy/deploy gate, not SAST-on-compile.
- Tracewall Cursor skills:
  - [`.cursor/skills/tracewall-zta/SKILL.md`](.cursor/skills/tracewall-zta/SKILL.md)
  - [`.cursor/skills/tracewall-paper/SKILL.md`](.cursor/skills/tracewall-paper/SKILL.md)
- Operator docs: `GETTING_STARTED` / **`INTEGRATION`** / `RESULTS` / `RUNBOOK` / `ENTERPRISE` / `DEVSECOPS` / `SUPPORT` / `ARCHITECTURE_OVERVIEW`.

## Planning artifacts

| Artifact | Role |
|----------|------|
| [`docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md) | Autoplan — Gate B + E4 shipped |
| [`docs/plans/2026-10-21-tracewall-karpathy-review.md`](docs/plans/2026-10-21-tracewall-karpathy-review.md) | **Separate** review — do not merge into autoplan |
| [`TODOS.md`](TODOS.md) | Deferred (E5/E6, HTTP/SSE, HITL, SPIFFE, …) |

## Paper candidates path

Freeze stays in [`paper/EVIDENCE.md`](paper/EVIDENCE.md). Future revision candidates
(E1/E2/E4, 19/19, 21/21, firewall-only 7/7, live ASR TBD): same file §Paper candidates.
Cost / how to re-run live: [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)#live-eval-cost-rough-usd.
Submit: [`paper/SUBMIT.md`](paper/SUBMIT.md).

## Still open (post-submit / non-blocking for arXiv)

1. **Signed identity** — still ledger register (no SPIFFE / IdP verifier).
2. **SBOM** — not generated in CI yet.
3. **Full OTLP/gRPC exporter** — JSONL bridge only.
4. **Optional AgentDojo expand** — other environments; not required while paper claims frozen.
5. **Live soft-block re-measure** when `LLM_API_KEY` + `.[bench]` available (~$0.05–$10 for `direct` 1×4 depending on provider).
6. **E5/E6 demoted** — see TODOS.
7. **Venue submission** after arXiv — separate from freeze.

## Done recently

| Item | Evidence |
|------|----------|
| v0.3.0: E1+E2+E4 + DEVSECOPS | release + CHANGELOG |
| Soft-block firewall-only reconfirm | RESULTS (live blocked) |
| Gate B E1/E2 shipped | `deny_unknown_tools`, `filter_tools_list` |
| CI AgentDojo importorskip | `320ee56` |
| Paper camera-ready + SUBMIT | `paper/` |

## Agent tooling (user-local; see TOOLING.md)

Details: [`docs/TOOLING.md`](docs/TOOLING.md). caveman/cavemem, claude-mem, superpowers, open-gsd, mattpocock skills, ruflo, graphify — process only; never override Tracewall product truth.

## Run it

```bash
pip install -e ".[dev]"
pytest -q
python examples/zta_demo.py
python -m tracewall.ops.explain --profile zta --tool send_email --args '{"to":"x@evil.com","body":"hi"}'
python -m tracewall.transports.mcp_proxy --profile zta -- <mcp-server>
```

See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) and [`docs/INTEGRATION.md`](docs/INTEGRATION.md).
