# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-10-21** (Gate **B**: E1/E2 **shipped**).

## Track

- **Product features (v0.2.0 paper claim set): FROZEN** — arXiv numbers stay evidence-backed; no claim inflation.
- **Gate B P0: DONE** — E1 unknown-tool deny + E2 `tools/list` filter on `zta`/`paranoid`. E4 delayed; E5/E6 demoted.
- **Paper: camera-ready / arXiv submit track** — see [`paper/SUBMIT.md`](paper/SUBMIT.md), [`paper/PAPER.md`](paper/PAPER.md), [`paper/tracewall.tex`](paper/tracewall.tex). Prefer the [v0.2.0 release PDF](https://github.com/beejak/agentwatch-firewall/releases/download/v0.2.0/tracewall.pdf) if GitHub’s blob preview fails ([`paper/README.md`](paper/README.md)).
- Evidence only from [`paper/EVIDENCE.md`](paper/EVIDENCE.md) + committed `tracewall/eval/results/` (not local `adojo_diag/` / `adojo_stress_live/` dumps). Do **not** upload stale [`paper/watchtower.tex`](paper/watchtower.tex).

## Decision log (Final Gate B — 2026-10-21)

| Item | Locked |
|------|--------|
| Premises P1–P5 | ACCEPTED |
| Gate | **B** with Karpathy overrides |
| P0 | **E1** default-deny unknown tools (`zta`/`paranoid`) + **E2** optional MCP `tools/list` filter |
| E3 | Prove E1/E2 + fail-safe polarity — not coverage vanity |
| E4 | DELAYED |
| E5 / E6 | DEMOTED |
| Success | `expected_limit`→`success` eval rows / real behavior |
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

- Tracewall **0.2.0**: enforcement core + MCP proxy + profiles zta/paranoid/balanced/permissive.
- **CI green:** AgentDojo soft-block test uses `importorskip` when `[bench]` absent ([`320ee56`](https://github.com/beejak/agentwatch-firewall/commit/320ee56)). CI runs `pytest` + harness + `mcp_brink` only — **not** `robustness_stress` / AgentDojo live.
- Gate B P0 shipped (E1+E2). **Current** verify: pytest **148**+2 skip; brink **21/21**; robustness **19/19**. Paper freeze quotes stay **18/18** — see [`docs/RESULTS.md`](docs/RESULTS.md), [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)#test-parameters.
- Tracewall Cursor skills:
  - [`.cursor/skills/tracewall-zta/SKILL.md`](.cursor/skills/tracewall-zta/SKILL.md)
  - [`.cursor/skills/tracewall-paper/SKILL.md`](.cursor/skills/tracewall-paper/SKILL.md)
- Operator docs: `GETTING_STARTED` / **`INTEGRATION`** / `RESULTS` / `RUNBOOK` / `ENTERPRISE` / `SUPPORT` / `ARCHITECTURE_OVERVIEW`.

## Planning artifacts

| Artifact | Role |
|----------|------|
| [`docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md) | Autoplan — **Gate B approved** (Karpathy overrides) |
| [`docs/plans/2026-10-21-tracewall-karpathy-review.md`](docs/plans/2026-10-21-tracewall-karpathy-review.md) | **Separate** review — do not merge into autoplan |
| [`TODOS.md`](TODOS.md) | Deferred (E4–E6, HTTP/SSE, HITL, SPIFFE, …) |

## Still open (post-submit / non-blocking for arXiv)

1. **Signed identity** — still ledger register (no SPIFFE / IdP verifier).
2. **SBOM** — not generated in CI yet.
3. **Full OTLP/gRPC exporter** — JSONL bridge only.
4. **Optional AgentDojo expand** — other environments; not required while paper claims frozen.
5. **E4 delayed; E5/E6 demoted** — see TODOS (soft-block measurement before E4).
6. **Venue submission** after arXiv — separate from freeze.

## Done recently

| Item | Evidence |
|------|----------|
| Gate B E1/E2 shipped | `deny_unknown_tools`, `filter_tools_list`; tests + brink/robustness |
| Gate B locked (P1–P5 + Karpathy overrides) | plans + this file |
| CI AgentDojo importorskip | `320ee56` |
| Skills expanded (paper + zta) | `.cursor/skills/tracewall-*` |
| Core enhancement + Karpathy plans | `docs/plans/2026-10-21-*.md` |
| Paper camera-ready + SUBMIT | `paper/` |
| Soft-block + explain/health/reload | `python_guard`; `tracewall.ops.*` |

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
