# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-10-21** (docs/tooling sync; **no E1–E6 coding**; awaiting Final Gate A–E).

## Track

- **Product features (v0.2.0 paper claim set): FROZEN** — arXiv numbers stay evidence-backed; no claim inflation.
- **Next capability wave: PLANNED, NOT STARTED** — core enhancement + test plan drafted; **do not implement** until human confirms premises and picks Final Gate A–E.
- **Paper: camera-ready / arXiv submit track** — see [`paper/SUBMIT.md`](paper/SUBMIT.md), [`paper/PAPER.md`](paper/PAPER.md), [`paper/tracewall.tex`](paper/tracewall.tex). Prefer the [v0.2.0 release PDF](https://github.com/beejak/agentwatch-firewall/releases/download/v0.2.0/tracewall.pdf) if GitHub’s blob preview fails ([`paper/README.md`](paper/README.md)).
- Evidence only from [`paper/EVIDENCE.md`](paper/EVIDENCE.md) + committed `tracewall/eval/results/` (not local `adojo_diag/` / `adojo_stress_live/` dumps). Do **not** upload stale [`paper/watchtower.tex`](paper/watchtower.tex).

## Product truth (non-negotiable)

Tracewall is a **tool-call PEP**: `await Firewall.check(event) → FirewallVerdict` (ALLOW/BLOCK). Companion to agentwatch observability.

| Is | Is not |
|----|--------|
| Gate screened tool calls (`guard` / `mcp_proxy` / `GuardedToolNode`) | Chat-stream prompt scanner / jailbreak neutralizer |
| Soft-block can preserve utility while blocking attack tools | OS/kernel sandbox or on-disk FS scanner |
| Lab = `balanced`; prod = `zta` / `paranoid` | Full NIST ZTA / SPIFFE-as-shipped |
| AgentDojo evidence = **banking slice** only | Full AgentDojo (workspace/travel/…) |
| Robustness **18/18**; latency ≈6.4 ms mean / ≈9.8 ms p99 | WatchTower 17/17 or 0.011 ms-vs-Sentinel claims |

## Where things stand (2026-10-21)

- Tracewall **0.2.0**: enforcement core + MCP proxy + profiles zta/paranoid/balanced/permissive.
- **CI green:** AgentDojo soft-block test uses `importorskip` when `[bench]` absent ([`320ee56`](https://github.com/beejak/agentwatch-firewall/commit/320ee56)); pytest collection succeeds without AgentDojo.
- Tracewall Cursor skills (project knowledge — update when PEP story changes):
  - [`.cursor/skills/tracewall-zta/SKILL.md`](.cursor/skills/tracewall-zta/SKILL.md) — PEP identity, profiles, blast radius, repo map
  - [`.cursor/skills/tracewall-paper/SKILL.md`](.cursor/skills/tracewall-paper/SKILL.md) — evidence→paper, safe numbers, fraud table
  - Other `.cursor/skills/*` Superpowers copies are **process**, not product truth.
  - Optional process packs: [`.agents/skills/`](.agents/skills/) (mattpocock), user-global caveman skills — see [`docs/TOOLING.md`](docs/TOOLING.md).
- Operator docs: `GETTING_STARTED` / **`INTEGRATION`** / `RESULTS` / `RUNBOOK` / `ENTERPRISE` / `SUPPORT` / `ARCHITECTURE_OVERVIEW`.
- Paper claims aligned: held-out regression bar, soft-block AgentDojo banking slice, robustness **18/18**, latency microbench, scope footnote, author **beejak**.

## Planning artifacts (awaiting human gate — NOT merged into code)

| Artifact | Role |
|----------|------|
| [`docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md) | Autoplan: premises P1–P5, bets E1–E11, test tranches — **AWAITING FINAL APPROVAL GATE** |
| [`docs/plans/2026-10-21-tracewall-karpathy-review.md`](docs/plans/2026-10-21-tracewall-karpathy-review.md) | **Separate** Karpathy lens review — **do not merge** into the autoplan file |
| [`TODOS.md`](TODOS.md) | Deferred items (HTTP/SSE, HITL, SPIFFE, OTLP, …) |

**Karpathy review recommendation (not assumed):** delay **E4** until measured need; demote **E5/E6** off P1; narrow P0 tests to **E1/E2** (unknown-tool deny + MCP `tools/list` filter) + eval row promotions — not coverage-count theater. Prefer Final Gate **B** (Karpathy overrides) unless you choose otherwise.

**Coding status:** Tracewall core bets **E1–E6 not started**. Final Gate **A–E not executed**.

### Paper prep next (no new fake evidence)

1. Keep SUBMIT checklist current; author **beejak**; PDF via [release download](https://github.com/beejak/agentwatch-firewall/releases/download/v0.2.0/tracewall.pdf).
2. Scope/non-claims stay aligned with EVIDENCE (banking soft-block, 18/18, latency, PEP ≠ chat/OS/SPIFFE).
3. Rebuild PDF only if `tracewall.tex` changes and tectonic is available.
4. After arXiv ID lands: record in this file + `paper/PAPER.md`.
5. Post-gate implementation → new eval JSON → EVIDENCE row → only then paper numbers.

## Still open (post-submit / non-blocking for arXiv)

1. **Signed identity** — still ledger register (no SPIFFE / IdP verifier).
2. **SBOM** — not generated in CI yet.
3. **Full OTLP/gRPC exporter** — JSONL bridge only; document limits.
4. **Optional AgentDojo expand** — other environments; **not required** while paper claims frozen.
5. **Unknown tool names** — still `expected_limit`; `tools/list` unscanned → planned as **E1/E2** after gate.
6. **Venue submission** after arXiv (S&P / USENIX / CCS) — separate from freeze.
7. **Human Final Gate A–E** — required before any E1–E6 implementation.

## Done recently

| Item | Evidence |
|------|----------|
| CI AgentDojo importorskip | `320ee56`; soft-block skipped without `[bench]` |
| Skills expanded (paper + zta playbooks) | `.cursor/skills/tracewall-*` |
| PDF binary + release download pointers | `5fcbf0f` / `9da591b` |
| Core enhancement + Karpathy plans (docs only) | `docs/plans/2026-10-21-*.md` |
| Paper camera-ready + SUBMIT checklist | `paper/tracewall.tex`, `paper/SUBMIT.md` |
| Operator docs pack + INTEGRATION | `docs/GETTING_STARTED.md`, `docs/INTEGRATION.md` |
| Soft-block + explain/health/reload | `python_guard.SoftBlockResult`; `tracewall.ops.*` |
| SECURITY + CHANGELOG + Dependabot | repo root / `.github/` |

## Agent tooling (user-local; see TOOLING.md)

Installed/configured for **docs/paper/context** work (not product features). Details: [`docs/TOOLING.md`](docs/TOOLING.md) and [`docs/SUPPORT.md`](docs/SUPPORT.md).

| Tool | Role |
|------|------|
| caveman / cavemem | Token-lean replies; frozen memory (core also in caveman) |
| claude-mem | Persistent session memory (Cursor/Claude; Bun dep note on Windows) |
| obra/superpowers | Process skills (already under `.cursor/skills/`) |
| open-gsd/gsd-core | Successor to archived `get-shit-done` |
| mattpocock/skills | Engineering skills under `.agents/skills/` |
| ruflo | Optional agent harness (`npx ruflo`) |
| graphify | Codebase → knowledge graph (`pip install graphifyy`) |

## Run it

```bash
pip install -e ".[dev]"
pytest -q
python examples/zta_demo.py
python examples/reference_mcp_app/run_pep_demo.py
python examples/langgraph_tool_node_demo.py
python -m tracewall.ops.health --profile zta
python -m tracewall.ops.http_metrics --port 9100 --profile zta
python -m tracewall.ops.explain --profile zta --tool send_email --args '{"to":"x@evil.com","body":"hi"}'
python -m tracewall.transports.mcp_proxy --profile zta -- <mcp-server>
```

See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) and
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).
