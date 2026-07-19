# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-07-20.**

## Where things stand

- Tracewall v1 core is shipped: enforcement pipeline, YAML policy pack, multi-hop
  taint ledger (live `check()` trust feedback), optional semantic tier, Python
  guard + **MCP stdio proxy with profiles** (zta / paranoid / balanced / permissive).
- ZTA practicality: org allowlist default-deny pack, proxy-owned call trees,
  `require_caps`, match-level `rate_exceeds`, audit `rule_id`/`args_hash`.
- Observe-first discipline: [`docs/GOALS.md`](docs/GOALS.md),
  [`paper/EVIDENCE.md`](paper/EVIDENCE.md), [`docs/DETECTION.md`](docs/DETECTION.md).
- Paper draft: [`paper/PAPER.md`](paper/PAPER.md) / [`paper/tracewall.pdf`](paper/tracewall.pdf).
  `watchtower.tex` still stale — do not submit as-is.
- Tests: **105 passed** locally (1 skipped without `LLM_API_KEY` if run with llm).
- Companion repo `agentwatch` = Paper 1 (observability). This repo = Paper 2 (enforcement).

## Done recently (do not re-do)

| Item | Evidence |
|------|----------|
| P0 live-path fixes | `test_p0_correctness.py` |
| Default policy pack | held-out tier1 R=1.0 FPR=0 |
| MCP profiles + brink | `mcp_brink.json` |
| AgentDojo stress + soft-block + latency + CL framing | EVIDENCE |
| Cross-domain robustness | `robustness_stress.json` 14/14 |
| Paper ELI5/TL;DR | `paper/tracewall.tex` |
| **ZTA practicality** (allowlists, own call-tree, require_caps, rate_exceeds, zta profile) | `test_zta_practical.py`; brink zta rows; `rules/zta/` |

## Still open

1. **Signed workload identity** — ledger register ≠ IdP/SPIFFE continuous auth.
2. **LangGraph / HTTP sidecar PEP** — make bypass harder than skipping in-process guard.
3. **Close expected limits** — IBAN ZWSP normalize; case-insensitive tool aliases.
4. **Venue polish** — related work depth; camera-ready floats.
5. Expand allowlists beyond email/http (upload destinations, channels).

## LLM setup (env-only)

```bash
export LLM_API_KEY="<key>"
export LLM_BASE_URL="https://api.deepseek.com"   # default
export LLM_MODEL="<model id>"                    # default deepseek-chat
# TRACEWALL_SEMANTIC_LLM=0 disables LLM even if key present
# TRACEWALL_ORG_DOMAINS=acme.com,corp.com        # email allowlist
```

## Run it

```bash
py -3.12 -m venv .venv && .venv/Scripts/activate   # Windows; or python3.12 -m venv
pip install -e ".[dev]"
pytest -q
python -m tracewall.eval.harness --split test
python -m tracewall.eval.mcp_brink
python -m tracewall.eval.robustness_stress
python -m tracewall.eval.latency
python examples/guard_demo.py
python -m tracewall.transports.mcp_proxy --profile balanced -- <real-mcp-server-cmd>
```

AgentDojo (keyed machine):

```bash
pip install -e ".[dev,bench,llm]"
python -m tracewall.eval.adojo_stress --live
python -m tracewall.eval.adapters.agentdojo --suite banking --arm both
```

## Paper

- Evidence → [`paper/EVIDENCE.md`](paper/EVIDENCE.md) only; never invent metrics in LaTeX first.
- Build: `%TEMP%\tectonic-bin\tectonic.exe paper/tracewall.tex` (or `tectonic`).
- Inspect PDF for rivers / overlapping floats — do not trust exit code alone.

## Roadmap (priority)

1. Close expected limits (IBAN ZWSP normalize; tool-name aliases).
2. AgentDojo workspace/travel live slices — append EVIDENCE.
3. Venue polish (related work depth; camera-ready floats).
4. Keep taint as research moat; don’t delete it to “simplify.”
5. Org allowlists for production (vs attacker-IBAN probes).

## Paper 2 reminder

- Brand: **tracewall**, enforcement-only.
- Evidence: held-out corpus + mcp_brink limits + AgentDojo when run.
- Never cite WatchTower draft numbers without checking EVIDENCE.

## Conventions

- Commits: no AI attribution. Author `beejak <beejak@users.noreply.github.com>`.
- Workflow: branch → PR → CI → merge when collaborating; one owner of `master`.
- Append [`LESSONS_LEARNED.md`](LESSONS_LEARNED.md) each session.
