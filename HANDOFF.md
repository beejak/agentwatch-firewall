# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-07-19.**

## Where things stand

- Tracewall v1 core is shipped: enforcement pipeline, YAML policy pack, multi-hop
  taint ledger (live `check()` trust feedback), optional semantic tier, Python
  guard + **MCP stdio proxy with profiles** (paranoid / balanced / permissive).
- Observe-first discipline: [`docs/GOALS.md`](docs/GOALS.md),
  [`paper/EVIDENCE.md`](paper/EVIDENCE.md), [`docs/DETECTION.md`](docs/DETECTION.md).
- Paper draft: [`paper/PAPER.md`](paper/PAPER.md) rewritten as **Tracewall** from EVIDENCE (G5).
  `watchtower.tex` still stale IEEE port — do not submit as-is.
- Tests (this machine): **85+ passed**, 1 skipped (`test_llm_judge` needs `LLM_API_KEY`).
- CI: pytest + deterministic harness smoke + `mcp_brink`.
- Companion repo `agentwatch` = Paper 1 (observability). This repo = Paper 2 (enforcement).

## Done recently (do not re-do)

| Item | Evidence |
|------|----------|
| P0 live-path fixes (ORG_DOMAIN, secret-reader aliases, ledger feedback, score polarity, `require_identity`) | commits `0321698`+; `test_p0_correctness.py` |
| Default policy pack (paraphrases + egress + remote-exec) | held-out tier1 R=1.0 FPR=0; `corpus_v0.1_test_deterministic.json` |
| MCP profiles + brink (success **and** expected limits) | `mcp_brink.json` 14/14; `test_mcp_profiles.py` |
| AgentDojo firewall stress (`send_money` rules + bypass rows) | `adojo_stress.json` 7/7; `test_adojo_stress.py` |

## Still open

1. **AgentDojo live expand** — soft-block `direct` 1×4: ASR 1.0→0.0, util 1.0. More suites optional.
2. **Venue polish** — [`paper/tracewall.pdf`](paper/tracewall.pdf) thickened (arch figure, latency, soft-block). Still short of full venue polish (related work depth, camera-ready).
3. **MCP Content-Length** — shipped (auto-detect + tests). Further hardening optional.
4. Optional: LangGraph / HTTP sidecar; IBAN normalization / `schedule_transaction` rule.

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
python examples/guard_demo.py
python -m tracewall.transports.mcp_proxy --profile balanced -- <real-mcp-server-cmd>
```

AgentDojo (keyed machine):

```bash
pip install -e ".[dev,bench,llm]"
python -m tracewall.eval.adapters.agentdojo --suite banking --arm both
```

## Roadmap (priority)

1. AgentDojo ASR/utility (smoke one suite, then all) — append EVIDENCE.
2. Paper rewrite from EVIDENCE (Tracewall brand; drop 17-case / 0.011ms).
3. MCP framing / process hardening if adoption needs it.
4. Keep taint as research moat; don’t delete it to “simplify.”
5. Venue: IEEE S&P / USENIX when G4+G5 VERIFIED.

## Paper 2 reminder

- Brand: **tracewall**, enforcement-only.
- Evidence: held-out corpus + mcp_brink limits + AgentDojo when run.
- Never cite WatchTower draft numbers without checking EVIDENCE.

## Conventions

- Commits: no AI attribution. Author `beejak <beejak@users.noreply.github.com>`.
- Workflow: branch → PR → CI → merge when collaborating; one owner of `master`.
- Append [`LESSONS_LEARNED.md`](LESSONS_LEARNED.md) each session.
