# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes for continuing this repo on another machine. Last updated 2026-06-23.

## Where things stand

- `master` is clean and synced to `origin`. Tracewall standalone v1 is shipped:
  enforcement core, deterministic policy DSL, multi-hop taint solver, optional
  semantic tier, and two working transports (in-process Python guard + MCP stdio
  proxy).
- Test suite is green: `62 passed, 1 skipped` (skip = `test_llm_judge.py`, needs
  `LLM_API_KEY`). All committed tests are pure / infra-free.
- Companion repo `agentwatch` (Paper 1, observability) is the upstream library;
  this repo is Paper 2 (enforcement). One-directional dependency.

## Work in progress (the reason for this branch)

Two uncommitted artifacts were carried here on branch `wip/agentdojo-handoff`:

1. `tracewall/eval/adapters/agentdojo.py` — AgentDojo benchmark adapter, rewritten
   82→166 lines (async ledger binding, DeepSeek LLM backend, ASR + utility
   reporting). **STATUS: SCAFFOLD, NOT WORKING.** It has never run successfully.
   Known blockers (from review):
   - `agentdojo.py:65` — nested `run_until_complete()` inside the sync `query()`
     method crashes with "event loop is already running" on any real run.
   - `agentdojo.py:37` — same nested-loop crash when the setup loop is reused.
   - `:118-119` event loop never closed; `:131` temp dir leak; `:38` temp file fd
     leak; `:105` `os.environ["LLM_API_KEY"]` raw KeyError; `:147-148` `nargs="*"
     default=None` yields `[]` not `None` so the "use all tasks" path is dead.
   **Fix these before the adapter is used as the Paper 2 benchmark** — a broken
   benchmark is a retraction risk.
   - `[bench]` extra (AgentDojo) is likely not installed; install before running.

2. `tracewall/eval/results/corpus_v0.1_test_llm.json` — dated LLM-tier eval
   snapshot from `python -m tracewall.eval.harness --split test` (LLM backend on),
   generated 2026-06-16. Non-gating data (LLM runs never gate CI). Key finding:
   the **semantic/LLM tier carries the system** (recall 1.0, prec 1.0) while the
   deterministic tiers are weak on this corpus (tier0 recall 0.0, tier1 recall
   0.077). Integrated: recall 1.0 / prec 0.929 / FPR 0.071.

## LLM / DeepSeek v4 Pro setup (env-only, no code change)

The semantic tier and the AgentDojo adapter read the LLM from env vars
(`tracewall/semantic/judge.py`, `tracewall/eval/adapters/agentdojo.py`):

```bash
export LLM_API_KEY="<deepseek key>"
export LLM_BASE_URL="https://api.deepseek.com"   # default; override if needed
export LLM_MODEL="<deepseek v4 pro model id>"     # default is "deepseek-chat"
# TRACEWALL_SEMANTIC_LLM=0 disables the LLM tier even if a key is present
```

Set `LLM_MODEL` to the DeepSeek v4 Pro model string — that is the only change
needed to run the stronger model.

## Run it

```bash
source .venv/bin/activate            # or: python -m venv .venv && pip install -e ".[dev]"
pytest -q                            # 62 pass, 1 skip without a key
python -m tracewall.eval.harness --split test          # deterministic eval
python -m tracewall.eval.harness --split test --llm    # LLM-tier eval (needs key)
# benchmark adapter (after fixing the blockers above + pip install -e ".[bench,llm]"):
python -m tracewall.eval.adapters.agentdojo --suite banking --arm defended
```

## Open roadmap (priority order suggested below)

- Fix `agentdojo.py` event-loop blockers, then run the benchmark.
- Ship a curated **default policy pack** — deterministic tier currently catches
  ~1/13 attacks without an LLM, so "key-free by default" is security-empty today.
- Lead integration story with the **MCP proxy** (zero agent-code change); add 3
  config profiles (paranoid / balanced / permissive).
- Keep taint + semantic clearly opt-in (taint is the research differentiator —
  do not remove it to simplify; simplify the integration surface instead).
- One framework adapter at most (LangGraph), or defer all and lean on MCP proxy.
- HTTP sidecar transport; multi-agent contagion proof (Q2).
- Target venue: IEEE S&P / USENIX.

## Conventions

- Commits: no AI attribution, no Co-Authored-By. Author `beejak
  <beejak@users.noreply.github.com>`.
- Workflow: branch → PR → CI → merge; one owner of `master`.
- Update `agentwatch/LESSONS_LEARNED.md` each session (portable rules).
