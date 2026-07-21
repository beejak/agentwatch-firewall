# Tooling (this repo)

## Cursor skills (project-local)

Under [`.cursor/skills/`](../.cursor/skills/):

- **tracewall-paper** — required before paper/metric edits (evidence → paper)
- **tracewall-zta** — allowlists, own call-tree, caps, profiles
- **Superpowers** copies: brainstorming, TDD, systematic-debugging, verification-before-completion, writing-plans, executing-plans, using-superpowers, dispatching-parallel-agents

May need a **new Cursor chat** for skills to appear.

## Operator entry points

- [`docs/GETTING_STARTED.md`](GETTING_STARTED.md)
- [`docs/INTEGRATION.md`](INTEGRATION.md) — put it on the tool-call path
- [`docs/RESULTS.md`](RESULTS.md)
- [`docs/RUNBOOK.md`](RUNBOOK.md)
- [`docs/ENTERPRISE.md`](ENTERPRISE.md)

## Goals / evidence

- [`docs/GOALS.md`](GOALS.md) — success/failure + named verify commands  
- [`docs/DETECTION.md`](DETECTION.md) — what algorithm fits the POC  
- [`paper/EVIDENCE.md`](../paper/EVIDENCE.md) — claim ledger  
- [`docs/TEST_PLAN.md`](TEST_PLAN.md) — scenarios; harness = metrics only  
- MCP brink: `python -m tracewall.eval.mcp_brink` → `eval/results/mcp_brink.json`

## Doc map

Full index: [`docs/README.md`](README.md). Architecture (incl. network/MCP): [`FIREWALL.md`](FIREWALL.md).

## Out of scope here

Graphify, Ruflo-as-product, gstack reinstall.
