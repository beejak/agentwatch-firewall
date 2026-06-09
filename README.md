# agentwatch-firewall

Agent firewall — the **enforcement** layer for AI agents: hook-level interception,
identity/delegation checks, a deterministic policy DSL, cross-session taint
propagation, and a semantic detection tier. It exists to keep agents **contained**
(no interference from the outside environment) by deciding ALLOW / BLOCK / HOLD on
every tool call and cross-agent message.

## Relationship to watchtower

This repo **depends on** [`watchtower`](https://github.com/beejak/agentwatch) (the
mature observability platform) as a library — for the canonical signal model and
the append-only Chronicle, and as a stable test harness. The dependency is
**one-directional**: firewall → watchtower. watchtower never imports firewall.

```
runtime:   agent tool call → [firewall: intercept + enforce] → [watchtower: observe + audit]
code dep:   firewall  ──imports──▶  watchtower   (pinned by tag for reproducibility)
```

Splitting the firewall into its own repo lets it iterate quickly against a frozen,
mature watchtower without churning the observability codebase.

## Layout
- `firewall/` — core signal model, the watchtower↔firewall chronicle bridge, semantic judge
- `agents/adapters/` — hermes (hooks), cavemem (taint ledger), superpowers (policy DSL), graphify, ruflo, …
- `policies/` — YAML policy rules (injection, exfil, destructive ops)
- `eval/` — frozen corpus + ablation harness (see `eval/README.md`)
- `tests/` — `known_bad/` (KB corpus), `integration/` (seam + e2e), `eval/`

## Develop
```bash
make install          # creates .venv, installs this + watchtower (pinned tag)
make infra-up         # ClickHouse (needed by integration tests)
make test             # deterministic, key-free
make eval             # held-out evaluation metrics
```
The semantic tier uses a deterministic structural backend by default; set
`LLM_API_KEY` (and unset `WT_SEMANTIC_LLM=0`) to exercise the LLM classifier.

## Status
Active development. `graphify` (call-tree enrichment) and `ruflo` (swarm) are
maturing; the semantic tier and taint ledger are functional. See `eval/README.md`
for honest, held-out metrics and their caveats.
