# Changelog

## Unreleased

### Docs / planning (2026-10-21)

- Synced human-facing docs + Tracewall skills with current state: paper claim freeze,
  release PDF download, CI green via AgentDojo `importorskip` (`320ee56`), soft-block /
  banking-slice / robustness **18/18** / latency honesty.
- Added planning deliverables (no product coding):
  [`docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md),
  [`docs/plans/2026-10-21-tracewall-karpathy-review.md`](docs/plans/2026-10-21-tracewall-karpathy-review.md)
  (Karpathy lens kept **separate**), [`TODOS.md`](TODOS.md).
- Documented user-local agent tooling (caveman, cavemem, claude-mem, superpowers,
  open-gsd/gsd-core successor, mattpocock skills, ruflo, graphify) in
  [`docs/TOOLING.md`](docs/TOOLING.md) / [`HANDOFF.md`](HANDOFF.md).
- **Awaiting human Final Gate A–E** before E1–E6 implementation (coding not started).

## 0.2.0 — 2026-07-21

### Added
- Operator docs: `docs/GETTING_STARTED.md`, `RESULTS.md`, `RUNBOOK.md`, `ENTERPRISE.md`, `SUPPORT.md`
- `docs/INTEGRATION.md` — how to put Tracewall on the tool-call path (guard / MCP proxy / GuardedToolNode)
- `docs/ARCHITECTURE_OVERVIEW.md` — pipeline diagrams, test inventory, QA gaps
- `SECURITY.md`, support matrix (`docs/SUPPORT.md`)
- ZTA practicality (0.1.x follow-on): allowlist pack, proxy-owned call trees, `require_caps`, `rate_exceeds`
- Arg NFKC/ZWSP normalize + canonical tool names (closes IBAN ZWSP + case aliases)
- Soft-block product contract: `guard(..., on_block="soft")` → `SoftBlockResult`
- Ops: `python -m tracewall.ops.explain|health|reload`, YAML `TRACEWALL_CONFIG`
- In-process metrics (`Firewall.metrics`) + HTTP scrape `python -m tracewall.ops.http_metrics` (`/metrics`, `/health`)
- OTel-shaped audit JSONL (`OTelJsonlAuditSink` / `audit.format: otel`) — not OTLP/gRPC
- Reference MCP PEP app: `examples/reference_mcp_app/`
- LangGraph-style tool node: `GuardedToolNode` + `examples/langgraph_tool_node_demo.py` (no langgraph dep)
- Examples: `examples/zta_demo.py`, `examples/reference_mcp.py`

### Changed
- Profiles: `zta` added; lab `balanced` keeps non-ZTA pack for regression stability
- AgentDojo / robustness stress: former ZWSP/case limits promoted to success blocks
- Robustness matrix expanded (ZWSP, caps-empty, unknown-tool limits) — **18/18**
- Root README refreshed for visitor path (INTEGRATION + v0.2.0 status)

## 0.1.0

Initial Tracewall package: firewall core, YAML policy, MCP proxy, eval harness, brink, paper draft.
