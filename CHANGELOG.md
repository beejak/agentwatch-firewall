# Changelog

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
