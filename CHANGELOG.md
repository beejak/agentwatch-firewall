# Changelog

## 0.2.0 — 2026-07-21

### Added
- Operator docs: `docs/GETTING_STARTED.md`, `RESULTS.md`, `RUNBOOK.md`
- `SECURITY.md`, support matrix (`docs/SUPPORT.md`)
- ZTA practicality (0.1.x follow-on): allowlist pack, proxy-owned call trees, `require_caps`, `rate_exceeds`
- Arg NFKC/ZWSP normalize + canonical tool names (closes IBAN ZWSP + case aliases)
- Soft-block product contract: `guard(..., on_block="soft")` → `SoftBlockResult`
- Ops: `python -m tracewall.ops.explain|health|reload`, YAML `TRACEWALL_CONFIG`
- In-process metrics (`Firewall.metrics`), `StdoutAuditSink` / `TeeAuditSink`
- Examples: `examples/zta_demo.py`, `examples/reference_mcp.py`

### Changed
- Profiles: `zta` added; lab `balanced` keeps non-ZTA pack for regression stability
- AgentDojo stress: former ZWSP/case limits promoted to success blocks

## 0.1.0

Initial Tracewall package: firewall core, YAML policy, MCP proxy, eval harness, brink, paper draft.
