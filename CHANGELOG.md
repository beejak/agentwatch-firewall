# Changelog

## 0.3.0 — 2026-10-21

### Added

- **E1 — default-deny unknown tools** on profiles `zta` / `paranoid`
  (`deny_unknown_tools`; allowlist = `caps ∪` YAML-declared tools). Lab
  `balanced` unchanged (pack-only). Robustness: `S-block-unknown-tool-deny`
  success; balanced pack-miss stays `expected_limit`.
- **E2 — optional MCP `tools/list` filter** on `zta` / `paranoid` (response
  filter; request still forwards). CLI: `--filter-tools-list` /
  `--no-filter-tools-list` / `--tools-allowlist`. `balanced` pass-through.
- **E4 — session progressive containment** (`session_ratchet`): after a
  screened BLOCK, elevate the session key; subsequent egress-sensitive tools
  BLOCK with `rule_id=session_ratchet`. **On** for `zta`/`paranoid`; **off** for
  `balanced`/`permissive`. CLI: `--session-ratchet` / `--no-session-ratchet`.
  New session_id clears posture. Soft-block / MCP `isError` control flow unchanged.
- **DevSecOps guide:** [`docs/DEVSECOPS.md`](docs/DEVSECOPS.md) — build-blocker
  honesty, CI/deploy gates, threat landscape vs SAST/SCA.

### Docs / measurement (2026-10-21)

- Soft-block banking: firewall-only `adojo_stress` **7/7** reconfirmed; **live**
  AgentDojo re-measure **blocked** (no `LLM_API_KEY`) — no invented ASR.
  Paper freeze soft-block quotes unchanged in [`paper/EVIDENCE.md`](paper/EVIDENCE.md).
- Results / test-plan: **current** matrix (robustness **19/19**, brink **21/21**)
  distinct from **paper freeze** robustness **18/18**; live eval **$** ranges +
  TDD seams in [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).
- Paper **candidates** section (E1/E2/E4, 19/19, 21/21, 7/7, live ASR TBD) in
  EVIDENCE — not freeze headlines.
- Gate B + E4 documented across README / SECURITY / INTEGRATION / RUNBOOK /
  HANDOFF / skills / operator docs.

### Test matrix (current vs paper)

| | Paper freeze (quote in paper) | Current (v0.3.0 HEAD) |
|--|-------------------------------|------------------------|
| Robustness | **18/18** | **19/19** |
| Brink | freeze-era | **21/21** |
| Soft-block live banking `direct` | ASR 1.0→0.0 util 1.0→1.0 | Not re-measured this release |
| E1 / E2 / E4 | n/a (post-freeze) | Shipped |

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
