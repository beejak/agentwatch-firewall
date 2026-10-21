# Support matrix

| Surface | Supported | Notes |
|---------|-----------|-------|
| Python | ≥ 3.12 | CI on 3.12 |
| In-process `guard` / `Firewall.check` | Yes | Soft-block via `on_block=` |
| LangGraph-style `GuardedToolNode` | Yes | No `langgraph` package required |
| MCP stdio proxy | Yes | Content-Length + NDJSON |
| MCP methods screened | `tools/call` | `tools/list` response filter on zta/paranoid |
| Reference MCP app | Yes | `examples/reference_mcp_app/` |
| Profiles | zta, paranoid, balanced, permissive | Lab = balanced; prod = zta |
| Policy packs | `rules/` + `rules/zta/` | zta/paranoid load both |
| Config | Env + optional `TRACEWALL_CONFIG` YAML | |
| Audit | JSONL, stdout tee, OTel-shaped JSONL | Not OTLP/gRPC exporter |
| Metrics | In-process + HTTP `/metrics` | Prometheus text; no cluster agg |
| HTTP sidecar PEP | Roadmap | MCP proxy is the shipped PEP |
| Signed SPIFFE identity | No | Ledger register only |
| Chat-stream prompt-injection scanner | No | Tool-call PEP; tier-0 is tool-arg noisy prior, never sole BLOCK |
| OS sandbox / kernel / on-disk FS scan | No | Pair with a real sandbox; see [`SECURITY.md`](../SECURITY.md) |
| Full AgentDojo (all suites) | No | Banking slice measured only |

OS: Linux / macOS / Windows (dev). Production assumption: Linux containers with proxy as sole MCP path.

**CI (2026-10):** pytest + harness + mcp_brink on ubuntu; AgentDojo soft-block
test **skipped** when `[bench]` / agentdojo absent (`importorskip`) so collection
stays green — commit `320ee56`.

**v0.3.0 (2026-10-21):** E1 unknown-tool deny + E2 `tools/list` filter + E4
`session_ratchet` shipped on `zta`/`paranoid` (lab `balanced` off for E1/E2/E4).
Deferred: E5/E6, live soft-block re-measure (needs `LLM_API_KEY`) — see
[`../HANDOFF.md`](../HANDOFF.md), [`TEST_PLAN.md`](TEST_PLAN.md).

### Agent tooling (dev machine; not product)

See [`TOOLING.md`](TOOLING.md) for install/invoke of caveman, cavemem, claude-mem,
superpowers, open-gsd/gsd-core, mattpocock skills, ruflo, graphify. These assist
docs/paper context only — they are **not** Tracewall security controls.

**How to wire:** [`INTEGRATION.md`](INTEGRATION.md). Threat model: [`../SECURITY.md`](../SECURITY.md).
