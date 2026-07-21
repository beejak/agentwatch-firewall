# Support matrix

| Surface | Supported | Notes |
|---------|-----------|-------|
| Python | ≥ 3.12 | CI on 3.12 |
| In-process `guard` / `Firewall.check` | Yes | Soft-block via `on_block=` |
| LangGraph-style `GuardedToolNode` | Yes | No `langgraph` package required |
| MCP stdio proxy | Yes | Content-Length + NDJSON |
| MCP methods screened | `tools/call` | `tools/list` unscanned (limit) |
| Reference MCP app | Yes | `examples/reference_mcp_app/` |
| Profiles | zta, paranoid, balanced, permissive | Lab = balanced; prod = zta |
| Policy packs | `rules/` + `rules/zta/` | zta/paranoid load both |
| Config | Env + optional `TRACEWALL_CONFIG` YAML | |
| Audit | JSONL, stdout tee, OTel-shaped JSONL | Not OTLP/gRPC exporter |
| Metrics | In-process + HTTP `/metrics` | Prometheus text; no cluster agg |
| HTTP sidecar PEP | Roadmap | MCP proxy is the shipped PEP |
| Signed SPIFFE identity | No | Ledger register only |

OS: Linux / macOS / Windows (dev). Production assumption: Linux containers with proxy as sole MCP path.

**How to wire:** [`INTEGRATION.md`](INTEGRATION.md).
