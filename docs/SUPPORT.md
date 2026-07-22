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
| Chat-stream prompt-injection scanner | No | Tool-call PEP; tier-0 is tool-arg noisy prior, never sole BLOCK |
| OS sandbox / kernel / on-disk FS scan | No | Pair with a real sandbox; see [`SECURITY.md`](../SECURITY.md) |
| Full AgentDojo (all suites) | No | Banking slice measured only |

OS: Linux / macOS / Windows (dev). Production assumption: Linux containers with proxy as sole MCP path.

**How to wire:** [`INTEGRATION.md`](INTEGRATION.md). Threat model: [`../SECURITY.md`](../SECURITY.md).
