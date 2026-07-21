# Support matrix

| Surface | Supported | Notes |
|---------|-----------|-------|
| Python | ≥ 3.12 | CI on 3.12 |
| In-process `guard` / `Firewall.check` | Yes | Soft-block via `on_block=` |
| MCP stdio proxy | Yes | Content-Length + NDJSON |
| MCP methods screened | `tools/call` | `tools/list` unscanned (limit) |
| Profiles | zta, paranoid, balanced, permissive | Lab = balanced; prod = zta |
| Policy packs | `rules/` + `rules/zta/` | zta/paranoid load both |
| Config | Env + optional `TRACEWALL_CONFIG` YAML | |
| Audit | JSONL, stdout tee | Not OTel exporter yet |
| Metrics | In-process snapshot | No HTTP `/metrics` yet |
| LangGraph / HTTP sidecar | Roadmap | Pattern only in docs/examples |
| Signed SPIFFE identity | No | Ledger register only |

OS: Linux / macOS / Windows (dev). Production assumption: Linux containers with proxy as sole MCP path.
