# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-07-21 (v0.2.0 + integration docs).**

## Where things stand

- Tracewall **0.2.0**: enforcement core + MCP proxy + zta/paranoid/balanced/permissive.
- Operator docs: `GETTING_STARTED` / **`INTEGRATION`** / `RESULTS` / `RUNBOOK` / `ENTERPRISE` / `SUPPORT` / `ARCHITECTURE_OVERVIEW`.
- **Put Tracewall on the tool-call path:** [`docs/INTEGRATION.md`](docs/INTEGRATION.md) (Python `guard`, MCP `mcp_proxy` as sole path, `GuardedToolNode`).
- Bypass closes: ZWSP/NFKC args + canonical tool names.
- Ops: explain dry-run, health, reload, in-process + HTTP `/metrics`, OTel-shaped audit JSONL.
- Soft-block product contract on `guard(on_block="soft")`.
- Reference MCP PEP app + LangGraph-style `GuardedToolNode` (no langgraph dep).
- Enterprise checklist: [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md).

## Still open (priority)

1. **Signed identity** — still ledger register (no SPIFFE / IdP verifier).
2. **SBOM** — not generated in CI yet.
3. **Full OTLP/gRPC exporter** — JSONL bridge only; document limits.
4. **Venue polish** — paper camera-ready.
5. **Unknown tool names** — still expected_limit (pack gap); `tools/list` unscanned.

## Done recently

| Item | Evidence |
|------|----------|
| Operator docs pack + INTEGRATION | `docs/GETTING_STARTED.md`, `docs/INTEGRATION.md` |
| Architecture overview | `docs/ARCHITECTURE_OVERVIEW.md` |
| ZTA practicality | `rules/zta/`, own call-tree, `require_caps` |
| Bypass closes (ZWSP, tool case) | `policy/normalize.py`; adojo/robustness success rows |
| Soft-block + explain/health/reload | `python_guard.SoftBlockResult`; `tracewall.ops.*` |
| HTTP `/metrics` + OTel JSONL audit | `ops/http_metrics.py`; `audit.sink.OTelJsonlAuditSink` |
| MCP reference PEP + tool-node | `examples/reference_mcp_app/`; `transports/tool_node.py` |
| SECURITY + CHANGELOG + Dependabot | repo root / `.github/` |

## Run it

```bash
pip install -e ".[dev]"
pytest -q
python examples/zta_demo.py
python examples/reference_mcp_app/run_pep_demo.py
python examples/langgraph_tool_node_demo.py
python -m tracewall.ops.health --profile zta
python -m tracewall.ops.http_metrics --port 9100 --profile zta
python -m tracewall.ops.explain --profile zta --tool send_email --args '{"to":"x@evil.com","body":"hi"}'
python -m tracewall.transports.mcp_proxy --profile zta -- <mcp-server>
```

See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) and
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).
