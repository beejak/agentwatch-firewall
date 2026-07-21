# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-07-21.**

## Where things stand

- Tracewall **0.2.0**: enforcement core + MCP proxy + zta/paranoid/balanced/permissive.
- Operator docs shipped (`GETTING_STARTED` / `RESULTS` / `RUNBOOK`).
- Bypass closes: ZWSP/NFKC args + canonical tool names.
- Ops: explain dry-run, health, reload, in-process metrics, stdout audit tee.
- Soft-block product contract on `guard(on_block="soft")`.
- Enterprise checklist: [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md).

## Still open (priority)

1. **LangGraph / real sidecar PEP** — reference MCP pattern exists; full framework adapter not shipped.
2. **HTTP `/metrics` + OTel audit exporter** — in-process metrics/stdout only.
3. **Signed identity** — still ledger register.
4. **SBOM / release tags** — CHANGELOG ready; cut GitHub release when ready.
5. **Venue polish** — paper camera-ready.

## Done recently

| Item | Evidence |
|------|----------|
| Operator docs pack | `docs/GETTING_STARTED.md` etc. |
| ZTA practicality | `rules/zta/`, own call-tree, `require_caps` |
| Bypass closes (ZWSP, tool case) | `policy/normalize.py`; adojo stress success rows |
| Soft-block + explain/health/reload | `python_guard.SoftBlockResult`; `tracewall.ops.*` |
| SECURITY + CHANGELOG + Dependabot | repo root / `.github/` |

## Run it

```bash
pip install -e ".[dev]"
pytest -q
python examples/zta_demo.py
python -m tracewall.ops.health --profile zta
python -m tracewall.ops.explain --profile zta --tool send_email --args '{"to":"x@evil.com","body":"hi"}'
python -m tracewall.transports.mcp_proxy --profile zta -- <mcp-server>
```

See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md).
