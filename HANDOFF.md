# HANDOFF — agentwatch-firewall (tracewall)

Pick-up notes. **Last updated 2026-07-22 (features frozen → paper submit).**

## Track

- **Product features: FROZEN** for this paper submit (no new AgentDojo suites / live ASR unless explicitly requested).
- **Paper: submit track in progress / camera-ready** — see [`paper/SUBMIT.md`](paper/SUBMIT.md), [`paper/PAPER.md`](paper/PAPER.md), [`paper/tracewall.tex`](paper/tracewall.tex), [`paper/tracewall.pdf`](paper/tracewall.pdf).
- Evidence only from [`paper/EVIDENCE.md`](paper/EVIDENCE.md) + `tracewall/eval/results/`. Do **not** upload stale [`paper/watchtower.tex`](paper/watchtower.tex).

## Where things stand

- Tracewall **0.2.0**: **tool-call PEP** — enforcement core + MCP proxy + zta/paranoid/balanced/permissive.
- Honest story (README / SECURITY / LESSONS + **skills**): **not** a chat-stream
  prompt scanner; tier-0 is a noisy prior on tool args (never sole BLOCK); contains
  screened tool side effects after LLM compromise — not OS/kernel monitoring, not
  on-disk FS scan, not sandbox escape; AgentDojo = **banking slice** only; no
  SPIFFE/sandbox-as-shipped.
- Tracewall Cursor skills (update these when the PEP story changes — **not**
  `using-superpowers`):
  [`.cursor/skills/tracewall-zta/SKILL.md`](.cursor/skills/tracewall-zta/SKILL.md),
  [`.cursor/skills/tracewall-paper/SKILL.md`](.cursor/skills/tracewall-paper/SKILL.md).
- Operator docs: `GETTING_STARTED` / **`INTEGRATION`** / `RESULTS` / `RUNBOOK` / `ENTERPRISE` / `SUPPORT` / `ARCHITECTURE_OVERVIEW`.
- **Put Tracewall on the tool-call path:** [`docs/INTEGRATION.md`](docs/INTEGRATION.md) (Python `guard`, MCP `mcp_proxy` as sole path, `GuardedToolNode`).
- Bypass closes: ZWSP/NFKC args + canonical tool names (success in adojo/robustness stress).
- Ops: explain dry-run, health, reload, in-process + HTTP `/metrics`, OTel-shaped audit JSONL.
- Soft-block product contract on `guard(on_block="soft")`.
- Reference MCP PEP app + LangGraph-style `GuardedToolNode` (no langgraph dep).
- Enterprise checklist: [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md).
- Paper claims aligned: held-out regression bar, soft-block AgentDojo banking slice, robustness **18/18**, latency microbench, scope footnote, author **beejak**.

## Still open (post-submit / non-blocking for arXiv)

1. **Signed identity** — still ledger register (no SPIFFE / IdP verifier).
2. **SBOM** — not generated in CI yet.
3. **Full OTLP/gRPC exporter** — JSONL bridge only; document limits.
4. **Optional AgentDojo expand** — other environments (workspace/travel/…) or more attacks/models; **not required** while frozen for submit.
5. **Unknown tool names** — still expected_limit (pack gap); `tools/list` unscanned.
6. **Venue submission** after arXiv (S&P / USENIX / CCS) — separate from freeze.

## Done recently

| Item | Evidence |
|------|----------|
| Paper camera-ready + SUBMIT checklist | `paper/tracewall.tex`, `paper/SUBMIT.md`, `paper/HANDOFF` note |
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
