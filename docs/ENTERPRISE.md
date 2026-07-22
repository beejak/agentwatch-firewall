# Enterprise readiness checklist

Honest status as of 2026-07-22 (v0.2.0). **Features frozen** for paper submit —
see [`../HANDOFF.md`](../HANDOFF.md). Update when items move.

**Product placement reminder:** Tracewall is a **tool-call PEP**, not a
chat-stream scanner, OS sandbox, or on-disk file scanner. AgentDojo evidence is a
**banking slice** only. No SPIFFE / kernel / sandbox-as-shipped claims.

## 1. Operator UX (docs)

| Item | Status |
|------|--------|
| `docs/GETTING_STARTED.md` | **Done** |
| `docs/INTEGRATION.md` (tool-call path) | **Done** |
| `docs/RESULTS.md` | **Done** |
| `docs/RUNBOOK.md` | **Done** |
| Fix `docs/README.md` | **Done** |
| `docs/SUPPORT.md` | **Done** |
| `docs/ARCHITECTURE_OVERVIEW.md` | **Done** |

## 2. Product packaging

| Item | Status |
|------|--------|
| Versioned releases + `CHANGELOG.md` | **Done** (GitHub `v0.2.0` when tagged) |
| `SECURITY.md` | **Done** |
| Config file YAML (`TRACEWALL_CONFIG`) | **Done** (basic + OTel format / metrics_http) |
| Policy dry-run / explain | **Done** (`python -m tracewall.ops.explain`) |

## 3. Ops hard requirements

| Item | Status |
|------|--------|
| Metrics (block / starve / p99) | **Done** — in-process + HTTP `/metrics` (`ops.http_metrics`) |
| Structured audit → stdout / OTel-shaped JSONL | **Done** — `OTelJsonlAuditSink` (not full OTLP/gRPC) |
| Health + rule reload | **Done** (`ops.health`, `ops.reload` smoke) |
| Signed / config-managed identity | **Not done** (ledger register only) |

## 4. Integration depth

| Item | Status |
|------|--------|
| One real reference deploy | **Done** — `examples/reference_mcp_app/` (+ subprocess PEP demo) |
| LangGraph-style tool node | **Done** — `GuardedToolNode` (no langgraph dep) |
| Soft-block product contract | **Done** (`SoftBlockResult` + RUNBOOK) |
| Support matrix | **Done** |

## 5. Assurance

| Item | Status |
|------|--------|
| CI: pytest + harness + brink | **Done** (already) |
| Dependabot | **Done** (`.github/dependabot.yml`) |
| SBOM | **Not done** |
| Lab vs prod packs | **Done** (`balanced` vs `zta`) |

## Bypass closes

| Item | Status |
|------|--------|
| ZWSP / NFKC on args | **Done** |
| Tool-name case / PascalCase | **Done** |
| Unknown tool names | Still expected_limit |

## Do not prioritize yet

More paper ASR tables (non-banking AgentDojo suites), deeper MTP math, SPIFFE
branding before a real verifier, OS sandbox productization, or chat-stream
scanning (out of product scope).
