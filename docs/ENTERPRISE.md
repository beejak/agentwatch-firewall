# Enterprise readiness checklist

Honest status as of 2026-07-21. Update when items move.

## 1. Operator UX (docs)

| Item | Status |
|------|--------|
| `docs/GETTING_STARTED.md` | **Done** |
| `docs/RESULTS.md` | **Done** |
| `docs/RUNBOOK.md` | **Done** |
| Fix `docs/README.md` | **Done** |
| `docs/SUPPORT.md` | **Done** |

## 2. Product packaging

| Item | Status |
|------|--------|
| Versioned releases + `CHANGELOG.md` | **Done** (0.2.0 notes; tag when you cut a release) |
| `SECURITY.md` | **Done** |
| Config file YAML (`TRACEWALL_CONFIG`) | **Done** (basic) |
| Policy dry-run / explain | **Done** (`python -m tracewall.ops.explain`) |

## 3. Ops hard requirements

| Item | Status |
|------|--------|
| Metrics (block / starve / p99) | **Partial** — in-process `Firewall.metrics`; no HTTP endpoint |
| Structured audit → stdout | **Done** (`StdoutAuditSink` / tee); OTel **not** done |
| Health + rule reload | **Done** (`ops.health`, `ops.reload` smoke) |
| Signed / config-managed identity | **Not done** (ledger register only) |

## 4. Integration depth

| Item | Status |
|------|--------|
| One real reference deploy | **Partial** — MCP proxy pattern + `examples/reference_mcp.py`; no LangGraph package |
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

More paper ASR tables, deeper MTP math, SPIFFE branding before a real verifier.
