# TODOS

Companion to planning docs:

- Autoplan: [`docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md)
- Karpathy lens (separate): [`docs/plans/2026-10-21-tracewall-karpathy-review.md`](docs/plans/2026-10-21-tracewall-karpathy-review.md)
- Pick-up: [`HANDOFF.md`](HANDOFF.md)

**Gate B / v0.3.0 (2026-10-21):** P1–P5 accepted; E1+E2+E4 **shipped**; E5/E6 demoted.
Live soft-block re-measure still pending API key.

## Done (Gate B + E4)
- E1 — default-deny unknown tools on `zta`/`paranoid`
- E2 — MCP `tools/list` response filter on `zta`/`paranoid`
- E3 (narrowed) — focused tests for E1/E2 + fail-safe polarity
- E4 — session progressive containment (`session_ratchet`; prod on / lab off)

## Deferred
- Live AgentDojo soft-block re-measure (needs `LLM_API_KEY` + `.[bench]`)
- E5 — arg JSON Schema rail (demoted)
- E6 — decision certificates (demoted)
- E7 — workspace/travel firewall-only shapes — backlog
- HTTP/SSE MCP sidecar PEP
- HITL approve-hold mode
- SPIFFE/OIDC identity verifier
- Full OTLP/gRPC exporter + SBOM CI
- GitHub Actions Windows matrix
- Adaptive paraphrase corpus (measure before claim)
- Distributed rate limits
