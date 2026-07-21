---
name: tracewall-zta
description: >-
  Use when implementing or reviewing Tracewall production/ZTA controls:
  allowlists, own call-tree, caps, rate limits, profiles, MCP PEP placement,
  metrics scrape, or OTel-shaped audit.
---

# Tracewall ZTA / practicality skill

## Priority order (ship these, not branding)

1. **Default-deny egress** via `TRACEWALL_ORG_DOMAINS` + `policy/rules/zta/` (email/http).
2. **Proxy-owned call tree** (`SessionCallTree`, `own_call_tree=True`) — ignore client `caller_chain`.
3. **Non-bypassable PEP** — MCP proxy (or `GuardedToolNode`) must sit on the only tool path.
4. **`require_caps`** on zta profile — empty caps = BLOCK.
5. **Match-level `rate_exceeds`** — in-process blast radius only; say so in docs.
6. **Audit** — `rule_id` + `args_hash` + `context_completeness`; OTel JSONL optional.
7. **Metrics** — `Firewall.metrics` + HTTP `/metrics` (Prometheus text).

## Profile cheat sheet

| Profile | Identity | Caps | Own tree | ZTA pack |
|---------|----------|------|----------|----------|
| zta | required | required | yes | yes |
| paranoid | required | optional | yes | yes |
| balanced | optional | optional | no | no (lab) |
| permissive | optional | optional | no | no (subset) |

## Reference proof

```bash
py -3.12 examples/reference_mcp_app/run_pep_demo.py
py -3.12 examples/langgraph_tool_node_demo.py
python -m tracewall.ops.http_metrics --port 9100 --profile zta
```

## Do not

- Claim SPIFFE / continuous auth until a real verifier exists.
- Claim full OTLP/gRPC exporter (JSONL bridge only).
- Load ZTA default-deny into `balanced` without re-running held-out + EVIDENCE.
- Treat semantic LLM as a security gate.
- Wipe `adojo_stress.json` `live[]` on firewall-only reruns.

## Verify

```bash
pytest tracewall/tests/test_zta_practical.py tracewall/tests/test_mcp_profiles.py tracewall/tests/test_enterprise_ready.py -q
python -m tracewall.eval.mcp_brink
python -m tracewall.eval.robustness_stress
```

Update [`paper/EVIDENCE.md`](../../paper/EVIDENCE.md) and [`LESSONS_LEARNED.md`](../../LESSONS_LEARNED.md) when behavior changes.
