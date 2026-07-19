---
name: tracewall-zta
description: >-
  Use when implementing or reviewing Tracewall production/ZTA controls:
  allowlists, own call-tree, caps, rate limits, profiles, or MCP PEP placement.
---

# Tracewall ZTA / practicality skill

## Priority order (ship these, not branding)

1. **Default-deny egress** via `TRACEWALL_ORG_DOMAINS` + `policy/rules/zta/` (email/http).
2. **Proxy-owned call tree** (`SessionCallTree`, `own_call_tree=True`) — ignore client `caller_chain`.
3. **Non-bypassable PEP** — MCP proxy (or future sidecar) must sit on the only tool path.
4. **`require_caps`** on zta profile — empty caps = BLOCK.
5. **Match-level `rate_exceeds`** — in-process blast radius only; say so in docs.
6. **Audit** — `rule_id` + `args_hash` + `context_completeness` on every verdict.

## Profile cheat sheet

| Profile | Identity | Caps | Own tree | ZTA pack |
|---------|----------|------|----------|----------|
| zta | required | required | yes | yes |
| paranoid | required | optional | yes | yes |
| balanced | optional | optional | no | no (lab) |
| permissive | optional | optional | no | no (subset) |

## Do not

- Claim SPIFFE / continuous auth until a real verifier exists.
- Load ZTA default-deny into `balanced` without re-running held-out + EVIDENCE.
- Treat semantic LLM as a security gate.
- Wipe `adojo_stress.json` `live[]` on firewall-only reruns.

## Verify

```bash
pytest tracewall/tests/test_zta_practical.py tracewall/tests/test_mcp_profiles.py -q
python -m tracewall.eval.mcp_brink
```

Update [`paper/EVIDENCE.md`](../../paper/EVIDENCE.md) and [`LESSONS_LEARNED.md`](../../LESSONS_LEARNED.md) when behavior changes.
