# Getting started (operators)

Install → register identity → run with `--profile zta` → see one BLOCK.

## 1. Install

```bash
# Python >= 3.12
pip install -e ".[dev]"
pytest -q   # expect ~105 passed (key-free)
```

Optional: `pip install -e ".[llm]"` for LLM semantic tier; `.[bench]` for AgentDojo.

## 2. Env (minimum for prod-ish)

```bash
export TRACEWALL_ORG_DOMAINS=acme.com,corp.com   # allowlisted email/http hosts
# optional:
# export TRACEWALL_SEMANTIC_LLM=0                 # force deterministic judge
# export TRACEWALL_CONFIG=./tracewall.yaml        # see RUNBOOK
```

## 3. In-process (fastest demo)

```bash
python examples/guard_demo.py
# allow: read_file ok
# block: deterministic …
```

Or with the **zta** profile + identity:

```bash
python examples/zta_demo.py
```

## 4. MCP proxy (the real PEP path)

Put Tracewall **in front of** the MCP server so agents cannot skip it:

```bash
python -m tracewall.transports.mcp_proxy --profile zta --agent-id my-agent -- \
  npx @modelcontextprotocol/server-filesystem /data
```

| Profile | When to use |
|---------|-------------|
| **zta** | Production posture: identity + caps, allowlists, proxy-owned call tree |
| paranoid | Identity required; allowlists; caps optional |
| balanced | Lab / eval (no ZTA default-deny pack) |
| permissive | Availability-first; fewer rules |

## 5. Register identity (required for `zta` / `paranoid`)

Identity lives in the ledger SQLite DB (`--db`, default `tracewall_mcp.db`).

```python
from tracewall.core.signal import IdentityCtx
# after build_firewall_for_profile(...):
await fw._ledger.register_identity(IdentityCtx(
    agent_id="my-agent",
    caps=["read_file", "list_directory"],  # zta: empty caps = BLOCK
    trust=0.9,
))
```

`examples/zta_demo.py` does this for you.

## 6. One blocked call (what success looks like)

External email / HTTP to a host **not** in `TRACEWALL_ORG_DOMAINS` under `zta` → **BLOCK**, reason like `default-deny: …`.

```bash
python -m tracewall.ops.explain --profile zta --tool send_email --args-file args.json
# action=block rule_id=zta_email_default_deny_external …
```

(`args.json` example: `{"to":"x@evil.com","body":"hi"}`. On Windows prefer `--args-file` over shell-escaped `--args`.)

## 7. Next

- How to read eval JSON: [`RESULTS.md`](RESULTS.md)  
- Day-2 ops: [`RUNBOOK.md`](RUNBOOK.md)  
- Architecture: [`FIREWALL.md`](FIREWALL.md)  
- Threat model / what we don’t protect: [`../SECURITY.md`](../SECURITY.md)
