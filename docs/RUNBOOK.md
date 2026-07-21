# Runbook (day-2 ops)

## Profiles

| Profile | Identity | Caps | Own call-tree | ZTA allowlist pack | Fail |
|---------|----------|------|---------------|--------------------|------|
| **zta** | required | required (empty = BLOCK) | yes | yes | closed |
| paranoid | required | optional | yes | yes | closed |
| balanced | optional | optional | no (client `_meta`) | no | closed |
| permissive | optional | optional | no | no (subset rules) | open |

Lab vs prod: **balanced** for eval/regression; **zta** for production posture.

```bash
python -m tracewall.transports.mcp_proxy --profile zta --db /var/lib/tracewall/tw.db -- \
  <real-mcp-server-cmd>
```

## Environment

| Variable | Purpose |
|----------|---------|
| `TRACEWALL_ORG_DOMAINS` | Comma-separated allowlisted domains (email/http) |
| `TRACEWALL_SEMANTIC_LLM` | `0` = deterministic judge only |
| `TRACEWALL_CONFIG` | Path to YAML config (optional; see below) |
| `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` | Optional semantic LLM |

## Config file (optional)

`TRACEWALL_CONFIG=./tracewall.yaml`:

```yaml
profile: zta
org_domains: [acme.com, corp.com]
db_path: /var/lib/tracewall/tw.db
audit:
  path: /var/log/tracewall/audit.jsonl
  stdout: true
metrics: true
normalize_args: true
canonical_tool_names: true
```

Load via `tracewall.ops.config.load_config()`. CLI modules honor `TRACEWALL_CONFIG` when set.

## Audit JSONL

Default sink: append-only JSONL (`LocalAuditSink`). Each line includes:

- `action`, `source`, `reason`, `rule_id`, `args_hash`
- `context_completeness` (`identity`, `call_tree`, `ledger`, `session_chain`)
- optional full `event` (tool + args)

Stdout / tee: set `audit.stdout: true` or use `StdoutAuditSink`.

**BLOCK storm triage**

1. Sample recent JSONL: `grep '"action": "block"' audit.jsonl | tail`  
2. Group by `rule_id` / `reason` — allowlist miss vs capability vs rate limit.  
3. If `context_completeness.call_tree` is false under `balanced`, expect call-tree rules to miss — switch to `zta` (proxy-owned tree) or fix session wiring.  
4. Dry-run before widening allowlists: `python -m tracewall.ops.explain ...`  
5. Reload rules after YAML edits: `python -m tracewall.ops.reload --db ...` (or restart proxy).

## Metrics (in-process)

With metrics enabled, `Firewall.metrics.snapshot()` exposes:

- `n_check`, `n_allow`, `n_block`, `block_rate`
- `starve_call_tree` (checks with empty call tree)
- `latency_ms` p50 / p95 / p99

No network metrics server yet — scrape via your process or log snapshots.

## Health

```bash
python -m tracewall.ops.health --profile zta
# ok: rules_loaded=N profile=zta
```

## Soft-block contract (agents)

| Mode | Behavior |
|------|----------|
| `on_block=raise` (default guard) | Raises `GuardBlocked` with `.verdict` |
| `on_block=soft` | Returns `SoftBlockResult` — do **not** execute the tool; surface `verdict.reason` to the model as a tool error |

MCP proxy always returns MCP `isError: true` text (`tracewall blocked this tool call: …`) — soft at the wire.

Error shape for soft:

```text
tracewall BLOCK [<source>]: <reason>
# SoftBlockResult.verdict.rule_id / .args_hash available for operators
```

## Support matrix

| Item | Supported |
|------|-----------|
| Python | ≥ 3.12 |
| MCP framing | Content-Length + NDJSON (auto-detect) |
| Screens | `tools/call` only (`tools/list` unscanned — known limit) |
| Policy packs | `rules/*.yaml` (lab) + `rules/zta/*.yaml` (prod profiles) |

## What Tracewall does **not** do

See [`SECURITY.md`](../SECURITY.md). Host compromise, bypassing the PEP, and model-weight jailbreaks are out of scope.
