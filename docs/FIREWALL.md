# tracewall — architecture

A standalone, pluggable agent firewall. It decides **ALLOW / BLOCK** on every
tool call an agent makes, behind one stable async seam:

```python
from tracewall import Firewall
verdict = await firewall.check(event)   # -> FirewallVerdict
```

Installable without cloud services. Deterministic tiers are key-free; an optional
LLM semantic backend is opt-in. **Fail-safe: any internal error → BLOCK.**

Canonical goals / evidence: [`GOALS.md`](GOALS.md), [`../paper/EVIDENCE.md`](../paper/EVIDENCE.md).

---

## Pipeline (`tracewall/core/firewall.py`)

```
HookEvent
   │
   ▼
L0  identity        token expiry · delegation depth ≤ 8 · capability set
   │                (optional require_identity=True → missing identity BLOCK)
   ▼
enrich              attach optional call-tree context (caller_chain)
   │
   ▼
tier-0 content      surface-form injection screen — NOISY PRIOR, never blocks alone
   │
   ▼
tier-1 policy       deterministic YAML DSL  ──► BLOCK (known-bad)
   │ (no match)
   ▼
trust/taint gate    _route(trust, taint): ALLOW · ESCALATE · NARROW
   │ ALLOW & not flagged      │ ESCALATE / NARROW / content-flagged
   ▼                          ▼
 ALLOW                  tier-2 semantic judge (await; off the fast path)
   │                          │
   └───────────┬──────────────┘
               ▼
        FirewallVerdict ──► audit sink (always)
                         ──► ledger feedback (ALLOW→on_clean_call, BLOCK→on_taint_event)
```

The deterministic tiers (L0 → content → policy → gate) are the fast path
(target in-process p99 < 10ms). Only ESCALATE/NARROW (or a tier-0 flag) awaits the
semantic judge. `context_completeness` on every verdict records which signals
(`identity`, `call_tree`, `ledger`) were actually available — so a
context-starved transport never silently over-claims.

`FirewallVerdict.score` is always **0.0 bad … 1.0 clean** (semantic malicious
scores are inverted at the facade).

`_route(trust, taint)`:

| condition | route |
|---|---|
| `taint ≥ 0.7` | ESCALATE (quarantine threshold) |
| `trust > 0.7` | ALLOW |
| `trust ≥ 0.3` | ESCALATE |
| else | NARROW (reserved; currently escalates like ESCALATE) |

---

## Modules

### `core/signal.py` — the wire contract
`HookEvent` (one mandatory field: `agent_id`), `EnrichedEvent`, `IdentityCtx`,
`Taint`, `FirewallVerdict` (`action`/`score`/`source`/`reason`/`context_completeness`),
`EdgeType`, `TaintEdge`. Defined once; transports build a `HookEvent` and get a
`FirewallVerdict` — the core sees nothing else.

### `core/firewall.py` — `Firewall` facade
`Firewall(ledger, policy, judge, content_filter=…, audit=…, require_identity=False)`.
`await check(event)` runs the pipeline above, writes the audit sink, and updates
ledger trust on ALLOW/BLOCK. Any exception →
`FirewallVerdict(action=BLOCK, source="fail_safe")`.

### `taint/ledger.py` — `Ledger` (trust / taint / identity / graph)
Local SQLite, clock-injectable for deterministic decay. Per `agent_id`:

```python
await ledger.get_trust(aid)                     # → float [0,1]
await ledger.on_clean_call(aid, tool)            # trust += α(1-trust),  α=0.02   (recovering)
await ledger.on_taint_event(aid, severity)       # trust *= (1 - β·sev), β=0.6
await ledger.get_taint(aid)                      # → Taint | None (with time decay)
await ledger.set_taint(aid, taint)
await ledger.propagate_read_taint(reader, w)     # T3 contagion: max(reader, w·ρ)
await ledger.register_identity(ctx) / get_identity(aid)
await ledger.record_edge(src, …, dst, …, edge_type)
await ledger.propagate_graph()                   # drives taint/mtp.propagate()
await ledger.get_blast_radius(node, threshold)
```

Constants: ρ=0.8 hop decay · α=0.02 trust recovery · β=0.6 degrade · λ=0.1/hr
time decay · Q=0.7 quarantine. Edge weights: WRITE 0.95 · READ 0.80 · DELEGATE
0.90 · TOOL_CALL 0.85.

### `taint/mtp.py` — multi-hop taint propagation (the research moat)
Pure, DB-free fixed-point solver — the ledger drives it.
`T^(k+1)[v] = max(T^(k)[v], max_{u→v} T^(k)[u]·w·e^{-λΔt})`. Converges in ≤ |V|
iterations. Quarantine recovers — no permanent DoS.

### `policy/engine.py` — `PolicyEngine` (tier-1)
Loads `policy/rules/*.yaml`. Profiles **zta** / **paranoid** also load
`policy/rules/zta/` (default-deny allowlists + rate budgets).
`${ORG_DOMAIN}` expands from `TRACEWALL_ORG_DOMAINS`
(comma-separated; default `org.com,trusted.com,customer.com`).

Operators include `not_in_domain`, `in_domain`, `host_not_in` / `host_in` (URL/email),
`matches_secret_pattern`, `regex`, `glob`, and match-level `rate_exceeds`
(`window_s` / `max` / `key`) via an in-process `RateBudget`.
Unknown operators log a warning and non-match.

Context keys:
- `call_tree_contains` — all listed callers must appear
- `call_tree_contains_any` — any listed caller (secret-reader aliases)

### `content/filter.py` — tier-0 pre-filter
Standalone instruction-injection regex family (`flagged(text) -> bool`). High-recall /
lower-precision; never sole BLOCK authority.

### `semantic/judge.py` — `SemanticJudge` (tier-2)
**Deterministic** structural scorer (default) or **LLM** (`LLM_API_KEY`, disable with
`TRACEWALL_SEMANTIC_LLM=0`). Judge score is 0=clean…1=malicious; facade inverts for verdict.

### `audit/sink.py` — append-only audit
`AuditSink` ABC + `LocalAuditSink` (JSONL) + `NullAuditSink`.
Verdicts include `rule_id`, `args_hash`, and `context_completeness` for SIEM-friendly trails.

### `transports/` — how it plugs in

```
Agent / MCP client
        │
        ▼
┌───────────────────┐     ┌──────────────────────────┐
│ python_guard      │     │ mcp_proxy + profile       │
│ guard / @guarded  │     │ zta|paranoid|balanced|    │
└─────────┬─────────┘     │ permissive               │
          │               └──────────┬───────────────┘
          └────────────┬─────────────┘
                       ▼
              Firewall.check(event)
                       │
                       ▼
              real tool / MCP server
```

- `python_guard.py` — in-process `guard` / `@guarded`. `agent_id` required; fail-closed default.
- `tool_node.py` — `GuardedToolNode` (LangGraph-style named dispatch; no `langgraph` dep).
- `mcp_proxy.py` + `profiles.py` + `session_chain.py` — MCP stdio proxy; screens only `tools/call`.
  - **zta** — prod posture: `require_identity` + `require_caps`, ZTA pack, **proxy-owned call tree**
  - **paranoid** — identity required, ZTA pack, proxy-owned call tree, caps optional
  - **balanced** — lab default; fail-closed; full rules; client `_meta` call tree (honor-system)
  - **permissive** — fail-open; destructive + MINJA rules only
  - CLI: `--profile`, `--fail-closed` / `--fail-open`
  - Optional `_meta.tracewall` (`agent_id`, `session_id`; `caller_chain` ignored when `own_call_tree`)

**How to wire PEPs:** [`INTEGRATION.md`](INTEGRATION.md).

**ZTA honesty:** client-asserted `caller_chain` is not authentication. Use `--profile zta`
(or paranoid) so the PEP owns the chain. Identity is still ledger-registered (not SPIFFE yet).

**Network note:** MCP proxy auto-detects **Content-Length** framing and legacy
**NDJSON** readline (see `mcp_framing.py`). Both are shipped — not deferred.

---

## Writing a policy

`policy/rules/<name>.yaml`:

```yaml
rule:    my_rule_id
surface: capability_abuse          # or: input_corruption | contagion
on:      pre_tool_call
match:
  tool: the_tool_name
  any:
    - arg.some_field: { regex: "pattern" }
    - arg.other_field: { in: ["a", "b"] }
  context:
    call_tree_contains_any: [read_secret, read_credentials, get_secret]
verdict:  BLOCK
reason:   "human-readable reason for the audit log"
severity: 0.9
```

Operators: `regex` · `glob` · `in` · `not_in` · `not_in_domain` ·
`matches_secret_pattern` · `delegation_depth_gt` · `taint_gte`.
Shipped packs: MINJA memory, destructive/remote-exec bash, exfil email/http/message/upload.

---

## Evaluation

| Lane | Command | What it proves |
|------|---------|----------------|
| Held-out ablation | `python -m tracewall.eval.harness --split test` | Detection P/R/F1 on frozen corpus |
| MCP brink | `python -m tracewall.eval.mcp_brink` | Profile success **and** expected limits |
| AgentDojo stress | `python -m tracewall.eval.adojo_stress` | Firewall-only banking chains + limits |
| Cross-domain robustness | `python -m tracewall.eval.robustness_stress` | Workspace/HTTP/contagion/host/identity |
| Latency | `python -m tracewall.eval.latency` | Full `Firewall.check` microbenchmark |
| AgentDojo live | `python -m tracewall.eval.adapters.agentdojo …` | Live ASR/utility (needs key; often UNVERIFIED) |
| Unit gate | `pytest -q` | Contracts / regressions |

Held-out deterministic snapshot (post policy pack): tier1 recall **1.0** / FPR **0**;
integrated recall **1.0** / FPR ≈ **0.07**. That is a **regression bar**, not adaptive
or AgentDojo proof — see EVIDENCE.

---

## Testing invariants

Pure, infra-free (`pytest -q`, Python ≥3.12):
- known-bad + MTP + semantic + `Firewall.check` + transports + **MCP profiles**
- frozen-corpus hash (CRLF-normalized) + eval reproducibility + pure-tier pins
- brink JSON: all `kind=success` pass; `kind=expected_limit` must reproduce misses

Fail-safe: internal error → `source="fail_safe"` BLOCK; trust recovers on clean calls.
