# tracewall — architecture

A standalone, pluggable agent firewall. It decides **ALLOW / BLOCK** on every
tool call an agent makes, behind one stable async seam:

```python
from tracewall import Firewall
verdict = await firewall.check(event)   # -> FirewallVerdict
```

Key-free and infra-free by default. **Fail-safe: any internal error → BLOCK.**

---

## Pipeline (`tracewall/core/firewall.py`)

```
HookEvent
   │
   ▼
L0  identity        token expiry · delegation depth ≤ 8 · capability set
   │ (ok)
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
        FirewallVerdict ──► audit sink (always, append-only)
```

The deterministic tiers (L0 → content → policy → gate) are the fast path
(in-process p99 < 10ms). Only ESCALATE/NARROW (or a tier-0 flag) awaits the
semantic judge. `context_completeness` on every verdict records which signals
(`identity`, `call_tree`, `ledger`) were actually available — so a
context-starved transport never silently over-claims.

`_route(trust, taint)`:

| condition | route |
|---|---|
| `taint ≥ 0.7` | ESCALATE (quarantine threshold) |
| `trust > 0.7` | ALLOW |
| `trust ≥ 0.3` | ESCALATE |
| else | NARROW |

---

## Modules

### `core/signal.py` — the wire contract
`HookEvent` (one mandatory field: `agent_id`), `EnrichedEvent`, `IdentityCtx`,
`Taint`, `FirewallVerdict` (`action`/`score`/`source`/`reason`/`context_completeness`),
`EdgeType`, `TaintEdge`. Defined once; transports build a `HookEvent` and get a
`FirewallVerdict` — the core sees nothing else.

### `core/firewall.py` — `Firewall` facade
`Firewall(ledger, policy, judge, content_filter=…, audit=…)`. `await check(event)`
runs the pipeline above and always writes to the audit sink. Wraps the body so any
exception → `FirewallVerdict(action=BLOCK, source="fail_safe")`.

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

### `taint/mtp.py` — multi-hop taint propagation (the moat)
Pure, DB-free fixed-point solver — single source of truth (the ledger drives it).
`T^(k+1)[v] = max(T^(k)[v], max_{u→v} T^(k)[u]·w·e^{-λΔt})`. Converges in ≤ |V|
iterations (monotone, bounded, strict decay); proof + `convergence_bound()` in the
module docstring. Quarantine recovers — no permanent DoS.

### `policy/engine.py` — `PolicyEngine` (tier-1)
Loads `policy/rules/*.yaml`, compiles to a per-tool lookup. `await evaluate(event)`
returns the first BLOCK `RuleMatch` or `None`. Pure-deterministic, hot-path. Keeps
the last-good ruleset if a reload fails.

### `content/filter.py` — tier-0 pre-filter
Standalone instruction-injection regex family (`flagged(text) -> bool`). No YAML,
no network. High-recall / lower-precision; routes into the semantic tier, never the
sole authority.

### `semantic/judge.py` — `SemanticJudge` (tier-2)
Two backends behind one interface. **Deterministic** structural scorer (key-free,
reproducible — the default and the fail-open fallback). **LLM** (provider-agnostic,
OpenAI-compatible; opt-in via `LLM_API_KEY`, disable with `TRACEWALL_SEMANTIC_LLM=0`).
The judge treats the call as UNTRUSTED DATA and never obeys instructions in it.

### `audit/sink.py` — append-only audit
`AuditSink` ABC + `LocalAuditSink` (JSONL, default) + `NullAuditSink`. Auditing
never breaks enforcement (errors swallowed + logged).

### `transports/` — how it plugs in
- `python_guard.py` — in-process `guard(fw, tool, args, ctx)` + `@guarded` decorator.
  Full context passthrough; `agent_id` required; fail-closed default.
- `mcp_proxy.py` — MCP stdio gateway proxy: spawns the real server, screens only
  `tools/call`; BLOCK → MCP `isError` tool result. Optional `_meta.tracewall`
  context convention; degrades gracefully when absent.

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
    call_tree_contains: [read_secret]   # optional — only fires with this caller present
verdict:  BLOCK
reason:   "human-readable reason for the audit log"
severity: 0.9
```

Operators (`_eval_op`): `regex` · `glob` · `in` · `not_in` · `not_in_domain` ·
`matches_secret_pattern` · `delegation_depth_gt` · `taint_gte`. Dotted arg paths:
`arg.body` → `args["body"]`.

---

## Evaluation

`tracewall/eval/` — a frozen, human-labeled corpus + a deterministic ablation
harness (per-tier precision/recall/F1/FPR with bootstrap 95% CIs on a held-out
split). Tiers: `tier0_content`, `tier1_policy`, `tier2_semantic`, plus
`integrated_or` (naive OR) and `integrated` (**gated**: policy OR semantic; tier-0
routes only). Gated beats naive OR on the held-out split (higher precision, lower
FPR, same recall) — the verdict is gated, not a blunt union. The deterministic
result is the stable baseline; an LLM run is a dated, non-reproducible snapshot and
never gates tests.

```bash
python -m tracewall.eval.harness --split test          # deterministic
python -m tracewall.eval.harness --split test --llm     # LLM backend (needs key)
```

---

## Testing invariants

Pure, infra-free, deterministic (`pytest -q`, no services):
- known-bad gate (3 surfaces + fail-safe + proofs + perf), MTP taint math,
  semantic tier, full `Firewall.check` paths, both transports;
- frozen-corpus hash + eval-reproducibility + pure-tier regression pins;
- LLM path mocked (never live in the gate); frozen agent-trace replay (data only).

Fail-safe checklist: identity/policy/semantic blocks fire; any internal error →
`source="fail_safe"`, `action=BLOCK`; trust recovers after clean calls (no
permanent DoS); deterministic hot path p99 < 10ms.
