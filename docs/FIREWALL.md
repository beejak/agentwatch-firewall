# WatchTower Firewall Layer

Two-tier enforcement on top of the 16-layer observability stack.  
**Hot path: < 10ms p99. Cold path: async BFT swarm. Fail-safe: any error → BLOCK.**

---

## Architecture

```
pre_tool_call hook (hermes)
        │
        ▼
L0  Identity check     token expiry · delegation depth · capability set
        │
        ▼
L1  Intercept          hermes plugin, returns block dict or None
        │
        ▼
L2  Enrichment         graphify AST path (cached; miss → needs_async)
        │
        ▼
L3  Deterministic      superpowers YAML policy match  ──► BLOCK (known-bad)
        │ (no match)
        ▼
L4  Trust gate         cavemem score: >0.7 ALLOW · 0.3–0.7 ESCALATE · <0.3 NARROW
        │ (ALLOW)         │ (ESCALATE / NARROW)
        ▼                 ▼
      ALLOW          register hold + submit to ruflo swarm
                          │
                          ▼ (async, off hot-path)
                    L6  Ruflo BFT consensus (3 agents, 5s timeout)
                          │
                          ▼
                    L7  Barrier resolves hold → return verdict
        │
        ▼
L8  Chronicle       append-only ClickHouse write (always)
```

---

## Adapters

### `hermes.py` — Hook Interceptor

Entry point. Implements `pre_tool_call` and `pre_gateway_dispatch` as Hermes plugin hooks.

**`_enforce(event: HookEvent) -> FirewallVerdict`**

Pipeline:
1. Build `EnrichedEvent` from `HookEvent` + graphify AST enrichment
2. Check identity (L0): token expiry, delegation depth, capability membership
3. Evaluate superpowers rules (L3)
4. Get trust score from cavemem (L4)
5. Route: ALLOW / ESCALATE to ruflo / NARROW
6. If ESCALATE/NARROW: register asyncio.Future hold, submit to ruflo swarm
7. Fail-safe: any exception → `FirewallVerdict(action=BLOCK, source="fail_safe")`

**In-process trust cache:** 5-second TTL. Reduces cavemem reads on repeated calls.

**Hold registry:** `_holds: dict[str, asyncio.Future]` — keyed by `event_id`. Async verdicts must match a registered hold to be accepted (KB15 — unauthenticated verdict rejection).

---

### `cavemem.py` — Taint Ledger + Trust Store

SQLite + aiosqlite. MCP-accessible. Cross-session persistent.

**Tables:**
- `agents` — identity registration (`agent_id`, `caps`, `delegation_depth`, `trust`)
- `taint` — taint records (`agent_id`, `level`, `source`, `reason`, `ts`, `session_id`)
- `verdicts` — append-only verdict log

**Key methods:**

```python
await cavemem.get_trust(agent_id)                   # → float [0,1]
await cavemem.on_clean_call(agent_id, tool)          # trust += α(1-trust), α=0.02
await cavemem.on_taint_event(agent_id, severity)     # trust *= (1 - β×sev), β=0.6
await cavemem.get_taint(agent_id)                    # → Taint | None (with time decay)
await cavemem.set_taint(agent_id, taint)
await cavemem.propagate_read_taint(reader_id, writer_taint)  # T3 contagion
await cavemem.propagate_taint_if_blocked(agent_id, verdict)  # T2 capability abuse
await cavemem.register_identity(ctx: IdentityCtx)
await cavemem.get_identity(agent_id)
await cavemem.record_verdict(v: FirewallVerdict)     # append-only, never UPDATE
```

**Taint propagation constants:**

| Constant | Value | Meaning |
|----------|-------|---------|
| ρ (rho) | 0.8 | Hop decay — `T_B = T_A × ρ` |
| λ (lambda) | 0.1/hr | Time decay — `T(t) = T₀ × e^{−λt}` |
| α (alpha) | 0.02 | Trust recovery per clean call |
| β (beta) | 0.6 | Trust degradation factor |
| Q | 0.7 | Quarantine threshold |

**Quarantine recovery** (P5 — no permanent DoS):  
For `T₀=0.9`: quarantine lifts at `t₀ + 2.52 hours`.  
For `T₀=1.0`: quarantine lifts at `t₀ + 3.57 hours`.

---

### `superpowers.py` — Policy Evaluator

Loads `*.yaml` from `policies/` at session start. Compiles to per-tool lookup table.

**Evaluation:** O(1) tool lookup + O(rules) linear scan. Returns first BLOCK match, or `None` (ALLOW). Keeps last-good ruleset if reload fails (partial parse protection).

**`_matches(rule, event) -> bool`**

1. `context.call_tree_contains` — checks both `event.call_tree` and `event.event.caller_chain` (combined list)
2. `any` clauses — OR, short-circuits on first match
3. `all` clauses — AND, short-circuits on first miss

**`_eval_op(op, val, operand) -> bool`**

| Operator | Type | Description |
|----------|------|-------------|
| `not_in_domain` | `list[str]` | Email domain not in allowed list |
| `in` | `list` | Value in list |
| `not_in` | `list` | Value not in list |
| `matches_secret_pattern` | `bool` | Regex: API keys, tokens, private keys |
| `regex` | `str` | `re.search(operand, str(val))` |
| `glob` | `str` | `fnmatch(str(val), operand)` |
| `rate_exceeds` | `int` | Delegated to rate tracker (stub) |
| `delegation_depth_gt` | `int` | Integer comparison |
| `taint_gte` | `float` | Float comparison against taint level |

**Secret patterns matched by `matches_secret_pattern`:**
```
(?i)(api[_-]?key|password|secret|token|bearer|credentials?)\s*[:=]\s*\S+
(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xox[bporas]-[0-9A-Za-z-]+)
(?i)-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----
```

---

### `graphify.py` — AST Enrichment

Wraps graphify-ts (tree-sitter WASM, 12 languages) via subprocess bridge to Node.js.

Returns `(ast_path: str | None, cache_hit: bool)`.

**Cache miss behaviour:** sets `needs_async=True` on `EnrichedEvent`. This routes the event to L5/L6 for async analysis but **never blocks inline** (KB16 — cache miss must not block).

**Fallback:** if Node.js is unavailable, returns `(None, False)` gracefully. No exception. No BLOCK.

---

### `ruflo.py` — Async BFT Swarm

3-agent consensus off the hot path. Runs inside `asyncio.ensure_future`.

**Roles:** `semantic` · `contagion` · `intent` — each votes 0.0–1.0 suspicion.

**Quorum:** ≥ 2/3 block votes → `BLOCK`. Otherwise → `ALLOW`.

**Timeout:** 5 seconds → `ALLOW` (not BLOCK — to prevent DoS via swarm delay).

**Error:** exception in swarm → `BLOCK, source="fail_safe"` (P3 — fail-safe applies here too).

---

### `claude_mem.py` — Persistent Memory Client

Thin client over the cavemem MCP server. Tracks writer provenance for every memory entry.

Callers are responsible for checking writer taint and calling `cavemem.propagate_read_taint` if the writer is tainted — this is the taint propagation entry point for memory reads.

---

### `caveman.py` — Token Compression

UTC compression via JuliusBrussee/caveman. Used to keep args lean before policy evaluation.

`compress_args(args, max_tokens=512)` — compresses all string values in an args dict. ~75% reduction on verbose LLM output.

---

## Signal shapes (`firewall/core/signal.py`)

```python
class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HOLD  = "HOLD"

class HookEvent(BaseModel):
    event_id:     str             # UUID, unique per call
    agent_id:     str
    tool:         str
    args:         dict
    call_site:    Optional[str]   # source location if available
    caller_chain: list[str]       # call stack as tool names
    session_id:   Optional[str]
    ts:           datetime

class EnrichedEvent(BaseModel):
    event:       HookEvent
    ast_path:    Optional[str]   # graphify result; None on cache miss
    call_tree:   list[str]       # combined tree from graphify + caller_chain
    cache_hit:   bool
    needs_async: bool            # True → route to ruflo, not inline block

class IdentityCtx(BaseModel):
    agent_id:         str
    parent_id:        Optional[str]
    delegation_depth: int = 0    # MAX_DEPTH = 8
    caps:             list[str]  # allowed tools
    trust:            float = 0.5
    taint:            float = 0.0
    token_exp:        Optional[datetime]

class Taint(BaseModel):
    agent_id:   str
    level:      float           # [0.0, 1.0]
    source:     str             # "T1" | "T2" | "T3"
    reason:     str
    ts:         datetime
    session_id: Optional[str]

class FirewallVerdict(BaseModel):
    verdict_id:  str            # UUID
    event_id:    str            # matches HookEvent.event_id
    agent_id:    str
    tool:        str
    action:      Verdict
    score:       float          # [0.0, 1.0]
    source:      str            # "superpowers" | "trust_gate" | "ruflo_swarm" | "fail_safe"
    reason:      str
    latency_ms:  float = 0.0
    ts:          datetime
```

**Taint source codes:**

| Code | Meaning |
|------|---------|
| T1 | Direct injection detected in content |
| T2 | Capability abuse — tool call blocked |
| T3 | Contagion — inherited from tainted memory writer |

---

## Writing a policy

1. Create `policies/<name>.yaml`
2. Policies are hot-reloaded at session start. Reload manually via `sp.load_policies("policies/")`
3. Test with `pytest tests/known_bad/test_firewall_kb.py -k <your_test>`

**Template:**
```yaml
rule:    my_rule_id
surface: capability_abuse          # or: input_corruption | contagion
on:      pre_tool_call
match:
  tool: the_tool_name
  any:
    - arg.some_field: { regex: "pattern" }
    - arg.other_field: { in: ["val1", "val2"] }
  context:
    call_tree_contains: [required_caller]   # optional — semantic context
verdict:  BLOCK
reason:   "human-readable reason for audit log"
severity: 0.8                      # used for taint update on block
```

**Dotted arg paths:** `arg.body` → `args["body"]`, `arg.config.key` → `args["config"]["key"]`

---

## Adding a test case to the gate corpus

```python
# tests/known_bad/test_firewall_kb.py

@pytest.mark.asyncio
async def test_KB_my_case(policies):
    ev = make_event("tool_name", {"arg": "value"}, caller_chain=["optional_caller"])
    match = await policies.evaluate(ev)
    assert match is not None, "KB_my_case: not blocked"
    assert match.verdict == "BLOCK"
```

All cases in the gate file must pass. Adding a case that fails = failing the gate. Fix the policy first, then add the test.

---

## Fail-safe checklist

Before deploying, verify all five security properties hold:

- [ ] **P1** `pytest tests/known_bad/ -v` → 17/17 pass
- [ ] **P2** KB09, KB10, Q2 pass — taint propagation working
- [ ] **P3** KB13 pass — `source="fail_safe"` on crash → `action=BLOCK`
- [ ] **P4** PB01 pass — p99 < 10ms on N=1000
- [ ] **P5** KB12 pass — trust recovers after 10 clean calls

---

## Performance notes

| Path | Budget | Current |
|------|--------|---------|
| L3 policy eval (in-process) | < 10ms | 0.011ms |
| L2 graphify (cache hit) | < 3ms | ~0.1ms |
| L2 graphify (cache miss) | no inline block | routes to async |
| L4 cavemem trust (in-proc cache) | < 1ms | ~0.05ms |
| L6 ruflo swarm | off hot-path | < 5s |

The in-process trust cache (5s TTL) means cavemem SQLite reads happen at most once per 5 seconds per agent. On cache hit the full L0–L5 pipeline costs ~0.2ms end-to-end.
