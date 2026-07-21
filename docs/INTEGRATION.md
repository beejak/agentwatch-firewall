# Put Tracewall on the tool-call path

Operator / developer guide. Tracewall only protects what it **sees**. If a tool
runs without going through a PEP (policy enforcement point), Tracewall did
nothing — no matter how good the rules are.

**ELI5:** Imagine a bouncer at one door. If guests also sneak in through a side
door, the bouncer never gets to say “no.” Put Tracewall on **every** tool door.

## Why the tool-call path only

Tracewall’s job is: **before** a tool executes, decide ALLOW or BLOCK.

```
Agent decides tool → PEP (Tracewall) → ALLOW → real tool runs
                                 └→ BLOCK → tool never runs
```

If the agent (or another library) calls the MCP server, filesystem API, or HTTP
egress **around** Tracewall, that is a bypass. Host compromise and
rewriting the proxy binary are out of scope; see [`SECURITY.md`](../SECURITY.md).

There is **one** enforcement seam:

```python
verdict = await firewall.check(event)   # ALLOW or BLOCK
```

Transports (`guard`, `mcp_proxy`, `GuardedToolNode`) only build a `HookEvent`
and turn the verdict into control flow. They are not optional “nice to have”
layers — they **are** how you sit on the path.

---

## Pattern A — In-process Python guard

Best when your agent loop is already Python and you own every tool callable.

### Minimal wiring

```python
import os
from tracewall.core.signal import IdentityCtx
from tracewall.transports.profiles import build_firewall_for_profile
from tracewall.transports.python_guard import guard, GuardBlocked, SoftBlockResult

os.environ.setdefault("TRACEWALL_ORG_DOMAINS", "acme.com")

fw, prof = await build_firewall_for_profile("zta", db_path="tw.db")

# zta: identity + non-empty caps required
await fw._ledger.register_identity(
    IdentityCtx(
        agent_id="agent-1",
        caps=["read_file", "send_email", "list_directory"],
        trust=0.9,
    )
)

ctx = {"agent_id": "agent-1", "session_id": "sess-1"}

# ALLOW → FirewallVerdict; then run the real tool yourself
await guard(fw, "read_file", {"path": "/ok"}, ctx=ctx)
# ... call the real read_file ...

# BLOCK (default): raises
try:
    await guard(fw, "send_email", {"to": "x@evil.com", "body": "hi"}, ctx=ctx)
except GuardBlocked as b:
    print(b.verdict.reason)   # do NOT run send_email
```

Decorator form (keyword args = tool args):

```python
from tracewall.transports.python_guard import guarded

@guarded(fw, tool="send_email", ctx={"agent_id": "agent-1"})
async def send_email(*, to, body, ctx=None):
    ...
```

### Soft-block vs raise

| `on_block=` | Behavior | When to use |
|-------------|----------|-------------|
| `"raise"` (default) | Raises `GuardBlocked` with `.verdict` | Fail fast; sync agent loops |
| `"soft"` | Returns `SoftBlockResult` — **do not execute the tool**; surface `.message` / `.verdict.reason` to the model as a tool error | AgentDojo-style utility: keep the loop alive while stopping the attack |

```python
out = await guard(fw, "send_email", args, ctx=ctx, on_block="soft")
if isinstance(out, SoftBlockResult):
    return out.message   # tool error string — never call the real tool
# else: ALLOW — run the real tool
```

### Demos

- [`examples/zta_demo.py`](../examples/zta_demo.py) — `build_firewall_for_profile("zta")`, identity, soft + raise
- [`examples/guard_demo.py`](../examples/guard_demo.py) — minimal `Firewall` + `guard` (no profile)

---

## Pattern B — MCP stdio proxy (recommended for MCP agents)

Best when tools live behind an MCP server. The proxy is the **only** process the
client should open on stdio.

### Exact command

```bash
python -m tracewall.transports.mcp_proxy \
  --profile zta \
  --agent-id my-agent \
  --db /var/lib/tracewall/tw.db \
  -- \
  <real-mcp-server-cmd>
```

Example:

```bash
python -m tracewall.transports.mcp_proxy \
  --profile zta --agent-id app-1 --db tw.db -- \
  npx @modelcontextprotocol/server-filesystem /data
```

What it does: forwards all MCP traffic; **screens only `tools/call`**. ALLOW →
forward to the real server; BLOCK → MCP result with `isError: true` (tool never
runs on the server). Framing: Content-Length + NDJSON, auto-detected.

### Client must talk ONLY to the proxy

```
MCP client  ──stdio──▶  mcp_proxy  ──stdio──▶  real MCP server
                ▲
         Tracewall PEP here
```

Point the agent / IDE MCP config at **this** command, not at the bare
`npx …server…`. A second MCP entry that hits the same server without the proxy
is an alternate path = unprotected.

### Register identity into the same `--db`

Under `zta` / `paranoid`, identity lives in the ledger SQLite file. Register
**before** clients connect, using the **same** `--db` path the proxy uses:

```python
from tracewall.core.signal import IdentityCtx
from tracewall.transports.profiles import build_firewall_for_profile

fw, _ = await build_firewall_for_profile("zta", db_path="/var/lib/tracewall/tw.db")
await fw._ledger.register_identity(
    IdentityCtx(agent_id="my-agent", caps=["read_file", "list_directory"], trust=0.9)
)
```

`agent_id` should match `--agent-id` (or `_meta.tracewall.agent_id` if you set it).

### `_meta` / session / own call-tree

Optional enrichment on `tools/call` params:

```json
{
  "name": "read_file",
  "arguments": { "path": "/x" },
  "_meta": {
    "tracewall": {
      "agent_id": "my-agent",
      "session_id": "sess-1"
    }
  }
}
```

Under **`zta` / `paranoid`**, the proxy sets `own_call_tree=True`: it records
tools it screened and **ignores client-supplied `caller_chain`** (anti-forge).
Pass a stable `session_id` so the owned tree has a session key. Under
**`balanced`**, client `_meta.caller_chain` is honored (lab / honor-system only).

### Demos

- [`examples/reference_mcp.py`](../examples/reference_mcp.py) — production shape blurb
- [`examples/reference_mcp_app/`](../examples/reference_mcp_app/) — runnable PEP demo  
  `python examples/reference_mcp_app/run_pep_demo.py`  
  `python examples/reference_mcp_app/run_pep_demo.py --subprocess`

---

## Pattern C — Framework tool node (`GuardedToolNode`)

Best when a framework dispatches named tools (LangGraph-style `ToolNode` shape)
and you want Tracewall inside the dispatcher — **no `langgraph` package required**.

```python
from tracewall.transports.profiles import build_firewall_for_profile
from tracewall.transports.tool_node import GuardedToolNode
from tracewall.core.signal import IdentityCtx

fw, _ = await build_firewall_for_profile("zta", db_path="tw.db")
await fw._ledger.register_identity(
    IdentityCtx(agent_id="lg", caps=["read_file", "send_email"], trust=0.9)
)

node = GuardedToolNode(
    fw,
    {"read_file": read_file, "send_email": send_email},
    on_block="soft",   # default: soft → ToolInvokeResult.allowed=False
)
ctx = {"agent_id": "lg", "session_id": "s1"}

result = await node.ainvoke(
    {"name": "send_email", "args": {"to": "x@evil.com", "body": "hi"}},
    ctx=ctx,
)
# result.allowed / result.error / result.result
```

Accepts `{"name", "args"}` or `{"name", "arguments"}` (or `"tool"`). Only tools
registered on the node are invokable; unknown names fail closed by default.

### Demo

- [`examples/langgraph_tool_node_demo.py`](../examples/langgraph_tool_node_demo.py)

---

## Checklist — am I actually protected?

- [ ] **Every** tool invocation goes through Tracewall (`guard` / `mcp_proxy` /
      `GuardedToolNode`) — no “just this one” escape hatch.
- [ ] **`zta` in prod:** `TRACEWALL_ORG_DOMAINS` set; identity registered; **non-empty**
      `caps` (empty caps + `require_caps` = BLOCK).
- [ ] MCP: client talks **only** to `mcp_proxy`; no alternate MCP / HTTP / SDK
      path to the same tools.
- [ ] BLOCK means the real tool **did not run** (raise or soft — either way, no execute).
- [ ] Same ledger `--db` for proxy and identity registration.
- [ ] Under `zta`, rely on proxy-owned call tree + `session_id`, not forged
      `_meta.caller_chain`.

Quick self-test: external email under `zta` should BLOCK:

```bash
python -m tracewall.ops.explain --profile zta --tool send_email \
  --args-file args.json
# action=block …
```

---

## Anti-patterns

| Anti-pattern | Why it fails |
|--------------|--------------|
| Call the real tool, **then** call `guard` | PEP must be **before** execution |
| Soft-block result ignored → still execute tool | Soft means “deny + tell the model,” not “warn and proceed” |
| MCP client pointed at the real server **and** the proxy | Side door bypasses the bouncer |
| **`balanced` in production** | No ZTA default-deny pack; client `_meta` chain is forgeable |
| **Empty `caps` with `zta` (`require_caps`)** | Empty capability set → BLOCK (not allow-all) |
| Register identity in a different DB than `--db` | Proxy never sees the agent → identity BLOCKs / wrong posture |
| Relying on `tools/list` screening | Proxy does **not** screen `tools/list` (known limit) |
| Claiming SPIFFE / signed identity | Ledger `register_identity` only — not shipped |

---

## Next

- Day-0 install: [`GETTING_STARTED.md`](GETTING_STARTED.md)  
- Profiles / audit / soft-block ops: [`RUNBOOK.md`](RUNBOOK.md)  
- Architecture: [`FIREWALL.md`](FIREWALL.md) · [`ARCHITECTURE_OVERVIEW.md`](ARCHITECTURE_OVERVIEW.md)  
- Threat model: [`../SECURITY.md`](../SECURITY.md)
