# tracewall

A standalone, pluggable **agent firewall**: it decides ALLOW / BLOCK on every
tool call an AI agent makes, so a compromised prompt or a poisoned memory can't
turn into a destructive or exfiltrating action.

Transport-agnostic enforcement core behind one stable seam:

```python
from tracewall import Firewall
verdict = await firewall.check(event)   # -> FirewallVerdict (allow / block)
```

Installable without cloud services. Deterministic tiers run key-free; an optional
LLM semantic backend improves recall when configured. **Honest baseline:** on the
frozen held-out corpus, deterministic integrated recall is ~0.46 (tier-1 policy
alone ~0.08) — see `tracewall/eval/results/` and [`paper/EVIDENCE.md`](paper/EVIDENCE.md).
Do not treat “key-free” as “security-complete.”

## What's inside

- **Identity / delegation** — token expiry, delegation-depth cap, capability set
  (`require_identity=True` for fail-closed L0).
- **Deterministic policy DSL** — human-writable YAML rules (injection, exfil,
  destructive ops); zero ML, runs on the hot path.
- **Cross-session multi-hop taint propagation** — fixed-point solver with
  recovering quarantine dynamics. Live `check()` updates trust via the ledger.
- **Semantic tier** — intent classifier for escalations. Deterministic scorer by
  default; optional OpenAI-compatible LLM when `LLM_API_KEY` is set.
- **Append-only audit** — pluggable sink (local JSONL by default).

## Where it runs

| Placement | Status |
|-----------|--------|
| In-process Python (`guard` / `Firewall.check`) | Shipped |
| MCP stdio proxy in front of a real server | Shipped |
| LangGraph / HTTP sidecar | Roadmap |

See [`docs/GOALS.md`](docs/GOALS.md) and [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).

## Pipeline

```
HookEvent ─▶ L0 identity ─▶ tier-0 content screen ─▶ tier-1 policy DSL
          ─▶ trust/taint gate ─(escalate)▶ tier-2 semantic judge ─▶ verdict ─▶ audit
```
Deterministic tiers are the fast path; only escalations await the judge. Any
internal error → fail-safe **BLOCK**.

## Install & use

```bash
pip install -e ".[dev]"        # base + test deps (Python >=3.12)
pytest -q                      # pure, infra-free, deterministic
python -m tracewall.eval.harness --split test   # held-out eval
python examples/guard_demo.py
```

Org allowlist for email rules: `TRACEWALL_ORG_DOMAINS=acme.com,corp.com` (default
`org.com,trusted.com,customer.com`).

Plug it into an agent loop with the in-process guard:

```python
from tracewall.transports.python_guard import guard, GuardBlocked

try:
    await guard(firewall, "send_email", {"to": addr, "body": body},
                ctx={"agent_id": agent_id, "caller_chain": chain})
except GuardBlocked as b:
    ...  # b.verdict has the reason
```

Or drop it in front of an MCP server with **zero agent code change** — the proxy
spawns the real server and screens every `tools/call` on the wire:

```bash
python -m tracewall.transports.mcp_proxy -- npx @modelcontextprotocol/server-filesystem /data
```
A cooperating client can pass `agent_id` / `caller_chain` via the MCP `_meta`
field to feed the taint and call-tree tiers; without it the proxy degrades
gracefully and records reduced `context_completeness`.

Optional extras: `.[llm]` (LLM semantic backend), `.[bench]` (AgentDojo adapter).

## Evaluation

`tracewall/eval/` carries a **frozen, human-labeled corpus** and a deterministic
ablation harness (per-tier precision/recall/F1/FPR with bootstrap 95% CIs on a
held-out split). The deterministic backend is the stable, reproducible baseline;
an LLM run is a dated snapshot and is never used to gate tests. See
`tracewall/eval/results/` and [`paper/EVIDENCE.md`](paper/EVIDENCE.md).

Pick-up / roadmap: [`HANDOFF.md`](HANDOFF.md). Process rules: [`LESSONS_LEARNED.md`](LESSONS_LEARNED.md).

## Status

v1 transports: in-process Python guard + MCP stdio gateway proxy. Framework
callback adapters (LangChain/LangGraph/CrewAI) and an HTTP sidecar are
designed-for and on the roadmap.
