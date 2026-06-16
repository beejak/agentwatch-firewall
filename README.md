# tracewall

A standalone, pluggable **agent firewall**: it decides ALLOW / BLOCK on every
tool call an AI agent makes, so a compromised prompt or a poisoned memory can't
turn into a destructive or exfiltrating action.

Transport-agnostic enforcement core behind one stable seam:

```python
from tracewall import Firewall
verdict = await firewall.check(event)   # -> FirewallVerdict (allow / block)
```

Key-free and infra-free by default — `pip install` and run, no services.

## What's inside

- **Identity / delegation** — token expiry, delegation-depth cap, capability set.
- **Deterministic policy DSL** — human-writable YAML rules (injection, exfil,
  destructive ops); zero ML, runs on the hot path.
- **Cross-session multi-hop taint propagation** — a fixed-point solver with a
  convergence proof and recovering quarantine dynamics (no permanent DoS). This
  is the part the literature doesn't do quantitatively.
- **Semantic tier** — an intent classifier for the ambiguous cases the trust
  gate escalates. Deterministic structural scorer by default; an optional,
  provider-agnostic LLM backend when a key is configured.
- **Append-only audit** — every verdict written to a pluggable sink (local JSONL
  by default).

## Pipeline

```
HookEvent ─▶ L0 identity ─▶ tier-0 content screen ─▶ tier-1 policy DSL
          ─▶ trust/taint gate ─(escalate)▶ tier-2 semantic judge ─▶ verdict ─▶ audit
```
Deterministic tiers are the fast path; only escalations await the judge. Any
internal error → fail-safe **BLOCK**.

## Install & use

```bash
pip install -e ".[dev]"        # base + test deps
pytest -q                      # pure, infra-free, deterministic
python -m tracewall.eval.harness --split test   # held-out eval on the frozen corpus
```

Plug it into an agent loop with the in-process guard:

```python
from tracewall.transports.python_guard import guard, GuardBlocked

try:
    await guard(firewall, "send_email", {"to": addr, "body": body},
                ctx={"agent_id": agent_id, "caller_chain": chain})
except GuardBlocked as b:
    ...  # b.verdict has the reason
```

Optional extras: `.[llm]` (LLM semantic backend), `.[bench]` (AgentDojo adapter).

## Evaluation

`tracewall/eval/` carries a **frozen, human-labeled corpus** and a deterministic
ablation harness (per-tier precision/recall/F1/FPR with bootstrap 95% CIs on a
held-out split). The deterministic backend is the stable, reproducible baseline;
an LLM run is a dated snapshot and is never used to gate tests. See
`tracewall/eval/results/` for committed metrics.

## Status

v1: in-process Python guard transport. MCP gateway proxy, framework callback
adapters, and an HTTP sidecar are designed-for and on the roadmap.
