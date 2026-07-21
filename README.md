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
LLM semantic backend is available when configured. On the frozen held-out corpus
(n=27), the expanded default policy pack reaches deterministic integrated
recall **1.0** (FPR ≈ 0.07) — see `tracewall/eval/results/` and
[`paper/EVIDENCE.md`](paper/EVIDENCE.md). That is **not** proof against adaptive
attacks or AgentDojo; treat it as a regression bar, not a solved claim.

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

**Operators:** start at [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)  
(results: [`docs/RESULTS.md`](docs/RESULTS.md) · day-2: [`docs/RUNBOOK.md`](docs/RUNBOOK.md) · checklist: [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md)).

```bash
pip install -e ".[dev]"        # base + test deps (Python >=3.12)
pytest -q                      # pure, infra-free, deterministic
python examples/zta_demo.py    # identity + default-deny + soft-block
python examples/guard_demo.py
python -m tracewall.ops.explain --profile zta --tool send_email --args '{"to":"x@evil.com","body":"hi"}'
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

Or drop it in front of an MCP server — pick a **profile** (strict → loose):

```bash
python -m tracewall.transports.mcp_proxy --profile zta -- npx @modelcontextprotocol/server-filesystem /data
python -m tracewall.transports.mcp_proxy --profile balanced -- npx @modelcontextprotocol/server-filesystem /data
python -m tracewall.transports.mcp_proxy --profile paranoid --fail-closed -- ...
python -m tracewall.transports.mcp_proxy --profile permissive --fail-open -- ...
```

| Profile | Meaning |
|---------|---------|
| **zta** | Prod: identity + caps, org allowlist default-deny, proxy-owned call tree |
| paranoid | Identity required; ZTA pack; proxy-owned call tree |
| balanced | Lab default; fail-closed; full rules; client `_meta` chain |
| permissive | Fail-open; fewer rules (destructive + MINJA only) |

Set allowlists: `TRACEWALL_ORG_DOMAINS=acme.com,corp.com`

Brink tests (success **and** known limits): `python -m tracewall.eval.mcp_brink`  
Detection fit notes: [`docs/DETECTION.md`](docs/DETECTION.md).

Optional extras: `.[llm]` (LLM semantic backend), `.[bench]` (AgentDojo adapter).

## Evaluation

`tracewall/eval/` carries a **frozen, human-labeled corpus** and a deterministic
ablation harness (per-tier precision/recall/F1/FPR with bootstrap 95% CIs on a
held-out split). The deterministic backend is the stable, reproducible baseline;
an LLM run is a dated snapshot and is never used to gate tests. See
`tracewall/eval/results/` and [`paper/EVIDENCE.md`](paper/EVIDENCE.md).

Pick-up / roadmap: [`HANDOFF.md`](HANDOFF.md). Process rules: [`LESSONS_LEARNED.md`](LESSONS_LEARNED.md).

## Status

Shipped: Python guard + MCP stdio proxy with **zta/paranoid/balanced/permissive**
profiles, ZTA allowlist pack, proxy-owned call trees, working `rate_exceeds`,
observe-first GOALS/EVIDENCE/brink. Open: signed workload identity, LangGraph sidecar,
closing Unicode/alias bypasses. See [`HANDOFF.md`](HANDOFF.md).

## Doc map

- **Start here:** [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)  
- Results / ASR: [`docs/RESULTS.md`](docs/RESULTS.md)  
- Runbook: [`docs/RUNBOOK.md`](docs/RUNBOOK.md)  
- Enterprise checklist: [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md)  
- Architecture: [`docs/FIREWALL.md`](docs/FIREWALL.md)  
- Security: [`SECURITY.md`](SECURITY.md) · Changelog: [`CHANGELOG.md`](CHANGELOG.md)  
- Evidence ledger: [`paper/EVIDENCE.md`](paper/EVIDENCE.md)  
- All docs: [`docs/README.md`](docs/README.md)
