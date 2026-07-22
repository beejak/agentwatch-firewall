# tracewall

A standalone, pluggable **tool-call PEP** (policy enforcement point): it decides
**ALLOW / BLOCK** on every screened tool call an AI agent makes, so a
compromised-via-prompts agent cannot turn screened tools into destructive or
exfiltrating side effects.

**Version:** 0.2.0 · **Author:** beejak · **Features frozen** for paper submit
(see [`HANDOFF.md`](HANDOFF.md), [`paper/EVIDENCE.md`](paper/EVIDENCE.md)).

## What we do / don’t

| We **do** | We **don’t** |
|-----------|--------------|
| Gate **tool calls** at a PEP (`guard` / `mcp_proxy` / `GuardedToolNode`) | Sit on the LLM **chat stream** as a prompt-injection scanner |
| Contain **screened** side effects when rules match: exfil, money probes, destructive `bash` patterns, caps/rates, owned call trees | OS/kernel monitoring, on-disk file scanners, or sandbox-escape prevention |
| Treat tier-0 content filter as a **noisy prior on tool args** (never sole BLOCK) | Claim tier-0 / regex as the detector of record |
| Report AgentDojo **banking slice** evidence only | Imply full AgentDojo (banking + workspace + travel + …) |
| Ship library + MCP stdio PEP + ZTA-adjacent profiles | Ship SPIFFE/IdP, gVisor/landlock/seccomp/VM, or full NIST ZTA |

**Brand:** **tracewall** (enforcement-only) — not WatchTower / observation-first OS.  
**Threat model:** [`SECURITY.md`](SECURITY.md). Process rules: [`LESSONS_LEARNED.md`](LESSONS_LEARNED.md).  
Cursor skills: [`.cursor/skills/tracewall-zta`](.cursor/skills/tracewall-zta/SKILL.md),
[`.cursor/skills/tracewall-paper`](.cursor/skills/tracewall-paper/SKILL.md).

One stable seam:

```python
from tracewall import Firewall
verdict = await firewall.check(event)   # -> FirewallVerdict (allow / block)
```

Installable without cloud services. Deterministic tiers run key-free; an optional
LLM semantic backend is available when configured. On the frozen held-out corpus
(n=27), the default policy pack reaches deterministic integrated recall **1.0**
(FPR ≈ 0.07) — see `tracewall/eval/results/` and
[`paper/EVIDENCE.md`](paper/EVIDENCE.md). That is a **regression bar**, not proof
against adaptive attacks.

## Put it on the tool-call path

Tracewall only protects calls that go through a PEP. If tools bypass it, you are
unprotected. Pair with an OS sandbox for host containment — Tracewall is the
tool gate, not the sandbox.

→ **[`docs/INTEGRATION.md`](docs/INTEGRATION.md)** — Python `guard`, MCP
`mcp_proxy` as the sole path, `GuardedToolNode`, checklist, anti-patterns.

| Pattern | When |
|---------|------|
| In-process `guard` | You own the Python tool loop |
| MCP stdio `mcp_proxy` | MCP agents (recommended sole path to the server) |
| `GuardedToolNode` | LangGraph-style named tool dispatch (no `langgraph` install) |

## Install & quickstart

**Python ≥ 3.12.** Operators: [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md).

```bash
pip install -e ".[dev]"
pytest -q
python examples/zta_demo.py
python examples/guard_demo.py
python -m tracewall.ops.explain --profile zta --tool send_email \
  --args '{"to":"x@evil.com","body":"hi"}'
python -m tracewall.ops.health --profile zta
python -m tracewall.ops.http_metrics --port 9100 --profile zta
```

Org allowlist: `TRACEWALL_ORG_DOMAINS=acme.com,corp.com`

MCP proxy (client must talk **only** to this process):

```bash
python -m tracewall.transports.mcp_proxy \
  --profile zta --agent-id my-agent --db tw.db -- \
  npx @modelcontextprotocol/server-filesystem /data
```

Optional extras: `.[llm]` (LLM semantic), `.[bench]` (AgentDojo adapter).

## Profiles

| Profile | When |
|---------|------|
| **zta** | Production: identity + caps, org allowlist default-deny, proxy-owned call tree |
| paranoid | Identity required; ZTA pack; caps optional; own call tree |
| **balanced** | Lab / eval default; fail-closed; no ZTA pack; client `_meta` chain |
| permissive | Availability-first; fail-open; fewer rules |

## What's inside

- **Identity / caps** — ledger register; `require_identity` / `require_caps` on zta  
- **Deterministic policy DSL** — YAML rules on the hot path (injection, exfil, destructive)  
- **Cross-session taint** — ledger trust updates on ALLOW/BLOCK  
- **Semantic tier** — deterministic by default; optional LLM when `LLM_API_KEY` is set  
- **Audit + metrics** — JSONL / OTel-shaped JSONL; HTTP `/metrics`

## Pipeline

```
HookEvent ─▶ L0 identity ─▶ tier-0 content ─▶ tier-1 policy
          ─▶ trust/taint gate ─(escalate)▶ tier-2 semantic ─▶ verdict ─▶ audit
```

Tier-0 flags tool-arg text only (noisy prior). Internal error → fail-safe **BLOCK**.
Detail: [`docs/FIREWALL.md`](docs/FIREWALL.md) ·
[`docs/ARCHITECTURE_OVERVIEW.md`](docs/ARCHITECTURE_OVERVIEW.md).

## Status (v0.2.0)

**Shipped:** Python `guard` + MCP stdio proxy (Content-Length + NDJSON) +
`GuardedToolNode`; profiles `zta` / `paranoid` / `balanced` / `permissive`;
ZTA allowlist pack; proxy-owned call trees; match-level `rate_exceeds`; soft-block;
ops (`explain` / `health` / `reload` / HTTP metrics); arg NFKC/ZWSP normalize +
canonical tool names.

**Open (not shipped):** signed workload identity (SPIFFE), full OTLP/gRPC exporter,
SBOM, HTTP sidecar PEP, unknown-tool / `tools/list` limits, OS sandbox / on-disk scan.

**Eval honesty:** AgentDojo has multiple suites; we measured a **banking slice**
only — see [`docs/RESULTS.md`](docs/RESULTS.md) and EVIDENCE.

Pick-up: [`HANDOFF.md`](HANDOFF.md). Evidence: [`paper/EVIDENCE.md`](paper/EVIDENCE.md).

## Doc map

| Doc | Purpose |
|-----|---------|
| [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) | Install → identity → first BLOCK |
| [`docs/INTEGRATION.md`](docs/INTEGRATION.md) | **Put it on the tool-call path** |
| [`docs/ARCHITECTURE_OVERVIEW.md`](docs/ARCHITECTURE_OVERVIEW.md) | Pipeline diagrams, tests, QA gaps |
| [`docs/RESULTS.md`](docs/RESULTS.md) | How to read eval JSON / ASR vs utility |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Profiles, audit, soft-block, BLOCK storms |
| [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md) | Enterprise readiness checklist |
| [`SECURITY.md`](SECURITY.md) | Threat model / what we don’t protect |
| [`CHANGELOG.md`](CHANGELOG.md) | Versioned notes |
| [`docs/README.md`](docs/README.md) | Full docs index |
