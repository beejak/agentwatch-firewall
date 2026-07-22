# Docs index

| Doc | Purpose |
|-----|---------|
| **[GETTING_STARTED.md](GETTING_STARTED.md)** | Install → identity → `zta` → first BLOCK |
| **[INTEGRATION.md](INTEGRATION.md)** | **Put Tracewall on the tool-call path** (guard / MCP proxy / GuardedToolNode) |
| **[ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md)** | Pipeline / modules / network diagrams, ALLOW·BLOCK, tests done, QA gaps |
| **[RESULTS.md](RESULTS.md)** | How to read eval JSON / ASR vs utility (AgentDojo = banking slice) |
| **[RUNBOOK.md](RUNBOOK.md)** | Profiles, env, audit, BLOCK storms, soft-block |
| [FIREWALL.md](FIREWALL.md) | Architecture / pipeline / modules (detail) |
| [GOALS.md](GOALS.md) | Success **and** failure criteria (Fable) |
| [TEST_PLAN.md](TEST_PLAN.md) | Scenario lanes; harness ≠ scenario suite |
| [DETECTION.md](DETECTION.md) | What detection work fits the POC |
| [TOOLING.md](TOOLING.md) | Cursor skills, brink commands |
| [SUPPORT.md](SUPPORT.md) | Support matrix (Python / MCP / profiles / metrics) |
| [ENTERPRISE.md](ENTERPRISE.md) | Enterprise readiness checklist (honest) |
| [../SECURITY.md](../SECURITY.md) | Threat model + what we don’t protect |
| [../CHANGELOG.md](../CHANGELOG.md) | Versioned release notes |
| [../HANDOFF.md](../HANDOFF.md) | Pick-up status + roadmap (features frozen) |
| [../paper/EVIDENCE.md](../paper/EVIDENCE.md) | Claim ledger (repo → paper) |
| [../LESSONS_LEARNED.md](../LESSONS_LEARNED.md) | Process rules (incl. PEP ≠ chat scanner) |
| [../.cursor/skills/tracewall-zta/SKILL.md](../.cursor/skills/tracewall-zta/SKILL.md) | ZTA / blast-radius skill |
| [../.cursor/skills/tracewall-paper/SKILL.md](../.cursor/skills/tracewall-paper/SKILL.md) | Paper evidence→claim skill |

## Tracewall at a glance

**Tool-call PEP:** `await firewall.check(event)` → ALLOW or BLOCK on screened
tool calls — **not** a chat-stream prompt scanner, OS sandbox, or on-disk file
scanner. Tier-0 is a noisy prior on **tool args** and never sole-BLOCKs.

Fast path is L0 → content → policy → trust/taint gate; semantic only on escalate /
content-flag. PEPs: in-process `guard` / `GuardedToolNode`, or MCP stdio
`mcp_proxy` (screens `tools/call` only). Profiles: `zta` / `paranoid` /
`balanced` / `permissive`.

**First integration step:** [`INTEGRATION.md`](INTEGRATION.md).  
**Threat model:** [`../SECURITY.md`](../SECURITY.md).

```mermaid
flowchart LR
  Agent --> PEP{PEP}
  PEP -->|python_guard| FW[Firewall.check]
  PEP -->|mcp_proxy tools/call| FW
  FW -->|ALLOW| Tool
  FW -->|BLOCK| Deny[raise / soft-block / MCP isError]
```

Full diagrams, test inventory, and QA gap matrix:
[`ARCHITECTURE_OVERVIEW.md`](ARCHITECTURE_OVERVIEW.md).

## Paper

- Draft: [`paper/PAPER.md`](../paper/PAPER.md), PDF: [`paper/tracewall.pdf`](../paper/tracewall.pdf)  
- Evidence-only claims: [`paper/EVIDENCE.md`](../paper/EVIDENCE.md)  
- Author **beejak**; v0.2.0; features frozen for submit.  
- `paper/watchtower.tex` is **stale brand** — do not submit.
