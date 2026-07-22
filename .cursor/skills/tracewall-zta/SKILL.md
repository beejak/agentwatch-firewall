---
name: tracewall-zta
description: >-
  Use when implementing or reviewing Tracewall production/ZTA controls:
  allowlists, own call-tree, caps, rate limits, profiles, MCP PEP placement,
  metrics scrape, or OTel-shaped audit. Tracewall is a tool-call PEP only.
---

# Tracewall ZTA / practicality skill

## What Tracewall is (honest)

**Tracewall = tool-call PEP** — `Firewall.check` / `guard` / `mcp_proxy` /
`GuardedToolNode` decide ALLOW/BLOCK **before a screened tool side effect runs**.

| Is | Is **not** |
|----|------------|
| Tool-call policy enforcement point | Full NIST ZTA product |
| Gate after LLM compromise/confusion | Chat-stream prompt-injection scanner |
| Soft-block can keep utility while blocking attack tools | OS/kernel sandbox (gVisor, landlock, seccomp, VM) |
| Lab = `balanced`; prod = `zta` / `paranoid` | On-disk file content scanner |
| ZTA-adjacent profiles (allowlists, owned tree, caps) | SPIFFE / continuous IdP auth as shipped |

## Priority order (ship these, not branding)

1. **Default-deny egress** via `TRACEWALL_ORG_DOMAINS` + `policy/rules/zta/` (email/http).
2. **Proxy-owned call tree** (`SessionCallTree`, `own_call_tree=True`) — ignore client `caller_chain`.
3. **Non-bypassable PEP** — MCP proxy (or `GuardedToolNode`) must sit on the only tool path.
4. **`require_caps`** on zta profile — empty caps = BLOCK.
5. **Match-level `rate_exceeds`** — in-process blast radius only; say so in docs.
6. **Audit** — `rule_id` + `args_hash` + `context_completeness`; OTel JSONL optional.
7. **Metrics** — `Firewall.metrics` + HTTP `/metrics` (Prometheus text).

## Profile cheat sheet

| Profile | Identity | Caps | Own tree | ZTA pack | Use |
|---------|----------|------|----------|----------|-----|
| zta | required | required | yes | yes | **prod** |
| paranoid | required | optional | yes | yes | **prod** (stricter) |
| balanced | optional | optional | no | no (lab) | **lab / demos only** |
| permissive | optional | optional | no | no (subset) | debug |

## Soft-block contract

`guard(on_block="soft")` / MCP soft-block: the **tool never runs**, but the agent
loop can continue — utility on the user task can stay high while attack tools are
blocked. Prefer soft-block for AgentDojo-style utility reporting; do not claim
utility preservation without a measured slice in EVIDENCE.

## Evidence numbers (quote only these; see `paper/EVIDENCE.md`)

- Held-out corpus = **regression bar**, not adaptive proof, not full AgentDojo.
- Cross-domain robustness: **18/18** (16 success + 2 expected_limit).
- Full `Firewall.check` latency ≈ **6.4 ms mean / p99 ≈ 9.8 ms** (microbench).
- AgentDojo **banking** live (DeepSeek, soft-block, documented `direct` 1×4 slice):
  ASR **1.0 → 0.0**, utility **1.0 → 1.0**.
- Travel / workspace / slack suites: **UNVERIFIED** — do not imply measured.
- Held-out ≠ adaptive ≠ full AgentDojo.

## Reference proof

```bash
py -3.12 examples/reference_mcp_app/run_pep_demo.py
py -3.12 examples/langgraph_tool_node_demo.py
python -m tracewall.ops.http_metrics --port 9100 --profile zta
```

## Do not

- Claim **WatchTower 17/17**, **0.011 ms vs Sentinel**, or observation-first OS branding.
- Claim SPIFFE / continuous auth until a real verifier exists.
- Claim full NIST ZTA as the shipped product (profiles are ZTA-adjacent only).
- Claim full OTLP/gRPC exporter (JSONL bridge only).
- Load ZTA default-deny into `balanced` without re-running held-out + EVIDENCE.
- Treat semantic LLM as a security gate.
- Wipe `adojo_stress.json` `live[]` on firewall-only reruns.
- Claim **prompt-injection scanning of the chat LLM** as the product — tier-0 is a
  noisy prior on tool args and never sole BLOCK; Tracewall gates **tool calls**
  after compromise/confusion.
- Claim **OS sandbox / containment** (gVisor, landlock, seccomp, VM) — Tracewall is
  a tool-call PEP; pair with a real sandbox per `SECURITY.md`.
- Claim **on-disk file scanning** — only tool-call args (+ call-tree / identity) at
  the PEP are inspected.
- Imply AgentDojo travel/workspace/slack or “full suite” from banking-slice results.

## Blast-radius model (honest)

**Contains (when sole PEP + zta/paranoid):** default-deny email/http allowlists,
`require_caps`, proxy-owned call-tree (anti-forge), `rate_exceeds` (in-process),
deterministic exfil/money/bash/MINJA rules, soft-block (tool never runs).

**Does not contain:** PEP bypass, unknown/unlisted tools, host escape, model still
emitting attack text, distributed rate limits, chat-stream jailbreaks, on-disk
post-write FS watchers.

## Verify

```bash
pytest tracewall/tests/test_zta_practical.py tracewall/tests/test_mcp_profiles.py tracewall/tests/test_enterprise_ready.py -q
python -m tracewall.eval.mcp_brink
python -m tracewall.eval.robustness_stress
```

Update [`paper/EVIDENCE.md`](../../paper/EVIDENCE.md) and [`LESSONS_LEARNED.md`](../../LESSONS_LEARNED.md) when behavior changes.

Sibling skill for paper/metrics prose: [`.cursor/skills/tracewall-paper`](../tracewall-paper/SKILL.md).
