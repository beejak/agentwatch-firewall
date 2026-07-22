---
name: tracewall-zta
description: >-
  REQUIRED when implementing or reviewing Tracewall enforcement: profiles,
  allowlists, own call-tree, caps, rate limits, MCP PEP placement, soft-block,
  metrics/audit, or SECURITY threat-model wording. Encodes product identity
  (tool-call PEP only), production vs lab profiles, blast-radius honesty, and
  where code/rules live. Use with tracewall-paper when metrics or paper claims
  change.
---

# Tracewall ZTA / enforcement skill

This is the **project-specific** skill for shipping and reviewing Tracewall
controls. Generic Superpowers skills in this repo (`using-superpowers`, TDD,
debugging, …) teach process — they do **not** define Tracewall. For paper
metrics honesty use [`tracewall-paper`](../tracewall-paper/SKILL.md).

## Product identity (memorize)

**Tracewall = tool-call PEP**, not a chat firewall and not an OS sandbox.

```
HookEvent in → identity → content(tier-0 prior) → policy YAML → trust/taint
            → optional semantic → audit → FirewallVerdict (ALLOW|BLOCK)
```

One seam everywhere:

```python
verdict = await firewall.check(event)  # fail-safe: internal error → BLOCK
```

Transports only wrap that seam:

| Transport | Module | When |
|-----------|--------|------|
| Python `guard` | `tracewall/transports/python_guard.py` | You own the Python tool loop |
| MCP `mcp_proxy` | `tracewall/transports/mcp_proxy.py` | MCP agents — **sole path** to server |
| `GuardedToolNode` | `tracewall/transports/tool_node.py` | LangGraph-*style* named dispatch (no langgraph dep) |

**If tools bypass the PEP, Tracewall did nothing.** Pair with a real OS sandbox
for host containment; Tracewall is the tool gate only. Wire-up guide:
[`docs/INTEGRATION.md`](../../../docs/INTEGRATION.md). Threat model:
[`SECURITY.md`](../../../SECURITY.md).

### Honest is / is-not

| Is | Is not |
|----|--------|
| ALLOW/BLOCK before screened tool side effects | Full NIST ZTA product |
| Soft-block can preserve utility while blocking attack tools | Chat prompt scanner / jailbreak neutralizer |
| Lab = `balanced`; prod = `zta` / `paranoid` | On-disk file scanner |
| Default-deny egress + owned call-tree + caps/rates (zta pack) | SPIFFE / continuous IdP auth shipped |
| Tier-0 = noisy prior on **tool args**, never sole BLOCK | gVisor / landlock / seccomp / VM |

---

## Priority order (ship these, not branding)

When adding “enterprise / ZTA” work, prefer this order:

1. **Default-deny egress** — `TRACEWALL_ORG_DOMAINS` + `policy/rules/zta/` (email/http).
2. **Proxy-owned call tree** — `SessionCallTree`, `own_call_tree=True`; **ignore** client `caller_chain`.
3. **Non-bypassable PEP** — MCP proxy or `GuardedToolNode` on the **only** tool path.
4. **`require_caps`** (zta) — empty caps = BLOCK.
5. **Match-level `rate_exceeds`** — in-process blast radius only; document that limit.
6. **Audit** — `rule_id` + `args_hash` + `context_completeness`; optional OTel JSONL.
7. **Metrics** — `Firewall.metrics` + HTTP `/metrics` (Prometheus text).

Do **not** prioritize: SPIFFE, full OTLP/gRPC, distributed rate limits, LLM-as-gate,
OS sandbox productization, or loading ZTA packs into `balanced` without re-eval.

---

## Profile cheat sheet

| Profile | Identity | Caps | Own tree | ZTA pack | Use |
|---------|----------|------|----------|----------|-----|
| **zta** | required | **required** | yes | yes | **production** |
| **paranoid** | required | optional | yes | yes | **production** (stricter posture) |
| **balanced** | optional | optional | no | no | **lab / demos only** |
| **permissive** | optional | optional | no | subset (skips exfil pack) | debug |

Code: `tracewall/transports/profiles.py`.  
Rules: `tracewall/policy/rules/*.yaml` + `tracewall/policy/rules/zta/`.

**Never** claim every profile ships production default-deny. Under `balanced`,
missing `_meta` / forged `caller_chain` can starve context (brink limit
`L-context-starvation-no-meta`).

---

## Soft-block contract

- Default hard block: raise / MCP error — tool never runs; agent loop may abort.
- Soft-block: `guard(..., on_block="soft")` → `SoftBlockResult`; tool **never
  executes**, but the agent can continue (utility-friendly).
- AgentDojo adapter uses soft-block for honest util reporting.
- Soft-block does **not** stop the model from *proposing* further attacks; it
  stops screened execution.

Documented win (quote via EVIDENCE, not memory): banking DeepSeek `direct` 1×4
soft-block ASR **1→0**, util **1**. Abort-era defended util collapsed to **0.25**.

---

## Blast radius (what we contain vs miss)

**Contains when sole PEP + zta/paranoid + matching rules:**

- Default-deny email/http allowlists
- `require_caps` / empty-caps BLOCK
- Proxy-owned call-tree (anti-forge)
- In-process `rate_exceeds`
- Deterministic exfil / money / destructive-bash / MINJA-style memory rules
- Soft- or hard-block (tool never runs)

**Does not contain:**

- PEP bypass (side door to tools / raw sockets / direct `open()`)
- Unknown / unlisted tools; MCP `tools/list` unscanned
- Host escape / OS compromise / stealing ledger DB
- Chat-only jailbreaks with no screened tool call
- Distributed rate limits / multi-node consensus
- On-disk post-write FS watchers
- Model still emitting attack text (only tool execution is gated)

**Destructive policy precision:** `destructive_ops.yaml` matches tool `bash`
with specific command patterns only — **no** dedicated `write_file` /
`create_file` host-escape rule. AgentDojo drive tools ≠ host FS controls.

---

## Repo map (implementation)

| Area | Path |
|------|------|
| Core check | `tracewall/core/firewall.py` |
| Profiles | `tracewall/transports/profiles.py` |
| Guard / soft-block | `tracewall/transports/python_guard.py` |
| MCP proxy + framing | `tracewall/transports/mcp_proxy.py`, `mcp_framing.py` |
| Owned call tree | `tracewall/transports/session_chain.py` (and related) |
| Tool node | `tracewall/transports/tool_node.py` |
| Policy engine + normalize | `tracewall/policy/engine.py`, `normalize.py`, `rate.py` |
| Main rules | `tracewall/policy/rules/` |
| ZTA pack | `tracewall/policy/rules/zta/` |
| Taint / ledger | `tracewall/taint/` |
| Ops | `tracewall/ops/` (`explain`, `health`, `reload`, `http_metrics`) |
| Audit OTel JSONL | `tracewall/audit/` (`OTelJsonlAuditSink`) |
| Reference PEP demo | `examples/reference_mcp_app/` |
| LangGraph-style demo | `examples/langgraph_tool_node_demo.py` |
| ZTA demo | `examples/zta_demo.py` |
| Brink / robustness / adojo | `tracewall/eval/` |
| Enterprise checklist | `docs/ENTERPRISE.md` |
| Runbook | `docs/RUNBOOK.md` |
| Evidence ledger | `paper/EVIDENCE.md` |

---

## Evidence numbers (do not invent; see EVIDENCE)

- Held-out = **regression bar** (R=1.0 / FPR≈0.07) — not adaptive, not full AgentDojo.
- Robustness **18/18**; latency ≈ **6.4 ms mean / p99 ≈ 9.8 ms**.
- AgentDojo = **banking slice** verified; travel/workspace/slack **UNVERIFIED**.
- Reject: WatchTower 17/17, 0.011 ms vs Sentinel, SPIFFE-as-shipped, LLM chat scanning.

When behavior or metrics change → update EVIDENCE + LESSONS; use
[`tracewall-paper`](../tracewall-paper/SKILL.md) before paper/README headlines.

---

## Reference proof commands

```bash
py -3.12 examples/reference_mcp_app/run_pep_demo.py
py -3.12 examples/langgraph_tool_node_demo.py
python examples/zta_demo.py
python -m tracewall.ops.health --profile zta
python -m tracewall.ops.explain --profile zta --tool send_email --args '{"to":"x@evil.com","body":"hi"}'
python -m tracewall.ops.http_metrics --port 9100 --profile zta
python -m tracewall.transports.mcp_proxy --profile zta -- <mcp-server>
```

Org allowlist: `TRACEWALL_ORG_DOMAINS=acme.com,corp.com`

---

## Do not (implementation + claims)

- Claim SPIFFE / continuous auth without a real verifier.
- Claim full NIST ZTA as the shipped product.
- Claim full OTLP/gRPC (JSONL bridge only).
- Load ZTA default-deny into `balanced` without held-out + EVIDENCE re-run.
- Treat semantic LLM tier as a security gate.
- Wipe `adojo_stress.json` `live[]` on firewall-only reruns.
- Claim prompt-injection scanning of the chat LLM as the product.
- Claim OS sandbox / on-disk scanning as Tracewall.
- Imply AgentDojo travel/workspace/slack from banking-slice results.
- Commit `adojo_diag/`, `adojo_stress_live/`, local util scripts, or secrets.

---

## Verify after ZTA / PEP changes

```bash
pytest tracewall/tests/test_zta_practical.py tracewall/tests/test_mcp_profiles.py tracewall/tests/test_enterprise_ready.py -q
python -m tracewall.eval.mcp_brink
python -m tracewall.eval.robustness_stress
# if AgentDojo-shaped banking rules changed:
python -m tracewall.eval.adojo_stress
```

Update [`paper/EVIDENCE.md`](../../../paper/EVIDENCE.md) and
[`LESSONS_LEARNED.md`](../../../LESSONS_LEARNED.md) when behavior changes.
Features are **frozen** for paper submit unless the user explicitly unfreezes
(`HANDOFF.md`).
