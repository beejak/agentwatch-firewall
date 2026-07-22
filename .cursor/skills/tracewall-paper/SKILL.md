---
name: tracewall-paper
description: >-
  Use when editing Tracewall paper prose, SHARE copy, abstracts, or metrics.
  Forces evidence→paper only: open paper/EVIDENCE.md, LESSONS_LEARNED.md §4,
  eval/results JSON, and HANDOFF Paper 2 before writing claims. Tracewall is a
  tool-call PEP — not chat scanner, NIST ZTA, sandbox, or on-disk scanner.
---

# Tracewall paper data skill

## Before any paper edit

Open, in order:

1. [`paper/EVIDENCE.md`](../../paper/EVIDENCE.md) — claim status table  
2. [`LESSONS_LEARNED.md`](../../LESSONS_LEARNED.md) §4 (research integrity) + dated appendices  
3. Relevant `tracewall/eval/results/*.json`  
4. [`HANDOFF.md`](../../HANDOFF.md) Paper 2 section  

If a sentence would assert something not **VERIFIED** in EVIDENCE, either:

- mark it **CAVEATS / UNVERIFIED** in prose, or  
- **do not write it** — change the claim, not the data.

## Product framing (must match README / SECURITY)

- Brand: **tracewall**, enforcement-only — not WatchTower / observation-first  
- Tracewall = **tool-call PEP** (ALLOW/BLOCK before screened side effects)  
- **Not** full NIST ZTA; **not** chat prompt scanner; **not** OS/kernel sandbox;
  **not** on-disk file scanner; **not** SPIFFE-as-shipped  
- Soft-block: tool never runs; can preserve **utility** while cutting ASR on
  measured banking slices  
- Profiles: `balanced` = **lab**; `zta` / `paranoid` = **prod** (allowlist pack +
  own call-tree). Do not imply every profile ships production default-deny.

## Binding metric rules

- Primary metrics: held-out corpus ablation (deterministic + optional LLM snapshot)  
- Held-out recall = **regression bar** — held-out ≠ adaptive ≠ full AgentDojo  
- KB / unit suite = regression gate, not “100% detection” headline  
- AgentDojo: **banking slice only** where logged in EVIDENCE; travel / workspace /
  slack = **UNVERIFIED**  
- Soft-block AgentDojo banking (DeepSeek, documented `direct` 1×4): ASR **1 → 0**,
  utility **1** — quote only with method + slice id from EVIDENCE  
- Robustness matrix: **18/18** (16 success + 2 expected_limit)  
- Latency: full `Firewall.check` ≈ **6.4 ms mean / p99 ≈ 9.8 ms** — never 0.011 ms
  / Sentinel multipliers without a matched e2e study  
- Integrations: MCP proxy + `examples/reference_mcp_app/` are the PEP proof;
  `GuardedToolNode` is LangGraph-*style* (no LangGraph CI claim)  
- Telemetry: HTTP `/metrics` + OTel-*shaped* JSONL VERIFIED; full OTLP/gRPC is not  

## Fraud table (reject these)

| Fraud | Symptom |
|-------|---------|
| Stale WatchTower **17/17** / **0.011 ms** | Abstract ignores held-out JSON / full-`check` microbench |
| Fantasy stack as shipped | Hermes, ruflo BFT, ClickHouse, graphify AST, SPIFFE as “implemented” |
| Full NIST ZTA | Treats allowlists + owned tree as complete ZTA product |
| Key-free = secure | Omits deterministic recall caveats / overfitting warning |
| Unrun / overclaimed AgentDojo | “We evaluate on AgentDojo” without banking-slice ASR table; implies travel/workspace |
| Held-out as adaptive proof | Equates frozen corpus recall with paraphrase / adaptive robustness |
| Apples-to-oranges latency | Rule lookup vs competitor e2e; invents sub-ms p99 |
| Client `_meta` = identity | Treats forged caller_chain as authenticated history |
| Denylist = ZTA | Claims zero-trust from attacker-IBAN probes alone |
| Prompt-scanning product | Claims Tracewall scans/blocks chat-LLM jailbreaks; tier-0 is noisy prior on tool args, never sole BLOCK |
| Sandbox as shipped | Claims gVisor/landlock/seccomp/VM containment; Tracewall is tool-call PEP only |
| On-disk scanner | Claims FS post-write / file-content scanning as Tracewall |

## After edits

Update EVIDENCE if new measurements landed. Append LESSONS if you learned a process rule.

Sibling skill for impl/ZTA: [`.cursor/skills/tracewall-zta`](../tracewall-zta/SKILL.md).
