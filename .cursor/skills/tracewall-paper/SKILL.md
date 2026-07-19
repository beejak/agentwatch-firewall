---
name: tracewall-paper
description: >-
  Use when editing Tracewall paper prose, SHARE copy, abstracts, or metrics.
  Forces evidence→paper only: open paper/EVIDENCE.md, LESSONS_LEARNED.md §4,
  eval/results JSON, and HANDOFF Paper 2 before writing claims.
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

## Binding rules

- Brand: **tracewall**, enforcement-only — not WatchTower / observation-first  
- Primary metrics: held-out corpus ablation (deterministic + optional LLM snapshot)  
- KB / unit suite = regression gate, not “100% detection” headline  
- AgentDojo numbers only after a live run is logged in EVIDENCE  
- Latency: only quote measured `Firewall.check` / policy numbers with method  
- **ZTA wording:** Tracewall is a tool-call PDP/PEP. Do **not** claim full NIST ZTA,
  SPIFFE, or continuous IdP auth unless VERIFIED. Prefer: “ZTA-adjacent”,
  “default-deny allowlists”, “proxy-owned call tree”, “require_caps”.  
- **Profiles:** `balanced` = lab; `zta`/`paranoid` = allowlist pack + own call-tree.
  Do not imply every profile ships production default-deny.

## Fraud table (reject these)

| Fraud | Symptom |
|-------|---------|
| Stale 17/17 / 0.011ms | Abstract ignores held-out JSON |
| Fantasy stack as shipped | Hermes, ruflo BFT, ClickHouse, graphify AST, SPIFFE as “implemented” |
| Key-free = secure | Omits deterministic recall caveats / overfitting warning |
| Unrun AgentDojo | “We evaluate on AgentDojo” without ASR table |
| Apples-to-oranges latency | Rule lookup vs competitor e2e |
| Client `_meta` = identity | Treats forged caller_chain as authenticated history |
| Denylist = ZTA | Claims zero-trust from attacker-IBAN probes alone |

## After edits

Update EVIDENCE if new measurements landed. Append LESSONS if you learned a process rule.
