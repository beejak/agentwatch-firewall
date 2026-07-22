# Tracewall: Tool-Call Enforcement for AI Agents
## Deterministic Policy, Multi-Hop Taint, and Transport-Agnostic ALLOW/BLOCK

**Author:** beejak (`beejak@users.noreply.github.com`)  
**Status:** Camera-ready / arXiv-ready draft — aligned to [`EVIDENCE.md`](EVIDENCE.md) (through 2026-07-22); features frozen for submit (v0.2.0).  
**Brand:** **tracewall** (enforcement-only). Companion to *agentwatch* (observability / Paper 1).  
**Target:** arXiv preprint → venue TBD (IEEE S&P / USENIX Security / ACM CCS)  
**Submit:** [`SUBMIT.md`](SUBMIT.md)  
**Rule:** Only **VERIFIED** claims from EVIDENCE appear as unqualified assertions below.

---

## Abstract

AI agents invoke tools that can move money, send email, and mutate shared state. Prompt injection and capability misuse turn those tools into an attack surface that content filters and network firewalls see poorly: the wire request often looks legitimate. We present **Tracewall**, a transport-agnostic **tool-call PEP** (policy enforcement point) with a single seam—`await Firewall.check(event) → FirewallVerdict`—that decides ALLOW or BLOCK **before a screened tool side effect runs**. Tracewall does **not** sit on the LLM chat stream to detect or neutralize jailbreaks; after a prompt has already confused the agent, it gates the resulting tool calls. The pipeline combines optional identity checks, a deterministic YAML policy DSL (including call-tree context), a recovering multi-hop taint ledger, and an optional semantic escalation tier (tier-0 content filtering is a noisy prior on **tool-arg text** and never sole-BLOCKs). Fail-safe behavior is BLOCK on internal error.

On a frozen held-out corpus (n=27), the key-free path reaches deterministic integrated recall **1.0** (precision ≈ **0.929**, FPR ≈ **0.071**); tier-1 policy alone reaches recall **1.0** / FPR **0** on that split. These numbers are a **regression bar**, not proof against adaptive attacks. AgentDojo defines multiple environment suites; we report a **banking slice** only. On that banking suite under DeepSeek with bill-preserving injections and **soft-block**, a `direct` slice (1×4) shows baseline ASR **1.0** / utility **1.0**, falling to ASR **0.0** / utility **1.0** under Tracewall. A cross-domain robustness matrix (workspace / HTTP / contagion / host / identity) passes **18/18** (16 success + 2 expected_limit: unknown tools, unscanned `tools/list`). Full `Firewall.check` mean ≈ **6.4 ms** (p99 ≈ **9.8 ms**). MCP stdio supports Content-Length + NDJSON with brink tests that record successes and known limits.

We do **not** claim 100% detection on a small known-bad suite as a primary result, nor sub-millisecond p99 latency versus GPU sentinels without a matched measurement of full `Firewall.check`, nor OS sandbox / on-disk scanning / SPIFFE as shipped Tracewall controls.

### TL;DR

One API decides ALLOW/BLOCK before **tools** run — a tool-call PEP, not a chat prompt scanner. YAML + call trees catch exfil; taint tracks contagion; soft-block keeps agents useful while stopping screened attacks. Held-out recall 1.0 = regression bar. Soft-block AgentDojo banking `direct` 1×4: ASR 0, util 1. Cross-domain stress 18/18. Mean `check` ≈ 6.4 ms.

### ELI5

Tracewall is a **bouncer for AI agents’ tools**. Before an agent emails, pays a bill, posts to chat, or uploads a file, the bouncer looks at which tool, what arguments, and what it just did. Steal a secret and ship it out? No. Pay a normal bill? Yes. Not a mind reader, not a chat-jailbreak scanner, and not a full OS sandbox—just a gate in front of dangerous **tool** actions after the model is already confused.

---

## 1. Introduction

### 1.1 Problem

Agent deployments add attack surfaces beyond single-turn chat:

1. **Input corruption** — instructions embedded in files, bills, or tool results (e.g. MINJA-style memory/injection [Zheng et al., 2503.03704]).
2. **Capability abuse** — legitimate tools used for illegitimate goals (`send_email` / `send_money` after a sensitive read).
3. **Contagion** — taint flowing across agents or sessions via shared memory and messages.

Content guardrails lack tool semantics. Wire gateways see destinations, not *why* a call was made. Dual-LLM interpreters (e.g. CaMeL-style IFC) redesign the agent stack. Tracewall targets a narrower, deployable wedge: **intercept tool calls, decide with policy + taint, keep evidence honest**. LLM compromise is assumed; the product is blast-radius control on screened tools, not prompt neutralization.

> **Scope footnote.** This paper is an evidence-backed description of Tracewall as a **tool-call PEP** (ALLOW/BLOCK before screened side effects)—not a chat-stream prompt scanner, OS sandbox, or on-disk file scanner. **What it proves (narrow):** only claims marked VERIFIED in [`EVIDENCE.md`](EVIDENCE.md)—held-out corpus regression bars; MCP brink success+limits; firewall-only and soft-block AgentDojo **banking** *slices* where cited; latency microbench; cross-domain stress matrix. **What it does NOT prove:** adaptive robustness; full AgentDojo (AgentDojo has multiple suites; we measured banking only); production ZTA/SPIFFE; OS sandbox / kernel containment as shipped; that Tracewall works if agents bypass the PEP; superiority vs GPU sentinels; “100% detection” marketing claims.

### 1.2 Contributions

1. **Stable enforcement seam** — `Firewall.check` with identity → content screen → YAML policy → trust/taint gate → optional semantic judge → audit; internal errors → BLOCK.
2. **Deterministic policy pack** — human-writable rules for injection, exfil, destructive ops, and AgentDojo-shaped banking probes (`send_money` to known attacker IBANs).
3. **Multi-hop taint ledger** — recovering trust dynamics and fixed-point MTP (research moat; live `check()` updates trust on ALLOW/BLOCK).
4. **Transports** — in-process Python guard, MCP stdio proxy (Content-Length + NDJSON), and LangGraph-style `GuardedToolNode`; limitations documented (`tools/list` unscanned; optional `_meta`).
5. **Evaluation discipline** — held-out ablation, MCP brink (success + expected limits), AgentDojo live slices; claim ledger in EVIDENCE.

### 1.3 Non-claims

- Not an observation-first OS; not WatchTower branding.
- Not Hermes / graphify AST / ruflo BFT / ClickHouse / SPIFFE CA as shipped product.
- Not a chat-stream prompt-injection scanner; tier-0 is a noisy prior on tool args and never sole BLOCK.
- Not OS sandbox / kernel monitoring / on-disk file scanning as shipped Tracewall controls.
- Held-out 100% tier-1 recall ≠ adaptive robustness.
- AgentDojo results are **banking-slice** and model-specific (DeepSeek often refuses some jailbreaks); AgentDojo has multiple suites—we do not claim full coverage.

---

## 2. Related Work

**Injection & misuse.** Indirect prompt injection remains a leading risk for tool-using LLMs (e.g. MINJA memory poisoning). String filters miss tool-level misuse after a sensitive read.

**Firewalls / guardrails / IFC.** LlamaFirewall-style stacks combine classifiers with secondary LLM checks; AgentSpec offers a runtime DSL without cross-session taint. Wire gateways see destinations, not call trees. Dual-LLM IFC (e.g. CaMeL) redesigns the agent; Tracewall inserts one ALLOW/BLOCK seam before tools.

**Benchmarks & taint.** AgentDojo scores utility/ASR across environments (banking, workspace, travel, …). We treat it as an **external bar** and report only measured **banking** slices—AgentDojo has multiple suites; we do not claim full coverage—plus frozen corpus, MCP brink, and a non-banking robustness matrix. Classical taint is binary; Tracewall uses continuous trust/taint with hop/time decay. End-to-end MINJA vs GPT-4 agents remains **UNVERIFIED** beyond synthetic ledger tests.

---

## 3. Threat Model

**Assumed:** the LLM may already be confused or compromised via prompts / tool results (indirect injection). Tracewall does not claim to detect or neutralize that compromise in the chat stream.

**In scope (tool-call blast radius):** misuse of available tools that pass through the PEP; secret exfil via screened send/upload/http tools after a secret-reader in the call tree; money-movement probes (`send_money` / `schedule_transaction`); destructive/remote-exec `bash` patterns when rules match; capability / rate / allowlist abuse under `zta`/`paranoid`; single-agent compromise that should raise taint for downstream reads when edges are recorded. Tier-0 content filtering flags tool-arg text as a noisy prior and never sole-BLOCKs.

**Out of scope:** host / OS / kernel compromise; defeating or bypassing the PEP; on-disk file content scanning; sandbox escape prevention (gVisor, landlock, seccomp, VM); model-weight jailbreaks as the primary defense layer; chat-only compromise with no screened tool call; adaptive paraphrases beyond the frozen held-out set unless measured; SPIFFE / continuous IdP authentication as shipped; full AgentDojo (non-banking suites) unless measured.

---

## 4. Design

### 4.1 Pipeline

```
HookEvent → L0 identity → tier-0 content (flag only)
         → tier-1 YAML policy → trust/taint route
         → (escalate) tier-2 semantic → FirewallVerdict → audit
         → ledger feedback (ALLOW→on_clean_call, BLOCK→on_taint_event)
```

`FirewallVerdict.score` is **0 bad … 1 clean**. `context_completeness` records which signals were present.

### 4.2 Policy DSL

Rules match tool name, argument operators (`regex`, `not_in_domain`, `host_not_in`, `matches_secret_pattern`, …), and call-tree constraints (`call_tree_contains` / `_any`). `${ORG_DOMAIN}` expands from `TRACEWALL_ORG_DOMAINS`. Match-level `rate_exceeds` is an in-process sliding window (not a cluster limiter).

### 4.3 Taint / MTP

Ledger (SQLite) stores trust, taint, identity, and edges. MTP solves a max-product fixed point with quarantine recovery. Product value today: trust feedback on the live path; full contagion edges on MCP still partial.

### 4.4 Transports

| Placement | Status |
|-----------|--------|
| Python `guard` / `Firewall.check` | Shipped |
| MCP stdio proxy + profiles | Shipped (Content-Length + NDJSON auto-detect) |
| LangGraph-style `GuardedToolNode` | Shipped as pattern (no `langgraph` dep) |
| Full LangGraph package / HTTP sidecar | Roadmap |

Profiles: **zta** (identity+caps, allowlist pack, proxy-owned call tree), **paranoid** (identity, allowlist pack, own call tree), **balanced** (lab default), **permissive** (fail-open, subset rules).

---

## 5. Evaluation

All primary numbers are from committed artifacts under `tracewall/eval/results/` and EVIDENCE.

### 5.1 Held-out corpus (key-free)

**Corpus:** `corpus_v0.1` test split, n=27 (13 malicious / 14 benign), deterministic semantic backend.

| Evaluator | Recall | Precision | FPR | Notes |
|-----------|--------|-----------|-----|-------|
| Tier-0 content | 0.0 | 0.0 | 0.143 | Noisy prior; never sole BLOCK |
| Tier-1 policy | **1.0** | **1.0** | **0.0** | After policy-pack expansion |
| Integrated | **1.0** | ≈0.929 | ≈0.071 | Regression bar |
| Tier-2 semantic alone | 0.462 | 0.857 | 0.071 | Ablation |

**Caveat:** not adaptive attacks; not AgentDojo.

### 5.2 Latency

Full `Firewall.check` (deterministic, warmup 40, n=400): mean **6.41 ms**, p99 **9.82 ms** (`latency_check.json`). Not a GPU-sentinel comparison.

### 5.3 MCP brink

Fourteen rows (9 success + 5 expected_limit): profiles block MINJA/exfil when configured; limits include missing `_meta` (call-tree starvation), permissive skipping exfil pack, unscanned `tools/list`. Success criterion: all `kind=success` pass **and** limits still reproduce.

### 5.4 Firewall-only AgentDojo-shaped stress

Without an LLM, Tracewall **BLOCKs** `send_money` and `schedule_transaction` to the AgentDojo attacker IBAN and **ALLOWs** legitimate UK bill pay after `read_file`. Former bypasses (ZWSP-prefixed IBAN, wrong tool-name case) are **closed** as of 2026-07-21 via NFKC/ZWSP normalize and canonical tool names—now success rows, not expected_limit.

### 5.5 Cross-domain robustness (non-banking)

Firewall-only matrix (`robustness_stress.json`): workspace messaging, HTTP POST, upload, memory contagion, host writes, identity/caps — **16 success + 2 expected_limit = 18/18**. Tracked limits: unknown tool names (MCP `tools/list` unscanned). ZWSP IBAN and PascalCase aliases are success rows after normalize/canonical. Widens domain surface; still not adaptive proof.

\subsection 5.6 AgentDojo live (DeepSeek, banking slice)

**Setup:** AgentDojo **banking** suite only (not workspace/travel/…); bill-preserving injections; benchmark system prompt (eval-only); model `deepseek-chat`. Default defense: **soft-block**.

| Attack / slice | Arm | ASR | Utility |
|----------------|-----|-----|---------|
| important_instructions (1×1) | base / def. | 0.0 / 0.0 | 1.0 / 1.0 |
| ignore_previous (1×1) | base / def. | 0.0 / 0.0 | 1.0 / 1.0 |
| direct (1×1, abort) | base → def. | 1.0 → 0.0 | 1.0 → 1.0 |
| direct (1×4, abort) | base → def. | 1.0 → 0.0 | 1.0 → **0.25** |
| **direct (1×4, soft-block)** | base → def. | **1.0 → 0.0** | **1.0 → 1.0** |

Jailbreaks with baseline ASR 0 are model refusals—not credited as Tracewall wins.

### 5.7 What we refuse to headline

- “100% on 17 known-bad cases” as the primary result (overfitting trap).
- “0.011 ms p99 / 9636× vs Sentinel” without a committed full-`check` latency study.
- Unrun AgentDojo as if measured.

---

## 6. Making it more robust (roadmap)

Not yet VERIFIED paper wins: AgentDojo workspace/travel; signed workload identity; full LangGraph package integration / HTTP sidecar PEP; adaptive paraphrase corpus; distributed (cluster) rate limits. (ZWSP/NFKC IBAN normalize and canonical tool-name aliases are shipped.)

---

## 7. Limitations

- Tracewall is a **tool-call PEP**, not a chat-stream scanner or OS sandbox; PEP bypass, unknown tools, host escape, and chat-only jailbreaks without a screened tool call remain open.
- Contagion on live MCP edges is incomplete; corpus contagion surface deferred.
- Semantic LLM tier is optional, non-gating, and can diverge from deterministic bypass contracts (firewall stress forces semantic off).
- AgentDojo defines multiple suites; our coverage is a **banking slice**, not all suites × all attacks × all models.
- Policy attacker-IBAN rules are eval-aligned probes; production needs org allowlists / risk scores.
- Unknown tool names and unscanned MCP `tools/list` remain expected limits (ZWSP IBAN and PascalCase aliases are closed).
- No SPIFFE / signed workload identity; ledger register only.

---

## 8. Conclusion

Tracewall is a practical **tool-call PEP**: deterministic policy and taint-aware routing behind one API, with transports for Python and MCP. It contains screened tool side effects after LLM compromise—not chat-stream neutralization or OS sandboxing. Evidence favors held-out ablation, brink honesty, cross-domain stress, measured latency, and AgentDojo **banking** slices where the model actually attempts the attack—so ALLOW/BLOCK can be attributed to the firewall rather than to refusal.

---

## Appendix A — Evidence map

| Claim class | Where |
|-------------|--------|
| Claim status | [`EVIDENCE.md`](EVIDENCE.md) |
| Held-out JSON | `tracewall/eval/results/corpus_v0.1_test_deterministic.json` |
| MCP brink | `tracewall/eval/results/mcp_brink.json` |
| AgentDojo stress | `tracewall/eval/results/adojo_stress.json` |
| Robustness stress | `tracewall/eval/results/robustness_stress.json` |
| Latency | `tracewall/eval/results/latency_check.json` |
| Architecture | [`docs/FIREWALL.md`](../docs/FIREWALL.md) |
| Goals | [`docs/GOALS.md`](../docs/GOALS.md) |

## Appendix B — LaTeX / PDF

- **Current PDF:** [`tracewall.pdf`](tracewall.pdf) from [`tracewall.tex`](tracewall.tex) (IEEE 2-col draft, evidence-aligned).
- `watchtower.tex` remains **stale** (old brand/metrics) — do not submit.
- How to upload: [`SUBMIT.md`](SUBMIT.md).
