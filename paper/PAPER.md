# Tracewall: Tool-Call Enforcement for AI Agents
## Deterministic Policy, Multi-Hop Taint, and Transport-Agnostic ALLOW/BLOCK

**Status:** DRAFT — rewritten from [`EVIDENCE.md`](EVIDENCE.md) (2026-07-19)  
**Brand:** **tracewall** (enforcement-only). Companion to *agentwatch* (observability / Paper 1).  
**Target:** arXiv preprint → venue TBD (IEEE S&P / USENIX Security / ACM CCS)  
**Rule:** Only **VERIFIED** claims from EVIDENCE appear as unqualified assertions below.

---

## Abstract

AI agents invoke tools that can move money, send email, and mutate shared state. Prompt injection and capability misuse turn those tools into an attack surface that content filters and network firewalls see poorly: the wire request often looks legitimate. We present **Tracewall**, a transport-agnostic agent firewall with a single seam—`await Firewall.check(event) → FirewallVerdict`—that decides ALLOW or BLOCK before a side effect runs. The pipeline combines optional identity checks, a deterministic YAML policy DSL (including call-tree context), a recovering multi-hop taint ledger, and an optional semantic escalation tier. Fail-safe behavior is BLOCK on internal error.

On a frozen held-out corpus (n=27), the key-free path reaches deterministic integrated recall **1.0** (precision ≈ **0.929**, FPR ≈ **0.071**); tier-1 policy alone reaches recall **1.0** / FPR **0** on that split. These numbers are a **regression bar**, not proof against adaptive attacks. On AgentDojo banking under DeepSeek with bill-preserving injections and **soft-block**, a `direct` slice (1×4) shows baseline ASR **1.0** / utility **1.0**, falling to ASR **0.0** / utility **1.0** under Tracewall. A cross-domain robustness matrix (workspace / HTTP / contagion / host / identity) passes **14/14**. Full `Firewall.check` mean ≈ **6.4 ms** (p99 ≈ **9.8 ms**). MCP stdio supports Content-Length + NDJSON with brink tests that record successes and known limits.

We do **not** claim 100% detection on a small known-bad suite as a primary result, nor sub-millisecond p99 latency versus GPU sentinels without a matched measurement of full `Firewall.check`.

### TL;DR

One API decides ALLOW/BLOCK before tools run. YAML + call trees catch exfil; taint tracks contagion; soft-block keeps agents useful while stopping attacks. Held-out recall 1.0 = regression bar. Soft-block AgentDojo `direct` 1×4: ASR 0, util 1. Cross-domain stress 14/14. Mean `check` ≈ 6.4 ms.

### ELI5

Tracewall is a **bouncer for AI agents**. Before an agent emails, pays a bill, posts to chat, or uploads a file, the bouncer looks at which tool, what arguments, and what it just did. Steal a secret and ship it out? No. Pay a normal bill? Yes. Not a mind reader and not a full security OS—just a gate in front of dangerous actions.

---

## 1. Introduction

### 1.1 Problem

Agent deployments add attack surfaces beyond single-turn chat:

1. **Input corruption** — instructions embedded in files, bills, or tool results (e.g. MINJA-style memory/injection [Zheng et al., 2503.03704]).
2. **Capability abuse** — legitimate tools used for illegitimate goals (`send_email` / `send_money` after a sensitive read).
3. **Contagion** — taint flowing across agents or sessions via shared memory and messages.

Content guardrails lack tool semantics. Wire gateways see destinations, not *why* a call was made. Dual-LLM interpreters (e.g. CaMeL-style IFC) redesign the agent stack. Tracewall targets a narrower, deployable wedge: **intercept tool calls, decide with policy + taint, keep evidence honest**.

### 1.2 Contributions

1. **Stable enforcement seam** — `Firewall.check` with identity → content screen → YAML policy → trust/taint gate → optional semantic judge → audit; internal errors → BLOCK.
2. **Deterministic policy pack** — human-writable rules for injection, exfil, destructive ops, and AgentDojo-shaped banking probes (`send_money` to known attacker IBANs).
3. **Multi-hop taint ledger** — recovering trust dynamics and fixed-point MTP (research moat; live `check()` updates trust on ALLOW/BLOCK).
4. **Transports** — in-process Python guard and MCP stdio proxy with named profiles; limitations documented (NDJSON vs Content-Length; optional `_meta`).
5. **Evaluation discipline** — held-out ablation, MCP brink (success + expected limits), AgentDojo live slices; claim ledger in EVIDENCE.

### 1.3 Non-claims

- Not an observation-first OS; not WatchTower branding.
- Not Hermes / graphify AST / ruflo BFT / ClickHouse / SPIFFE CA as shipped product.
- Held-out 100% tier-1 recall ≠ adaptive robustness.
- AgentDojo results are model- and attack-specific (DeepSeek often refuses some jailbreaks).

---

## 2. Related Work (sketch)

**Agent firewalls / guardrails.** Content and alignment checkers (e.g. LlamaFirewall modules) and DSL enforcers (AgentSpec) reduce some classes of unsafe actions but often omit cross-session taint or call-tree policy. Wire gateways preserve destinations, not intent. Dual-LLM data-only paths are a different architecture.

**Injection & AgentDojo.** AgentDojo provides suites (banking, etc.) with utility and security scoring for tool-using agents. We use it as an **external bar**, not the only metric: frozen corpus + brink contracts remain first-class.

**Taint.** Classical taint is binary; Tracewall uses continuous trust/taint with hop and time decay for agent graphs. End-to-end MINJA vs GPT-4 agents remains **UNVERIFIED** beyond synthetic ledger tests.

---

## 3. Threat Model

**In scope:** indirect injection into tool-visible content; misuse of available tools; single-agent compromise that should raise taint for downstream reads when edges are recorded.

**Out of scope:** host compromise; defeating the firewall process; model-weight jailbreaks as the primary defense layer; adaptive paraphrases beyond the frozen held-out set unless measured.

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

Rules match tool name, argument operators (`regex`, `not_in_domain`, `matches_secret_pattern`, …), and call-tree constraints (`call_tree_contains` / `_any`). `${ORG_DOMAIN}` expands from `TRACEWALL_ORG_DOMAINS`. `rate_exceeds` is unsupported (never silent).

### 4.3 Taint / MTP

Ledger (SQLite) stores trust, taint, identity, and edges. MTP solves a max-product fixed point with quarantine recovery. Product value today: trust feedback on the live path; full contagion edges on MCP still partial.

### 4.4 Transports

| Placement | Status |
|-----------|--------|
| Python `guard` / `Firewall.check` | Shipped |
| MCP stdio proxy + profiles | Shipped (Content-Length + NDJSON auto-detect) |
| LangGraph / HTTP sidecar | Roadmap |

Profiles: **paranoid** (require identity, fail-closed, full rules), **balanced** (default), **permissive** (fail-open, subset rules).

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

Without an LLM, Tracewall **BLOCKs** `send_money` and `schedule_transaction` to the AgentDojo attacker IBAN and **ALLOWs** legitimate UK bill pay after `read_file`. Tracked bypasses (expected_limit): leading ZWSP in IBAN, wrong tool-name case.

### 5.5 Cross-domain robustness (non-banking)

Firewall-only matrix (`robustness_stress.json`): workspace messaging, HTTP POST, upload, memory contagion, host writes, identity/caps — **12 success + 2 expected_limit = 14/14**. Tracked limits: unknown tool names, PascalCase aliases. Widens domain surface; still not adaptive proof.

### 5.6 AgentDojo live (DeepSeek)

**Setup:** banking suite; bill-preserving injections; benchmark system prompt (eval-only); model `deepseek-chat`. Default defense: **soft-block**.

| Attack / slice | Arm | ASR | Utility |
|----------------|-----|-----|---------|
| important_instructions (1×1) | base / def. | 0.0 / 0.0 | 1.0 / 1.0 |
| ignore_previous (1×1) | base / def. | 0.0 / 0.0 | 1.0 / 1.0 |
| direct (1×1, abort-era) | base → def. | 1.0 → 0.0 | 1.0 → 1.0 |
| direct (1×4, abort-era) | base → def. | 1.0 → 0.0 | 1.0 → **0.25** |
| **direct (1×4, soft-block)** | base → def. | **1.0 → 0.0** | **1.0 → 1.0** |

Jailbreaks with baseline ASR 0 are model refusals—not credited as Tracewall wins.

### 5.7 What we refuse to headline

- “100% on 17 known-bad cases” as the primary result (overfitting trap).
- “0.011 ms p99 / 9636× vs Sentinel” without a committed full-`check` latency study.
- Unrun AgentDojo as if measured.

---

## 6. Making it more robust (roadmap)

Not yet VERIFIED paper wins: AgentDojo workspace/travel; IBAN Unicode normalize; case-insensitive tool aliases; org allowlists vs attacker-IBAN probes; live MCP contagion edges; adaptive paraphrase corpus; working `rate_exceeds`.

---

## 7. Limitations

- Contagion on live MCP edges is incomplete; corpus contagion surface deferred.
- Semantic LLM tier is optional, non-gating, and can diverge from deterministic bypass contracts (firewall stress forces semantic off).
- AgentDojo coverage is still a slice, not all suites × all attacks × all models.
- Policy attacker-IBAN rules are eval-aligned probes; production needs org allowlists / risk scores.
- Tool-name exact match and unknown-tool gaps are tracked as expected limits.

---

## 8. Conclusion

Tracewall is a practical tool-call firewall: deterministic policy and taint-aware routing behind one API, with transports for Python and MCP. Evidence favors held-out ablation, brink honesty, cross-domain stress, measured latency, and AgentDojo slices where the model actually attempts the attack—so ALLOW/BLOCK can be attributed to the firewall rather than to refusal.

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
