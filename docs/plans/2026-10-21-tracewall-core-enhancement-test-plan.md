<!-- /autoplan restore point: C:\Users\Master\.gstack\projects\beejak-agentwatch-firewall\master-autoplan-restore-20261021-091048.md -->
# Tracewall Core Capability Enhancement + Test Plan

**Status:** GATE **B** APPROVED (Karpathy overrides) — 2026-10-21  
**Date:** 2026-10-21 · **Branch:** master · **Repo:** beejak/agentwatch-firewall  
**Platform:** GitHub · **Base branch:** master  
**UI scope:** NO (skip Design) · **DX scope:** YES (developer tool)  
**Codex:** `[codex-unavailable: binary not found]` — Claude-only dual voices  
**Mode:** SELECTIVE EXPANSION (post-paper-freeze capability + tests; no claim fraud)

**Companion (NOT merged into this file):** [Karpathy lens review](2026-10-21-tracewall-karpathy-review.md).  
**Pick-up / product truth:** [`../../HANDOFF.md`](../../HANDOFF.md) · Deferred: [`../../TODOS.md`](../../TODOS.md).

### Human decision log (Gate B)

| Item | Decision |
|------|----------|
| Premises P1–P5 | **ACCEPTED** |
| Gate option | **B** — approve with overrides |
| P0 | **E1** (deny unknown tools on zta/paranoid) + **E2** (optional MCP `tools/list` filter) |
| E3 | Tests that prove E1/E2 + fail-safe polarity only — **not** 160+/85% chase |
| E4 | **DELAYED** (session progressive containment) |
| E5 / E6 | **DEMOTED** (schema rail, decision certificates) |
| Success metric | Promoted `expected_limit`→`success` eval rows / real behavior |
| Paper claims | **FROZEN** (no invented numbers) |

---

## 0. Product truth (non-negotiable)

Tracewall is a **tool-call PEP**: `await Firewall.check(event) → FirewallVerdict` (ALLOW/BLOCK). Companion to agentwatch observability. Lab = `balanced`; prod = `zta`/`paranoid`. Soft-block can preserve utility.

**NOT:** full NIST ZTA, chat prompt scanner, OS/kernel sandbox, on-disk file scanner, SPIFFE-as-shipped, full AgentDojo, WatchTower 17/17, 0.011ms-vs-Sentinel claims.

Evidence → paper only for numbers. This plan proposes **new work to measure**, not inventing paper claims.

---

## Premises (D1 — HUMAN CONFIRMATION REQUIRED)

These are **not** auto-decided. Parent should present to user.

### Premise P1 — Problem
After prompt injection (or other LLM compromise), the residual risk that matters for Tracewall is **misused tool side effects**. The product job is gating screened `tools/call` (and in-process equivalents), not neutralizing jailbreaks on the chat stream.

### Premise P2 — Goal
Enhance **core PEP capability** (firewall / policy / transports / taint) and ship a **risk-ordered test writing plan** so capability claims stay evidence-backed. Prefer code+tests over more docs.

### Premise P3 — Competitive framing
Compete as a **deterministic, key-free, profiled tool-call PEP** with owned call-tree + soft-block utility contract + honest expected-limit evals — not as a general LLM content safety API or OS sandbox.

### Premise P4 — Freeze posture
Paper features for the *current* arXiv submit remain frozen for *paper claims*. This plan is a **post-submit / next-release** roadmap. No number enters `paper/` without an EVIDENCE row + artifact.

### Premise P5 — Scope honesty
Signed SPIFFE, OS sandbox productization, chat-stream scanning, and “full AgentDojo” are **out of scope** unless the user explicitly expands premises.

**Auto-decision pending human:** Accept P1–P5 as stated (P6 bias-to-action for planning only). User may reject/amend any premise at the gate.

---

## 1. Current state (what already exists)

| Sub-problem | Existing code |
|-------------|---------------|
| Single enforcement seam | `tracewall/core/firewall.py` `Firewall.check` |
| Wire types | `tracewall/core/signal.py` |
| Deterministic YAML DSL | `tracewall/policy/engine.py` + `rules/*.yaml` (12) + `rules/zta/*` |
| Normalize / bypass close | `policy/normalize.py` (NFKC, ZWSP, canonical tool names) |
| Rates | `policy/rate.py` in-process `RateBudget` |
| Tier-0 prior | `content/filter.py` (never sole BLOCK) |
| Tier-2 semantic | `semantic/judge.py` (deterministic default) |
| Trust/taint + MTP | `taint/ledger.py`, `taint/mtp.py` |
| Profiles | `transports/profiles.py` zta/paranoid/balanced/permissive |
| MCP stdio PEP | `transports/mcp_proxy.py` + `mcp_framing.py` |
| Own call tree | `transports/session_chain.py` |
| In-process guard / soft-block | `transports/python_guard.py` |
| LangGraph-style node | `transports/tool_node.py` |
| Ops | `ops/explain`, `health`, `reload`, `http_metrics`, `metrics` |
| Eval lanes | harness, mcp_brink, adojo_stress, robustness_stress, latency |
| Tests | **133** collected (`pytest`); AgentDojo soft-block skipped without `[bench]` |
| CI | `.github/workflows/ci.yml`: pytest + harness + mcp_brink (no AgentDojo live) |
| QA gaps documented | `docs/ARCHITECTURE_OVERVIEW.md` §6 |

---

## 2. Competitive research (2026-10-21)

Positioning is 1–2 sentences; gaps are vs Tracewall’s **PEP** scope.

| Product | Positioning | Key features | Gaps vs Tracewall | License / OSS |
|---------|-------------|--------------|-------------------|---------------|
| **Meta LlamaFirewall** | Framework of **scanners** over chat/tool/code roles (PromptGuard, AlignmentCheck, CodeShield). | Message/tool-result scanning; agent alignment replay; code shield. | Chat/reasoning scanners, not a sole-path MCP PEP with profiles/taint/call-tree. No owned call-tree ZTA pack. | OSS (PurpleLlama / LlamaFirewall) |
| **NVIDIA NeMo Guardrails** | Conversation rails + experimental **IORails tool call/result schema validation**. | Colang flows; allowlist+JSON Schema on tool calls; fail-closed structural checks. | Schema/structure focus; not exfil/call-tree/taint PEP; tool rails opt-in/experimental; not MCP stdio PEP. | Apache-2.0 OSS |
| **Guardrails AI** | I/O validators + structured generation; Hub of risk validators. | Reask/fix/filter; function-calling schema helpers; many LLM wrappers. | Output/schema reliability product, not tool-side-effect PEP or MCP proxy. | Apache-2.0 OSS (+ commercial Hub) |
| **Microsoft Prompt Shields / Foundry** | Cloud **content-safety** at user/tool/output intervention points. | Jailbreak + indirect attack classifiers; Foundry tool-call/tool-response (preview); ~50–100ms. | Proprietary cloud; classifier latency; limited tool list for moderation; not offline key-free YAML PEP. | Commercial Azure |
| **Invariant Labs** (gateway + guardrails) | Transparent **LLM+MCP proxy** with contextual dataflow rules (`ToolCall`→`ToolOutput`). | Secrets/PII; dataflow; MCP SSE/HTTP; Explorer traces; Python-ish policy language. | Strongest near-peer on contextual tool rules; often API-keyed gateway; Tracewall differentiates offline key-free + profiles + soft-block utility evidence discipline. | OSS components + hosted Explorer |
| **AgentDojo** (ETH tooling) | **Benchmark** for prompt-injection → tool misuse, not a product firewall. | Banking/workspace/travel suites; ASR/utility. | Tracewall *consumes* a slice; AgentDojo is eval, not PEP. | Academic OSS |
| **McpVanguard** | MCP security gateway (stdio/SSE/HTTP) with profiles monitor→strict. | Policy layers; auth/scope; metadata inspect; audit. | Broader gateway; Tracewall deeper trust/taint + AgentDojo-shaped evidence. | MIT OSS |
| **Arbitus** | Full MCP gateway: OPA/Rego, HITL, tools/list filter, rates, OTel, Helm. | Schema validate; response filter; supply-chain binary verify; dashboard. | Enterprise gateway breadth Tracewall lacks; Tracewall has taint/MTP + soft-block utility contract + held-out regression bar. | OSS (check repo license) |
| **tool-use-firewall** | TS PEP between agents and MCP: budgets, SQL/shell checks, approvals. | Arg validation; cost budgets; HITL. | No Python Firewall.check ecosystem / AgentDojo lanes / taint ledger. | MIT OSS |
| **MCP Guard** (permission-protocol) | YAML allow/deny/approve + audit receipts. | Observe mode; human approval. | Simpler ACL; no trust/taint/semantic tiers. | OSS |
| **mcpclerk** | Governance proxy: allowlist, quotas, redaction, hash-chained audit, HITL. | Hides denied tools from list; approve-class holds. | Strong DX for approval/audit chain; no multi-tier trust gate / soft-block ASR evidence. | OSS |
| **OpenAI Agents SDK** | Framework-native input/output/**tool guardrails** + HITL `needs_approval`. | Pre/post tool guardrails; soft rejectContent; MCP local server hooks. | Locked to OpenAI runtime; hosted tools often unguarded; not a transport-agnostic PEP library. | OSS SDK (runtime-tied) |

### Feature matrix: Tracewall today vs field

| Capability | Tracewall 0.2 | Match / Exceed / Unique opportunity |
|------------|---------------|-------------------------------------|
| Deterministic tool-arg policy (YAML) | Yes | **Match** field; **Exceed** many scanners that are LLM-only |
| Key-free hot path | Yes | **Exceed** cloud Prompt Shields / many LLM judges |
| Profiles (lab vs prod posture) | Yes (4) | **Match** McpVanguard/Arbitus; clearer lab/prod story |
| Proxy-owned call tree | Yes | **Exceed** most ACL gateways; **Match** spirit of Invariant dataflow |
| Cross-session trust/taint + MTP | Yes | **Unique opportunity** (few ship fixed-point taint with live ledger) |
| Soft-block utility contract | Yes | **Unique opportunity** if measured systematically (ASR↓ + utility↑) |
| MCP stdio sole-path PEP | Yes | **Match** gateways; **Gap:** SSE/HTTP |
| `tools/list` filter / hide denied | No (expected_limit) | **Match gap** — Arbitus/mcpclerk have it |
| Default-deny unknown tools | Partial (caps only on zta) | **Match gap** — close expected_limit |
| JSON Schema on args | No | **Match gap** — NeMo IORails / Arbitus |
| HITL approve hold | No | **Defer** (P2) — crowded; soft-block is Tracewall’s lever |
| Tool-response / document injection scan | No (by design) | **NOT in scope** (chat/tool-result scanner lane) |
| OS sandbox | No (by design) | **NOT in scope** |
| Honest expected_limit eval rows | Yes | **Unique opportunity** as product discipline |
| AgentDojo banking slice evidence | Yes (narrow) | **Exceed** gateways that ship zero ASR/utility |
| OTel-shaped audit JSONL | Yes | **Match** partially; **Gap:** full OTLP |
| Decision replay / certificate | Partial (args_hash, rule_id) | **Unique opportunity** if hardened |

---

## 3. Prioritized core enhancements

Effort: human-team vs CC+gstack. Blast radius = files/modules touched.

### P0 — Close known PEP holes (do first)

| ID | Bet | Why | Effort | Blast radius |
|----|-----|-----|--------|--------------|
| **E1** | **Default-deny unknown tools** under `zta`/`paranoid` (allowlist = caps ∪ declared tools); `balanced` stays pack-only for regression | Closes robustness `L-unknown-tool-name`; matches gateway default-deny | human: 1–2d / CC: ~2–4h | `profiles.py`, `firewall.py` or policy gate, brink/robustness expected_limit→success, docs SECURITY |
| **E2** | **Optional `tools/list` filter** on MCP proxy (hide/deny tools not in allowlist; pass-through mode remains default for balanced) | Closes `L-tools-list-unscanned`; competitors already ship this | human: 2–3d / CC: ~4–8h | `mcp_proxy.py`, framing, brink rows, INTEGRATION |
| **E3** | **Test-writing tranche A** (see §7) — property + concurrency + golden metrics | Capability without tests = claim risk | human: 2d / CC: ~4–6h | `tracewall/tests/*` new files |

### P1 — Differentiating PEP depth

| ID | Bet | Why | Effort | Blast radius |
|----|-----|-----|--------|--------------|
| **E4** | **Session progressive containment** (“no one has done this” — honest PEP bet): after soft/hard BLOCK, ratchet session taint and optionally apply ephemeral stricter egress for *subsequent* calls in same `session_id`, while soft-block keeps loop alive | Unique vs ACL gateways and chat scanners; measurable AgentDojo utility | human: 1w / CC: ~1–2d | `session_chain.py`, ledger, `python_guard`, profiles hook, adojo soft-block evals |
| **E5** | **Arg JSON Schema validation** (optional per-tool schemas file / from MCP list cache) | Match NeMo/Arbitus structural rail; fail-closed on zta | human: 3–4d / CC: ~1d | new `policy/schema.py`, proxy list cache, tests |
| **E6** | **Decision certificates** — structured, hash-chained verdict records (`rule_id`, normalized args digest, call_tree digest, profile, completeness) with offline replay verifier CLI | Unique observability bridge to agentwatch; stronger than plain JSONL | human: 3–5d / CC: ~1d | `audit/sink.py`, new `ops/verify_decision.py`, tests |
| **E7** | **Test-writing tranche B** — AgentDojo firewall shapes for workspace/travel (firewall-only, not live) + soft-block matrix | Expand evidence surface without paper fraud | human: 3–5d / CC: ~1–2d | `eval/adojo_stress.py`, robustness, optional `[bench]` CI job |

### P2 — Later / selective

| ID | Bet | Why defer |
|----|-----|-----------|
| **E8** | HTTP/SSE MCP sidecar PEP | Market match; larger transport surface; Windows/path care |
| **E9** | HITL approve-hold mode | Crowded; soft-block+ratchet covers many needs |
| **E10** | Full OTLP exporter / SBOM in CI | Enterprise checklist; not core PEP |
| **E11** | Signed identity (SPIFFE/OIDC) | Explicit non-goal until verifier design; don’t fake |

### The “no one has done this” bet (honest)

**Session progressive containment (E4):** Not a sandbox. Not a prompt scanner. After the PEP blocks a screened tool, Tracewall **changes the security posture of the rest of that session** (taint ratchet + optional ephemeral allowlist tighten) while **soft-block** returns a non-fatal tool error so benign completion paths can still succeed. Ship with AgentDojo soft-block ASR/utility measurements (new evidence rows only). Closest neighbor is Invariant dataflow rules; they don’t publish this progressive session posture + utility-preserving soft-block contract as a productized profile knob.

---

## 4. Explicit NOT in scope

- Chat-stream / jailbreak neutralization as primary control  
- OS sandbox, landlock, gVisor, seccomp, VM isolation productization  
- On-disk FS scanners / post-write watchers  
- Claiming full NIST ZTA or SPIFFE continuous auth  
- Inventing paper metrics (WatchTower 17/17, Sentinel latency, full AgentDojo)  
- Loading ZTA pack into `balanced` without re-running held-out harness  
- Distributed multi-node rate limiting (document limit only)  
- Rewriting policy DSL into OPA/Rego (P4 DRY — keep YAML unless forced)

---

## 5. Architecture notes (chosen approach)

```
                    ┌─────────────────────────────────────────┐
  HookEvent ───────▶│ Firewall.check (unchanged seam)         │
                    │  L0 identity/caps (+ unknown-tool deny) │
                    │  tier-0 prior → tier-1 YAML → gate      │
                    │  (+ optional schema rail before/with T1)│
                    │  semantic → audit/certificate → metrics │
                    └───────────────┬─────────────────────────┘
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
     python_guard              mcp_proxy                 GuardedToolNode
     soft-block +              tools/call +              named dispatch
     session ratchet           optional tools/list
                               filter (E2)
```

**Principles:** Keep `Firewall.check` the only decision seam (P5). Put unknown-tool and schema as **explicit gates** with profile flags, not silent magic. `tools/list` filtering stays in **transport** (proxy), not core, so in-process guard remains framework-agnostic. Progressive containment reads/writes **ledger + SessionCallTree** only — no OS hooks.

**Windows:** aiosqlite / tempfile paths already have operator notes; new tests should use `tmp_path` and avoid POSIX-only shell assumptions in unit tests; CI remains ubuntu-latest — add a documented local Windows pytest smoke in DX checklist (not required in GitHub Actions for P0).

---

## 6. Dream state

```
CURRENT (0.2.0)          THIS PLAN (0.3.x)              12-MONTH IDEAL
─────────────────        ─────────────────             ────────────────
stdio MCP PEP            + list filter + unknown deny  + HTTP/SSE sidecar
YAML exfil/ZTA pack      + schema rail                 + signed identity opt-in
soft-block contract      + session progressive         + HITL optional
taint/MTP                + decision certificates       + agentwatch correlation UX
banking slice evidence   + workspace/travel firewall   + measured adaptive corpus
133 pytest               + property/concurrency/golden + Windows CI optional
honest expected_limits   + close 2 limits as success   + still publish remaining limits
```

---

## 7. Test writing plan (concrete)

### 7.1 Goals / coverage targets

| Suite | Target | Success criteria |
|-------|--------|------------------|
| Unit/integration pytest | **160+** tests (from 133); core modules line coverage **≥85%** on `core/`, `policy/`, `transports/` (measure with `pytest --cov` once added to `[dev]`) | All green on `pip install -e ".[dev]"` |
| Property / hypothesis | New file; **≥12** properties | Normalize idempotence; fail-safe; score polarity; rate monotonic |
| Concurrency | New file; **≥4** cases | Ledger + SessionCallTree under concurrent sessions |
| Regression / eval | Brink + robustness + harness stay green; promote closed limits | Exit 0; EVIDENCE updated only with artifacts |
| AgentDojo | Soft-block stays `importorskip`; optional CI job with `[bench]` | No collection failure without bench |
| MCP brink | Add rows for E1/E2 | success or expected_limit honesty preserved |

### 7.2 Risk-ordered implementation order

1. **R1 — Fail-safe & polarity locks** (regression armor before features)  
   - Extend `test_firewall_kb.py` / `test_p0_correctness.py`  
   - Add `tracewall/tests/test_fail_safe_properties.py`  
2. **R2 — Normalize & alias properties**  
   - `tracewall/tests/test_normalize_properties.py` (ZWSP/NFKC/canonical roundtrips)  
3. **R3 — Profile contract table tests**  
   - Expand `test_mcp_profiles.py` + `test_zta_practical.py` for E1 flags  
4. **R4 — MCP list filter + unknown-tool** (with E1/E2 code)  
   - `tracewall/tests/test_mcp_tools_list_filter.py`  
   - Update brink JSON expectations via `mcp_brink` scenarios  
5. **R5 — Soft-block + session ratchet** (with E4)  
   - `tracewall/tests/test_session_progressive.py`  
   - Extend `test_agentdojo_soft_block.py` (still importorskip)  
6. **R6 — Concurrency / Windows tempfile**  
   - `tracewall/tests/test_ledger_concurrency.py`  
7. **R7 — Metrics golden + explain CLI**  
   - `tracewall/tests/test_metrics_golden.py`  
8. **R8 — Firewall-only workspace/travel shapes**  
   - Extend `adojo_stress` / `robustness_stress` (no live LLM required)  
9. **R9 — Optional `[bench]` CI job** (non-blocking or nightly)  
10. **R10 — Decision certificate verify** (with E6)

### 7.3 File path checklist (new / touch)

| Path | Action |
|------|--------|
| `tracewall/tests/test_fail_safe_properties.py` | **NEW** |
| `tracewall/tests/test_normalize_properties.py` | **NEW** |
| `tracewall/tests/test_mcp_tools_list_filter.py` | **NEW** |
| `tracewall/tests/test_session_progressive.py` | **NEW** |
| `tracewall/tests/test_ledger_concurrency.py` | **NEW** |
| `tracewall/tests/test_metrics_golden.py` | **NEW** |
| `tracewall/tests/test_schema_rail.py` | **NEW** (E5) |
| `tracewall/tests/test_decision_certificate.py` | **NEW** (E6) |
| `tracewall/tests/test_firewall_core.py` | extend unknown-tool |
| `tracewall/tests/test_mcp_proxy.py` | list filter / forward |
| `tracewall/tests/test_adojo_stress.py` | new scenarios |
| `tracewall/tests/test_robustness_stress.py` | promote closed limits |
| `tracewall/eval/mcp_brink.py` (+ results JSON) | new rows |
| `tracewall/eval/adojo_stress.py` | workspace/travel firewall shapes |
| `.github/workflows/ci.yml` | keep pure job; add optional `bench` job with `continue-on-error` or workflow_dispatch |
| `docs/TEST_PLAN.md` | sync lanes |
| `paper/EVIDENCE.md` | only after measured artifacts |

### 7.4 CI notes

- Default CI stays **infra-free**: `pip install -e ".[dev]"` → `pytest -q` → harness → brink.  
- Keep `pytest.importorskip("agentdojo")` pattern in soft-block test.  
- Do **not** require `LLM_API_KEY` on PR CI.  
- Optional job: `pip install -e ".[dev,bench]"` + soft-block + firewall-only adojo stress.  
- Windows: document `pytest -q` locally; GitHub Windows matrix is P2.

### 7.5 Test diagram (codepaths → coverage)

```
Firewall.check
  ├─ identity/caps/unknown-deny ── unit: test_firewall_core, test_zta_practical, NEW fail_safe
  ├─ normalize args/tool ──────── property: NEW normalize_properties; enterprise_ops
  ├─ tier-1 YAML match ────────── kb + p0 + brink
  ├─ trust/taint gate ─────────── kb + taint_mtp + NEW session_progressive
  ├─ semantic ─────────────────── test_semantic_tier (+ mocked llm)
  └─ audit/metrics/certificate ── enterprise_ready + NEW metrics_golden + decision_certificate

python_guard soft-block ───────── test_guard + test_agentdojo_soft_block [bench skip]
mcp_proxy tools/call ──────────── test_mcp_proxy + brink
mcp_proxy tools/list filter ───── NEW test_mcp_tools_list_filter + brink
GuardedToolNode ───────────────── test_enterprise_ready
SessionCallTree forge ignore ──── test_zta_practical + brink
adojo/robustness matrices ─────── test_*_stress + eval JSON artifacts
```

---

## Phase 1 — CEO Review (SELECTIVE EXPANSION)

### 0A Premise challenge
Premises P1–P5 are **sound** for a tool-call PEP. Risk if wrong: building chat scanners (dilutes brand) or sandbox theater (unshippable). Challenge only if user wants “full security platform” — that would be a different product.

### 0B Existing leverage
See §1. Do **not** rebuild ACL gateway from scratch; extend Firewall.check + proxy + eval lanes.

### 0C Dream state
See §6.

### 0C-bis Alternatives

| Approach | Effort | Risk | Pros | Cons |
|----------|--------|------|------|------|
| A. Core PEP holes + tests first (E1–E3), then E4 unique bet | Med | Low | Honest; matches QA gaps | Slower “wow” marketing |
| B. HTTP gateway race vs Arbitus | High | High | Market checkbox | Dilutes PEP; Windows/transport debt |
| C. Docs/enterprise checklist only | Low | Med | Cheap | Violates user intent (core > docs) |

**Auto-decide:** **A** (P1 completeness + P3 pragmatic + P5 explicit).

### 0D Scope decisions
Approve E1–E3 in blast radius. Approve E4 as flagship differentiator. Defer E8–E11 to TODOS. E5–E6 after E4 skeleton.

### 0E Temporal
HOUR 1: unknown-tool flag + tests. HOUR 6: list filter prototype. DAY 3–5: session ratchet. WEEK 2: schema + certificates.

### 0F Mode
SELECTIVE EXPANSION confirmed.

### CEO dual voices

#### CLAUDE SUBAGENT (CEO — strategic independence) `[subagent-only]`
1. Right problem: yes — tool misuse after compromise.  
2. Premises: solid; watch freeze vs next-release confusion.  
3. 6-month regret: shipping HTTP gateway without closing unknown-tool/`tools/list`.  
4. Alternatives: don’t chase Prompt Shields classifiers.  
5. Competitive: Invariant/Arbitus are real; Tracewall wins on offline PEP + soft-block evidence + taint — lean in.  
Severity: **high** if E1/E2 slip behind E8.

#### CODEX SAYS (CEO) `[codex-unavailable]`
N/A — binary missing. Proceed Claude-only.

#### CEO CONSENSUS TABLE
```
CEO DUAL VOICES — CONSENSUS TABLE:
═══════════════════════════════════════════════════════════════
  Dimension                           Claude  Codex  Consensus
  ──────────────────────────────────── ─────── ─────── ─────────
  1. Premises valid?                   YES     N/A    [subagent-only]
  2. Right problem to solve?           YES     N/A    [subagent-only]
  3. Scope calibration correct?        YES     N/A    [subagent-only]
  4. Alternatives sufficiently explored? YES   N/A    [subagent-only]
  5. Competitive/market risks covered? YES     N/A    [subagent-only]
  6. 6-month trajectory sound?         YES*    N/A    [subagent-only]
═══════════════════════════════════════════════════════════════
* Caveat: E4 uniqueness claim must stay measurement-backed.
```

### CEO Sections 1–10 (compressed full-depth findings)

1. **Strategy fit:** Core-first matches HANDOFF open list (unknown tools, tools/list).  
2. **Error & Rescue Registry:**

| Error | Rescue |
|-------|--------|
| Unknown tool ALLOW under zta | E1 default-deny + brink success row |
| tools/list schema poison | E2 filter + expected_limit honesty until shipped |
| Soft-block kills utility | E4 + AgentDojo soft matrix; keep on_block knobs |
| Paper claim creep | EVIDENCE gate; skills already encode |
| Schema false BLOCK (benign) | E5 optional on balanced; on by default only zta |
| Session ratchet sticky too hard | Profile flag + reset on new session_id |

3. **Failure modes:** PEP bypass remains untestable fully (document); don’t pretend.  
4. **Dependencies:** No new mandatory cloud APIs. Optional `jsonschema` lib for E5.  
5. **Metrics:** New work → new eval JSON → EVIDENCE; never reverse.  
6. **Team:** Solo beejak — sequence E1→E3→E4.  
7. **Competitive:** See §2.  
8. **Design (UI):** N/A.  
9. **DX:** Developer tool — Phase 3.5 required.  
10. **Completion:** Proceed Eng.

### NOT in scope (CEO)
See §4 + E8–E11 deferred.

### CEO Completion Summary
| Item | Result |
|------|--------|
| Mode | SELECTIVE EXPANSION |
| Premises | P1–P5 awaiting human |
| Top bets | E1, E2, E4, E3 tests, E5 |
| Deferred | HTTP sidecar, HITL, SPIFFE, OTLP |
| Voices | `[subagent-only]` `[codex-unavailable]` |

**Phase 1 complete.** Codex: unavailable. Claude subagent: 1 high (don’t delay E1/E2). Consensus: subagent-only. Passing to Phase 2.

---

## Phase 2 — Design Review

**SKIPPED — no UI scope** (no component/screen/form/dashboard in plan intent; Tracewall is library/CLI/MCP).

**Phase 2 complete.** Skipped, no UI scope. Passing to Phase 3.

---

## Phase 3 — Eng Review

### Step 0 Scope challenge (code-grounded)
Read: `firewall.py`, `policy/engine.py`, `normalize.py`, `mcp_proxy.py` (via architecture), tests inventory, CI. Complexity check: E1 is small; E2 medium (MCP method routing); E4 medium-high (state interactions with ledger); E5 needs schema source of truth; E6 audit format versioning.

**Finding:** Do not put `tools/list` filtering inside `Firewall.check` — wrong layer (P5). Unknown-tool deny may live in L0 next to caps **or** as first YAML-equivalent gate with profile flag.

**Auto-decide:** Unknown-tool in L0 when `deny_unknown_tools=True` (zta/paranoid). List filter in proxy only.

### Eng dual voices

#### CLAUDE SUBAGENT (eng — independent) `[subagent-only]`
1. Architecture: sound if list filter stays in transport.  
2. Edge: concurrent session ratchet; Windows sqlite; schema from stale tools/list.  
3. Tests: §7 is the right spine; add concurrency before declaring E4 done.  
4. Security: deny_unknown must not break MCP initialize; filter must not break non-tools methods.  
5. Hidden complexity: ephemeral profile overlay (E4) — prefer explicit `SessionPolicyOverlay` object over mutating global profile.

#### CODEX SAYS (eng) `[codex-unavailable]`
N/A.

#### ENG CONSENSUS TABLE
```
ENG DUAL VOICES — CONSENSUS TABLE:
═══════════════════════════════════════════════════════════════
  Dimension                           Claude  Codex  Consensus
  ──────────────────────────────────── ─────── ─────── ─────────
  1. Architecture sound?               YES*    N/A    [subagent-only]
  2. Test coverage sufficient?         YES†    N/A    [subagent-only]
  3. Performance risks addressed?      YES     N/A    [subagent-only]
  4. Security threats covered?         PARTIAL N/A    [subagent-only]
  5. Error paths handled?              YES     N/A    [subagent-only]
  6. Deployment risk manageable?       YES     N/A    [subagent-only]
═══════════════════════════════════════════════════════════════
* if SessionPolicyOverlay explicit
† after §7 tranche A+B implemented
PARTIAL: PEP bypass remains threat-model only
```

### Section 1 Architecture ASCII

```
[Agent]--tools/call-->[mcp_proxy]--list filter?--+-->[Firewall.check]<--guard/ToolNode
                              |                  |         |
                              +--non-call bypass-+         +--> ledger/taint
                                                           +--> policy YAML
                                                           +--> audit/cert
                                                           +--> metrics
[SessionCallTree]----own chain----^
[SessionPolicyOverlay E4]---------^
```

Coupling: overlay must be session-scoped; never process-global. Scaling: in-process rates stay single-node (document).

### Section 2 Code quality
Reuse `canonical_tool_name`, `RateBudget`, brink expected_limit pattern. Avoid second policy language (P4).

### Section 3 Test Review
Full plan in §7. Artifact also at:
`~/.gstack/projects/beejak-agentwatch-firewall/beejak-master-test-plan-20261021.md`

**Auto-decisions on gaps:** Add all R1–R8 tests (P1). Defer Windows CI matrix (P3). Keep agentdojo optional skip (existing pattern).

### Section 4 Performance
Unknown-tool + schema = O(1)/O(schema) on hot path; keep p99 budget — re-run `eval/latency` after E1/E5; target stay **p99 < 15ms** deterministic (current ~9.8ms) or document delta in EVIDENCE (no Sentinel comparisons).

### Eng Failure modes registry

| Mode | Critical? | Mitigation |
|------|-----------|------------|
| Stale tools/list allowlist | Yes | Refresh on list; fail-closed option |
| Ratchet never resets | Med | New session_id clears overlay |
| Schema blocks all tools | High | Feature flag; balanced off |
| Certificate verify false negative | Med | Version field + golden tests |
| PEP bypass | Critical (inherent) | Docs + integration checklist only |

### Eng Completion Summary
Architecture approved with overlay explicitness. Test plan mandatory companion to E1–E4.

**Phase 3 complete.** Codex: unavailable. Claude: 2 medium (overlay design, stale list). Passing to Phase 3.5.

---

## Phase 3.5 — DX Review (DX POLISH)

### Step 0 DX scope
Product type: **Python library + CLI + MCP proxy** (developer tool). Persona: agent-platform engineer wiring sole-path PEP.

**TTHW today:** ~5–10 min (`pip install -e ".[dev]"` → pytest → `explain` / zta_demo).  
**Target:** **<5 min** to first intentional BLOCK via copy-paste from GETTING_STARTED (already close).

Initial DX completeness: **7/10**. Gaps: unknown-tool footguns, list filter discovery, progressive containment knobs need guessable flags.

### DX dual voices

#### CLAUDE SUBAGENT (DX) `[subagent-only]`
1. TTHW OK if demos stay green.  
2. Naming: `deny_unknown_tools`, `filter_tools_list`, `session_ratchet` — explicit.  
3. Errors: every new BLOCK reason must be `explain`-visible with fix hint.  
4. Docs: INTEGRATION gets E1/E2/E4 sections; avoid new doc sprawl.  
5. Escape hatches: balanced unchanged; flags off by default on balanced.

#### CODEX SAYS (DX) `[codex-unavailable]`
N/A.

#### DX CONSENSUS TABLE
```
DX DUAL VOICES — CONSENSUS TABLE:
═══════════════════════════════════════════════════════════════
  Dimension                           Claude  Codex  Consensus
  ──────────────────────────────────── ─────── ─────── ─────────
  1. Getting started < 5 min?          YES     N/A    [subagent-only]
  2. API/CLI naming guessable?         YES*    N/A    [subagent-only]
  3. Error messages actionable?        PARTIAL N/A    [subagent-only]
  4. Docs findable & complete?         YES†    N/A    [subagent-only]
  5. Upgrade path safe?                YES     N/A    [subagent-only]
  6. Dev environment friction-free?    YES     N/A    [subagent-only]
═══════════════════════════════════════════════════════════════
* if flag names stay snake_case consistent with require_caps
† update INTEGRATION/RUNBOOK only — not a new book
```

### Developer journey map

| Stage | Today | Plan delta |
|-------|-------|------------|
| Discover | README honesty table | Keep |
| Install | pip -e .[dev] | Unchanged |
| Hello BLOCK | explain / zta_demo | Add unknown-tool demo line |
| Integrate | INTEGRATION.md | List filter + sole-path checklist |
| Configure | profiles + ORG_DOMAINS | New knobs documented |
| Debug | explain/health/metrics | Certificate verify CLI |
| Eval | brink/adojo | New rows |
| Upgrade | CHANGELOG | Semver 0.3; balanced stable |
| Production | zta profile | deny_unknown on |

### Empathy narrative
“I pip installed, ran explain, saw a BLOCK. I pointed MCP at the proxy. I need to know why an unknown tool was denied and how to allow it via caps — one error string, one doc anchor.”

### DX Scorecard (0–10)

| Dimension | Score | Notes |
|-----------|-------|-------|
| 1 Getting started | 8 | Keep demos |
| 2 API/CLI naming | 8 | Explicit flags |
| 3 Error messages | 6 → 8 | Require reason+fix on E1/E2/E4 |
| 4 Docs IA | 8 | INTEGRATION updates only |
| 5 Examples | 7 → 8 | One progressive-containment demo |
| 6 Upgrade safety | 8 | balanced frozen behavior |
| 7 Escape hatches | 9 | profile flags |
| 8 Debug tooling | 7 → 9 | explain + verify_decision |

**Overall DX:** 7.5/10 → target **8.5/10** after checklist.

### DX Implementation Checklist
- [ ] Flag names in profiles + `--help` on mcp_proxy  
- [ ] BLOCK reasons include allow-fix (`register caps`, `add to allowlist`)  
- [ ] INTEGRATION.md § unknown tools / list filter / session ratchet  
- [ ] RUNBOOK: ratchet storm / how to reset session  
- [ ] GETTING_STARTED: one new copy-paste BLOCK  
- [ ] CHANGELOG 0.3.0 section when shipping  
- [ ] Windows note: pytest path in SUPPORT.md  

**Phase 3.5 complete.** DX overall: 7.5→8.5 target. TTHW: ~7 → <5 min. Passing to Phase 4.

---

## Cross-phase themes

**Theme: Close expected_limits before new transports** — CEO + Eng. High-confidence.  
**Theme: Soft-block/utility is the differentiator — measure it** — CEO + DX.  
**Theme: Codex unavailable** — all dual-voice tables degraded to `[subagent-only]`.

---

## Taste decisions (surface at Final Gate)

| # | Choice | Recommendation | Alt |
|---|--------|----------------|-----|
| T1 | Flagship unique bet = E4 session progressive containment vs E6 certificates-first | **E4 first** (P1 user-visible security) | E6 first (observability-first) |
| T2 | `deny_unknown_tools` default on for `paranoid` only vs both zta+paranoid | **Both zta+paranoid** (P1 completeness) | paranoid-only (gentler) |
| T3 | Optional bench CI job vs never in CI | **workflow_dispatch / nightly optional job** | never |

No User Challenge against user’s stated direction (core PEP + competitive + tests). Models agree with user intent.

---

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|----------------|-----------|-----------|----------|
| 1 | 0 | Skip Design phase | Mechanical | — | No UI scope | Running empty design review |
| 2 | 0 | Run DX phase | Mechanical | — | Developer tool | Skip DX |
| 3 | 0 | Codex unavailable → Claude-only | Mechanical | — | No binary | Block pipeline |
| 4 | 1 | Mode SELECTIVE EXPANSION | Mechanical | P1 | Post-freeze capability | FULL REWRITE / REDUCE |
| 5 | 1 | Approach A (holes+tests then E4) | Taste→rec | P1/P3 | Beat gateways on honesty | B HTTP race |
| 6 | 1 | Defer HITL/SPIFFE/HTTP | Mechanical | P3 | Crowded / non-goal | Build gateway now |
| 7 | 1 | Accept premises for planning | Mechanical* | P6 | *Human still gates D1 | Rewrite problem as chat scan |
| 8 | 3 | Unknown-tool in L0; list filter in proxy | Mechanical | P5 | Layering | Filter inside Firewall.check |
| 9 | 3 | Explicit SessionPolicyOverlay | Taste→rec | P5 | Avoid global mutate | Mutate profile in place |
| 10 | 3 | Require §7 tests with E1–E4 | Mechanical | P1 | Claim discipline | Features without tests |
| 11 | 3 | Latency re-measure after E1/E5 | Mechanical | P1 | EVIDENCE honesty | Skip microbench |
| 12 | 3.5 | Update INTEGRATION not new book | Mechanical | P4/P5 | DX without doc sprawl | New DX site |
| 13 | 3.5 | Error = problem+cause+fix | Mechanical | P1 | DX completeness | Opaque BLOCK |
| 14 | 4 | Plan path docs/plans/ | Mechanical | P5 | Repo-local deliverable | Only ~/.gstack |

\* Premise acceptance for drafting only; human confirmation required.

---

## Deferred to TODOS.md (suggested bullets)

- HTTP/SSE MCP sidecar PEP  
- HITL approve-hold mode  
- SPIFFE/OIDC identity verifier  
- Full OTLP/gRPC exporter + SBOM CI  
- GitHub Actions Windows matrix  
- Adaptive paraphrase corpus (measure before claim)  
- Distributed rate limits  

---

## Implementation Tasks (aggregated)

- [x] **T-E1 (P0)** — `deny_unknown_tools` on zta/paranoid  
- [x] **T-E2 (P0)** — optional MCP `tools/list` filter  
- [x] **T-E3 (P0, narrowed)** — tests proving E1/E2 + fail-safe polarity  
- [x] **T-E4** — Session progressive containment — **SHIPPED** (v0.3.0; optional / prod on)  
- [ ] **T-E5** — JSON Schema rail — **DEMOTED** (Gate B)  
- [ ] **T-E6** — decision certificates — **DEMOTED** (Gate B)  
- [ ] **T-E7** — workspace/travel firewall-only shapes — backlog  

```
/autoplan gate: B APPROVED (Karpathy overrides) 2026-10-21
status: P0 E1+E2+E4 SHIPPED (v0.3.0); E5/E6 demoted; paper frozen
```


---

## Final Approval Gate material (for parent → user)

### Plan summary
Post-submit Tracewall plan: close unknown-tool and tools/list holes, write risk-ordered tests, then ship session progressive containment as the honest unique PEP bet — without becoming a chat scanner or OS sandbox, and without inventing paper numbers.

### Decisions: 14 logged (11 mechanical, 3 taste, 0 user challenges)

### Taste choices for user
1. **T1** E4 progressive containment first vs E6 certificates first → recommend E4  
2. **T2** deny_unknown on zta+paranoid vs paranoid-only → recommend both  
3. **T3** optional bench CI vs never → recommend optional/nightly  

### Review scores
- CEO: SELECTIVE EXPANSION; premises await human; Approach A  
- CEO Voices: `[subagent-only]` / `[codex-unavailable]`  
- Design: skipped (no UI)  
- Eng: architecture OK with overlay+layering constraints; tests mandatory  
- Eng Voices: `[subagent-only]` / `[codex-unavailable]`  
- DX: 7.5→8.5; TTHW <5 min target  
- DX Voices: `[subagent-only]` / `[codex-unavailable]`  

### Gate options (A–E)
- **A)** Approve as-is (accept all recommendations)  
- **B)** Approve with overrides (specify T1/T2/T3 changes)  
- **C)** Interrogate (ask about a specific decision)  
- **D)** Revise (plan needs changes — re-run affected phases)  
- **E)** Reject (start over)

---

## GSTACK REVIEW REPORT

```
/autoplan complete
plan: docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md
restore: ~/.gstack/projects/beejak-agentwatch-firewall/master-autoplan-restore-20261021-091048.md
test-plan-artifact: ~/.gstack/projects/beejak-agentwatch-firewall/beejak-master-test-plan-20261021.md
ui_scope: no
dx_scope: yes
codex: unavailable
status: AWAITING_HUMAN (premises D1 + gate A–E)
phases: CEO done | Design skipped | Eng done | DX done
```
```
