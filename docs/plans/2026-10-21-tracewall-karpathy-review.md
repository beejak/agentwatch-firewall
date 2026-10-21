# Tracewall Plan — Karpathy Lens Review (SEPARATE)

**Status:** Review only — **do not merge into** [`2026-10-21-tracewall-core-enhancement-test-plan.md`](2026-10-21-tracewall-core-enhancement-test-plan.md)  
**Gate outcome (2026-10-21):** Human chose **B** with §5 overrides (E1/E2 P0; delay E4; demote E5/E6). This file stays separate; status only.  
**Date:** 2026-10-21 · **Repo:** beejak/agentwatch-firewall · **Branch context:** master  
**Reviewed artifact:** [`2026-10-21-tracewall-core-enhancement-test-plan.md`](2026-10-21-tracewall-core-enhancement-test-plan.md)  
**Companion test artifact (read):** `~/.gstack/projects/beejak-agentwatch-firewall/beejak-master-test-plan-20261021.md`  
**Product truth (read):** [`HANDOFF.md`](../../HANDOFF.md), `README.md`, `SECURITY.md`, `docs/ARCHITECTURE_OVERVIEW.md` §6 QA gaps

---

## 1. Lens used

### Skill search result

Searched extensively under:

- `C:\Users\Master\.claude\skills` (including gstack trees)
- `C:\Users\Master\.cursor\skills`
- `C:\Users\Master\.claude\plugins`
- repo `.cursor/skills`
- filename/content patterns: `karpathy`, `andrej`, `karpathy-review`, `llm-curriculum`, `build-from-scratch`

**No dedicated Karpathy / Andrej / llm-curriculum / build-from-scratch skill file exists on this machine.**

Closest references (not a substitute skill file):

- gstack README cites [forrestchang/andrej-karpathy-skills](https://github.com/forrestchang/andrej-karpathy-skills) (four LLM coding failure modes).
- That repo’s `CLAUDE.md` was fetched for methodology: *Think Before Coding*, *Simplicity First*, *Surgical Changes*, *Goal-Driven Execution*.
- gstack `ETHOS.md` quotes Karpathy’s “Iron Man suit” (augment, don’t replace the human) — relevant to approval gates, not to PEP design.

### Explicit philosophy lens (used for this review)

Because no dedicated skill file was found, this review uses Karpathy’s well-known engineering philosophy **plus** the four coding rules above:

| Principle | Meaning for Tracewall planning |
|-----------|--------------------------------|
| First principles / from scratch | Can you rebuild the threat model + one rule + one test without the autoplan ceremony? |
| Prefer simple, hackable systems | YAML + `Firewall.check` + brink rows beat new frameworks (`SessionPolicyOverlay`, cert chains, schema engines) until measured need |
| Recipe → code → experiment | Close an `expected_limit` → ship flag → re-run `mcp_brink` / `robustness_stress` → only then claim |
| Avoid premature abstraction | Name the file/flag that closes the hole; don’t invent overlay types in the plan before E1 lands |
| Small verifiable increments | Make it work (deny unknown) → make it right (list filter + docs) → make it fast (latency re-measure) |
| Data/eval-driven | If brink still says `expected_limit`, you don’t “have” the capability |
| Teaching clarity | If a new contributor can’t explain the PEP in one diagram, the plan is wrong |
| Boring reliable primitives | Profile flag + allowlist check > certificate product > HITL gateway race |
| Autoresearch / tight loops | One failing eval row → one fix → green → next row |

**Four failure modes (Karpathy coding rules) applied to the plan itself:**

1. **Wrong assumptions** — plan assumes E4 “no one has done this” uniqueness before measuring whether soft-block+taint already delivers the utility story.
2. **Overcomplexity** — competitive matrix + dual-voice tables + DX scorecards + 10-step test tranche risk becoming the product.
3. **Orthogonal edits** — E5 schema, E6 certificates, E7 workspace/travel, coverage % targets are adjacent to HANDOFF open items #5 (unknown tools / `tools/list`).
4. **Imperative over declarative** — success as “160+ tests / ≥85% coverage / ≥12 properties” instead of “`L-unknown-tool-name` and `L-tools-list-unscanned` promote from `expected_limit` → `success` with artifacts.”

---

## 2. What the current plan gets right (Karpathy-aligned)

Concrete wins — keep these even if you rewrite priorities:

1. **Product truth is sharp.** §0 + premises P1–P5 match `README.md` / `SECURITY.md` / `HANDOFF.md`: tool-call PEP, not chat scanner, not OS sandbox, not full AgentDojo, not SPIFFE-as-shipped. Teaching clarity is already there.
2. **Single seam.** Keeping `tracewall/core/firewall.py` `Firewall.check` as the only decision point (P5) is the boring primitive that makes the system hackable.
3. **Approach A over gateway race.** CEO alternative A (close holes + tests, then differentiate) beats B (HTTP/SSE vs Arbitus). That’s “don’t compete on surface area.”
4. **E1 / E2 map to real measured gaps.** HANDOFF open #5 and architecture QA gaps name unknown tools + unscanned `tools/list`. Robustness IDs `L-unknown-tool-name`, `L-tools-list-unscanned` in `tracewall/eval/robustness_stress.py` are the right experiment hooks.
5. **Evidence discipline.** “New work → eval JSON → `paper/EVIDENCE.md`” and freeze posture for paper claims are data-driven and honest.
6. **Layering for E2.** List filter in `transports/mcp_proxy.py`, not inside `Firewall.check` — correct from-scratch mental model (core = verdict; transport = MCP surface).
7. **Defer crowded theater.** E8 HTTP sidecar, E9 HITL, E10 OTLP/SBOM, E11 SPIFFE as P2 matches “delete cleverness / enterprise checklist later.”
8. **Soft-block as utility lever.** `python_guard.SoftBlockResult` + banking-slice AgentDojo is the right differentiator *if measured*, not marketed.

---

## 3. What the plan overcomplicates / abstracts too early

### 3.1 Ceremony before the afternoon experiment

The autoplan is ~680 lines of CEO/Eng/DX dual voices, consensus tables, taste matrices, and dream-state timelines. Karpathy bias: that process is fine as a *restore point*, but it is not the recipe. The recipe is three sentences:

> Under `zta`/`paranoid`, unknown tools BLOCK. MCP `tools/list` can hide non-allowlisted tools. Prove both by flipping brink/robustness rows from `expected_limit` to `success`.

Everything else is optional amendment input.

### 3.2 Speculative uniqueness (E4) before tightening the loop you already have

**E4 session progressive containment** (`SessionCallTree` + ledger + ephemeral stricter egress + soft-block) is interesting, but the plan elevates it to flagship P1 *before*:

- E1/E2 are closed and measured;
- existing soft-block banking utility is re-run as a tight loop (firewall-only + optional `[bench]`);
- anyone has shown that “BLOCK then ratchet” beats “BLOCK + existing taint” on a metric.

Naming `SessionPolicyOverlay` in Eng review before E1 ships is premature abstraction.

### 3.3 P1 stack is three products

| Bet | Why it’s early |
|-----|----------------|
| **E5** JSON Schema rail (`policy/schema.py`) | Competitor match (NeMo/Arbitus), not Tracewall’s residual risk after E1. Structural validation is a different product muscle than exfil/call-tree. |
| **E6** Decision certificates + `ops/verify_decision.py` | Observability polish; agentwatch bridge fantasy. Audit JSONL already exists (`audit/sink.py`). Hash-chained certificates are “make it fancy” before “make unknown tools die.” |
| **E7** workspace/travel firewall-only shapes | Expands eval surface while banking soft-block evidence is still the honest story. Breadth without deeper learning. |

### 3.4 Test plan as checklist density

§7 and the gstack test artifact optimize for:

- **160+** pytest count (from 133)
- **≥85%** line coverage on `core/` / `policy/` / `transports/`
- **≥12** Hypothesis properties
- **≥4** concurrency cases
- R1–R10 file checklist

Karpathy critique: **counts are not capability.** Filling `test_metrics_golden.py` and `test_ledger_concurrency.py` in “Tranche A (P0)” while E1 is unfinished is orthogonal busywork. Properties on normalize are valuable *after* E1’s deny path exists, or as a 30-minute armor pass — not as a P0 co-equal bet with the hole close.

### 3.5 Competitive research as plan spine

§2’s 12-product matrix is useful *once* for positioning, but it pulls the roadmap toward “match NeMo schema / match mcpclerk list filter / unique vs Invariant.” First-principles Tracewall already knows its holes from `SECURITY.md` and brink `expected_limit` rows. Competing on matrix cells invites E5/E8 early.

---

## 4. What to cut, simplify, or reorder

### Cut from the *critical path* (keep as optional later notes)

| Cut / demote | Why |
|--------------|-----|
| E5 schema as P1 | Match-feature; ship only if a real MCP server schema poison breaks E1/E2 story |
| E6 certificates as P1 | Observability; existing JSONL + `args_hash` / `rule_id` enough for 0.3 |
| E7 workspace/travel in same wave as E1–E2 | Dilutes banking learning loop |
| Coverage % / 160+ test targets as success criteria | Replace with eval row promotions |
| R6 concurrency + R7 metrics golden in Tranche A P0 | Move behind first eval promotions (or behind E4 if E4 ships) |
| Dual-voice / DX scorecard as implementation gate | Already drafted; don’t re-litigate before coding |
| `SessionPolicyOverlay` type in design | Implement E4 (if ever) as a dict/flag on session first; extract type only if it hurts |

### Simplify

- **E1:** One profile flag `deny_unknown_tools` on `zta`/`paranoid` in `transports/profiles.py` + L0 check beside `require_caps` in `firewall.py`. One unit test. One robustness/brink promotion. Done.
- **E2:** Proxy-only filter on `tools/list` response; pass-through default on `balanced`. One new test file. Brink row. Done.
- **Tests with features:** For each bet, *one* unit + *one* eval artifact. Not eight NEW test modules in P0.

### Reorder (Karpathy loop)

```
Day 0 afternoon:  E1 work → pytest on unknown-tool → robustness/brink promote L-unknown-*
Day 1:            E2 work → test_mcp_tools_list_filter → promote L-tools-list-*
Day 1–2:          Re-measure soft-block banking (firewall-only; optional live) — log ASR/utility
Day 2+:           Decide E4 ONLY if measurement shows “need ratchet”
Later:            E5 / E6 / E7 / HTTP — backlog, not P1
```

Hour-1 / Hour-6 / Day-3–5 / Week-2 timeline in the main plan is fine *if* Week-2 is allowed to be “stop and measure” instead of “must ship schema + certificates.”

---

## 5. Core-first rewrite of priorities (through this lens)

This is an **alternate priority table**, not an edit to the main plan.

### P0 — Make the known holes die (work → measure)

| ID | Bet | Verifiable goal (Karpathy-style) |
|----|-----|----------------------------------|
| **K-E1** | Default-deny unknown tools on `zta`/`paranoid` | `L-unknown-tool-name` becomes `success` (or documented successor row) in robustness/brink; `balanced` unchanged for held-out harness |
| **K-E2** | Optional MCP `tools/list` filter | `L-tools-list-unscanned` closes or shrinks with honesty; proxy non-`tools/call` paths still pass |
| **K-T0** | Minimal tests *tied to K-E1/K-E2* | Extend `test_firewall_core.py` / `test_zta_practical.py`; NEW `test_mcp_tools_list_filter.py` only — not full Tranche A |

### P1 — Prove learning on the differentiator you already shipped

| ID | Bet | Verifiable goal |
|----|-----|-----------------|
| **K-SB** | Soft-block measurement loop (banking) | Same harness shape as today: firewall-only green; optional `[bench]` ASR↓/utility↑ logged under `tracewall/eval/results/` — **no new paper claims without EVIDENCE** |
| **K-ARMOR** | Fail-safe + polarity + normalize properties | Small files (`test_fail_safe_properties.py`, `test_normalize_properties.py`) *after* K-E1 green — regression armor, not feature theater |

### P2 — Only if P0/P1 data says “need more”

| ID | Bet | Gate to start |
|----|-----|---------------|
| **K-E4** | Session progressive containment | Written note: soft-block+taint insufficient on metric X (utility after repeated BLOCK, or re-attack rate) |
| **K-E5** | Arg JSON Schema | Concrete MCP server where allowlisted tool + bad args bypass YAML |
| **K-E6** | Decision certificates | agentwatch correlation need with a failing offline replay story |
| **K-E7** | workspace/travel firewall shapes | After banking loop is boringly reproducible |
| **K-E8+** | HTTP/SSE, HITL, OTLP, SPIFFE | Unchanged deferrals from main plan §4 / E8–E11 |

**Vs main plan:** Main puts E3 (broad Tranche A) in P0 and E4/E5/E6/E7 in P1. This lens keeps E1/E2 as true P0, demotes broad test density and E4–E7 until measurement pulls them forward.

---

## 6. Test philosophy critique + Karpathy-style eval loop

### Critique of §7 / master test plan artifact

| Main plan success signal | Problem |
|--------------------------|---------|
| 160+ tests | Inflates checklist; easy to add weak tests |
| ≥85% line coverage | Coverage ≠ threat coverage; encourages testing getters |
| ≥12 properties / ≥4 concurrency | Good *eventually*; wrong as P0 co-requisite with hole closes |
| R1→R10 linear mega-tranche | Looks complete; delays the first promoted `expected_limit` |
| Optional bench CI | Fine — keep. Don’t pretend CI density = capability |

**Are tests proving learning/capability or filling checklists?**  
As written, ~half of Tranche A is checklist armor (metrics golden, concurrency, property quotas). The half that matters is: unknown-tool BLOCK, list filter behavior, polarity/fail-safe locks, brink honesty.

### Proposed loop (tiny, measurable, iterative)

```
Recipe (one card):
  Gap:     robustness L-unknown-tool-name is expected_limit under zta
  Code:    deny_unknown_tools in profiles + L0 in firewall.py
  Test:    unit: unknown tool → BLOCK source=… ; balanced still allows pack miss
  Eval:    python -m tracewall.eval.robustness_stress
           python -m tracewall.eval.mcp_brink
  Learn:   Did the limit promote? Any harness FPR spike on balanced?
  Next:    Only then start tools/list card

Soft-block card (after E1/E2 or in parallel if disciplined):
  Gap:     Do we know soft-block utility on banking this week?
  Code:    none required if contract unchanged
  Eval:    pytest test_agentdojo_soft_block (importorskip) OR firewall-only adojo_stress
  Learn:   utility/ASR numbers in results JSON — decide if E4 is warranted
```

**One-line rule:** A test earns its keep if it would have caught a regression that re-opens an `expected_limit` or breaks soft-block utility. Otherwise it’s backlog.

---

## 7. “From scratch” mental model (afternoon test)

**Question:** Could a new contributor rebuild the threat model + one rule + one test in an afternoon?

### Ideal yes-path (what Tracewall already almost allows)

1. **Threat model (30–45 min):** Read `SECURITY.md` “In scope” + “Out of scope”; draw: compromised LLM → screened `tools/call` → `Firewall.check` → ALLOW/BLOCK. Say out loud: not chat scanner, not sandbox.
2. **One rule (60–90 min):** Add or tighten a YAML rule under `tracewall/rules/` (or a profile flag equivalent to a rule) — e.g. unknown-tool deny as L0 — wire through `Firewall` / `profiles.py`.
3. **One test (60 min):** Pytest that builds a `HookEvent` with a novel tool name under `zta` and asserts BLOCK; run `pytest -q` on that file; optionally run one brink case.

**Afternoon total:** yes — *if* the roadmap doesn’t require understanding E4 overlays, certificate verifiers, schema rails, and a 12-product matrix first.

### What the main plan does to that afternoon

| Helps | Hurts |
|-------|-------|
| Clear NOT-in-scope list | 14-decision audit trail before first commit |
| Points at real modules | P0 couples E1 with eight NEW test files |
| Eval lanes already exist | Dream-state / competitive spine distracts from HANDOFF #5 |

**Verdict:** The *product* is afternoon-learnable. The *plan document* is not. Prefer a one-page “E1 recipe card” as the onboarding path; keep the autoplan as restore/archive.

### Minimal from-scratch diagram (teaching)

```
Agent tool intent
    → PEP transport (guard | mcp_proxy tools/call | GuardedToolNode)
        → Firewall.check
            → L0 identity/caps/[deny unknown]
            → tier-0 prior (never sole BLOCK)
            → tier-1 YAML
            → taint gate → optional semantic
        → ALLOW execute | BLOCK (hard or soft-block to loop)
```

If a contributor can’t redraw that from `README.md` + `firewall.py` docstring alone, fix docs — don’t add E6.

---

## 8. Do not merge into main plan — how to use this review

### Explicit constraint

- **Do NOT** edit, append, or fold this file into  
  `docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`.
- **Do NOT** treat this review as approved scope. It is **optional amendment input** for the human Final Approval Gate (options A–E on the main plan).

### How to use

1. At the gate, if choosing **B) Approve with overrides**, consider overrides inspired by §5 (demote E5/E6/E7; narrow E3; delay E4 until K-SB measurement).
2. If choosing **D) Revise**, re-run only Eng/test ordering — not another full competitive matrix.
3. Implementation agents should prefer **recipe cards** (gap → code → eval → learn) over executing R1–R10 as a checklist.
4. Keep paper freeze: no new numbers in `paper/` without EVIDENCE + artifacts (main plan is correct; this review agrees).

### Relationship summary

| Document | Role |
|----------|------|
| Main autoplan + test plan | Authoritative pending human gate; CEO/Eng/DX restore point |
| This Karpathy review | Separate critique; simplify/reorder lens; not a second source of truth |
| HANDOFF / README / SECURITY | Product truth that both must obey |

---

## Appendix A — Top disagreements with the main plan (quick index)

1. **E4 is not P1-next** until soft-block banking is re-measured and shown insufficient.  
2. **E5/E6 leave P1** — competitor/observability pull, not residual PEP risk after E1/E2.  
3. **E3 Tranche A is too wide for P0** — ship tests that close E1/E2; defer metrics golden + concurrency quotas.  
4. **Success = promoted eval rows**, not 160+/85%/≥12 property targets.  
5. **Competitive matrix is appendix**, not a reason to pull schema/HTTP forward.

---

## Appendix B — Search log (skill discovery)

| Location | Result |
|----------|--------|
| `~/.claude/skills` | No skill named karpathy/andrej/llm-curriculum/build-from-scratch; gstack mentions Karpathy in README/ETHOS only |
| `~/.cursor/skills` | No match |
| `~/.claude/plugins` | No dedicated skill; unrelated marketplace hits only |
| repo `.cursor/skills` | `tracewall-zta`, `tracewall-paper`, superpowers copies — no Karpathy skill |
| Local clone of `andrej-karpathy-skills` | Not present; remote `CLAUDE.md` fetched for four rules |

**Skill file found for methodology?** No. Philosophy + remote Karpathy coding rules used instead.
