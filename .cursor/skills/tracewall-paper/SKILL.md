---
name: tracewall-paper
description: >-
  REQUIRED when editing Tracewall paper prose, abstracts, SHARE/submit copy,
  metrics tables, PDF claims, or any public evaluation statement. Encodes the
  evidence→paper protocol, product non-claims, and the only numbers safe to
  quote. Open this skill before changing paper/PAPER.md, paper/tracewall.tex,
  paper/EVIDENCE.md claim wording, or README metric headlines.
---

# Tracewall paper / evidence skill

This is the **project-specific** skill for research integrity and public claims.
Generic process skills (`using-superpowers`, `brainstorming`, …) do **not** encode
Tracewall product truth — open **this** file (and `tracewall-zta` for impl).

## Hard gate (do this first)

Before writing or rewriting **any** metric, capability, or comparison sentence:

1. Open [`paper/EVIDENCE.md`](../../../paper/EVIDENCE.md) — claim status table.
2. Open [`LESSONS_LEARNED.md`](../../../LESSONS_LEARNED.md) §4 + dated appendices.
3. Open the matching JSON under `tracewall/eval/results/` (not memory).
4. Open [`HANDOFF.md`](../../../HANDOFF.md) Paper / freeze notes.

**Rule:** evidence repo → paper. Never invent a number in LaTeX/Markdown first.
If EVIDENCE marks it **UNVERIFIED** / **REFUTED** / **CAVEATS**, the paper must
say so or omit the claim.

Status vocabulary (copy into prose when needed):

| Status | Meaning for agents |
|--------|--------------------|
| VERIFIED | May assert unqualified **if** method/slice matches the artifact |
| CAVEATS | Assert only with the caveat inline |
| UNVERIFIED | Do not claim; mark future work |
| REFUTED | Actively reject; do not revive WatchTower-era numbers |

---

## Product identity (must appear correctly)

**Tracewall** is a transport-agnostic **tool-call PEP** (policy enforcement point):

```
Agent proposes tool → Firewall.check / guard / mcp_proxy / GuardedToolNode
                   → ALLOW → tool may run
                   → BLOCK → screened tool never runs (hard raise or soft-block)
```

| Tracewall **is** | Tracewall is **not** |
|------------------|----------------------|
| ALLOW/BLOCK on screened **tool calls** | Full NIST Zero Trust Architecture product |
| Containment of screened side effects after LLM compromise | Chat-stream prompt-injection scanner / jailbreak neutralizer |
| Soft-block: tool blocked, agent loop can continue (utility) | OS/kernel sandbox (gVisor, landlock, seccomp, VM) |
| ZTA-**adjacent** profiles (`zta`/`paranoid` allowlists + owned tree) | On-disk file content scanner / FS post-write watcher |
| Library + MCP stdio PEP + ops metrics/audit | SPIFFE / continuous IdP auth as shipped |
| Brand: **tracewall** (enforcement-only) | WatchTower / observation-first OS |

Tier-0 content filtering is a **noisy prior on tool-arg text** and **never**
sole-BLOCKs. Do not describe Tracewall as “detecting prompt injection in the LLM.”

Profiles for paper wording:

- `balanced` = **lab** (optional identity/caps; no ZTA pack; client `_meta` forgeable).
- `zta` / `paranoid` = **production-shaped** (org allowlists, own call-tree; zta requires caps).

---

## Numbers you may quote (2026-07 freeze — re-check EVIDENCE before submit)

Only quote these when the matching artifact still agrees:

| Claim | Safe quote | Artifact / caveat |
|-------|------------|-------------------|
| Held-out deterministic | integrated R=**1.0**, P≈**0.929**, FPR≈**0.071** (n=27) | `corpus_v0.1_test_deterministic.json` — **regression bar**, not adaptive |
| Tier-1 policy on held-out | R=**1.0**, FPR=**0** | same — not AgentDojo |
| Robustness matrix | **18/18** (16 success + 2 expected_limit) | `robustness_stress.json` |
| Latency | mean ≈ **6.4 ms**, p99 ≈ **9.8 ms** full `Firewall.check` | `latency_check.json` (n=400) — **not** vs Sentinel |
| AgentDojo banking soft-block | `direct` 1×4: ASR **1.0→0.0**, util **1.0→1.0** (DeepSeek) | `adojo_stress.json` `live[]` — **banking slice only** |
| Soft-block vs abort | abort-era defended util was **0.25**; soft-block restored util **1.0** | same live expand note in EVIDENCE |

**Must say explicitly when discussing AgentDojo:**

- AgentDojo has **multiple suites** (banking, workspace, travel, …).
- We measured a **banking slice** only.
- Workspace / travel / slack (and full suite × all attacks × all models) = **UNVERIFIED**.
- Held-out ≠ adaptive ≠ full AgentDojo.

---

## Fraud / reject list (never write these)

| Fraud | Why |
|-------|-----|
| WatchTower **17/17** / “100% detection” as primary result | REFUTED overfitting / wrong brand |
| **0.011 ms** p99 / **9636× vs Sentinel** | No matched full-`check` study; REFUTED/UNVERIFIED |
| Hermes / graphify AST / ruflo BFT / ClickHouse / SPIFFE CA “shipped” | Not in `tracewall/` package |
| “We evaluate on AgentDojo” without banking-slice ASR table | Overclaim |
| Implying travel/workspace from banking results | UNVERIFIED |
| Equating held-out recall with adaptive robustness | Integrity failure |
| Client `_meta.caller_chain` = authenticated history under `balanced` | Forgeable |
| Denylist IBAN probes alone = “zero trust” | Not NIST ZTA |
| Tracewall scans/blocks chat jailbreaks | Wrong surface |
| gVisor/landlock/seccomp/VM as Tracewall | Wrong product |
| On-disk FS scanning as Tracewall | Wrong product |
| Full OTLP/gRPC exporter shipped | Only OTel-*shaped* JSONL |
| Distributed / cluster `rate_exceeds` | In-process only |

---

## Repo map (where to look)

| Need | Path |
|------|------|
| Claim ledger | `paper/EVIDENCE.md` |
| Narrative draft | `paper/PAPER.md` |
| Camera-ready TeX / PDF | `paper/tracewall.tex`, `paper/tracewall.pdf` |
| Submit checklist | `paper/SUBMIT.md` |
| Stale do-not-upload | `paper/watchtower.tex` (ignore for submit) |
| Eval JSON | `tracewall/eval/results/*.json` |
| AgentDojo stress + live | `adojo_stress.json` (`live[]` fragile — don’t wipe on firewall-only reruns) |
| Robustness | `robustness_stress.json` |
| Latency | `latency_check.json` |
| Brink (MCP success+limits) | `mcp_brink.json` |
| Threat model | `SECURITY.md` |
| Process integrity | `LESSONS_LEARNED.md` |
| Operator freeze status | `HANDOFF.md` |
| How to read ASR/util | `docs/RESULTS.md` |
| Sibling impl skill | `.cursor/skills/tracewall-zta/SKILL.md` |

---

## Workflow: changing paper claims

Copy this checklist into todos and complete in order:

1. **Diff the intended sentence** against EVIDENCE status (VERIFIED?).
2. **Open the JSON** that backs the number; copy figures from file, not chat history.
3. **Scope footnote / caveats:** banking-slice, soft-block, model id, held-out ≠ adaptive.
4. Edit `paper/PAPER.md` and/or `paper/tracewall.tex` together — keep them aligned.
5. Rebuild PDF (`paper/` build path per SUBMIT) and **visually** check abstract + tables (exit 0 ≠ correct floats).
6. If a **new** measurement landed: append/update EVIDENCE row **before** or **with** the paper edit.
7. Append LESSONS only if you learned a process rule (not every typo fix).
8. Do **not** commit `adojo_diag/`, `adojo_stress_live/`, local `adojo_util_check.py`, or secrets.

---

## Workflow: new eval → evidence → paper

1. Run the eval module; confirm JSON wrote under `tracewall/eval/results/`.
2. Update EVIDENCE with status + artifact path + date.
3. Only then update abstract / §Results / SHARE copy.
4. Prefer soft-block when reporting AgentDojo **utility**; abort-era util collapse is a known pitfall (see EVIDENCE soft-block row).

---

## After edits

- EVIDENCE updated if measurements changed.
- No REFUTED numbers resurrected.
- README / docs metric headlines still match EVIDENCE (if you touched public numbers).
- Sibling skill for shipping controls: [`tracewall-zta`](../tracewall-zta/SKILL.md).
