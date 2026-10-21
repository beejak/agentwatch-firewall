# Tracewall test plan

**Harness as scenario suite? NO.**  
pytest = edges · harness = offline P/R/F1 · mcp_brink = profile success+limits · AgentDojo = live ASR.

**Gate B (2026-10-21): SHIPPED** — E1 (`deny_unknown_tools`) + E2 (`tools/list` filter) on
`zta`/`paranoid`. Prefer eval-row promotions over coverage-count targets. Plan archive:
[`plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](plans/2026-10-21-tracewall-core-enhancement-test-plan.md)
(+ [Karpathy review](plans/2026-10-21-tracewall-karpathy-review.md)). E4 `session_ratchet`
shipped (optional; off on lab); E5/E6 demoted. Soft-block **live** re-measure blocked
(no `LLM_API_KEY`) — see [`RESULTS.md`](RESULTS.md). Paper freeze numbers unchanged
(robustness **18/18** in EVIDENCE); **current** matrix is robustness **19/19**, brink
**21/21** — see [`RESULTS.md`](RESULTS.md).

## Test parameters

### Profiles

| Profile | Role | E1 unknown-tool deny | E2 `tools/list` filter | E4 session ratchet |
|---------|------|----------------------|-------------------------|--------------------|
| `balanced` | Lab / held-out regression | Off (pack-only; pack-miss stays expected_limit) | Off (pass-through) | Off |
| `zta` | Prod default | On (`deny_unknown_tools`) | On (response filter) | On |
| `paranoid` | Strict prod | On | On | On |
| `permissive` | Demo / omit exfil pack | Off | Off | Off |

CLI (MCP proxy): `--profile`, `--filter-tools-list` / `--no-filter-tools-list`,
`--session-ratchet` / `--no-session-ratchet`, `--tools-allowlist`, `--fail-closed` /
`--fail-open`.

### CI (`.github/workflows/ci.yml`)

```bash
pip install -e ".[dev]"
pytest -q
python -m tracewall.eval.harness --split test
python -m tracewall.eval.mcp_brink
```

**CI does NOT run:** `robustness_stress`, `adojo_stress` / `--live`, `latency`, AgentDojo adapter live.
AgentDojo soft-block unit test uses `pytest.importorskip` when `[bench]` / `agentdojo` absent
(`320ee56`) → expect **2 skipped** in default CI.

### Local hard gate (pre-merge / release)

```bash
pip install -e ".[dev]"          # includes aiosqlite; required for KB17–20 ledger tests
pytest -q                        # expect 153 passed, 2 skipped without [bench]
python -m tracewall.eval.mcp_brink
python -m tracewall.eval.robustness_stress
```

Optional (not CI): `python -m tracewall.eval.adojo_stress`, `--live` with `.[bench]` + `LLM_API_KEY`,
`python -m tracewall.eval.latency`. **2026-10-21:** firewall-only adojo **7/7** reconfirmed;
live soft-block re-measure **blocked** (no API key) — do not invent ASR.

### Do you need an API key?

| Lane | Needs `LLM_API_KEY`? |
|------|----------------------|
| `pytest -q`, brink, robustness, harness (deterministic), firewall-only `adojo_stress` | **No** |
| Live AgentDojo ASR/utility (`adojo_stress --live`, adapter) | **Yes** (`LLM_API_KEY`; optional `LLM_BASE_URL` / `LLM_MODEL`, default DeepSeek) |
| Optional semantic LLM judge | **Yes** (only if you enable that tier) |

**Firewall-only 7/7** = AgentDojo-*shaped* banking tool chains through `Firewall.check` with
`TRACEWALL_SEMANTIC_LLM=0`. Proves PEP BLOCK/ALLOW — **not** live ASR.

**Live ASR re-measure** = real AgentDojo + LLM agent (`.[bench]`). Blocked last run = no keys
in env. Env var name in code: **`LLM_API_KEY`** (`tracewall/eval/adapters/agentdojo.py`).

### Live eval cost (rough USD)

Documented soft-block headline slice: banking **`direct`**, bill-preserving, benchmark system,
`user_task_0` × `injection_task_0..3` (**1×4**), **base + defended** = **8** agent episodes.

Harness default `--live` (no task flags): three attacks × two arms × **1×1** = **6** episodes.
Same 1×4 across all three default attacks ≈ **24** episodes.

Billed tokens are **multi-turn** (each LLM call resends history + tools). Rough range per
episode ≈ **8k–25k** cumulative tokens (from logged banking transcripts; honest ±2×).

| Slice | Episodes | Cheap API (DeepSeek-class) | Mid hosted | Frontier (GPT-4o / Claude-class) |
|-------|----------|----------------------------|------------|----------------------------------|
| Soft-block `direct` 1×4 re-measure | 8 | **~$0.05–$0.50** | **~$0.50–$2** | **~$2–$10** |
| Default `--live` 3×1×1 | 6 | similar / slightly less | similar | similar |
| 3 attacks × 1×4 | 24 | **~$0.15–$1.50** | **~$1.50–$6** | **~$5–$30** |

Estimates are **rough** (provider list prices move; loop length varies; retries add cost).
Default adapter model is `deepseek-chat` via `LLM_MODEL` — confirm current provider pricing
before budgeting. **No API key ⇒ $0** for CI / firewall-only / pytest.

Command for the paper soft-block slice when keyed:

```bash
pip install -e ".[bench]"
# export LLM_API_KEY=...   # optional: LLM_BASE_URL, LLM_MODEL
python -m tracewall.eval.adojo_stress --live --attacks direct \
  --user-tasks user_task_0 \
  --injection-tasks injection_task_0 injection_task_1 injection_task_2 injection_task_3
```

### Eval / CI seams (TDD)

Test at these **public seams** (not private helpers). Existing pytest covers them;
add a vertical slice only when a seam regresses without a test.

| Seam | What it catches | Primary tests / lane |
|------|-----------------|----------------------|
| `await Firewall.check(event) → FirewallVerdict` | Policy, identity, E1 deny-unknown, fail-safe | `test_firewall_*.py`, `test_deny_unknown_tools.py`, `test_p0_correctness.py` |
| MCP `tools/list` response filter (E2) | Hidden tools on zta/paranoid; request still forwards | `test_mcp_tools_list_filter.py`, brink |
| `session_ratchet` (E4) | Post-BLOCK egress containment; lab off / prod on | `test_session_progressive.py` |
| Soft-block contract | BLOCK → non-executing error; utility path | `test_agentdojo_soft_block.py` (`importorskip`), `python_guard` / enterprise soft-block tests |
| Firewall-only AgentDojo shape | Banking IBAN / schedule chains without LLM | `test_adojo_stress.py`, `python -m tracewall.eval.adojo_stress` |

How to run: §CI + §Local hard gate above. Full profile matrix: §Profiles.

### Current vs paper freeze (counts)

| Artifact | Paper freeze (quote in paper) | Current post–Gate B (HEAD) |
|----------|-------------------------------|----------------------------|
| Robustness | **18/18** | **19/19** (17 success + 2 expected_limit) |
| Brink | freeze-era success+limits | **21/21** (18 success + 3 expected_limit) |
| pytest | n/a | **153 passed, 2 skipped** (no `[bench]`; +E4) |

## Lanes

| Lane | Command | Proves |
|------|---------|--------|
| Unit / integration | `pytest -q` | Contracts, P0, profiles, transports, E1/E2 |
| Held-out detection | `python -m tracewall.eval.harness --split test` | Ablation metrics + CIs |
| MCP brink | `python -m tracewall.eval.mcp_brink` | Profile contracts + **expected limits** |
| AgentDojo stress | `python -m tracewall.eval.adojo_stress` | Firewall-only banking attack chains + bypass rows |
| AgentDojo live stress | `python -m tracewall.eval.adojo_stress --live` | Bill-preserving + benchmark prompt vs DeepSeek |
| Cross-domain robustness | `python -m tracewall.eval.robustness_stress` | Non-banking workspace/HTTP/contagion/host/identity + limits |
| Latency | `python -m tracewall.eval.latency` | Full `Firewall.check` microbenchmark |
| AgentDojo | `python -m tracewall.eval.adapters.agentdojo …` | Live ASR/utility (often unverified) |

## Success vs failure (Fable)

- **Success row fails** → feature not done (exit non-zero on brink).
- **Expected-limit row must still pass** — we are proving the miss still happens
  (no `_meta`, permissive skips exfil, balanced unknown-tool pack-miss, firewall-layer list probe).
  Hiding misses = failure.
- Held-out 100% ≠ adaptive attacks. Record that in EVIDENCE.

## Scenario families

1. Indirect injection → tool misuse  
2. Capability abuse (exfil / destructive)  
3. Memory / MINJA-class (multi-turn still thin)  
4. Multi-hop taint  
5. Identity / `require_identity`  
6. Context starvation (no `_meta`)  
7. Policy DSL (typos, stubs, org domains)  
8. Semantic escalate / LLM fallback  
9. Transport fail-open / fail-closed / profiles  
10. Benign utility (FP tax)  
11. Paraphrase / adaptive (future; don’t overclaim)  
12. Audit + fail-safe on crash  
13. **Workspace / Slack-shaped egress** (`send_message` after secret)  
14. **HTTP / upload exfil** (`http_post`, `upload`)  
15. **Host write paths** (destructive / path abuse)  
16. **Tool-name gaps** — PascalCase closed; unknown tools denied on zta/paranoid (E1); balanced pack-miss still expected_limit  
17. **Schedule / delayed money** (`schedule_transaction`)  
18. Soft-block vs abort (AgentDojo utility tax)  
19. **MCP `tools/list` filter** (E2 on zta/paranoid; firewall-only list probe stays expected_limit)

## Roadmap stress (not yet VERIFIED)

- AgentDojo **workspace** and **travel** suites (live + firewall-only shapes)
- Signed identity / SPIFFE-style verifier (beyond ledger register)
- HTTP sidecar PEP (`GuardedToolNode` is shipped; full LangGraph package integration optional)
- Adaptive paraphrase corpus (don’t claim until measured)
- Distributed rate limits (current match-level `rate_exceeds` is single-process)

**Closed in v0.2.0 (do not re-list as open):** IBAN ZWSP/NFKC normalize; PascalCase / case aliases via canonical tool names.

**Closed in Gate B (post-freeze capability, not paper rewrite):** unknown-tool deny on zta/paranoid (E1); MCP `tools/list` response filter on zta/paranoid (E2). Remaining honesty limits: balanced pack-miss; firewall-layer list probe; brink context-starvation / permissive / forged-meta rows.

**Closed in v0.3.0 (E4):** `session_ratchet` progressive containment after BLOCK — on for
`zta`/`paranoid`, off for `balanced`/`permissive`. Tests: `test_session_progressive.py`.
Not a paper claim rewrite; live soft-block ASR not re-measured this cut.

## Edge checklist

- Identity: missing + `require_identity`, caps, depth, expiry  
- Policy: secret-reader aliases, org domains, egress tools, remote-exec bash  
- Taint: live ledger updates on ALLOW/BLOCK  
- MCP: profiles differ; malformed fail-closed vs fail-open; brink limits; E2 list filter  
- Score: verdict 0=bad…1=clean  

See [`GOALS.md`](GOALS.md), [`DETECTION.md`](DETECTION.md).
