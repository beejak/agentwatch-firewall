# Tooling (this repo + user-local agent stack)

**Updated 2026-10-21.** Product truth lives in Tracewall skills and `SECURITY.md` —
process tools below must **not** override PEP identity or invent paper numbers.

## Tracewall product skills (source of truth)

Under [`.cursor/skills/`](../.cursor/skills/):

| Skill | Use when |
|-------|----------|
| **tracewall-paper** | Any paper/metric/public claim edit (evidence → paper) |
| **tracewall-zta** | Profiles, allowlists, own call-tree, caps, MCP PEP, soft-block |

May need a **new Cursor chat** for skills to appear.

## Process skills (already in-repo)

| Pack | Location | Notes |
|------|----------|-------|
| **Superpowers** (obra) | `.cursor/skills/` copies: brainstorming, TDD, systematic-debugging, verification-before-completion, writing-plans, executing-plans, using-superpowers, dispatching-parallel-agents | Process only — **not** Tracewall domain |
| **mattpocock/skills** | [`.agents/skills/`](../.agents/skills/) | Installed via `npx skills@latest add mattpocock/skills -a cursor`. Run `/setup-matt-pocock-skills` once if using the pack heavily |

## User-local installs (2026-10-21 Windows)

Reference clones (optional): `%USERPROFILE%\tools\{caveman,cavemem,claude-mem,superpowers,gsd-core,mattpocock-skills,ruflo,graphify}`.  
Install log: `%USERPROFILE%\tools\install-log-2026-10-21.txt`.

| Tool | Upstream | How installed / invoke | Status |
|------|----------|------------------------|--------|
| **caveman** | [JuliusBrussee/caveman](https://github.com/JuliusBrussee/caveman) | `npx skills add JuliusBrussee/caveman -g` → `~\.agents\skills\caveman*`; CLI via `npx @caveman-ai/cli@latest` / `caveman help` | Skills copied; PromptScript global target skipped (harmless) |
| **cavemem** | [JuliusBrussee/cavemem](https://github.com/JuliusBrussee/cavemem) (**frozen**; memory core also in caveman) | `npm i -g cavemem` then `cavemem install --ide cursor` | Wired; `cavemem status` / `cavemem search "…"` |
| **claude-mem** | [thedotmack/claude-mem](https://github.com/thedotmack/claude-mem) | `npx claude-mem install --ide cursor --provider host` | Plugin registered; **Bun install failed** on this machine (`spawn EINVAL`) — update Claude Code ≥2.1.139 + fix Bun, or retry. Hooks need newer Claude Code. |
| **superpowers** | [obra/superpowers](https://github.com/obra/superpowers) | Cursor: `/add-plugin superpowers` or marketplace; repo already has skill copies under `.cursor/skills/` | Prefer plugin for updates; keep Tracewall skills authoritative for product |
| **GSD Core** | [open-gsd/gsd-core](https://github.com/open-gsd/gsd-core) (**successor** to archived [gsd-build/get-shit-done](https://github.com/gsd-build/get-shit-done)) | `npx @opengsd/gsd-core@latest --cursor -g` → installs into `~\.cursor` (72 skills + workflow assets) | Mention skill `gsd-new-project` / `gsd-onboard`. **Do not** start Tracewall E1–E6 via GSD until Final Gate. Notes unreplaced `.claude` path refs in some agent files (harmless warning). |
| **mattpocock skills** | [mattpocock/skills](https://github.com/mattpocock/skills) | `npx skills@latest add mattpocock/skills -a cursor` → [`.agents/skills/`](../.agents/skills/) + [`skills-lock.json`](../skills-lock.json) | Engineering discipline pack; does not replace Tracewall skills |
| **ruflo** | [ruvnet/ruflo](https://github.com/ruvnet/ruflo) | `npx ruflo@latest --help` (v3.x); optional `npx ruflo@latest init wizard` (writes harness files — skip unless wanted) | Optional meta-harness — **not** Tracewall product |
| **graphify** | [Graphify-Labs/graphify](https://github.com/Graphify-Labs/graphify) | `pip install graphifyy`; `graphify install --platform windows` (Claude skill → `~\.claude\skills\graphify`); CLI `graphify query` / `/graphify .` | PyPI name `graphifyy`. `graphify install --platform cursor` currently errors (`_cursor_install` missing `project_dir`) — use windows/claude skill + CLI. |

### Opportunistic use for this repo

- **graphify:** map `tracewall/` + `docs/` + `paper/` before large doc sweeps (`/graphify .` or CLI).
- **caveman-compress / cavemem:** shrink long HANDOFF/plan context; do not rewrite claim numbers.
- **ruflo:** only if coordinating multi-agent doc/paper chores — never as a security control claim.
- **GSD:** phase loop for *post-gate* implementation planning; paper freeze still applies to claims.

## Operator entry points

- [`docs/GETTING_STARTED.md`](GETTING_STARTED.md)
- [`docs/INTEGRATION.md`](INTEGRATION.md) — put it on the tool-call path
- [`docs/RESULTS.md`](RESULTS.md)
- [`docs/RUNBOOK.md`](RUNBOOK.md)
- [`docs/ENTERPRISE.md`](ENTERPRISE.md)

## Planning (awaiting Final Gate A–E)

- [`docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](plans/2026-10-21-tracewall-core-enhancement-test-plan.md) — autoplan
- [`docs/plans/2026-10-21-tracewall-karpathy-review.md`](plans/2026-10-21-tracewall-karpathy-review.md) — separate Karpathy lens (**not merged**)
- [`../TODOS.md`](../TODOS.md) — deferred backlog

**Coding E1–E6 is blocked** until the human accepts premises and picks gate A–E (recommend **B** = Karpathy overrides).

## Goals / evidence

- [`docs/GOALS.md`](GOALS.md) — success/failure + named verify commands  
- [`docs/DETECTION.md`](DETECTION.md) — what algorithm fits the POC  
- [`paper/EVIDENCE.md`](../paper/EVIDENCE.md) — claim ledger  
- [`docs/TEST_PLAN.md`](TEST_PLAN.md) — scenarios; harness = metrics only  
- MCP brink: `python -m tracewall.eval.mcp_brink` → `eval/results/mcp_brink.json`

## Doc map

Full index: [`docs/README.md`](README.md). Architecture (incl. network/MCP): [`FIREWALL.md`](FIREWALL.md).
