# AGENTS.md — Tracewall / agentwatch-firewall

Short entry for coding agents. **Last updated 2026-10-21.**

## Product (memorize)

**Tracewall = tool-call PEP** — `await Firewall.check(event) → FirewallVerdict`.
Not a chat scanner, OS sandbox, on-disk scanner, or full NIST ZTA.

| Lab | Prod |
|-----|------|
| `balanced` | `zta` / `paranoid` |

Wire-up: [`docs/INTEGRATION.md`](docs/INTEGRATION.md). Threat model: [`SECURITY.md`](SECURITY.md).

## Skills (priority)

1. [`.cursor/skills/tracewall-zta/SKILL.md`](.cursor/skills/tracewall-zta/SKILL.md) — enforcement
2. [`.cursor/skills/tracewall-paper/SKILL.md`](.cursor/skills/tracewall-paper/SKILL.md) — claims / paper
3. Process packs (optional): `.cursor/skills/*` Superpowers, [`.agents/skills/`](.agents/skills/) mattpocock, user caveman — **never override** Tracewall product truth

## Evidence → paper

Only [`paper/EVIDENCE.md`](paper/EVIDENCE.md) + committed eval JSON. **Paper freeze** quotes:
held-out R=1.0 / FPR≈0.07; soft-block banking `direct` ASR 1.0→0.0 util 1.0→1.0;
robustness **18/18**; latency ≈6.4 ms / p99 ≈9.8 ms. PDF:
[release v0.2.0](https://github.com/beejak/agentwatch-firewall/releases/download/v0.2.0/tracewall.pdf).

**Current HEAD (not paper):** robustness **19/19**, brink **21/21**, pytest ≈148+2 skip —
[`docs/RESULTS.md`](docs/RESULTS.md), [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)#test-parameters.

## Current gate (do not skip)

- Paper claims frozen; CI green (`320ee56` importorskip).
- **Gate B P0 shipped** (E1+E2); delay E4; demote E5/E6. Paper claims frozen.
- Verify skill: `.cursor/skills/verification-before-completion/SKILL.md` — run pytest + brink + robustness before completion claims.
- Plans: [`docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md`](docs/plans/2026-10-21-tracewall-core-enhancement-test-plan.md)
  + separate [Karpathy review](docs/plans/2026-10-21-tracewall-karpathy-review.md) (do not merge).
- Pick-up: [`HANDOFF.md`](HANDOFF.md). Tooling: [`docs/TOOLING.md`](docs/TOOLING.md).

## Do not commit

`adojo_diag/`, `adojo_stress_live/`, `adojo_util_check.py`, secrets, `.env`.
