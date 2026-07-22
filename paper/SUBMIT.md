# Submit Tracewall paper (arXiv checklist)

**Author:** beejak (`beejak@users.noreply.github.com`)  
**Source of truth:** [`EVIDENCE.md`](EVIDENCE.md) → [`tracewall.tex`](tracewall.tex) / [`PAPER.md`](PAPER.md) → [`tracewall.pdf`](tracewall.pdf).  
**Product track:** features frozen for this submit; no new AgentDojo suites required.

## Upload these

| Artifact | Path | Notes |
|----------|------|-------|
| Main TeX | `paper/tracewall.tex` | IEEE 2-col; self-contained (no external `.bib` required) |
| PDF | `paper/tracewall.pdf` | Rebuild before upload; visually check floats |
| Optional markdown | `paper/PAPER.md`, `paper/EVIDENCE.md` | Not required by arXiv; useful as ancillary or for reviewers |

## Do **not** upload

- `paper/watchtower.tex` — **stale** WatchTower brand + REFUTED metrics (17-case “100%”, 0.011 ms / 9636× Sentinel).
- `paper/Makefile` as-is if still pointed at `watchtower` (local helper only).
- Live LLM result trees under `tracewall/eval/results/adojo_*` unless you intend a full artifact dump (large; optional).
- Secrets, `.env`, API keys, or private bill/transcript payloads.

## Rebuild PDF locally

```powershell
# Prefer committed tectonic binary if present:
& "$env:TEMP\tectonic-bin\tectonic.exe" -X compile paper\tracewall.tex --outdir paper
# Or: tectonic -X compile paper/tracewall.tex --outdir paper
```

Inspect `paper/tracewall.pdf`: abstract non-claims, scope footnote, AgentDojo soft-block row (ASR 0 / util 1), robustness 18/18, latency ≈6.4 ms mean / ≈9.8 ms p99, author **beejak**.

## arXiv form (typical)

1. Category: **cs.CR** (primary); optional cross-list **cs.AI** / **cs.LG**.
2. Title / abstract: copy from `tracewall.tex` (ASCII-safe for the form if needed).
3. Authors: **beejak** + email on title page.
4. Comments line (optional): “Evidence-backed tool-call firewall; AgentDojo banking soft-block slice; features frozen.”
5. License: choose deliberately (often CC-BY-4.0 or arXiv perpetual non-exclusive).
6. Source package: zip `tracewall.tex` (+ PDF if dual-upload); omit `watchtower.tex`.

## Pre-flight claim check

Confirm every headline number still matches VERIFIED rows in EVIDENCE:

- Held-out integrated recall 1.0 / prec ≈0.929 / FPR ≈0.071; tier-1 recall 1.0 / FPR 0
- Soft-block `direct` 1×4: base ASR 1.0 util 1.0 → defended ASR 0.0 util 1.0
- Robustness matrix 18/18 (16 success + 2 expected_limit); ZWSP / PascalCase closed
- Latency mean ≈6.41 ms, p99 ≈9.82 ms (`latency_check.json`)
- Non-claims: no WatchTower OS, no 100% known-bad primary, no GPU-sentinel 0.011 ms claim

## After submit

- Record arXiv ID in `HANDOFF.md` and bump paper status in `PAPER.md`.
- Venue follow-up (S&P / USENIX / CCS) is separate; do not invent new ASR without a new live run + EVIDENCE update.
