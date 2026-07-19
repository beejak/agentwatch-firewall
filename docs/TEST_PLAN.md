# Tracewall test plan

**Harness as scenario suite? NO.**  
pytest = edges · harness = offline P/R/F1 · mcp_brink = profile success+limits · AgentDojo = live ASR.

## Lanes

| Lane | Command | Proves |
|------|---------|--------|
| Unit / integration | `pytest -q` | Contracts, P0, profiles, transports |
| Held-out detection | `python -m tracewall.eval.harness --split test` | Ablation metrics + CIs |
| MCP brink | `python -m tracewall.eval.mcp_brink` | Profile contracts + **expected limits** |
| AgentDojo stress | `python -m tracewall.eval.adojo_stress` | Firewall-only banking attack chains + bypass rows |
| AgentDojo live stress | `python -m tracewall.eval.adojo_stress --live` | Bill-preserving + benchmark prompt vs DeepSeek |
| AgentDojo | `python -m tracewall.eval.adapters.agentdojo …` | Live ASR/utility (often unverified) |

## Success vs failure (Fable)

- **Success row fails** → feature not done (exit non-zero on brink).
- **Expected-limit row must still pass** — we are proving the miss still happens
  (no `_meta`, permissive skips exfil, `tools/list` unscanned). Hiding misses = failure.
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

## Edge checklist

- Identity: missing + `require_identity`, caps, depth, expiry  
- Policy: secret-reader aliases, org domains, egress tools, remote-exec bash  
- Taint: live ledger updates on ALLOW/BLOCK  
- MCP: profiles differ; malformed fail-closed vs fail-open; brink limits  
- Score: verdict 0=bad…1=clean  

See [`GOALS.md`](GOALS.md), [`DETECTION.md`](DETECTION.md).
