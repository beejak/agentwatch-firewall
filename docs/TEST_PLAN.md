# Tracewall test plan (design)

**Harness as scenario suite? NO.** Use pytest for edges; harness for offline P/R/F1; AgentDojo for live ASR/utility.

## Lanes

| Lane | Purpose |
|------|---------|
| pytest | Scenarios, stateful taint, API, MCP edges, fail-safe |
| `python -m tracewall.eval.harness --split test` | Detection metrics + CIs |
| AgentDojo adapter | Live base vs defended |

## Scenario families

1. Indirect injection → later tool misuse  
2. Capability abuse (exfil / destructive)  
3. Memory / MINJA-class contagion (multi-turn)  
4. Multi-hop taint across agents  
5. Identity / delegation abuse  
6. Context starvation (no `_meta`)  
7. Policy DSL failure (typos, stubs, empty rules)  
8. Semantic / LLM escalate failures  
9. Transport framing / fail-open  
10. Benign utility (FP tax)  
11. Paraphrased / adaptive attacks  
12. Audit + fail-safe on crash  

## Edge checklist (pytest)

- Identity: `require_identity`, expired token, depth, caps  
- Policy: unknown op warns; `rate_exceeds` unsupported; org domains; secret-reader aliases; egress tools  
- Taint: live ledger updates on ALLOW/BLOCK; quarantine escalate; decay  
- Content: never sole BLOCK  
- Semantic: score polarity 0=bad…1=clean on verdict; LLM fallback  
- MCP: tools/call block; completeness flags  
- Fail-safe: injected exception → BLOCK  

## Metrics

- Eng: pytest green  
- Paper: harness JSON + AgentDojo when run; disclose adaptive limits  

See also [`GOALS.md`](GOALS.md).
