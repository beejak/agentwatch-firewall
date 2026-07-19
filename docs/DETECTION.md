# Detection that fits Tracewall (not a new product)

## Concept we already have

Tool-call ALLOW/BLOCK via:

1. Identity / caps  
2. YAML policy (including call-tree)  
3. Trust / **multi-hop taint** ledger  
4. Optional semantic escalate  

That is the POC. Peers do YAML MCP WAFs or CaMeL-style IFC redesign. Our wedge is **quantitative taint + ablation evidence**, not “yet another neural detector.”

## Algorithm work that *fits* (worth building)

| Idea | Why it fits | Status |
|------|-------------|--------|
| Wire ledger edges on live MCP/tool reads→writes | Makes MTP real on the wire, not only unit tests | Partial (`check` updates trust; edges still mostly tests) |
| Sequence policy: secret-read → egress within N calls when `_meta` present | Same concept as call_tree rules; stronger if we store recent tools per agent | Not built — natural extension of policy DSL |
| AgentDojo-shaped `send_money` after file/banking reads | Makes banking ASR measurable without relying on DeepSeek refusal | Shipped (`exfil_send_money_*.yaml` + `adojo_stress`) |
| Bill-preserving + benchmark system probes | Raises model follow-through so Tracewall can show ASR drop | Harness in `adojo_stress --live` |
| Profile-aware degrade metrics (`context_completeness` rates) | Honest POC data when `_meta` missing | Brink runner starts this |
| Held-out + AgentDojo + **failure rows** | Fable: prove with data including misses | Corpus + mcp_brink + adojo_stress |

## What *not* to build (wrong concept)

- Dual-LLM CaMeL interpreter (different architecture)  
- “One more embedding classifier” as the core (commodity; doesn’t use taint)  
- Claiming adaptive robustness from frozen-corpus 100%  

## Fable / Karpathy stance

- **Success** = named verify passes (pytest + `mcp_brink` success rows).  
- **Failure** = we still **keep the row** (`expected_limit`, FPR, AgentDojo miss). POC “sits well” when data matches claims — including “we miss without `_meta`.”  
- Do not declare G3 success if any `kind=success` brink row fails.

See [`docs/GOALS.md`](GOALS.md) G3 and [`paper/EVIDENCE.md`](../paper/EVIDENCE.md).
