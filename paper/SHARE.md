# Social Share Copy

## LinkedIn Post

**We built a firewall for AI agents — and a formal paper to go with it.**

Multi-agent AI systems have a security problem nobody has fully solved.

There are 3 distinct attack surfaces:

**1️⃣ Input Corruption** — Prompt injection via documents, APIs, or memory. MINJA (arXiv:2503.03704) demonstrated 98.2% injection success via *query-only* interaction. The attacker never needs write access.

**2️⃣ Capability Abuse** — Legitimate tool, illegitimate purpose. `send_email` after `read_secret` looks identical to normal email at the network layer. Wire-level enforcement is completely blind to intent.

**3️⃣ Multi-Agent Contagion** — A compromised agent writes to shared memory. Downstream agents inherit taint through read-only queries. **No published defense existed for this before WatchTower.**

We built WatchTower to address all three — and wrote the paper.

**Results:**
- ✅ 100% detection on a 17-case known-bad corpus (zero false negatives)
- ⚡ 0.011ms p99 enforcement latency — 9,636× faster than the closest competitor
- 🔒 Cross-session MINJA taint propagation: detected before the next tool call executes
- 0️⃣ False positives on benign workload
- No GPU required — SQLite, not A100

**The core insight:** enforcement and observability must be co-designed. A firewall without call-tree context can't tell *why* a tool was called. An observer without enforcement produces alerts after the fact.

The key primitive is `call_tree_contains` — a policy operator that blocks based on the *semantic call chain*, not just the tool name. Zero ML. 0.011ms deterministic.

We also wrote a full IEEEtran-formatted paper with formal taint propagation proofs, latency benchmarks, and comparison against LlamaFirewall, AgentSpec, Distributed Sentinel, and Claw Patrol.

Targeting IEEE S&P / USENIX Security / ACM CCS.

Open source: github.com/beejak/agentwatch
Full paper (interactive): github.com/beejak/agentwatch/blob/master/paper/index.html

— Rohit Jinsiwale, Reliance Industries

---

## X / Twitter Thread

**🔐 Built an agent firewall. 17/17 attacks blocked. 0.011ms p99. Full paper included. Here's the thread.**

**1/** Multi-agent AI has 3 attack surfaces. Almost every existing defense covers exactly one. We cover all three.

**2/** Surface 1: Input Corruption
MINJA (Mar 2025) proved 98.2% injection success via query-only interaction — no write access needed. Standard content filters have no cross-session persistence. They're blind to what's already in memory.

**3/** Surface 2: Capability Abuse
`send_email(body="api_key=sk-abc123...")` after `read_secret` looks identical to legitimate email at the network layer. The difference is *why* it was called. That requires call-tree context — which wire-level firewalls don't have.

**4/** Surface 3: Multi-Agent Contagion
Agent A compromised → writes poisoned memory → Agent B does a query-only read → B inherits the attack. No existing system tracked this cross-session. WatchTower does.

**5/** The key primitive: `call_tree_contains`

```yaml
match:
  tool: send_email
  context:
    call_tree_contains: [read_secret]
  any:
    - arg.body: { matches_secret_pattern: true }
verdict: BLOCK
```

LLM checkers: 100ms+. WatchTower: 0.011ms. Deterministic. Zero ML.

**6/** MINJA defense — end-to-end proof (Q2):
- Agent A tainted at 0.9 (capability abuse)
- A writes poisoned memory
- B does query-only read
- WatchTower: T_B = 0.9 × 0.8 = 0.72
- 0.72 ≥ quarantine threshold 0.7
- B blocked before its next tool call

All of this happens in under 1ms.

**7/** 9-layer architecture — hot path is sub-millisecond:
- L0: Ed25519 identity + delegation chain (MAX_DEPTH=8)
- L3: Deterministic YAML policy eval — 0.011ms p99
- L4: Trust gate — routes, never hard-blocks alone
- L6: Async BFT swarm (3 agents, 5s timeout)
- L8: ClickHouse append-only chronicle

**8/** vs prior work:
- LlamaFirewall: S1 only, >100ms
- AgentSpec: S2 only, 70.96% recall
- Distributed Sentinel: S1+S2 partial, 106ms, needs A100 GPU
- Claw Patrol: S2 only, no semantic context
- WatchTower: all 3 surfaces, 0.011ms, SQLite not GPU

**9/** Full IEEEtran paper written. Formal taint model. Convergence proof. Latency benchmarks. 16 references.

Open source — code + paper:
github.com/beejak/agentwatch

Targeting IEEE S&P / USENIX Security / ACM CCS.

— Rohit Jinsiwale

---

## Short LinkedIn Caption (for sharing the paper link)

**New preprint: WatchTower — observation-first agent security.**

Three attack surfaces. One system. 0.011ms enforcement latency.

The unsolved problem: **multi-agent contagion**. Agent A is compromised, writes to shared memory. Agent B reads it in a query-only call — and inherits the attack. No prior system tracked this cross-session.

WatchTower does. Taint propagates in under 1ms. Quarantine resolves automatically in ~2.5 hours. No permanent DoS.

100% detection on 17-case known-bad corpus. 9,636× faster than the closest published competitor. No GPU required.

📄 Paper + interactive charts: github.com/beejak/agentwatch/blob/master/paper/index.html
💻 Code: github.com/beejak/agentwatch
📑 LaTeX source: paper/watchtower.tex

— Rohit Jinsiwale, Reliance Industries

#AIAgents #LLMSecurity #MultiAgentSystems #AgentFirewall #PromptInjection #MINJA #AIObservability #GenAI #LLM
