# Social Share Copy

## LinkedIn Post

**We built a firewall for AI agents. Here's what we learned. 🧵**

Multi-agent AI systems have a security problem no one is fully talking about.

There are 3 distinct attack surfaces:

**1️⃣ Input Corruption** — Prompt injection via documents, web content, or API responses. MINJA (arxiv 2503.03704) demonstrated 98.2% injection success via *query-only* interaction. The attacker never needs write access.

**2️⃣ Capability Abuse** — An agent uses a legitimate tool for an illegitimate purpose. `send_email` after `read_secret` looks identical to `send_email` for legitimate comms at the network layer. Wire-level enforcement is blind to intent.

**3️⃣ Multi-Agent Contagion** — A compromised agent writes to shared memory. Downstream agents inherit taint through read-only queries. **No published defense existed for this.**

We built WatchTower to address all three.

Key results:
- ✅ 100% detection on 17-case known-bad corpus
- ⚡ 0.011ms p99 enforcement latency (vs 106ms state-of-art — 9,636× faster)
- 🔒 Cross-session taint propagation: MINJA detected before the next tool call executes
- 0️⃣ False positives on benign workload
- No GPU required

The core insight: **enforcement and observability must be co-designed**. A firewall without call-tree context can't distinguish *why* a tool was called. An observer without enforcement produces alerts after the fact.

We're targeting IEEE S&P / USENIX Security.

Open source: github.com/beejak/agentwatch
Full paper: [link to paper/index.html]

---

## X / Twitter Thread

**🔐 We built an agent firewall. 17/17 attacks blocked. 0.011ms p99. Here's how.**

**1/** Multi-agent AI has 3 attack surfaces. Almost every existing defense covers only one.

**2/** Surface 1: Input Corruption
MINJA (Mar 2025) proved adversaries can achieve 98.2% injection success via *query-only* interaction — no write access needed. Standard content filters don't stop multi-hop contagion.

**3/** Surface 2: Capability Abuse
`send_email(to="partner@corp.com", body="api_key=sk-abc123...")` looks identical to legitimate email at the network layer. The difference is *why* it was called — which requires call-tree context.

**4/** Surface 3: Multi-Agent Contagion
Compromised Agent A writes to shared memory → Clean Agent B does a query-only read → B inherits taint. No existing system tracked this cross-session. We do.

**5/** WatchTower's approach: 9-layer enforcement
- L0: Ed25519 identity fabric per agent
- L3: Deterministic YAML policy rules (zero ML, 0.011ms)
- L4: Trust gate (routes, never hard-blocks alone)
- L6/L7: Async BFT swarm + task-completion barrier
- L8: ClickHouse append-only chronicle

**6/** The key innovation: `call_tree_contains`
Our policy DSL can say "block send_email only when read_secret appears in the call tree." Wire-level firewalls can't do this. LLM-based checkers add 100ms+ latency. We do it deterministically in 0.011ms.

**7/** MINJA defense (Q2 proof):
- Agent A tainted at level 0.9 (T2 capability abuse)
- A writes poisoned memory
- B does query-only read
- WatchTower propagates: T_B = 0.9 × 0.8 = 0.72
- 0.72 ≥ quarantine threshold 0.7
- B blocked BEFORE its next tool call executes

**8/** Results vs prior work:
- LlamaFirewall: S1 only, >100ms
- AgentSpec: S2 only, 70.96% recall
- Distributed Sentinel: partial S1+S2, 106ms, requires A100 GPU
- Claw Patrol: S2 only, no semantic context
- WatchTower: all 3, 0.011ms, SQLite not GPU

**9/** Open source, targeting IEEE S&P / USENIX Security.

Code: github.com/beejak/agentwatch
Paper: [link]

---

## Short LinkedIn Caption (for sharing the paper link)

**New research: WatchTower — an observation-first agent security framework.**

Three attack surfaces. One system. 0.011ms enforcement.

The part no one else has solved: **multi-agent contagion**. When Agent A is compromised and writes to shared memory, Agent B can inherit the attack through a read-only query — no direct interaction required. WatchTower detects this cross-session, before B's next tool call executes.

100% on a 17-case known-bad corpus. 9,636× faster than the closest competitor. No GPU required.

📄 Full paper: [link]
💻 Code: github.com/beejak/agentwatch

#AIAgents #LLMSecurity #MultiAgentSystems #AIFirewall #AgentSecurity #LLM #GenAI
