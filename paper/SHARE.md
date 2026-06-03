# Social Share Copy

---

## LinkedIn Post

Most agent security tools are solving the wrong problem.

They sit at the content layer — scanning inputs, flagging outputs. That works fine if your threat model is a chatbot. It breaks completely once you have agents calling tools, reading memory, and spawning sub-agents.

I've been thinking about this for a while. Here's what the actual threat surface looks like:

An attacker poisons a document. An agent reads it during a retrieval call — no write access, just a read. That's enough. The injected instruction travels with the agent's context into whatever it does next. MINJA demonstrated 98.2% success with exactly this pattern. The content filter saw nothing because the content was technically fine.

That's attack surface one. Surface two is subtler. `send_email` after `read_secret` looks identical to `send_email` for a meeting invite at the network layer. Same endpoint, same format. The difference is *why* it was called — and you can only know that if you tracked what happened before it.

Surface three is what kept me up at night. Agent A gets compromised. It writes to shared memory. Agent B — completely clean, never interacted with the attacker — does a routine query-only read. At the wire level, nothing happened. But B just inherited the attack.

No published system handled all three. So I built one.

WatchTower intercepts at the tool-call level, not the content level. Every call gets tagged with its full call tree. A YAML policy can say "block this tool call if `read_secret` appears anywhere in the chain" — deterministically, in 0.011ms. Cross-session taint propagates through memory reads before the next call executes.

17 known-bad test cases. 100% detection. Zero false positives on clean workloads. 9,636× faster than the closest published system — and that one needs an A100 GPU.

The paper is out. IEEEtran format, formal taint model, full evaluation. Targeting IEEE S&P / USENIX Security.

Code: github.com/beejak/agentwatch
Paper: github.com/beejak/agentwatch/blob/master/paper/index.html

Happy to discuss — especially if you're working on agent infrastructure and have seen variants of these attacks in the wild.

---

## X / Twitter Thread

**1/**
Most agent security work is solving a 2023 problem in 2026.

Scanning inputs. Filtering outputs. That's fine for chatbots.

It doesn't work once agents have tool access, shared memory, and sub-agents. Here's why — and what a different architecture looks like.

**2/**
The attack that changed my thinking: MINJA (arXiv:2503.03704)

98.2% injection success. Query-only. The attacker never wrote anything.

The agent read a poisoned document during retrieval. That was enough. Content filter saw clean content — because the content *was* clean. The instruction was in the structure, not the text.

**3/**
Surface 2 is the one nobody talks about enough.

`send_email(body="api_key=sk-...")` after `read_secret` vs `send_email` for a normal reply.

Same endpoint. Same HTTP method. Completely different intent.

You can't block one without allowing the other — unless you tracked the call chain that led there.

**4/**
Surface 3 is the scary one.

Agent A gets compromised → writes poisoned memory → Agent B does a routine read → B inherits the attack vector.

B never interacted with the attacker. At the wire level, nothing happened. But the taint moved.

No published system was tracking this cross-session.

**5/**
So the architecture I built — WatchTower — intercepts at the tool-call level, not content level.

Every call gets its full call tree. A policy can say:

```yaml
match:
  tool: send_email
  context:
    call_tree_contains: [read_secret]
verdict: BLOCK
```

Zero ML. 0.011ms. Deterministic.

**6/**
Taint propagation in practice:

Agent A tainted at 0.9 → writes to shared memory → Agent B reads it → T(B) = 0.9 × 0.8 = 0.72 → quarantine threshold is 0.7 → B blocked before its next call.

This all happens in under 1ms. Quarantine expires in ~2.5 hours. No permanent lockout.

**7/**
Numbers vs the field:

- LlamaFirewall: surface 1 only, >100ms
- AgentSpec: surface 2 only, 70.96% recall  
- Distributed Sentinel: surfaces 1+2 partial, 106ms, requires A100
- WatchTower: all 3 surfaces, 0.011ms, runs on SQLite

17 known-bad cases. 100% detection. 0% false positives.

**8/**
Full paper written — IEEEtran, formal proofs, benchmarks, 16 references.

Code + paper: github.com/beejak/agentwatch

If you're building agent infrastructure and have seen these attack patterns in the wild, I want to talk.

---

## Short Caption (paper link share)

Something I've been sitting on for a while.

Multi-agent systems have a taint propagation problem that content-layer security completely misses. Agent A gets compromised, writes to shared memory, Agent B reads it in a routine query — and inherits the attack. No write access required. No direct interaction. Just a read.

WatchTower is my answer to it: tool-call interception with semantic call-tree context and cross-session taint tracking. 0.011ms enforcement. Runs on SQLite, not a GPU cluster.

17 attack cases. 100% detection. Paper in IEEEtran format.

github.com/beejak/agentwatch

— Rohit Jinsiwale

#AIAgents #LLMSecurity #AgentSecurity #PromptInjection #MultiAgentSystems
