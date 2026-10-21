# Tracewall for DevOps / DevSecOps

Honest placement. **Last updated 2026-10-21** (v0.3.0).

Tracewall is a **runtime tool-call PEP** (`await Firewall.check(event) → FirewallVerdict`).
It is **not** a static analyzer that fails `npm build` / `pip install` by itself.

## Can it be a build blocker?

**Short answer:** as a **policy / deploy / agent-path gate**, yes. As a **drop-in SAST
step that blocks compile without a harness**, no.

| Pattern | Build blocker? | What it actually gates |
|---------|----------------|------------------------|
| Required CI job: `pytest` + `mcp_brink` (+ optional `robustness_stress`) | **Yes** | Policy/profile regressions before merge |
| Pre-deploy smoke: `ops.explain` / `ops.health` / reference MCP PEP | **Yes** (deploy gate) | Agent ships only if PEP config loads and known-bad tools BLOCK |
| Runtime: MCP proxy / `guard` / `GuardedToolNode` on every tool path | **Yes** (runtime) | Compromised agent cannot execute screened misuse |
| “Add Tracewall package → `npm run build` fails on prompt injection” | **No** | Tracewall never sees PR text or model weights |

**Recommended framing for security teams:** treat Tracewall like a **WAF / PEP for agent
tools**, not like Semgrep. Fail the pipeline when **policy tests** fail or when **deploy
config** omits the PEP. Do not claim it blocks prompt injection in pull requests.

## Threat landscape (where it sits)

```
Dev time          Build/CI              Deploy                 Runtime agent loop
──────────        ────────              ──────                 ─────────────────
SAST / lint       SCA / secrets         IaC / image scan       OS sandbox (gVisor/…)
secrets scan      unit + policy tests   signed config          ★ Tracewall PEP
IaC review        SBOM (not shipped)    PEP wired?             tool ALLOW/BLOCK
```

**Threat Tracewall targets:** LLM-compromised (or confused) agent → **tool misuse**
(exfil, money move, destructive shell) on the **screened** path.

**Peers (not substitutes):**

| Control | Catches | Misses Tracewall’s job |
|---------|---------|------------------------|
| SAST / Semgrep | Code bugs, insecure patterns | Live tool args from an agent session |
| SCA / Dependabot | Vulnerable deps | Runtime tool policy |
| Secrets scanners | Keys in repo / CI logs | Agent reading a secret then emailing it |
| IaC / admission | Bad cloud config | Agent `http_post` of data at runtime |
| OS sandbox | Host escape / FS blast radius | Deciding *which* tool calls are allowed |

Pair sandbox + Tracewall: sandbox limits *blast radius*; Tracewall decides *permission*.

## What Tracewall cannot block in CI

- Prompt injection text in PRs / issues / docs
- Model weights, fine-tunes, or chat-stream jailbreaks
- Sandbox escape / host compromise / alternate tool path that bypasses the PEP
- Full AgentDojo (we evidence a **banking slice** only)
- SPIFFE / continuous IdP (ledger register only today)

## Plug-and-play patterns

### 1) Required GitHub Actions policy job

CI already runs pytest + harness + brink (see `.github/workflows/ci.yml`). Make that
check **required** on the default branch. Optional local/release gate:

```bash
pip install -e ".[dev]"
pytest -q
python -m tracewall.eval.mcp_brink
python -m tracewall.eval.robustness_stress   # release gate; not default CI
```

AgentDojo **live** soft-block needs `.[bench]` + `LLM_API_KEY` — keep optional; do not
invent ASR numbers when the key is absent.

### 2) Pre-deploy smoke (refuse to ship agents without PEP)

```bash
python -m tracewall.ops.health --profile zta
python -m tracewall.ops.explain --profile zta --tool send_email \
  --args '{"to":"x@evil.com","body":"hi"}'
# expect action=block
```

Deploy only if health is ok and the known-bad explain is BLOCK.

### 3) MCP proxy in path (runtime)

```bash
python -m tracewall.transports.mcp_proxy --profile zta --db /var/lib/tw.db -- \
  <real-mcp-server>
```

Client must talk **only** to the proxy. Profiles: lab `balanced`; prod `zta` /
`paranoid` (fail-closed, E1 unknown-tool deny, E2 list filter, E4 session ratchet).

### 4) Soft-block vs hard-block (DX)

| Mode | DX | Security |
|------|----|----------|
| Soft-block (`on_block=soft` / MCP `isError`) | Agent loop continues; utility can recover | Attack tool does not execute |
| Hard raise (`GuardBlocked`) | Fail fast | Same execute denial |
| E4 `session_ratchet` (zta/paranoid) | After a BLOCK, later egress in-session is contained | Progressive containment; off on `balanced` |

## Ship checklist (DevSecOps)

- [ ] Tracewall on **every** agent tool path (`guard` / `mcp_proxy` / `GuardedToolNode`)
- [ ] Prod profile `zta` or `paranoid` (not `balanced`)
- [ ] `TRACEWALL_ORG_DOMAINS` set; identity + non-empty caps registered to the same `--db`
- [ ] CI: pytest + brink **required**; robustness before release tags
- [ ] Deploy gate: `ops.health` + known-bad `ops.explain` → BLOCK
- [ ] Soft-block wired if you need AgentDojo-style utility; still never execute on BLOCK
- [ ] Pair with OS sandbox / secrets / SCA — do not treat Tracewall as the only control
- [ ] Do not claim paper freeze numbers as “current HEAD” without checking [`RESULTS.md`](RESULTS.md)

## Cross-links

- Integration: [`INTEGRATION.md`](INTEGRATION.md)
- Enterprise checklist: [`ENTERPRISE.md`](ENTERPRISE.md)
- Threat model: [`../SECURITY.md`](../SECURITY.md)
- Results / test parameters: [`RESULTS.md`](RESULTS.md) · [`TEST_PLAN.md`](TEST_PLAN.md)
- Pick-up: [`../HANDOFF.md`](../HANDOFF.md)
