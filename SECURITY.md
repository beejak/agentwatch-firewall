# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes |
| < 0.2   | Best-effort |

## Reporting a vulnerability

Open a **private** GitHub security advisory on
[beejak/agentwatch-firewall](https://github.com/beejak/agentwatch-firewall)
or email the maintainer listed on the repo. Do not file public issues for
exploitable bypasses until a fix is available.

## Threat model (short)

**In scope:** tool-call misuse after prompt injection; egress to non-allowlisted
destinations when using `zta`/`paranoid`; capability abuse when caps are set;
call-tree exfil when the PEP owns the session chain.

**Out of scope / not protected:**

- Bypassing the PEP (calling tools without going through Tracewall)
- Host / OS compromise, stealing the ledger DB, rewriting the proxy binary
- Model-weight jailbreaks as the primary control
- Client-forged `_meta` under `balanced` (use `zta` for owned call trees)
- Distributed rate limiting / multi-node consensus
- Full NIST ZTA / SPIFFE continuous authentication (not shipped)

Architecture details: [`docs/FIREWALL.md`](docs/FIREWALL.md).  
Operator posture: [`docs/RUNBOOK.md`](docs/RUNBOOK.md).
