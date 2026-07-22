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
- **OS sandbox / containment** (gVisor, landlock, seccomp, VM isolation) — Tracewall is a tool-call firewall, not a sandbox
- **On-disk file content scanning** — only tool-call **args** (and call-tree / identity context) at the PEP are inspected; no post-write FS watcher
- MCP `tools/list` / unknown tools not covered by YAML (documented limits)
- Direct `open()` / subprocess / raw sockets that never become a screened `tools/call`

**Destructive policy precision:** `destructive_ops.yaml` matches tool `bash` only, and only when `arg.command` hits `rm -rf`, `shred`, `truncate … --size 0`, or curl/wget/`| bash` pipe patterns. There is **no** dedicated `write_file` / `create_file` / `append_to_file` rule; AgentDojo drive tools are not host FS escape controls.

For containment, pair Tracewall with an OS sandbox and make the PEP the sole tool path ([`docs/INTEGRATION.md`](docs/INTEGRATION.md)).

Architecture details: [`docs/FIREWALL.md`](docs/FIREWALL.md).  
Put Tracewall on the path: [`docs/INTEGRATION.md`](docs/INTEGRATION.md).  
Operator posture: [`docs/RUNBOOK.md`](docs/RUNBOOK.md).
