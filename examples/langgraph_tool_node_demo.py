"""LangGraph-style GuardedToolNode demo (no langgraph package required)."""
from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

from tracewall.core.signal import IdentityCtx
from tracewall.transports.profiles import build_firewall_for_profile
from tracewall.transports.tool_node import GuardedToolNode


def read_file(*, path: str) -> str:
    return f"ok:{path}"


def send_email(*, to: str, body: str) -> str:
    return f"sent:{to}"


async def main() -> None:
    os.environ.setdefault("TRACEWALL_ORG_DOMAINS", "acme.com")
    os.environ["TRACEWALL_SEMANTIC_LLM"] = "0"
    db = str(Path(tempfile.mkdtemp()) / "tw.db")
    fw, _ = await build_firewall_for_profile("zta", db_path=db)
    await fw._ledger.register_identity(
        IdentityCtx(agent_id="lg", caps=["read_file", "send_email"], trust=0.9)
    )
    node = GuardedToolNode(fw, {"read_file": read_file, "send_email": send_email})
    ctx = {"agent_id": "lg", "session_id": "s1"}

    a = await node.ainvoke({"name": "read_file", "args": {"path": "/x"}}, ctx=ctx)
    print("allow:", a.allowed, a.result)

    b = await node.ainvoke(
        {"name": "send_email", "args": {"to": "x@evil.com", "body": "hi"}},
        ctx=ctx,
    )
    print("block:", b.allowed, (b.error or "")[:80])


if __name__ == "__main__":
    asyncio.run(main())
