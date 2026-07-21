"""ZTA profile demo: register identity + default-deny external email."""
from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

from tracewall.core.signal import IdentityCtx
from tracewall.transports.profiles import build_firewall_for_profile
from tracewall.transports.python_guard import GuardBlocked, SoftBlockResult, guard


async def main() -> None:
    os.environ.setdefault("TRACEWALL_ORG_DOMAINS", "acme.com")
    os.environ["TRACEWALL_SEMANTIC_LLM"] = "0"
    td = tempfile.mkdtemp()
    db = str(Path(td) / "tw.db")
    fw, prof = await build_firewall_for_profile("zta", db_path=db)
    print(f"profile={prof.name} rules={len(fw._policy._rules)}")

    await fw._ledger.register_identity(
        IdentityCtx(
            agent_id="demo",
            caps=["read_file", "send_email", "list_directory"],
            trust=0.9,
        )
    )

    await guard(fw, "read_file", {"path": "/ok"}, ctx={"agent_id": "demo"})
    print("allow: read_file")

    soft = await guard(
        fw,
        "send_email",
        {"to": "x@evil.com", "body": "hi"},
        ctx={"agent_id": "demo"},
        on_block="soft",
    )
    assert isinstance(soft, SoftBlockResult)
    print("soft-block:", soft.message)

    try:
        await guard(
            fw,
            "send_email",
            {"to": "x@evil.com", "body": "hi"},
            ctx={"agent_id": "demo"},
        )
    except GuardBlocked as b:
        print("raise-block:", b.verdict.rule_id, b.verdict.reason)


if __name__ == "__main__":
    asyncio.run(main())
