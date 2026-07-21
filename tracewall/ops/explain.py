"""Dry-run explain: would Firewall.check ALLOW or BLOCK?"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

from tracewall.audit.sink import NullAuditSink
from tracewall.core.signal import HookEvent, IdentityCtx
from tracewall.ops.config import load_config
from tracewall.transports.profiles import build_firewall_for_profile, get_profile


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Dry-run: would Firewall.check BLOCK/ALLOW?")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--args", default="{}", help="JSON object of tool args")
    ap.add_argument("--args-file", default=None, help="path to JSON args file")
    ap.add_argument("--agent-id", default="explain-agent")
    ap.add_argument("--chain", default="", help="comma-separated caller_chain")
    ap.add_argument(
        "--caps",
        default="read_file,send_email,http_post,send_money,send_message",
        help="caps to register (needed for zta require_caps)",
    )
    args = ap.parse_args(argv)
    cfg = load_config()
    profile = args.profile or cfg.profile
    prof = get_profile(profile)

    async def _run() -> int:
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            fw, _ = await build_firewall_for_profile(profile, db_path=db, audit=NullAuditSink())
            caps = [c.strip() for c in args.caps.split(",") if c.strip()]
            if args.tool not in caps:
                caps.append(args.tool)
            if prof.require_identity or prof.require_caps:
                await fw._ledger.register_identity(
                    IdentityCtx(agent_id=args.agent_id, caps=caps, trust=0.9)
                )
            chain = [c for c in args.chain.split(",") if c.strip()]
            if args.args_file:
                tool_args = json.loads(Path(args.args_file).read_text(encoding="utf-8"))
            else:
                tool_args = json.loads(args.args)
            event = HookEvent(
                agent_id=args.agent_id,
                tool=args.tool,
                args=tool_args,
                caller_chain=chain,
            )
            v = await fw.check(event)
            print(json.dumps({
                "action": v.action.value,
                "source": v.source,
                "reason": v.reason,
                "rule_id": v.rule_id,
                "args_hash": v.args_hash,
                "score": v.score,
                "latency_ms": round(v.latency_ms, 3),
                "context_completeness": v.context_completeness,
                "profile": profile,
            }, indent=2))
            return 0 if v.action.value == "allow" else 2
        finally:
            try:
                await asyncio.sleep(0)  # let aiosqlite settle on Windows
                Path(db).unlink(missing_ok=True)
            except OSError:
                pass

    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
