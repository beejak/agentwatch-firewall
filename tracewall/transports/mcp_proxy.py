"""
tracewall/transports/mcp_proxy.py — MCP gateway proxy (transport #2).

Sits transparently between an MCP client (the agent) and an MCP server, relaying
newline-delimited JSON-RPC 2.0 over stdio. It forwards everything untouched
except ``tools/call``, which it screens through the firewall first: ALLOW →
forward to the real server; BLOCK → reply to the client with an MCP tool error
(``isError: true``) and never forward.

Zero code change in the agent: point the client at this proxy instead of the
real server (the proxy spawns the real server as a subprocess).

    python -m tracewall.transports.mcp_proxy -- npx @modelcontextprotocol/server-filesystem /data

Context starvation, handled honestly
------------------------------------
The MCP wire carries ``name`` + ``arguments`` but not the agent's call tree or
identity. A cooperating client MAY enrich a call via the reserved ``_meta``
field:

    "params": {"name": "...", "arguments": {...},
               "_meta": {"tracewall": {"agent_id": "...",
                                       "caller_chain": ["..."],
                                       "session_id": "..."}}}

When ``_meta.tracewall`` is absent we fall back to a configured ``default_agent_id``
(so cross-session taint still has a — coarse — stable id) and the verdict's
``context_completeness`` records that identity/call-tree were unavailable. The
taint and semantic tiers degrade gracefully rather than over-claim.

The screening core (`screen_tool_call`) is a pure async function over parsed
JSON-RPC dicts — the stdio plumbing is a thin shell around it, so the security
logic is fully testable without spawning a process or opening a socket.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass
from typing import Optional

from tracewall.core.firewall import Firewall
from tracewall.core.signal import HookEvent, Verdict
from tracewall.transports.python_guard import _ctx_get  # reuse dict/obj accessor

logger = logging.getLogger(__name__)

TOOLS_CALL = "tools/call"
_META_KEY = "tracewall"


@dataclass
class ProxyConfig:
    default_agent_id: str = "mcp-client"   # coarse stable id when _meta is absent
    fail_closed: bool = True               # malformed/unreachable → BLOCK
    profile: str = "balanced"              # named preset label (for audit/logs)


def _meta_ctx(params: dict) -> dict:
    """Extract the optional tracewall context block from MCP params._meta."""
    meta = params.get("_meta") or {}
    tw = meta.get(_META_KEY) if isinstance(meta, dict) else None
    return tw if isinstance(tw, dict) else {}


def build_event_from_mcp(params: dict, cfg: ProxyConfig) -> HookEvent:
    """Map an MCP ``tools/call`` params object onto a HookEvent."""
    ctx = _meta_ctx(params)
    agent_id = _ctx_get(ctx, "agent_id") or cfg.default_agent_id
    return HookEvent(
        agent_id=str(agent_id),
        tool=str(params.get("name", "")),
        args=dict(params.get("arguments") or {}),
        caller_chain=list(_ctx_get(ctx, "caller_chain", []) or []),
        session_id=str(_ctx_get(ctx, "session_id", "") or ""),
    )


def _block_response(req_id, reason: str) -> dict:
    """MCP tool-error result for the client (isError=true) — not a protocol error."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": f"tracewall blocked this tool call: {reason}"}],
            "isError": True,
        },
    }


async def screen_tool_call(
    firewall: Firewall,
    message: dict,
    cfg: ProxyConfig,
) -> Optional[dict]:
    """Screen one parsed JSON-RPC message.

    Returns ``None`` to forward the message to the real server (not a tools/call,
    or ALLOW). Returns a JSON-RPC response dict (the block) when a tools/call is
    denied — the proxy sends it straight back to the client and forwards nothing.
    """
    if message.get("method") != TOOLS_CALL:
        return None   # forward everything that isn't a tool call

    params = message.get("params") or {}
    try:
        event = build_event_from_mcp(params, cfg)
    except Exception as e:
        if cfg.fail_closed:
            return _block_response(message.get("id"), f"malformed tool call: {e}")
        logger.warning("mcp_proxy: fail-open on malformed call: %s", e)
        return None

    verdict = await firewall.check(event)
    if verdict.action == Verdict.BLOCK:
        return _block_response(message.get("id"), verdict.reason)
    return None   # ALLOW → forward to the real server


# ── stdio plumbing (thin shell around screen_tool_call) ──────────────────────

class McpStdioProxy:
    """Spawn a real MCP server and relay stdio, screening tools/call."""

    def __init__(self, firewall: Firewall, server_cmd: list[str],
                 cfg: Optional[ProxyConfig] = None) -> None:
        self._fw = firewall
        self._cmd = server_cmd
        self._cfg = cfg or ProxyConfig()

    async def run(self) -> int:
        proc = await asyncio.create_subprocess_exec(
            *self._cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        client_in = await _stdin_reader()
        client_out = _stdout_writer()

        async def client_to_server() -> None:
            # client → [screen] → server
            while True:
                line = await client_in.readline()
                if not line:
                    break
                blocked = await self._maybe_block(line)
                if blocked is not None:
                    client_out(blocked)          # reply to client, do not forward
                    continue
                proc.stdin.write(line)
                await proc.stdin.drain()
            if proc.stdin:
                proc.stdin.close()

        async def server_to_client() -> None:
            # server → client (untouched)
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                client_out_raw(line)

        await asyncio.gather(client_to_server(), server_to_client())
        return await proc.wait()

    async def _maybe_block(self, line: bytes) -> Optional[bytes]:
        try:
            message = json.loads(line)
        except Exception:
            # Unparseable line: fail-closed blocks only if it looks like tools/call.
            if self._cfg.fail_closed and b"tools/call" in line:
                fake_id = None
                resp = _block_response(fake_id, "unparseable tools/call line")
                return (json.dumps(resp) + "\n").encode()
            return None   # forward verbatim
        resp = await screen_tool_call(self._fw, message, self._cfg)
        if resp is None:
            return None
        return (json.dumps(resp) + "\n").encode()


# stdout helpers kept tiny so they can be monkeypatched in any embedding context
async def _stdin_reader() -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


def _stdout_writer():
    def _write(obj: dict) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()
    return _write


def client_out_raw(line: bytes) -> None:
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    from tracewall.audit.sink import LocalAuditSink
    from tracewall.transports.profiles import PROFILE_NAMES, build_firewall_for_profile, get_profile

    ap = argparse.ArgumentParser(description="tracewall MCP stdio proxy")
    ap.add_argument("--db", default="tracewall_mcp.db", help="ledger SQLite path")
    ap.add_argument("--agent-id", default="mcp-client", help="default agent_id when _meta absent")
    ap.add_argument(
        "--profile",
        default="balanced",
        choices=list(PROFILE_NAMES),
        help="paranoid | balanced | permissive (default: balanced)",
    )
    g = ap.add_mutually_exclusive_group()
    g.add_argument(
        "--fail-closed",
        dest="fail_closed",
        action="store_true",
        default=None,
        help="override profile: BLOCK on malformed tools/call",
    )
    g.add_argument(
        "--fail-open",
        dest="fail_closed",
        action="store_false",
        help="override profile: forward malformed tools/call",
    )
    ap.add_argument("server_cmd", nargs=argparse.REMAINDER,
                    help="-- <command to launch the real MCP server>")
    args = ap.parse_args(argv)

    cmd = args.server_cmd[1:] if args.server_cmd and args.server_cmd[0] == "--" else args.server_cmd
    if not cmd:
        ap.error("provide the real MCP server command after `--`")

    async def _boot() -> int:
        prof = get_profile(args.profile)
        fw, prof = await build_firewall_for_profile(prof, db_path=args.db, audit=LocalAuditSink())
        cfg = prof.proxy_config(default_agent_id=args.agent_id)
        if args.fail_closed is not None:
            cfg.fail_closed = args.fail_closed
        proxy = McpStdioProxy(fw, cmd, cfg)
        return await proxy.run()

    return asyncio.run(_boot())


if __name__ == "__main__":
    raise SystemExit(main())
