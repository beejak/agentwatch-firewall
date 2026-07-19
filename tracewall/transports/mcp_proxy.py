"""
tracewall/transports/mcp_proxy.py — MCP gateway proxy (transport #2).

Sits transparently between an MCP client and an MCP server over stdio.
Supports MCP **Content-Length** framing and legacy **NDJSON** (one JSON per line);
framing is auto-detected from the first message on each direction.

Forwards everything except ``tools/call``, which is screened:
ALLOW → forward; BLOCK → MCP tool error (``isError: true``), never forward.

When ``own_call_tree=True`` (zta/paranoid profiles), the proxy records tools it
screened and ignores client-supplied ``caller_chain`` (anti-forge).

    python -m tracewall.transports.mcp_proxy --profile zta -- <mcp-server-cmd>
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional

from tracewall.core.firewall import Firewall
from tracewall.core.signal import HookEvent, Verdict
from tracewall.transports.mcp_framing import (
    encode_cl_message,
    encode_ndjson_message,
)
from tracewall.transports.python_guard import _ctx_get
from tracewall.transports.session_chain import SessionCallTree

logger = logging.getLogger(__name__)

TOOLS_CALL = "tools/call"
_META_KEY = "tracewall"


@dataclass
class ProxyConfig:
    default_agent_id: str = "mcp-client"
    fail_closed: bool = True
    profile: str = "balanced"
    own_call_tree: bool = False


def _meta_ctx(params: dict) -> dict:
    meta = params.get("_meta") or {}
    tw = meta.get(_META_KEY) if isinstance(meta, dict) else None
    return tw if isinstance(tw, dict) else {}


def build_event_from_mcp(
    params: dict,
    cfg: ProxyConfig,
    *,
    call_tree: SessionCallTree | None = None,
) -> HookEvent:
    ctx = _meta_ctx(params)
    agent_id = str(_ctx_get(ctx, "agent_id") or cfg.default_agent_id)
    session_id = str(_ctx_get(ctx, "session_id", "") or "")
    if cfg.own_call_tree:
        # Never trust client-supplied caller_chain in ZTA mode.
        chain = call_tree.chain(session_id, agent_id) if call_tree is not None else []
    else:
        chain = list(_ctx_get(ctx, "caller_chain", []) or [])
    return HookEvent(
        agent_id=agent_id,
        tool=str(params.get("name", "")),
        args=dict(params.get("arguments") or {}),
        caller_chain=chain,
        session_id=session_id,
    )


def _block_response(req_id, reason: str) -> dict:
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
    call_tree: SessionCallTree | None = None,
) -> Optional[dict]:
    if message.get("method") != TOOLS_CALL:
        return None
    params = message.get("params") or {}
    try:
        event = build_event_from_mcp(params, cfg, call_tree=call_tree)
    except Exception as e:
        if cfg.fail_closed:
            return _block_response(message.get("id"), f"malformed tool call: {e}")
        logger.warning("mcp_proxy: fail-open on malformed call: %s", e)
        return None
    verdict = await firewall.check(event)
    if verdict.action == Verdict.BLOCK:
        return _block_response(message.get("id"), verdict.reason)
    if cfg.own_call_tree and call_tree is not None:
        call_tree.record(event.session_id, event.tool, event.agent_id)
    return None


def _encode(obj: dict, framing: str) -> bytes:
    if framing == "cl":
        return encode_cl_message(obj)
    return encode_ndjson_message(obj)


async def _read_with_mode(reader, mode_holder: dict, key: str) -> Optional[tuple[str, bytes]]:
    first = await reader.readline()
    if not first:
        return None
    if first.lower().startswith(b"content-length:"):
        mode_holder[key] = "cl"
        from tracewall.transports.mcp_framing import _finish_cl
        raw = await _finish_cl(reader, first)
        return "cl", raw
    mode_holder.setdefault(key, "ndjson")
    return "ndjson", first.rstrip(b"\r\n")


class McpStdioProxy:
    def __init__(
        self,
        firewall: Firewall,
        server_cmd: list[str],
        cfg: Optional[ProxyConfig] = None,
        call_tree: SessionCallTree | None = None,
    ) -> None:
        self._fw = firewall
        self._cmd = server_cmd
        self._cfg = cfg or ProxyConfig()
        self._modes: dict[str, str] = {"client": "ndjson", "server": "ndjson"}
        self._call_tree = call_tree if call_tree is not None else SessionCallTree()

    async def run(self) -> int:
        proc = await asyncio.create_subprocess_exec(
            *self._cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        client_in = await _stdin_reader()

        async def client_to_server() -> None:
            while True:
                got = await _read_with_mode(client_in, self._modes, "client")
                if got is None:
                    break
                framing, raw = got
                try:
                    message = json.loads(raw)
                except Exception:
                    if self._cfg.fail_closed and b"tools/call" in raw:
                        resp = _block_response(None, "unparseable tools/call")
                        sys.stdout.buffer.write(_encode(resp, self._modes["client"]))
                        sys.stdout.buffer.flush()
                        continue
                    proc.stdin.write(_encode_raw_forward(raw, framing))
                    await proc.stdin.drain()
                    continue
                blocked = await screen_tool_call(
                    self._fw, message, self._cfg, call_tree=self._call_tree,
                )
                if blocked is not None:
                    sys.stdout.buffer.write(_encode(blocked, self._modes["client"]))
                    sys.stdout.buffer.flush()
                    continue
                proc.stdin.write(_encode(message, self._modes.get("server", framing)))
                await proc.stdin.drain()
            if proc.stdin:
                proc.stdin.close()

        async def server_to_client() -> None:
            while True:
                got = await _read_with_mode(proc.stdout, self._modes, "server")
                if got is None:
                    break
                framing, raw = got
                try:
                    obj = json.loads(raw)
                    sys.stdout.buffer.write(_encode(obj, self._modes["client"]))
                except Exception:
                    sys.stdout.buffer.write(raw + b"\n")
                sys.stdout.buffer.flush()

        await asyncio.gather(client_to_server(), server_to_client())
        return await proc.wait()


def _encode_raw_forward(raw: bytes, framing: str) -> bytes:
    if framing == "cl":
        try:
            return encode_cl_message(json.loads(raw))
        except Exception:
            pass
    if not raw.endswith(b"\n"):
        return raw + b"\n"
    return raw


async def _stdin_reader() -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    from tracewall.audit.sink import LocalAuditSink
    from tracewall.transports.profiles import PROFILE_NAMES, build_firewall_for_profile, get_profile

    ap = argparse.ArgumentParser(description="tracewall MCP stdio proxy")
    ap.add_argument("--db", default="tracewall_mcp.db")
    ap.add_argument("--agent-id", default="mcp-client")
    ap.add_argument("--profile", default="balanced", choices=list(PROFILE_NAMES))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--fail-closed", dest="fail_closed", action="store_true", default=None)
    g.add_argument("--fail-open", dest="fail_closed", action="store_false")
    ap.add_argument("server_cmd", nargs=argparse.REMAINDER)
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
        return await McpStdioProxy(fw, cmd, cfg).run()

    return asyncio.run(_boot())


if __name__ == "__main__":
    raise SystemExit(main())
