"""
Toy MCP server (NDJSON) for the Tracewall reference PEP demo.

Speaks a minimal MCP subset over stdin/stdout:
  - initialize / notifications/initialized / tools/list pass-through
  - tools/call for read_file and send_email

Not a production MCP SDK — proves the proxy sits on the only tool path.
"""
from __future__ import annotations

import json
import sys


def _reply(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _ok(req_id, text: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {"content": [{"type": "text", "text": text}]},
    }


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            _reply({
                "jsonrpc": "2.0",
                "id": mid,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "tracewall-toy-mcp", "version": "0.2.0"},
                },
            })
            continue
        if method == "notifications/initialized":
            continue
        if method == "tools/list":
            _reply({
                "jsonrpc": "2.0",
                "id": mid,
                "result": {
                    "tools": [
                        {"name": "read_file", "description": "Read a path", "inputSchema": {"type": "object"}},
                        {"name": "send_email", "description": "Send email", "inputSchema": {"type": "object"}},
                    ],
                },
            })
            continue
        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name", "")
            args = params.get("arguments") or {}
            if name == "read_file":
                _reply(_ok(mid, f"contents of {args.get('path', '?')}"))
            elif name == "send_email":
                _reply(_ok(mid, f"sent to {args.get('to', '?')}"))
            else:
                _reply({
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "content": [{"type": "text", "text": f"unknown tool {name}"}],
                        "isError": True,
                    },
                })
            continue
        if mid is not None:
            _reply({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown {method}"}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
