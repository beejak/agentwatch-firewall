# Reference MCP app (PEP path)

Proves Tracewall sits on the only tool-call path to an MCP server.

## Quick (in-process screen — same code as the proxy)

```bash
py -3.12 examples/reference_mcp_app/run_pep_demo.py
```

Expect `read_file` ALLOW and `send_email` to `evil.com` BLOCK under `--profile zta`.

## Full subprocess (real `mcp_proxy` + toy server)

```bash
py -3.12 examples/reference_mcp_app/run_pep_demo.py --subprocess
```

## Production shape

```bash
python -m tracewall.transports.mcp_proxy --profile zta --db /var/lib/tw.db -- \
  <real-mcp-server-cmd>
```

Register identity into the same `--db` before clients connect (see `examples/zta_demo.py`).
Client `_meta.caller_chain` is ignored under `zta` / `paranoid`.

LangGraph-style in-process pattern (no LangGraph install required):
`examples/langgraph_tool_node_demo.py` and `tracewall.transports.tool_node.GuardedToolNode`.
