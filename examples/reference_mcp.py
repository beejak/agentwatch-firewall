"""
Reference MCP PEP wiring (pattern).

Run Tracewall as the only path to an MCP server. Clients that talk past the
proxy are out of scope — place the proxy where that is not possible.

  python -m tracewall.transports.mcp_proxy --profile zta --agent-id app-1 -- \\
    npx @modelcontextprotocol/server-filesystem /data

Register identity into the same --db before/during boot (see zta_demo.py).
Client _meta.caller_chain is ignored under zta/paranoid (proxy-owned tree).
Optional _meta.session_id binds the owned chain.

See docs/GETTING_STARTED.md and docs/RUNBOOK.md.
"""
print(__doc__)
