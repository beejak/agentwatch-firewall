"""
Reference MCP PEP wiring — see the runnable app:

  py -3.12 examples/reference_mcp_app/run_pep_demo.py
  py -3.12 examples/reference_mcp_app/run_pep_demo.py --subprocess

Production shape:

  python -m tracewall.transports.mcp_proxy --profile zta --agent-id app-1 -- \\
    npx @modelcontextprotocol/server-filesystem /data

Register identity into the same --db before boot (see zta_demo.py).
Client _meta.caller_chain is ignored under zta/paranoid (proxy-owned tree).

LangGraph-style (no langgraph install): examples/langgraph_tool_node_demo.py
"""
print(__doc__)
