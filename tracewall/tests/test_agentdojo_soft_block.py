"""Soft-block defense: BLOCKed tools become invalid names (no AbortAgentError)."""
from agentdojo.functions_runtime import FunctionCall

from tracewall.core.signal import Verdict
from tracewall.eval.adapters.agentdojo import _make_element


class _FakeVerdict:
    def __init__(self, action, reason="blocked"):
        self.action = action
        self.reason = reason


class _FakeFw:
    def __init__(self, block_tools):
        self.block_tools = set(block_tools)

    async def check(self, event):
        if event.tool in self.block_tools:
            return _FakeVerdict(Verdict.BLOCK, "nope")
        return _FakeVerdict(Verdict.ALLOW, "")


class _Loop:
    def run_until_complete(self, coro):
        import asyncio
        return asyncio.get_event_loop().run_until_complete(coro)


def test_soft_block_rewrites_tool_name_not_abort():
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        el = _make_element(_FakeFw({"send_money"}), loop, on_block="soft")
        fc_ok = FunctionCall(function="read_file", args={"p": "b.txt"}, id="1")
        fc_bad = FunctionCall(function="send_money", args={"recipient": "US133"}, id="2")
        msgs = [{"role": "assistant", "content": "", "tool_calls": [fc_ok, fc_bad]}]
        _, _, _, out, _ = el.query("q", None, None, msgs, {})
        names = [c.function for c in out[-1]["tool_calls"]]
        assert names[0] == "read_file"
        assert names[1] == "__tracewall_blocked__"
    finally:
        loop.close()
        asyncio.set_event_loop(None)
