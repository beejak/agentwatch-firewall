"""E1: deny_unknown_tools on zta/paranoid; balanced stays pack-only."""
from __future__ import annotations

import pytest

from tracewall.audit.sink import NullAuditSink
from tracewall.core.firewall import Firewall
from tracewall.core.signal import HookEvent, IdentityCtx, Verdict
from tracewall.semantic.judge import SemanticJudge
from tracewall.transports.profiles import build_firewall_for_profile, get_profile


def _ev(tool, args=None, agent_id="agent-x", caller_chain=None):
    return HookEvent(
        agent_id=agent_id,
        tool=tool,
        args=args or {},
        caller_chain=caller_chain or [],
    )


async def test_profile_flags_deny_unknown():
    assert get_profile("zta").deny_unknown_tools is True
    assert get_profile("paranoid").deny_unknown_tools is True
    assert get_profile("balanced").deny_unknown_tools is False
    assert get_profile("permissive").deny_unknown_tools is False


async def test_unknown_tool_blocked_when_deny_on(ledger, policy):
    await ledger._set_trust("agent-x", 0.9)
    fw = Firewall(
        ledger=ledger,
        policy=policy,
        judge=SemanticJudge(),
        audit=NullAuditSink(),
        deny_unknown_tools=True,
        declared_tools=policy.declared_tools(),
    )
    v = await fw.check(_ev("post_slack", {"text": "api_key=sk-abcdef0123456789abcd"}))
    assert v.action == Verdict.BLOCK
    assert v.source == "unknown_tool"
    assert v.rule_id == "deny_unknown_tools"
    assert "register caps" in v.reason


async def test_declared_tool_still_reaches_policy(ledger, policy):
    """Known YAML tool is not unknown-denied; destructive rule may still BLOCK."""
    fw = Firewall(
        ledger=ledger,
        policy=policy,
        judge=SemanticJudge(),
        audit=NullAuditSink(),
        deny_unknown_tools=True,
        declared_tools=policy.declared_tools(),
    )
    v = await fw.check(_ev("bash", {"command": "rm -rf /production"}))
    assert v.action == Verdict.BLOCK
    assert v.source == "deterministic"


async def test_caps_union_allows_undeclared_tool(ledger, policy):
    await ledger.register_identity(
        IdentityCtx(agent_id="agent-x", caps=["read_file", "post_slack"], trust=0.9)
    )
    await ledger._set_trust("agent-x", 0.9)
    fw = Firewall(
        ledger=ledger,
        policy=policy,
        judge=SemanticJudge(),
        audit=NullAuditSink(),
        deny_unknown_tools=True,
        declared_tools=policy.declared_tools(),
    )
    v = await fw.check(_ev("post_slack", {"text": "hi"}))
    # Caps ∪ declared: not unknown-denied (may ALLOW via trust gate)
    assert v.action == Verdict.ALLOW
    assert v.source != "unknown_tool"


async def test_balanced_pack_miss_still_allows(firewall, ledger):
    """Lab profile contract: pack miss is not default-deny."""
    await ledger._set_trust("agent-x", 0.9)
    v = await firewall.check(_ev("post_slack", {"text": "api_key=sk-abcdef0123456789abcd"}))
    assert v.action == Verdict.ALLOW


async def test_zta_profile_wires_deny_unknown(tmp_path):
    fw, prof = await build_firewall_for_profile("zta", db_path=str(tmp_path / "z.db"))
    assert prof.deny_unknown_tools is True
    await fw._ledger.register_identity(
        IdentityCtx(agent_id="a1", caps=["read_file"], trust=0.9)
    )
    v = await fw.check(_ev("post_slack", {"text": "x"}, agent_id="a1"))
    # Caps check fires first (not in caps) OR unknown — either is BLOCK
    assert v.action == Verdict.BLOCK


async def test_deny_unknown_fail_safe_polarity(ledger, policy):
    """Empty declared + no caps → BLOCK (fail-closed), never silent ALLOW."""
    fw = Firewall(
        ledger=ledger,
        policy=policy,
        judge=SemanticJudge(),
        audit=NullAuditSink(),
        deny_unknown_tools=True,
        declared_tools=(),
    )
    await ledger._set_trust("agent-x", 0.99)
    v = await fw.check(_ev("read_file", {"path": "/ok"}))
    assert v.action == Verdict.BLOCK and v.source == "unknown_tool"
