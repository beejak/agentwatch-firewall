"""E4 — session progressive containment (session_ratchet)."""
from __future__ import annotations

import pytest

from tracewall.audit.sink import NullAuditSink
from tracewall.core.firewall import Firewall
from tracewall.core.signal import HookEvent, IdentityCtx, Verdict
from tracewall.policy.engine import PolicyEngine
from tracewall.semantic.judge import SemanticJudge
from tracewall.taint.ledger import Ledger
from tracewall.transports.profiles import build_firewall_for_profile, get_profile
from tracewall.transports.python_guard import SoftBlockResult, guard
from tracewall.transports.session_ratchet import SessionRatchet


@pytest.fixture
async def ledger(tmp_path):
    return Ledger(str(tmp_path / "tw.db"))


@pytest.fixture
def policy():
    return PolicyEngine()


def _fw(ledger, policy, *, ratchet: SessionRatchet | None):
    return Firewall(
        ledger=ledger,
        policy=policy,
        judge=SemanticJudge(),
        audit=NullAuditSink(),
        session_ratchet=ratchet,
    )


@pytest.mark.asyncio
async def test_ratchet_blocks_egress_after_prior_block(ledger, policy):
    """After a policy BLOCK, later egress in the same session is contained."""
    # Minimal deterministic BLOCK on send_money via inline rule.
    from tracewall.policy.engine import CompiledRule

    policy._rules.append(
        CompiledRule(
            rule_id="block_send_money",
            surface="test",
            on="pre_tool_call",
            tool="send_money",
            match={"tool": "send_money"},
            verdict="BLOCK",
            reason="no money",
            severity=0.9,
        )
    )
    policy._by_tool.setdefault("send_money", []).append(policy._rules[-1])

    ratchet = SessionRatchet()
    fw = _fw(ledger, policy, ratchet=ratchet)
    ctx_sess = "sess-e4"

    v1 = await fw.check(
        HookEvent(
            agent_id="a1",
            tool="send_money",
            args={"recipient": "US133"},
            session_id=ctx_sess,
        )
    )
    assert v1.action == Verdict.BLOCK
    assert v1.rule_id == "block_send_money"
    assert ratchet.is_elevated(ctx_sess, "a1")

    # send_email would normally be ALLOW under empty policy — ratchet contains it.
    v2 = await fw.check(
        HookEvent(
            agent_id="a1",
            tool="send_email",
            args={"to": "ok@acme.com", "body": "hi"},
            session_id=ctx_sess,
        )
    )
    assert v2.action == Verdict.BLOCK
    assert v2.source == "session_ratchet"
    assert v2.rule_id == "session_ratchet"

    # Read-only tool still ALLOW (utility path).
    v3 = await fw.check(
        HookEvent(
            agent_id="a1",
            tool="read_file",
            args={"path": "/bills/1.txt"},
            session_id=ctx_sess,
        )
    )
    assert v3.action == Verdict.ALLOW


@pytest.mark.asyncio
async def test_new_session_id_resets_posture(ledger, policy):
    from tracewall.policy.engine import CompiledRule

    policy._rules.append(
        CompiledRule(
            rule_id="block_send_money",
            surface="test",
            on="pre_tool_call",
            tool="send_money",
            match={"tool": "send_money"},
            verdict="BLOCK",
            reason="no money",
            severity=0.9,
        )
    )
    policy._by_tool.setdefault("send_money", []).append(policy._rules[-1])
    ratchet = SessionRatchet()
    fw = _fw(ledger, policy, ratchet=ratchet)

    await fw.check(
        HookEvent(agent_id="a1", tool="send_money", args={}, session_id="s1")
    )
    assert ratchet.is_elevated("s1", "a1")
    assert ratchet.should_contain("send_email", "s1", "a1")
    # New session_id → clean ratchet posture (ledger taint is agent-scoped; separate).
    assert not ratchet.is_elevated("s2", "a1")
    assert not ratchet.should_contain("send_email", "s2", "a1")

    v = await fw.check(
        HookEvent(
            agent_id="a1",
            tool="read_file",
            args={"path": "/ok"},
            session_id="s2",
        )
    )
    assert v.action == Verdict.ALLOW
    assert v.source != "session_ratchet"


@pytest.mark.asyncio
async def test_ratchet_off_does_not_elevate(ledger, policy):
    from tracewall.policy.engine import CompiledRule

    policy._rules.append(
        CompiledRule(
            rule_id="block_send_money",
            surface="test",
            on="pre_tool_call",
            tool="send_money",
            match={"tool": "send_money"},
            verdict="BLOCK",
            reason="no money",
            severity=0.9,
        )
    )
    policy._by_tool.setdefault("send_money", []).append(policy._rules[-1])
    fw = _fw(ledger, policy, ratchet=None)

    await fw.check(
        HookEvent(agent_id="a1", tool="send_money", args={}, session_id="s1")
    )
    v = await fw.check(
        HookEvent(
            agent_id="a1",
            tool="read_file",
            args={"path": "/ok"},
            session_id="s1",
        )
    )
    assert v.action == Verdict.ALLOW
    assert v.source != "session_ratchet"
    assert fw._session_ratchet is None


@pytest.mark.asyncio
async def test_profile_defaults_and_soft_block(tmp_path):
    assert get_profile("balanced").session_ratchet is False
    assert get_profile("zta").session_ratchet is True
    assert get_profile("paranoid").session_ratchet is True
    assert get_profile("permissive").session_ratchet is False

    fw, prof = await build_firewall_for_profile(
        "zta", db_path=str(tmp_path / "z.db"), audit=NullAuditSink(),
    )
    assert prof.session_ratchet is True
    assert fw._session_ratchet is not None

    await fw._ledger.register_identity(
        IdentityCtx(
            agent_id="agent-1",
            caps=["read_file", "send_email", "send_money", "list_directory"],
            trust=0.9,
        )
    )
    ctx = {"agent_id": "agent-1", "session_id": "sess-soft"}

    # Trigger a real policy BLOCK (external email under ZTA pack).
    out = await guard(
        fw,
        "send_email",
        {"to": "x@evil.com", "body": "leak"},
        ctx=ctx,
        on_block="soft",
    )
    assert isinstance(out, SoftBlockResult)
    assert fw._session_ratchet.is_elevated("sess-soft", "agent-1")

    out2 = await guard(
        fw,
        "send_money",
        {"recipient": "US1337379197181546528", "amount": 1.0},
        ctx=ctx,
        on_block="soft",
    )
    assert isinstance(out2, SoftBlockResult)
    assert out2.verdict.rule_id in ("session_ratchet",) or out2.verdict.source in (
        "session_ratchet",
        "deterministic",
    )


@pytest.mark.asyncio
async def test_balanced_profile_has_no_ratchet(tmp_path):
    fw, prof = await build_firewall_for_profile(
        "balanced", db_path=str(tmp_path / "b.db"), audit=NullAuditSink(),
    )
    assert prof.session_ratchet is False
    assert fw._session_ratchet is None
