"""Enterprise readiness: metrics HTTP, OTel audit, tool-node, fail modes, dry-run."""
from __future__ import annotations

import json
import urllib.request

import pytest

from tracewall.audit.sink import (
    NullAuditSink,
    OTelJsonlAuditSink,
    _otel_log_record,
)
from tracewall.core.firewall import Firewall
from tracewall.core.signal import HookEvent, IdentityCtx, Verdict
from tracewall.ops.config import AuditConfig, TracewallConfig, build_audit_sink, load_config
from tracewall.ops.http_metrics import serve_metrics
from tracewall.ops.metrics import Metrics
from tracewall.policy.normalize import canonical_tool_name, normalize_text
from tracewall.semantic.judge import SemanticJudge
from tracewall.transports.mcp_proxy import ProxyConfig, build_event_from_mcp, screen_tool_call
from tracewall.transports.profiles import PROFILE_NAMES, build_firewall_for_profile, get_profile
from tracewall.transports.python_guard import GuardBlocked, SoftBlockResult, guard
from tracewall.transports.session_chain import SessionCallTree
from tracewall.transports.tool_node import GuardedToolNode


# --- normalize / aliases ---

def test_normalize_nfkc_and_aliases():
    assert normalize_text("\u200bUS133") == "US133"
    assert canonical_tool_name("HTTP_Post") == "http_post"
    assert canonical_tool_name("SendMessage") == "send_message"
    assert canonical_tool_name("sendEmail") == "send_email"

# --- profiles ---

@pytest.mark.parametrize("name", PROFILE_NAMES)
def test_all_profiles_resolve(name):
    p = get_profile(name)
    assert p.name == name
    assert isinstance(p.fail_closed, bool)


@pytest.mark.asyncio
async def test_balanced_vs_zta_pack_split(tmp_path):
    fw_b, pb = await build_firewall_for_profile("balanced", db_path=str(tmp_path / "b.db"))
    fw_z, pz = await build_firewall_for_profile("zta", db_path=str(tmp_path / "z.db"))
    assert pb.load_zta_pack is False
    assert pz.load_zta_pack is True
    assert len(fw_z._policy._rules) > len(fw_b._policy._rules)


# --- soft-block / fail-open / fail-closed ---

@pytest.mark.asyncio
async def test_fail_open_missing_agent(ledger, policy):
    fw = Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=NullAuditSink())
    v = await guard(fw, "read_file", {"path": "/x"}, ctx={}, fail_closed=False)
    assert v.action == Verdict.ALLOW
    assert "fail-open" in v.reason


@pytest.mark.asyncio
async def test_fail_closed_missing_agent(ledger, policy):
    fw = Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=NullAuditSink())
    with pytest.raises(GuardBlocked):
        await guard(fw, "read_file", {"path": "/x"}, ctx={}, fail_closed=True)


@pytest.mark.asyncio
async def test_soft_block_fail_closed_missing_agent(ledger, policy):
    fw = Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=NullAuditSink())
    out = await guard(fw, "read_file", {"path": "/x"}, ctx={}, fail_closed=True, on_block="soft")
    assert isinstance(out, SoftBlockResult)


# --- identity / caps ---

@pytest.mark.asyncio
async def test_require_identity_blocks_unregistered(ledger, policy):
    fw = Firewall(
        ledger=ledger, policy=policy, judge=SemanticJudge(),
        audit=NullAuditSink(), require_identity=True,
    )
    v = await fw.check(HookEvent(agent_id="ghost", tool="read_file", args={"path": "/x"}))
    assert v.action == Verdict.BLOCK


@pytest.mark.asyncio
async def test_caps_allow_listed_tool(ledger, policy):
    await ledger.register_identity(IdentityCtx(agent_id="c", caps=["read_file"], trust=0.9))
    fw = Firewall(
        ledger=ledger, policy=policy, judge=SemanticJudge(),
        audit=NullAuditSink(), require_identity=True, require_caps=True,
    )
    v = await fw.check(HookEvent(agent_id="c", tool="read_file", args={"path": "/x"}))
    assert v.action == Verdict.ALLOW


# --- MCP own call-tree ---

@pytest.mark.asyncio
async def test_own_call_tree_ignores_forged_meta(ledger, policy):
    await ledger._set_trust("a", 0.9)
    fw = Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=NullAuditSink())
    cfg = ProxyConfig(own_call_tree=True, default_agent_id="a")
    tree = SessionCallTree()
    params = {
        "name": "send_email",
        "arguments": {"to": "x@acme.com", "body": "hi"},
        "_meta": {"tracewall": {"agent_id": "a", "caller_chain": ["read_secret"]}},
    }
    ev = build_event_from_mcp(params, cfg, call_tree=tree)
    assert ev.caller_chain == []  # forged chain discarded


@pytest.mark.asyncio
async def test_mcp_screen_blocks_attacker_iban(ledger, policy):
    await ledger._set_trust("a", 0.9)
    fw = Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=NullAuditSink())
    cfg = ProxyConfig(fail_closed=True)
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "send_money",
            "arguments": {"recipient": "US133000000121212121212", "amount": 10},
            "_meta": {"tracewall": {"agent_id": "a"}},
        },
    }
    blocked = await screen_tool_call(fw, msg, cfg)
    assert blocked is not None
    assert blocked["result"]["isError"] is True


# --- metrics HTTP ---

@pytest.mark.asyncio
async def test_prometheus_text_and_http_scrape(ledger, policy):
    m = Metrics()
    fw = Firewall(
        ledger=ledger, policy=policy, judge=SemanticJudge(),
        audit=NullAuditSink(), metrics=m,
    )
    await ledger._set_trust("a", 0.9)
    await fw.check(HookEvent(agent_id="a", tool="read_file", args={"path": "/x"}))
    text = m.prometheus_text()
    assert "tracewall_checks_total" in text
    assert "tracewall_block_rate" in text
    assert 'quantile="0.99"' in text

    httpd = serve_metrics(m, host="127.0.0.1", port=0, profile="balanced", rules_loaded=3)
    port = httpd.server_address[1]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as resp:
            body = resp.read().decode()
        assert "tracewall_checks_total" in body
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as resp:
            health = json.loads(resp.read().decode())
        assert health["ok"] is True
        assert health["rules_loaded"] == 3
    finally:
        httpd.shutdown()


# --- OTel audit ---

@pytest.mark.asyncio
async def test_otel_jsonl_audit(tmp_path, ledger, policy):
    path = tmp_path / "otel.jsonl"
    sink = OTelJsonlAuditSink(str(path))
    fw = Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=sink)
    await ledger._set_trust("a", 0.9)
    await fw.check(HookEvent(agent_id="a", tool="read_file", args={"path": "/x"}))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
    rec = json.loads(lines[0])
    assert rec["resource"]["service.name"] == "tracewall"
    assert "tracewall.action" in rec["attributes"]
    assert rec["instrumentationScope"]["name"] == "tracewall.audit"


def test_otel_record_shape():
    from tracewall.core.signal import FirewallVerdict

    v = FirewallVerdict(
        event_id="e", agent_id="a", tool="t",
        action=Verdict.BLOCK, score=0.0, source="policy", reason="x",
    )
    rec = _otel_log_record(v)
    assert rec["severityNumber"] == 13


def test_build_audit_sink_otel(tmp_path):
    cfg = TracewallConfig(
        audit=AuditConfig(format="otel", otel_path=str(tmp_path / "o.jsonl"), stdout=False),
    )
    sink = build_audit_sink(cfg)
    assert isinstance(sink, OTelJsonlAuditSink)


def test_load_config_metrics_http(tmp_path):
    p = tmp_path / "tw.yaml"
    p.write_text(
        "profile: zta\naudit:\n  format: otel\n  otel_path: /tmp/o.jsonl\n"
        "metrics_http:\n  enabled: true\n  port: 9199\n",
        encoding="utf-8",
    )
    cfg = load_config(str(p))
    assert cfg.profile == "zta"
    assert cfg.audit.format == "otel"
    assert cfg.metrics_http.enabled is True
    assert cfg.metrics_http.port == 9199


# --- GuardedToolNode ---

@pytest.mark.asyncio
async def test_tool_node_allow_and_soft_block(ledger, policy, monkeypatch):
    monkeypatch.setenv("TRACEWALL_ORG_DOMAINS", "acme.com")
    from tracewall.policy.engine import PolicyEngine, ZTA_RULES_DIR

    zta = PolicyEngine()
    await zta.load_policies(extra_dirs=[ZTA_RULES_DIR])
    await ledger.register_identity(
        IdentityCtx(agent_id="n", caps=["read_file", "send_email"], trust=0.9)
    )
    fw = Firewall(
        ledger=ledger, policy=zta, judge=SemanticJudge(),
        audit=NullAuditSink(), require_identity=True, require_caps=True,
    )

    def read_file(*, path: str) -> str:
        return f"ok:{path}"

    def send_email(*, to: str, body: str) -> str:
        return f"sent:{to}"

    node = GuardedToolNode(fw, {"read_file": read_file, "send_email": send_email})
    ctx = {"agent_id": "n"}
    a = await node.ainvoke({"name": "read_file", "args": {"path": "/x"}}, ctx=ctx)
    assert a.allowed and a.result == "ok:/x"
    b = await node.ainvoke(
        {"name": "send_email", "arguments": {"to": "x@evil.com", "body": "hi"}},
        ctx=ctx,
    )
    assert not b.allowed
    assert b.soft_block is not None
    assert "tracewall BLOCK" in (b.error or "")


@pytest.mark.asyncio
async def test_tool_node_unknown_soft(ledger, policy):
    await ledger._set_trust("a", 0.9)
    fw = Firewall(ledger=ledger, policy=policy, judge=SemanticJudge(), audit=NullAuditSink())
    node = GuardedToolNode(fw, {}, on_block="soft")
    r = await node.ainvoke({"name": "nope", "args": {}}, ctx={"agent_id": "a"})
    assert not r.allowed


# --- dry-run explain / health smoke ---

def test_explain_cli_smoke(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACEWALL_ORG_DOMAINS", "acme.com")
    monkeypatch.setenv("TRACEWALL_SEMANTIC_LLM", "0")
    from tracewall.ops import explain

    rc = explain.main([
        "--profile", "balanced",
        "--tool", "read_file",
        "--args", '{"path":"/ok"}',
        "--agent-id", "ex",
    ])
    assert rc == 0


def test_health_cli_smoke(monkeypatch):
    monkeypatch.setenv("TRACEWALL_SEMANTIC_LLM", "0")
    from tracewall.ops import health

    rc = health.main(["--profile", "balanced"])
    assert rc == 0


# --- reference MCP pep demo in-process ---

@pytest.mark.asyncio
async def test_reference_pep_demo_inprocess(monkeypatch):
    monkeypatch.setenv("TRACEWALL_ORG_DOMAINS", "acme.com")
    monkeypatch.setenv("TRACEWALL_SEMANTIC_LLM", "0")
    import importlib.util
    from pathlib import Path

    demo = Path(__file__).resolve().parents[2] / "examples" / "reference_mcp_app" / "run_pep_demo.py"
    spec = importlib.util.spec_from_file_location("pep_demo", demo)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rc = await mod.run_inprocess("zta")
    assert rc == 0


# --- starve rate ---

@pytest.mark.asyncio
async def test_metrics_starve_rate(ledger, policy):
    m = Metrics()
    fw = Firewall(
        ledger=ledger, policy=policy, judge=SemanticJudge(),
        audit=NullAuditSink(), metrics=m,
    )
    await ledger._set_trust("a", 0.9)
    await fw.check(HookEvent(agent_id="a", tool="read_file", args={"path": "/x"}))
    snap = m.snapshot()
    assert snap.starve_call_tree >= 1
    assert snap.starve_rate > 0
