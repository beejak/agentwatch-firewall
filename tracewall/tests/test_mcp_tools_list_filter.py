"""E2: optional MCP tools/list response filtering (proxy transport)."""
from __future__ import annotations

import pytest

from tracewall.transports.mcp_proxy import (
    ProxyConfig,
    filter_tools_list_result,
    maybe_filter_tools_list_response,
    resolve_tools_allowlist,
    screen_tool_call,
)
from tracewall.transports.profiles import get_profile


def test_profile_filter_flags():
    assert get_profile("zta").filter_tools_list is True
    assert get_profile("paranoid").filter_tools_list is True
    assert get_profile("balanced").filter_tools_list is False
    assert get_profile("permissive").filter_tools_list is False


def test_filter_tools_list_result_keeps_allowlisted():
    result = {
        "tools": [
            {"name": "read_file", "description": "r"},
            {"name": "post_slack", "description": "p"},
            {"name": "SendEmail", "description": "e"},
        ]
    }
    out = filter_tools_list_result(result, {"read_file", "send_email"})
    names = [t["name"] for t in out["tools"]]
    assert names == ["read_file", "SendEmail"]


def test_filter_tools_list_result_fail_closed_on_bad_shape():
    assert filter_tools_list_result({"tools": "nope"}, {"read_file"})["tools"] == []
    assert filter_tools_list_result({}, {"read_file"})["tools"] == []


def test_maybe_filter_only_pending_list_ids():
    pending = {2}
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"tools": [{"name": "a"}, {"name": "b"}]},
    }
    out = maybe_filter_tools_list_response(
        msg, pending_list_ids=pending, allowlist=frozenset({"a"}), enabled=True,
    )
    assert [t["name"] for t in out["result"]["tools"]] == ["a"]
    assert 2 not in pending

    # Non-pending id unchanged
    other = {"jsonrpc": "2.0", "id": 9, "result": {"tools": [{"name": "b"}]}}
    pending2: set = set()
    same = maybe_filter_tools_list_response(
        other, pending_list_ids=pending2, allowlist=frozenset(), enabled=True,
    )
    assert same is other or same["result"]["tools"] == [{"name": "b"}]


def test_filter_disabled_passthrough():
    pending = {1}
    msg = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "x"}]}}
    out = maybe_filter_tools_list_response(
        msg, pending_list_ids=pending, allowlist=frozenset(), enabled=False,
    )
    assert out["result"]["tools"] == [{"name": "x"}]
    assert 1 in pending


async def test_tools_list_request_still_forwards(firewall):
    """E2 filters responses; request path remains forward (screen_tool_call=None)."""
    msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    assert await screen_tool_call(firewall, msg, ProxyConfig(filter_tools_list=True)) is None


async def test_resolve_allowlist_explicit_overrides(firewall):
    cfg = ProxyConfig(tools_allowlist=frozenset({"only_this"}))
    assert resolve_tools_allowlist(firewall, cfg) == frozenset({"only_this"})


async def test_resolve_allowlist_declared_union_caps(firewall):
    cfg = ProxyConfig()
    # Default firewall fixture has no deny_unknown → empty declared on fw
    al = resolve_tools_allowlist(firewall, cfg, caps=["read_file", "post_slack"])
    assert "read_file" in al and "post_slack" in al


def test_proxy_config_from_zta_profile():
    cfg = get_profile("zta").proxy_config()
    assert cfg.filter_tools_list is True
