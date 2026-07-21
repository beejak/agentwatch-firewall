"""
MCP deployment profiles — named presets for the stdio proxy bouncer.

  paranoid   — identity required, fail-closed, full rules + ZTA pack, own call-tree
  zta        — production posture: identity+caps, ZTA allowlists, own call-tree
  balanced   — product default / lab (fail-closed, full rules, identity optional)
  permissive — prefer availability (fail-open, core rules only)

Success is observed behavior under tests — not marketing names.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from tracewall.policy.engine import (
    DEFAULT_RULES_DIR,
    ZTA_RULES_DIR,
    CompiledRule,
    PolicyEngine,
    _expand_placeholders,
)
from tracewall.policy.normalize import canonical_tool_name
from tracewall.transports.mcp_proxy import ProxyConfig

PROFILE_NAMES = ("paranoid", "zta", "balanced", "permissive")

_PERMISSIVE_STEMS = frozenset({"destructive_ops", "minja_memory"})


@dataclass(frozen=True)
class Profile:
    name: str
    fail_closed: bool
    require_identity: bool
    require_caps: bool
    own_call_tree: bool
    load_zta_pack: bool
    rule_stems: Optional[frozenset[str]]
    description: str

    def proxy_config(self, default_agent_id: str = "mcp-client") -> ProxyConfig:
        return ProxyConfig(
            default_agent_id=default_agent_id,
            fail_closed=self.fail_closed,
            profile=self.name,
            own_call_tree=self.own_call_tree,
        )


PROFILES: dict[str, Profile] = {
    "paranoid": Profile(
        name="paranoid",
        fail_closed=True,
        require_identity=True,
        require_caps=False,
        own_call_tree=True,
        load_zta_pack=True,
        rule_stems=None,
        description="Fail closed; require identity; full pack + ZTA allowlists; proxy-owned call tree.",
    ),
    "zta": Profile(
        name="zta",
        fail_closed=True,
        require_identity=True,
        require_caps=True,
        own_call_tree=True,
        load_zta_pack=True,
        rule_stems=None,
        description="Prod ZTA: identity+caps; default-deny allowlists; proxy-owned call tree.",
    ),
    "balanced": Profile(
        name="balanced",
        fail_closed=True,
        require_identity=False,
        require_caps=False,
        own_call_tree=False,
        load_zta_pack=False,
        rule_stems=None,
        description="Fail closed; identity optional; lab full pack (no ZTA default-deny).",
    ),
    "permissive": Profile(
        name="permissive",
        fail_closed=False,
        require_identity=False,
        require_caps=False,
        own_call_tree=False,
        load_zta_pack=False,
        rule_stems=_PERMISSIVE_STEMS,
        description="Fail open; identity optional; destructive+MINJA rules only.",
    ),
}


def get_profile(name: str) -> Profile:
    key = (name or "balanced").strip().lower()
    if key not in PROFILES:
        raise ValueError(f"unknown profile {name!r}; choose one of {list(PROFILES)}")
    return PROFILES[key]


async def load_policy_for_profile(
    profile: Profile,
    rules_dir: str = DEFAULT_RULES_DIR,
) -> PolicyEngine:
    """Load YAML rules according to the profile (full pack ± ZTA ± permissive subset)."""
    import yaml

    engine = PolicyEngine()
    path = Path(rules_dir)
    if not path.exists():
        return engine

    stems = profile.rule_stems
    for f in sorted(path.glob("*.yaml")):
        if stems is not None and f.stem not in stems:
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            data = _expand_placeholders(data)
            match = data.get("match", {})
            rule = CompiledRule(
                rule_id=data.get("rule", f.stem),
                surface=data.get("surface", "unknown"),
                on=data.get("on", "pre_tool_call"),
                tool=canonical_tool_name(match["tool"]) if match.get("tool") else None,
                match=match,
                verdict=data.get("verdict", "BLOCK"),
                reason=data.get("reason", ""),
                severity=float(data.get("severity", 0.5)),
            )
            engine._rules.append(rule)
            engine._by_tool.setdefault(rule.tool or "_any", []).append(rule)
        except Exception:
            continue

    if profile.load_zta_pack:
        zta = Path(ZTA_RULES_DIR)
        if zta.exists():
            for f in sorted(zta.glob("*.yaml")):
                try:
                    data = yaml.safe_load(f.read_text(encoding="utf-8"))
                    if not isinstance(data, dict):
                        continue
                    data = _expand_placeholders(data)
                    match = data.get("match", {})
                    rule = CompiledRule(
                        rule_id=data.get("rule", f.stem),
                        surface=data.get("surface", "unknown"),
                        on=data.get("on", "pre_tool_call"),
                        tool=canonical_tool_name(match["tool"]) if match.get("tool") else None,
                        match=match,
                        verdict=data.get("verdict", "BLOCK"),
                        reason=data.get("reason", ""),
                        severity=float(data.get("severity", 0.5)),
                    )
                    engine._rules.append(rule)
                    engine._by_tool.setdefault(rule.tool or "_any", []).append(rule)
                except Exception:
                    continue
    return engine


async def build_firewall_for_profile(
    profile: Union[Profile, str],
    *,
    db_path: str,
    audit=None,
):
    """Construct a Firewall wired for the named profile. Returns (firewall, profile)."""
    from tracewall.audit.sink import NullAuditSink
    from tracewall.core.firewall import Firewall
    from tracewall.semantic.judge import SemanticJudge
    from tracewall.taint.ledger import Ledger

    prof = get_profile(profile) if isinstance(profile, str) else profile
    policy = await load_policy_for_profile(prof)
    sink = audit if audit is not None else NullAuditSink()
    fw = Firewall(
        ledger=Ledger(db_path),
        policy=policy,
        judge=SemanticJudge(),
        audit=sink,
        require_identity=prof.require_identity,
        require_caps=prof.require_caps,
    )
    return fw, prof
