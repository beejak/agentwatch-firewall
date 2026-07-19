"""
MCP deployment profiles — named presets for the stdio proxy bouncer.

Three presets (strict → loose). Same Firewall core; different knobs.

  paranoid   — block when unsure (identity required, fail-closed, full rules)
  balanced   — product default (fail-closed, full rules, identity optional)
  permissive — prefer availability (fail-open, core rules only, identity optional)

Success is observed behavior under tests — not marketing names.
Failures (context starvation, framing gaps) are first-class results we record.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from tracewall.policy.engine import DEFAULT_RULES_DIR, CompiledRule, PolicyEngine, _expand_placeholders, _match_uses_op
from tracewall.transports.mcp_proxy import ProxyConfig

PROFILE_NAMES = ("paranoid", "balanced", "permissive")

# Permissive loads only these rule file stems (basename without .yaml).
_PERMISSIVE_STEMS = frozenset({"destructive_ops", "minja_memory"})


@dataclass(frozen=True)
class Profile:
    name: str
    fail_closed: bool
    require_identity: bool
    rule_stems: Optional[frozenset[str]]
    description: str

    def proxy_config(self, default_agent_id: str = "mcp-client") -> ProxyConfig:
        return ProxyConfig(
            default_agent_id=default_agent_id,
            fail_closed=self.fail_closed,
            profile=self.name,
        )


PROFILES: dict[str, Profile] = {
    "paranoid": Profile(
        name="paranoid",
        fail_closed=True,
        require_identity=True,
        rule_stems=None,
        description="Fail closed; require registered identity; full policy pack.",
    ),
    "balanced": Profile(
        name="balanced",
        fail_closed=True,
        require_identity=False,
        rule_stems=None,
        description="Fail closed; identity optional; full policy pack. Default.",
    ),
    "permissive": Profile(
        name="permissive",
        fail_closed=False,
        require_identity=False,
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
    """Load YAML rules according to the profile (full pack or permissive subset)."""
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
            data = yaml.safe_load(f.read_text())
            if not isinstance(data, dict):
                continue
            data = _expand_placeholders(data)
            match = data.get("match", {})
            if _match_uses_op(match, "rate_exceeds"):
                continue
            rule = CompiledRule(
                rule_id=data.get("rule", f.stem),
                surface=data.get("surface", "unknown"),
                on=data.get("on", "pre_tool_call"),
                tool=match.get("tool"),
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
    )
    return fw, prof
