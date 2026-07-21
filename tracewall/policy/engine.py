"""
tracewall/policy/engine.py — deterministic policy DSL evaluator.

Loads YAML rules from a rules directory and compiles them to a per-tool lookup.
Human-writable, zero ML. Evaluation is pure-deterministic — no LLM calls — and
runs on the enforcement hot path.

Placeholders: `${ORG_DOMAIN}` in YAML is expanded from TRACEWALL_ORG_DOMAINS
(comma-separated; default org.com,trusted.com,customer.com).

``rate_exceeds`` is implemented via an in-process sliding-window RateBudget
(not distributed — fine for a single PEP process).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel

from tracewall.core.signal import EnrichedEvent
from tracewall.policy.normalize import canonical_tool_name, normalize_args
from tracewall.policy.rate import RateBudget

logger = logging.getLogger(__name__)

# Packaged default rules directory (tracewall/policy/rules/).
DEFAULT_RULES_DIR = str(Path(__file__).parent / "rules")
ZTA_RULES_DIR = str(Path(__file__).parent / "rules" / "zta")

_DEFAULT_ORG_DOMAINS = ["org.com", "trusted.com", "customer.com"]
_warned_ops: set[str] = set()


def _org_domains() -> list[str]:
    raw = os.environ.get("TRACEWALL_ORG_DOMAINS", "").strip()
    if not raw:
        return list(_DEFAULT_ORG_DOMAINS)
    return [d.strip() for d in raw.split(",") if d.strip()]


def _expand_placeholders(obj: Any) -> Any:
    """Replace `${ORG_DOMAIN}` with the configured org domain list (or keep structure)."""
    domains = _org_domains()
    if isinstance(obj, str):
        if obj == "${ORG_DOMAIN}":
            return domains[0] if len(domains) == 1 else domains
        if "${ORG_DOMAIN}" in obj:
            return obj.replace("${ORG_DOMAIN}", domains[0])
        return obj
    if isinstance(obj, list):
        out: list[Any] = []
        for item in obj:
            expanded = _expand_placeholders(item)
            if item == "${ORG_DOMAIN}" and isinstance(expanded, list):
                out.extend(expanded)
            else:
                out.append(expanded)
        return out
    if isinstance(obj, dict):
        return {k: _expand_placeholders(v) for k, v in obj.items()}
    return obj


def _extract_host(val: Any) -> str:
    """Hostname from URL, email, or bare host string."""
    s = str(val).strip()
    if not s:
        return ""
    if "@" in s and "://" not in s and not s.startswith("//"):
        # email-shaped
        return s.split("@")[-1].lower().rstrip(".")
    parsed = urlparse(s if "://" in s else f"//{s}", scheme="")
    host = (parsed.hostname or parsed.netloc or s).lower()
    if "@" in host:
        host = host.split("@")[-1]
    host = host.split("/")[0].split("?")[0].rstrip(".")
    # bare "evil.com/path" without //
    if "/" in host:
        host = host.split("/")[0]
    return host


def _host_in_allowlist(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for a in allowed:
        a = str(a).lower().rstrip(".")
        if not a:
            continue
        if host == a or host.endswith("." + a):
            return True
    return False


class RuleMatch(BaseModel):
    rule_id: str
    verdict: str       # "BLOCK"
    reason:  str
    severity: float


class CompiledRule(BaseModel):
    rule_id:    str
    surface:    str    # capability_abuse | input_corruption | contagion
    on:         str    # pre_tool_call | pre_gateway_dispatch
    tool:       Optional[str] = None
    match:      dict = {}
    verdict:    str = "BLOCK"
    reason:     str = ""
    severity:   float = 0.5


class PolicyEngine:
    """
    Loads and evaluates YAML policy rules.
    Rules are compiled to per-tool lookup at load time.
    Evaluation is pure-deterministic — no LLM calls.
    """

    def __init__(self, rates: RateBudget | None = None) -> None:
        self._rules:    list[CompiledRule] = []
        self._by_tool:  dict[str, list[CompiledRule]] = {}   # tool → rules
        self._rates = rates if rates is not None else RateBudget()

    async def load_policies(
        self,
        directory: str = DEFAULT_RULES_DIR,
        *,
        extra_dirs: list[str] | None = None,
    ) -> None:
        paths = [Path(directory)]
        for d in extra_dirs or []:
            paths.append(Path(d))
        rules: list[CompiledRule] = []
        for path in paths:
            if not path.exists():
                logger.warning("policy: rules dir not found: %s", path)
                continue
            for f in sorted(path.glob("*.yaml")):
                try:
                    data = yaml.safe_load(f.read_text(encoding="utf-8"))
                    data = _expand_placeholders(data) if isinstance(data, dict) else data
                    if not isinstance(data, dict):
                        continue
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
                    rules.append(rule)
                except Exception as e:
                    logger.error("policy: failed to load %s: %s", f, e)

        if not rules and self._rules:
            logger.warning("policy: keeping last-good ruleset (%d rules)", len(self._rules))
            return
        if not rules:
            logger.error("policy: loaded 0 rules — tier-1 is allow-all")

        self._rules = rules
        self._by_tool = {}
        for r in rules:
            self._by_tool.setdefault(r.tool or "_any", []).append(r)
        logger.info(
            "policy: loaded %d rules from %s (org domains=%s)",
            len(rules),
            [str(p) for p in paths],
            _org_domains(),
        )

    async def evaluate(self, event: EnrichedEvent) -> Optional[RuleMatch]:
        """
        Evaluate all rules matching the tool. O(1) lookup + linear scan of matching rules.
        Returns first BLOCK match, or None if ALLOW.
        """
        tool = canonical_tool_name(event.event.tool)
        candidates = self._by_tool.get(tool, []) + self._by_tool.get("_any", [])

        # Work on a copy with normalized string args (ZWSP/NFKC) without mutating the event.
        norm_event = event.model_copy(deep=True)
        norm_event.event.args = normalize_args(event.event.args)
        # Keep original tool on the wire event; matching uses canonical name via candidates.

        for rule in candidates:
            if self._matches(rule, norm_event):
                return RuleMatch(
                    rule_id=rule.rule_id,
                    verdict=rule.verdict,
                    reason=rule.reason,
                    severity=rule.severity,
                )
        return None

    def _matches(self, rule: CompiledRule, event: EnrichedEvent) -> bool:
        m = rule.match
        args = event.event.args

        # call_tree context (deterministic)
        if "context" in m:
            ctx = m["context"]
            actual_tree = list(event.call_tree or []) + list(event.event.caller_chain or [])
            required_all = ctx.get("call_tree_contains", [])
            if required_all and not all(c in actual_tree for c in required_all):
                return False
            required_any = ctx.get("call_tree_contains_any", [])
            if required_any and not any(c in actual_tree for c in required_any):
                return False

        # arg checks
        any_clauses = m.get("any", [])
        if any_clauses:
            matched_any = False
            for clause in any_clauses:
                if self._eval_clause(clause, args):
                    matched_any = True
                    break
            if not matched_any:
                return False

        all_clauses = m.get("all", [])
        for clause in all_clauses:
            if not self._eval_clause(clause, args):
                return False

        # match-level rate budget (counts this attempt)
        rate_spec = m.get("rate_exceeds")
        if rate_spec is not None:
            if not self._rate_exceeded(rate_spec, event):
                return False

        # If the rule has no any/all/context/rate constraints beyond tool name,
        # matching the tool alone is enough (tool-only rules).
        has_constraints = bool(
            any_clauses or all_clauses or m.get("context") or rate_spec is not None
        )
        if not has_constraints and m.get("tool"):
            return True
        if not has_constraints:
            return True
        return True

    def _rate_exceeded(self, spec: Any, event: EnrichedEvent) -> bool:
        if not isinstance(spec, dict):
            logger.error("policy: rate_exceeds must be a mapping — treating as non-match")
            return False
        window_s = float(spec.get("window_s", 60))
        max_n = int(spec.get("max", 10))
        key_mode = str(spec.get("key", "agent_tool"))
        aid = event.event.agent_id
        tool = canonical_tool_name(event.event.tool)
        if key_mode == "agent":
            key = f"agent:{aid}"
        elif key_mode == "tool":
            key = f"tool:{tool}"
        else:
            key = f"agent_tool:{aid}:{tool}"
        rule_key = f"{key}|{spec.get('bucket', 'default')}"
        return self._rates.exceeds(rule_key, window_s, max_n)

    def _eval_clause(self, clause: dict, args: dict) -> bool:
        for key, constraint in clause.items():
            # resolve dotted path: "arg.to" → args["to"]
            parts = key.split(".")
            val = args
            for p in parts[1:] if parts[0] == "arg" else parts:
                if not isinstance(val, dict):
                    return False
                val = val.get(p)
                if val is None:
                    return False

            if isinstance(constraint, dict):
                for op, operand in constraint.items():
                    if not self._eval_op(op, val, operand):
                        return False
            else:
                if val != constraint:
                    return False
        return True

    def _eval_op(self, op: str, val, operand) -> bool:
        if op == "not_in_domain":
            domain = str(val).split("@")[-1] if "@" in str(val) else str(val)
            return domain not in (operand if isinstance(operand, list) else [operand])
        if op == "in_domain":
            domain = str(val).split("@")[-1] if "@" in str(val) else str(val)
            return domain in (operand if isinstance(operand, list) else [operand])
        if op == "host_not_in":
            host = _extract_host(val)
            allowed = operand if isinstance(operand, list) else [operand]
            return not _host_in_allowlist(host, [str(x) for x in allowed])
        if op == "host_in":
            host = _extract_host(val)
            allowed = operand if isinstance(operand, list) else [operand]
            return _host_in_allowlist(host, [str(x) for x in allowed])
        if op == "in":
            return val in (operand if isinstance(operand, list) else [operand])
        if op == "not_in":
            return val not in (operand if isinstance(operand, list) else [operand])
        if op == "matches_secret_pattern":
            return operand and _looks_like_secret(str(val))
        if op == "regex":
            return bool(re.search(operand, str(val)))
        if op == "glob":
            from fnmatch import fnmatch
            return fnmatch(str(val), operand)
        if op == "rate_exceeds":
            # Prefer match-level rate_exceeds; arg-level form is unsupported shape.
            if op not in _warned_ops:
                logger.error(
                    "policy: arg-level 'rate_exceeds' is unsupported — use match.rate_exceeds"
                )
                _warned_ops.add(op)
            return False
        if op == "delegation_depth_gt":
            return isinstance(val, int) and val > operand
        if op == "taint_gte":
            return isinstance(val, float) and val >= operand
        if op not in _warned_ops:
            logger.warning("policy: unknown operator %r — treating as non-match", op)
            _warned_ops.add(op)
        return False


def _match_uses_op(match: Any, op_name: str) -> bool:
    """True if any nested constraint dict uses op_name."""
    if isinstance(match, dict):
        if op_name in match:
            return True
        return any(_match_uses_op(v, op_name) for v in match.values())
    if isinstance(match, list):
        return any(_match_uses_op(v, op_name) for v in match)
    return False


_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|password|secret|token|bearer|credentials?)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xox[bporas]-[0-9A-Za-z-]+)"),
    re.compile(r"(?i)-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
    re.compile(r"(?i)\bprivate[_\s-]?key\b"),
]


def _looks_like_secret(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)
