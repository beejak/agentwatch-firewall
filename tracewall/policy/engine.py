"""
tracewall/policy/engine.py — deterministic policy DSL evaluator.

Loads YAML rules from a rules directory and compiles them to a per-tool lookup.
Human-writable, zero ML. Evaluation is pure-deterministic — no LLM calls — and
runs on the enforcement hot path.

Placeholders: `${ORG_DOMAIN}` in YAML is expanded from TRACEWALL_ORG_DOMAINS
(comma-separated; default org.com,trusted.com,customer.com).
`rate_exceeds` is unsupported (never silently “works”).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel

from tracewall.core.signal import EnrichedEvent

logger = logging.getLogger(__name__)

# Packaged default rules directory (tracewall/policy/rules/).
DEFAULT_RULES_DIR = str(Path(__file__).parent / "rules")

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

    def __init__(self) -> None:
        self._rules:    list[CompiledRule] = []
        self._by_tool:  dict[str, list[CompiledRule]] = {}   # tool → rules

    async def load_policies(self, directory: str = DEFAULT_RULES_DIR) -> None:
        path = Path(directory)
        if not path.exists():
            logger.warning("policy: rules dir not found: %s", directory)
            return
        rules = []
        for f in path.glob("*.yaml"):
            try:
                data = yaml.safe_load(f.read_text())
                data = _expand_placeholders(data) if isinstance(data, dict) else data
                match = data.get("match", {}) if isinstance(data, dict) else {}
                if _match_uses_op(match, "rate_exceeds"):
                    logger.error(
                        "policy: skipping %s — operator 'rate_exceeds' is unsupported",
                        f.name,
                    )
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
                rules.append(rule)
            except Exception as e:
                logger.error("policy: failed to load %s: %s", f, e)

        if not rules and self._rules:
            logger.warning("policy: keeping last-good ruleset (%d rules)", len(self._rules))
            return
        if not rules:
            logger.error("policy: loaded 0 rules from %s — tier-1 is allow-all", directory)

        self._rules = rules
        self._by_tool = {}
        for r in rules:
            self._by_tool.setdefault(r.tool or "_any", []).append(r)
        logger.info("policy: loaded %d rules (org domains=%s)", len(rules), _org_domains())

    async def evaluate(self, event: EnrichedEvent) -> Optional[RuleMatch]:
        """
        Evaluate all rules matching the tool. O(1) lookup + linear scan of matching rules.
        Returns first BLOCK match, or None if ALLOW.
        """
        tool = event.event.tool
        candidates = self._by_tool.get(tool, []) + self._by_tool.get("_any", [])

        for rule in candidates:
            if self._matches(rule, event):
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

        return True

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
            if op not in _warned_ops:
                logger.error("policy: operator 'rate_exceeds' is unsupported — treating as non-match")
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
