"""
superpowers.py — Policy skill loader.
Loads YAML rules from policies/ dir. Compiles to decision tree.
Human-writable. Zero ML. Hot-reload on session start.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel

from firewall.core.signal import EnrichedEvent

logger = logging.getLogger(__name__)


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


class SuperpowersAdapter:
    """
    Loads and evaluates YAML policy rules.
    Rules are compiled to per-tool lookup at load time.
    Evaluation is pure-deterministic — no LLM calls.
    """

    def __init__(self) -> None:
        self._rules:    list[CompiledRule] = []
        self._by_tool:  dict[str, list[CompiledRule]] = {}   # tool → rules

    async def load_policies(self, directory: str) -> None:
        path = Path(directory)
        if not path.exists():
            logger.warning("superpowers: policies dir not found: %s", directory)
            return
        rules = []
        for f in path.glob("*.yaml"):
            try:
                data = yaml.safe_load(f.read_text())
                rule = CompiledRule(
                    rule_id=data.get("rule", f.stem),
                    surface=data.get("surface", "unknown"),
                    on=data.get("on", "pre_tool_call"),
                    tool=data.get("match", {}).get("tool"),
                    match=data.get("match", {}),
                    verdict=data.get("verdict", "BLOCK"),
                    reason=data.get("reason", ""),
                    severity=float(data.get("severity", 0.5)),
                )
                rules.append(rule)
            except Exception as e:
                logger.error("superpowers: failed to load %s: %s", f, e)

        if not rules and self._rules:
            logger.warning("superpowers: keeping last-good ruleset (%d rules)", len(self._rules))
            return

        self._rules = rules
        self._by_tool = {}
        for r in rules:
            self._by_tool.setdefault(r.tool or "_any", []).append(r)
        logger.info("superpowers: loaded %d rules", len(rules))

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

        # call_tree_contains — semantic context check (deterministic)
        if "context" in m:
            required_callers = m["context"].get("call_tree_contains", [])
            actual_tree = list(event.call_tree or []) + list(event.event.caller_chain or [])
            if required_callers and not all(c in actual_tree for c in required_callers):
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
            # rate limiting handled by rate tracker — stub returns False
            return False
        if op == "delegation_depth_gt":
            return isinstance(val, int) and val > operand
        if op == "taint_gte":
            return isinstance(val, float) and val >= operand
        return False


_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|password|secret|token|bearer|credentials?)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xox[bporas]-[0-9A-Za-z-]+)"),
    re.compile(r"(?i)-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
]


def _looks_like_secret(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)
