"""
tracewall/content/filter.py — standalone tier-0 content pre-filter.

A cheap, surface-form regex screen for instruction-injection / jailbreak shapes
in untrusted content (memory writes, tool args, retrieved docs). This is a
self-contained replacement for the external content-inspection + MINJA detector
the firewall previously borrowed: no YAML config, no network, no dependencies.

Tier-0 is deliberately high-recall / lower-precision; the policy DSL (tier-1)
and semantic judge (tier-2) refine its signal. The gated eval combiner uses
tier-0 as a noisy prior, never as a sole authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Instruction-injection / jailbreak pattern families. Case-insensitive,
# whitespace-flexible to catch light obfuscation.
_INSTRUCTION_PATTERNS: list[re.Pattern[str]] = [
    # ── Override / ignore directives ──────────────────────────────────────
    re.compile(r"(?i)ignore\s+(the\s+)?(previous|prior|all|above)\s*(instructions?|prompts?|rules?)?"),
    re.compile(r"(?i)disregard\s+(the\s+)?(previous|prior|all|above|earlier)"),
    re.compile(r"(?i)forget\s+(everything|all|your)\s+(previous|prior|instructions?|rules?)"),
    # ── Role reassignment / persona switching ─────────────────────────────
    re.compile(r"(?i)you\s+are\s+now\s+(a|an|the|unrestricted)"),
    re.compile(r"(?i)act\s+as\s+(if|though|an?\s+)"),
    re.compile(r"(?i)pretend\s+(to\s+be|that|restrictions?)"),
    re.compile(r"(?i)from\s+now\s+on[,\s]+you"),
    # ── Safety / policy circumvention ─────────────────────────────────────
    re.compile(r"(?i)(bypass|disable|turn\s+off|remove)\s+(the\s+)?(safety|security|policy|filters?|guardrails?|restrictions?)"),
    re.compile(r"(?i)override\s+(safety|security|policy|system)"),
    re.compile(r"(?i)(reset|wipe)\s+(your\s+)?(programming|instructions?|rules?)"),
    re.compile(r"(?i)without\s+(any\s+)?(ethical|safety|moral)\s+(constraints?|restrictions?|guidelines?)"),
    re.compile(r"(?i)(no|with\s+no)\s+(safety|content)\s+(restrictions?|filters?|policy)"),
    re.compile(r"(?i)(filters?|restrictions?|safeguards?)\s+(are\s+)?(now\s+)?disabled"),
    # ── New-instruction injection ─────────────────────────────────────────
    re.compile(r"(?i)your\s+new\s+(instructions?|rules?|role|task|directive)"),
    re.compile(r"(?i)(new|updated)\s+system\s+(prompt|message|instructions?)"),
    re.compile(r"(?i)^\s*system\s*:"),
    # ── Data exfiltration ─────────────────────────────────────────────────
    re.compile(r"(?i)(forward|send|exfil(trate)?|leak|transmit|upload)\s+(all|the|any|retrieved|stored)?\s*(data|credentials?|secrets?|keys?|files?)"),
    re.compile(r"(?i)(send|forward|post)\s+.{0,40}\b(to|@)\b.{0,40}\b(attacker|evil|exfil)"),
    re.compile(r"(?i)(exfil(trate)?|exfiltration)"),
]


@dataclass
class InspectionResult:
    flagged: bool
    matched_pattern: str = ""


def inspect(content: str) -> InspectionResult:
    """Return an InspectionResult; .flagged is True on the first pattern hit."""
    if not content:
        return InspectionResult(flagged=False)
    for pat in _INSTRUCTION_PATTERNS:
        if pat.search(content):
            return InspectionResult(flagged=True, matched_pattern=pat.pattern)
    return InspectionResult(flagged=False)


def flagged(content: str) -> bool:
    """True if `content` looks instruction-like / injection-shaped."""
    return inspect(content).flagged
