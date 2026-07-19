"""
tracewall signal shapes — the wire contract between transports and the core.

Defined ONCE here, never duplicated. Every transport builds a HookEvent and
receives a FirewallVerdict; the core never sees anything else.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    HOLD  = "hold"    # pending async analysis (networked transports; see core.firewall)


class TaintLevel(float, Enum):
    CLEAN      = 0.0
    LOW        = 0.2
    MEDIUM     = 0.5
    HIGH       = 0.7   # quarantine threshold
    CRITICAL   = 1.0


class HookEvent(BaseModel):
    """A single intercepted tool call. `agent_id` is the one mandatory field —
    cross-session taint needs a stable id. Everything else is optional and the
    tiers degrade gracefully when it is missing."""
    event_id:      str   = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id:      str
    tool:          str
    args:          dict
    call_site:     Optional[str] = None   # source file:line if available
    caller_chain:  list[str] = []         # [grandparent, parent, self]
    session_id:    str = ""
    ts:            float = Field(default_factory=time.time)


class EnrichedEvent(BaseModel):
    """HookEvent + optional call-tree context (for the policy/semantic tiers)."""
    event:          HookEvent
    ast_path:       Optional[list[str]] = None
    call_tree:      list[str] = []
    cache_hit:      bool = False
    needs_async:    bool = False   # True when enrichment missed — re-score async


class IdentityCtx(BaseModel):
    """Per-agent identity / capability record (L0)."""
    agent_id:         str
    parent_id:        Optional[str] = None
    delegation_depth: int = 0
    caps:             list[str] = []     # allowed tool names
    trust:            float = 0.5        # [0,1] from the ledger
    taint:            float = 0.0        # [0,1] from the taint ledger
    token_exp:        float = 0.0        # unix ts


class Taint(BaseModel):
    """Cross-session taint record stored in the ledger."""
    agent_id:   str
    level:      float = 0.0
    source:     str = ""          # T1/T2/T3
    reason:     str = ""
    ts:         float = Field(default_factory=time.time)
    session_id: str = ""


class FirewallVerdict(BaseModel):
    """
    Final enforcement decision. score + source + reason — always all three.
    `context_completeness` records which signals were available when the verdict
    was formed, so downstream analysis (and the paper) never over-claims on
    context-starved transports.
    """
    verdict_id:  str   = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id:    str
    agent_id:    str
    tool:        str
    action:      Verdict
    score:       float          # 0.0 bad .. 1.0 clean
    source:      str            # "deterministic|trust_gate|semantic|identity|content|fail_safe"
    reason:      str
    latency_ms:  float = 0.0
    context_completeness: dict[str, bool] = Field(default_factory=dict)
    rule_id:     str = ""       # matched policy rule id when source=deterministic
    args_hash:   str = ""       # sha256 prefix of args (SIEM-friendly; full args in event dump)
    ts:          float = Field(default_factory=time.time)


# ── Multi-hop Taint Graph ──────────────────────────────────────────────────

class EdgeType(str, Enum):
    WRITE     = "write"      # agent → memory entry
    READ      = "read"       # memory entry → agent
    DELEGATE  = "delegate"   # agent → agent (sub-agent spawn)
    TOOL_CALL = "tool_call"  # agent → agent (tool invocation)


class TaintEdge(BaseModel):
    edge_id:    str = Field(default_factory=lambda: str(uuid.uuid4()))
    src:        str          # node ID (agent_id or memory key)
    src_type:   str          # "agent" | "memory"
    dst:        str
    dst_type:   str          # "agent" | "memory"
    edge_type:  EdgeType
    weight:     float        # propagation weight for this edge type
    ts:         float = Field(default_factory=time.time)
    session_id: Optional[str] = None
