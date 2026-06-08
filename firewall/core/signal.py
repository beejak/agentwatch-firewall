"""
Firewall signal shapes — extends watchtower/core/signal.py.
Defined ONCE here. Never duplicated.
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
    HOLD  = "hold"    # pending async analysis


class TaintLevel(float, Enum):
    CLEAN      = 0.0
    LOW        = 0.2
    MEDIUM     = 0.5
    HIGH       = 0.7   # quarantine threshold
    CRITICAL   = 1.0


class HookEvent(BaseModel):
    """Fired by hermes.py on every pre_tool_call / pre_gateway_dispatch."""
    event_id:      str   = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id:      str
    tool:          str
    args:          dict
    call_site:     Optional[str] = None   # source file:line if available
    caller_chain:  list[str] = []         # [grandparent, parent, self]
    session_id:    str = ""
    ts:            float = Field(default_factory=time.time)


class EnrichedEvent(BaseModel):
    """HookEvent + graphify AST/call-tree context."""
    event:          HookEvent
    ast_path:       Optional[list[str]] = None   # call tree from graphify
    call_tree:      list[str] = []
    cache_hit:      bool = False
    needs_async:    bool = False   # True when graphify missed — re-score async


class IdentityCtx(BaseModel):
    """Per-agent identity from the identity fabric (L0)."""
    agent_id:         str
    parent_id:        Optional[str] = None
    delegation_depth: int = 0
    caps:             list[str] = []     # allowed tool names
    trust:            float = 0.5        # [0,1] from cavemem
    taint:            float = 0.0        # [0,1] from taint ledger
    token_exp:        float = 0.0        # unix ts


class Taint(BaseModel):
    """Cross-session taint record stored in cavemem."""
    agent_id:   str
    level:      float = 0.0
    source:     str = ""          # T1/T2/T3
    reason:     str = ""
    ts:         float = Field(default_factory=time.time)
    session_id: str = ""


class FirewallVerdict(BaseModel):
    """
    Final enforcement decision. score + source + reason — always all three.
    Written to Chronicle on every call (append-only).
    """
    verdict_id:  str   = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id:    str
    agent_id:    str
    tool:        str
    action:      Verdict
    score:       float          # 0.0 bad .. 1.0 clean
    source:      str            # "deterministic|trust_gate|async_ruflo|identity|fail_safe"
    reason:      str
    latency_ms:  float = 0.0
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
