"""
cavemem.py — Persistent verdict history, trust scores, taint ledger.
Wraps JuliusBrussee/cavemem (SQLite + FTS5 + MCP).
All reads are in-process cache-backed for hot-path latency.
All writes are async, never block enforcement.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from firewall.core.signal import FirewallVerdict, IdentityCtx, Taint, Verdict

logger = logging.getLogger(__name__)

# Taint propagation constants (§2.4)
_ρ = 0.8    # decay per hop
_α = 0.02   # trust recovery rate

# Multi-hop edge decay weights (§5.2 MTP)
RHO_WRITE    = 0.95   # agent → memory  (high fidelity transfer)
RHO_READ     = 0.80   # memory → agent  (existing ρ)
RHO_DELEGATE = 0.90   # agent → agent   (sub-agent spawn)
RHO_TOOL     = 0.85   # agent → agent   (tool call chain)
LAMBDA       = 0.1    # time decay constant (per hour)
_β = 0.6    # trust degrade rate
_λ = 0.1    # taint decay per hour

_QUARANTINE_THRESHOLD = 0.7


class CavememAdapter:
    """
    Local SQLite-backed store for:
      - trust scores per agent_id
      - taint records per agent_id
      - agent identity / capability tokens
      - verdict history (compressed via caveman grammar)
    """

    def __init__(self, db_path: str = "~/.hermes/firewall.db") -> None:
        self._db_path = db_path
        self._db = None
        self._lock = asyncio.Lock()
        # In-memory snapshots for hot-path reads
        self._trust:    dict[str, float] = {}
        self._taint:    dict[str, Taint] = {}
        self._identity: dict[str, IdentityCtx] = {}

    async def _ensure_db(self) -> None:
        if self._db is not None:
            return
        try:
            import aiosqlite, os
            path = os.path.expanduser(self._db_path)
            self._db = await aiosqlite.connect(path)
            await self._db.executescript("""
                CREATE TABLE IF NOT EXISTS trust (
                    agent_id TEXT PRIMARY KEY,
                    score    REAL NOT NULL DEFAULT 0.5,
                    updated  REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS taint (
                    agent_id TEXT PRIMARY KEY,
                    level    REAL NOT NULL DEFAULT 0.0,
                    source   TEXT,
                    reason   TEXT,
                    ts       REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verdicts (
                    id        TEXT PRIMARY KEY,
                    agent_id  TEXT,
                    tool      TEXT,
                    action    TEXT,
                    score     REAL,
                    source    TEXT,
                    reason    TEXT,
                    ts        REAL
                );
                CREATE TABLE IF NOT EXISTS identity (
                    agent_id         TEXT PRIMARY KEY,
                    parent_id        TEXT,
                    delegation_depth INTEGER DEFAULT 0,
                    caps             TEXT DEFAULT '[]',
                    trust            REAL DEFAULT 0.5,
                    taint            REAL DEFAULT 0.0,
                    token_exp        REAL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS taint_edges (
                    edge_id    TEXT PRIMARY KEY,
                    src        TEXT NOT NULL,
                    src_type   TEXT NOT NULL,
                    dst        TEXT NOT NULL,
                    dst_type   TEXT NOT NULL,
                    edge_type  TEXT NOT NULL,
                    weight     REAL NOT NULL,
                    ts         REAL NOT NULL,
                    session_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_edges_src ON taint_edges(src);
                CREATE INDEX IF NOT EXISTS idx_edges_dst ON taint_edges(dst);
            """)
            await self._db.commit()
        except Exception as e:
            logger.error("cavemem: db init failed: %s", e)
            self._db = None

    # ── Trust ────────────────────────────────────────────────────────────────

    async def get_trust(self, agent_id: str) -> float:
        if agent_id in self._trust:
            return self._trust[agent_id]
        await self._ensure_db()
        if self._db:
            try:
                async with self._db.execute(
                    "SELECT score FROM trust WHERE agent_id=?", (agent_id,)
                ) as cur:
                    row = await cur.fetchone()
                    score = row[0] if row else 0.5
                    self._trust[agent_id] = score
                    return score
            except Exception as e:
                logger.warning("cavemem: get_trust failed: %s", e)
        return 0.5

    async def on_clean_call(self, agent_id: str, tool: str) -> None:
        """Update trust upward on clean execution."""
        current = await self.get_trust(agent_id)
        new_trust = current + _α * (1.0 - current)
        await self._set_trust(agent_id, new_trust)

    async def on_taint_event(self, agent_id: str, severity: float) -> None:
        """Degrade trust fast on taint."""
        current = await self.get_trust(agent_id)
        new_trust = current * (1.0 - _β * severity)
        await self._set_trust(agent_id, new_trust)

    async def _set_trust(self, agent_id: str, score: float) -> None:
        score = max(0.0, min(1.0, score))
        self._trust[agent_id] = score
        await self._ensure_db()
        if self._db:
            try:
                await self._db.execute(
                    "INSERT OR REPLACE INTO trust VALUES (?,?,?)",
                    (agent_id, score, time.time()),
                )
                await self._db.commit()
            except Exception as e:
                logger.error("cavemem: set_trust write failed: %s", e)

    # ── Taint ────────────────────────────────────────────────────────────────

    async def get_taint(self, agent_id: str) -> Optional[Taint]:
        if agent_id in self._taint:
            return self._apply_decay(self._taint[agent_id])
        await self._ensure_db()
        if self._db:
            try:
                async with self._db.execute(
                    "SELECT level,source,reason,ts FROM taint WHERE agent_id=?",
                    (agent_id,),
                ) as cur:
                    row = await cur.fetchone()
                    if row:
                        t = Taint(
                            agent_id=agent_id,
                            level=row[0], source=row[1],
                            reason=row[2], ts=row[3],
                        )
                        self._taint[agent_id] = t
                        return self._apply_decay(t)
            except Exception as e:
                logger.warning("cavemem: get_taint failed: %s", e)
        return None

    def _apply_decay(self, t: Taint) -> Taint:
        """Taint decays at λ/hour since last event."""
        hours_elapsed = (time.time() - t.ts) / 3600.0
        decayed = t.level * (1.0 - _λ * hours_elapsed)
        decayed = max(0.0, decayed)
        return t.model_copy(update={"level": decayed})

    async def set_taint(self, agent_id: str, taint: Taint) -> None:
        self._taint[agent_id] = taint
        await self._ensure_db()
        if self._db:
            try:
                await self._db.execute(
                    "INSERT OR REPLACE INTO taint VALUES (?,?,?,?,?)",
                    (agent_id, taint.level, taint.source, taint.reason, taint.ts),
                )
                await self._db.commit()
            except Exception as e:
                logger.error("cavemem: set_taint write failed: %s", e)

    async def propagate_taint_if_blocked(
        self,
        agent_id: str,
        verdict: FirewallVerdict,
    ) -> None:
        """
        Taint propagation rules (§2.4):
          T2: capability-abuse block → taint the agent
          Downstream: send_message blocked → propagate to recipient
        """
        if verdict.action != Verdict.BLOCK:
            return
        severity = 1.0 - verdict.score
        await self.on_taint_event(agent_id, severity)
        # Write taint record
        source = "T2" if "send_message" not in verdict.tool else "T3"
        t = Taint(
            agent_id=agent_id,
            level=min(1.0, severity * _β),
            source=source,
            reason=verdict.reason,
        )
        await self.set_taint(agent_id, t)

    async def propagate_read_taint(self, reader_id: str, writer_taint: float) -> None:
        """
        T3 contagion: agent reads tainted memory.
        reader.taint = max(reader.taint, writer_taint × ρ)
        """
        current = await self.get_taint(reader_id)
        current_level = current.level if current else 0.0
        new_level = max(current_level, writer_taint * _ρ)
        if new_level > current_level:
            t = Taint(
                agent_id=reader_id,
                level=new_level,
                source="T3",
                reason=f"contagion from tainted memory (writer_taint={writer_taint:.2f})",
            )
            await self.set_taint(reader_id, t)
            if new_level >= _QUARANTINE_THRESHOLD:
                logger.warning(
                    "cavemem: agent %s taint=%.2f >= quarantine threshold", reader_id, new_level
                )

    # ── Identity ─────────────────────────────────────────────────────────────

    async def get_identity(self, agent_id: str) -> Optional[IdentityCtx]:
        if agent_id in self._identity:
            return self._identity[agent_id]
        await self._ensure_db()
        if self._db:
            try:
                import json
                async with self._db.execute(
                    "SELECT parent_id,delegation_depth,caps,trust,taint,token_exp "
                    "FROM identity WHERE agent_id=?",
                    (agent_id,),
                ) as cur:
                    row = await cur.fetchone()
                    if row:
                        ctx = IdentityCtx(
                            agent_id=agent_id,
                            parent_id=row[0],
                            delegation_depth=row[1],
                            caps=json.loads(row[2]),
                            trust=row[3],
                            taint=row[4],
                            token_exp=row[5],
                        )
                        self._identity[agent_id] = ctx
                        return ctx
            except Exception as e:
                logger.warning("cavemem: get_identity failed: %s", e)
        return None

    async def register_identity(self, ctx: IdentityCtx) -> None:
        import json
        self._identity[ctx.agent_id] = ctx
        await self._ensure_db()
        if self._db:
            try:
                await self._db.execute(
                    "INSERT OR REPLACE INTO identity VALUES (?,?,?,?,?,?,?)",
                    (
                        ctx.agent_id, ctx.parent_id, ctx.delegation_depth,
                        json.dumps(ctx.caps), ctx.trust, ctx.taint, ctx.token_exp,
                    ),
                )
                await self._db.commit()
            except Exception as e:
                logger.error("cavemem: register_identity failed: %s", e)

    # ── Verdicts ─────────────────────────────────────────────────────────────

    async def record_verdict(self, v: FirewallVerdict) -> None:
        """Append-only. Never UPDATE or DELETE."""
        await self._ensure_db()
        if self._db:
            try:
                await self._db.execute(
                    "INSERT OR IGNORE INTO verdicts VALUES (?,?,?,?,?,?,?,?)",
                    (v.verdict_id, v.agent_id, v.tool, v.action.value,
                     v.score, v.source, v.reason, v.ts),
                )
                await self._db.commit()
            except Exception as e:
                logger.error("cavemem: record_verdict failed: %s", e)

    # ── Multi-hop Taint Graph (MTP §5.2) ─────────────────────────────────────

    async def record_edge(self, src: str, src_type: str, dst: str, dst_type: str,
                          edge_type, ts=None, session_id: str = None) -> None:
        """Record a directed edge in the taint graph."""
        import uuid, math
        from firewall.core.signal import EdgeType
        await self._ensure_db()
        if not self._db:
            return
        # resolve weight from edge type
        weights = {
            EdgeType.WRITE:     RHO_WRITE,
            EdgeType.READ:      RHO_READ,
            EdgeType.DELEGATE:  RHO_DELEGATE,
            EdgeType.TOOL_CALL: RHO_TOOL,
        }
        weight = weights.get(edge_type, RHO_READ)
        ts_val = ts.timestamp() if hasattr(ts, 'timestamp') else (ts or time.time())
        try:
            await self._db.execute(
                "INSERT OR REPLACE INTO taint_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), src, src_type, dst, dst_type,
                 edge_type.value, weight, ts_val, session_id),
            )
            await self._db.commit()
        except Exception as e:
            logger.error("cavemem: record_edge failed: %s", e)

    async def propagate_graph(self, max_hops: int = 8) -> dict:
        """
        Multi-hop Taint Propagation (MTP) — iterative fixed-point solver.

        T^(k+1)[v] = max(T^(k)[v], max_{u:(u,v)∈E} T^(k)[u] × w(u,v) × e^{-λΔt})

        Convergence: T values are monotonically non-decreasing, bounded by 1.0,
        and w < 1 ensures strict decay with path length. Fixed point reached in
        at most |V| iterations (all simple paths explored). O(max_hops × |E|).
        """
        import math
        await self._ensure_db()
        if not self._db:
            return {}

        # Load all current taint levels
        T: dict[str, float] = {}
        async with self._db.execute("SELECT agent_id, level FROM taint") as cur:
            async for row in cur:
                T[row[0]] = row[1]

        # Load all edges
        edges = []
        async with self._db.execute(
            "SELECT src, dst, weight, ts FROM taint_edges"
        ) as cur:
            async for row in cur:
                edges.append((row[0], row[1], row[2], row[3]))

        now = time.time()
        changed_nodes = set()

        for _ in range(max_hops):
            changed = False
            for src, dst, weight, ts_val in edges:
                src_taint = T.get(src, 0.0)
                if src_taint <= 0.0:
                    continue
                hours_elapsed = max(0.0, (now - ts_val) / 3600.0)
                decay = weight * math.exp(-LAMBDA * hours_elapsed)
                propagated = src_taint * decay
                if propagated > T.get(dst, 0.0):
                    T[dst] = propagated
                    changed_nodes.add(dst)
                    changed = True
            if not changed:
                break  # converged

        # Write updated taint values back for agent nodes
        for node_id, level in T.items():
            if node_id in changed_nodes and level > 0.0:
                existing = await self.get_taint(node_id)
                if existing is None or level > existing.level:
                    await self.set_taint(node_id, Taint(
                        agent_id=node_id, level=level,
                        source="T3", reason="MTP graph propagation",
                    ))

        return T

    async def get_blast_radius(self, source_node: str, threshold: float = 0.3) -> list:
        """Return all nodes reachable from source_node with taint >= threshold."""
        T = await self.propagate_graph()
        return [node for node, level in T.items()
                if level >= threshold and node != source_node]
