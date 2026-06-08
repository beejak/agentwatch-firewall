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

import math
from datetime import datetime, timezone

from firewall.core.signal import EdgeType, FirewallVerdict, IdentityCtx, Taint, TaintEdge, Verdict

logger = logging.getLogger(__name__)

# Taint propagation constants (§2.4)
_ρ = 0.8    # decay per hop
_α = 0.02   # trust recovery rate
_β = 0.6    # trust degrade rate
_λ = 0.1    # taint decay per hour

_QUARANTINE_THRESHOLD = 0.7

# Edge-type decay constants for MTP
RHO_WRITE    = 0.95   # agent writes memory — high fidelity transfer
RHO_READ     = 0.80   # existing ρ hop decay
RHO_DELEGATE = 0.90   # sub-agent spawned — close trust relationship
RHO_TOOL     = 0.85   # tool call chain

_EDGE_WEIGHTS: dict[EdgeType, float] = {
    EdgeType.WRITE:     RHO_WRITE,
    EdgeType.READ:      RHO_READ,
    EdgeType.DELEGATE:  RHO_DELEGATE,
    EdgeType.TOOL_CALL: RHO_TOOL,
}


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
                    ts         TEXT NOT NULL,
                    session_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_edges_dst ON taint_edges(dst);
                CREATE INDEX IF NOT EXISTS idx_edges_src ON taint_edges(src);
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

    # ── Taint Graph / MTP ────────────────────────────────────────────────────

    async def record_edge(
        self,
        src: str,
        src_type: str,
        dst: str,
        dst_type: str,
        edge_type: EdgeType,
        ts: datetime,
        session_id: str = None,
    ) -> TaintEdge:
        """Record a directed edge in the taint graph."""
        weight = _EDGE_WEIGHTS.get(edge_type, _ρ)
        edge = TaintEdge(
            src=src,
            src_type=src_type,
            dst=dst,
            dst_type=dst_type,
            edge_type=edge_type,
            weight=weight,
            ts=ts,
            session_id=session_id,
        )
        await self._ensure_db()
        if self._db:
            try:
                await self._db.execute(
                    "INSERT OR IGNORE INTO taint_edges VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        edge.edge_id, edge.src, edge.src_type,
                        edge.dst, edge.dst_type, edge.edge_type.value,
                        edge.weight, edge.ts.isoformat(), edge.session_id,
                    ),
                )
                await self._db.commit()
            except Exception as e:
                logger.error("cavemem: record_edge failed: %s", e)
        return edge

    async def propagate_graph(self, max_hops: int = 8) -> dict[str, float]:
        """
        Multi-hop Taint Propagation (MTP) — iterative fixed-point solver.

        T^(k+1)[v] = max(T^(k)[v], max_{u:(u,v)∈E} T^(k)[u] × w(u,v) × e^{-λΔt})

        Convergence guaranteed: T values monotonically non-decreasing, bounded by 1.0,
        edge weights < 1 ensure strict decay. Worst case O(max_hops × |E|).
        """
        await self._ensure_db()
        if not self._db:
            return {}

        # Load all edges
        edges = []
        async with self._db.execute(
            "SELECT src, dst, weight, ts FROM taint_edges"
        ) as cur:
            rows = await cur.fetchall()
        now = datetime.now(timezone.utc)
        for src, dst, weight, ts_str in rows:
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                hours_elapsed = (now - ts).total_seconds() / 3600.0
                decay = weight * math.exp(-_λ * hours_elapsed)
                edges.append((src, dst, decay))
            except Exception as e:
                logger.warning("cavemem: edge ts parse error: %s", e)

        # Collect all known nodes
        node_ids: set[str] = set()
        for src, dst, _ in edges:
            node_ids.add(src)
            node_ids.add(dst)

        # Initialise taint vector from DB
        taint_vec: dict[str, float] = {}
        for node_id in node_ids:
            t = await self.get_taint(node_id)
            taint_vec[node_id] = t.level if t else 0.0

        changed_nodes: dict[str, float] = {}

        for _ in range(max_hops):
            changed = False
            for src, dst, decay in edges:
                propagated = taint_vec.get(src, 0.0) * decay
                if propagated > taint_vec.get(dst, 0.0):
                    taint_vec[dst] = propagated
                    changed_nodes[dst] = propagated
                    changed = True
            if not changed:
                break

        # Write updated taint back
        for node_id, new_level in changed_nodes.items():
            existing = self._taint.get(node_id)
            t = Taint(
                agent_id=node_id,
                level=new_level,
                source="T3",
                reason="MTP multi-hop propagation",
                ts=time.time(),
                session_id=existing.session_id if existing else "",
            )
            await self.set_taint(node_id, t)

        return changed_nodes

    async def get_taint_graph(self) -> dict:
        """Return full graph as {nodes: [...], edges: [...]} for visualization."""
        await self._ensure_db()
        if not self._db:
            return {"nodes": [], "edges": []}

        async with self._db.execute(
            "SELECT src, src_type, dst, dst_type, edge_type, weight, ts FROM taint_edges"
        ) as cur:
            rows = await cur.fetchall()

        node_ids: set[str] = set()
        edges = []
        for src, src_type, dst, dst_type, edge_type, weight, ts in rows:
            node_ids.add(src)
            node_ids.add(dst)
            edges.append({
                "src": src, "src_type": src_type,
                "dst": dst, "dst_type": dst_type,
                "edge_type": edge_type, "weight": weight, "ts": ts,
            })

        nodes = []
        for node_id in node_ids:
            t = await self.get_taint(node_id)
            nodes.append({"id": node_id, "taint": t.level if t else 0.0})

        return {"nodes": nodes, "edges": edges}

    async def get_blast_radius(self, source_node: str, threshold: float = 0.3) -> list[str]:
        """
        Given a compromised node, return all nodes reachable with taint >= threshold.
        Uses propagate_graph() result filtered by threshold.
        """
        changed = await self.propagate_graph()
        result = []
        for node_id, taint_level in changed.items():
            if node_id != source_node and taint_level >= threshold:
                result.append(node_id)
        return result

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
