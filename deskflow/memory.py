"""Contextual graph memory with decision traces (design doc section 7).

Edge tables in SQLite (the MVP choice in the doc). Eight node types and seven edge
types match the schema figure. Every edge carries a time and a source.
"""
from __future__ import annotations

import json
import sqlite3
import time

NODE_TYPES = {"User", "Application", "Device", "Incident", "Decision", "Policy", "Knowledge", "PastDecision"}
EDGE_TYPES = {"OWNS_DEVICE", "ACCESSED_BY", "FAILED_WITH_ERROR", "RESOLVED_BY", "PRECEDENT_FOR", "GOVERNED_BY", "CITES"}


class GraphMemory:
    def __init__(self, clock=time.time):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(
            "CREATE TABLE nodes(id TEXT PRIMARY KEY, type TEXT, props TEXT);"
            "CREATE TABLE edges(src TEXT, rel TEXT, dst TEXT, source TEXT, ts REAL,"
            " UNIQUE(src, rel, dst));")
        self.clock = clock

    def add_node(self, node_id: str, ntype: str, **props) -> None:
        assert ntype in NODE_TYPES, ntype
        self.db.execute("INSERT OR REPLACE INTO nodes VALUES (?,?,?)", (node_id, ntype, json.dumps(props)))

    def add_edge(self, src: str, rel: str, dst: str, source: str) -> None:
        assert rel in EDGE_TYPES, rel
        self.db.execute("INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?)", (src, rel, dst, source, self.clock()))

    def node(self, node_id: str) -> dict | None:
        row = self.db.execute("SELECT type, props FROM nodes WHERE id=?", (node_id,)).fetchone()
        return {"id": node_id, "type": row[0], **json.loads(row[1])} if row else None

    def neighbors(self, node_id: str, rel: str | None = None) -> list[tuple[str, str, str]]:
        q = "SELECT src, rel, dst FROM edges WHERE (src=? OR dst=?)" + (" AND rel=?" if rel else "")
        args = (node_id, node_id) + ((rel,) if rel else ())
        return self.db.execute(q, args).fetchall()

    def fix_succeeded(self, incident_id: str) -> bool:
        """True if the incident was resolved by a decision with a confirmed outcome."""
        for _, _, dec in self.neighbors(incident_id, "RESOLVED_BY"):
            n = self.node(dec)
            if n and n.get("outcome") == "confirmed":
                return True
        return False

    def seed_incidents(self, incidents: list[dict]) -> None:
        for inc in incidents:
            self.add_node(inc["id"], "Incident", title=inc["title"], resolution_code=inc["resolution_code"])
            dec = f"dec-{inc['id']}"
            self.add_node(dec, "PastDecision", outcome=inc["outcome"], code=inc["resolution_code"])
            self.add_edge(inc["id"], "RESOLVED_BY", dec, "seed")

    def write_trace(self, *, ticket_id: str, user: str, device: str | None, category: str, code: str,
                    outcome: str, policy_version: str, citations: list[str], error_code: str | None,
                    app: str | None, approver: str | None) -> str:
        src = f"ticket:{ticket_id}"
        dec, inc = f"dec-{ticket_id}", f"inc-{ticket_id}"
        self.add_node(user, "User")
        self.add_node(inc, "Incident", title=category, error=error_code)
        self.add_node(dec, "Decision", outcome=outcome, code=code, approver=approver)
        self.add_node(f"policy-{policy_version}", "Policy")
        if device:
            self.add_node(device, "Device")
            self.add_edge(user, "OWNS_DEVICE", device, src)
            if error_code:
                self.add_edge(device, "FAILED_WITH_ERROR", inc, src)
        self.add_edge(inc, "RESOLVED_BY", dec, src)
        self.add_edge(dec, "GOVERNED_BY", f"policy-{policy_version}", src)
        for c in citations:
            if c.startswith("kb-"):
                self.add_node(c, "Knowledge")
                self.add_edge(dec, "CITES", c, src)
            elif c.startswith("inc-"):
                self.add_edge(f"dec-{c}", "PRECEDENT_FOR", inc, src)
        if app and outcome == "confirmed":
            self.add_node(app, "Application")
            self.add_edge(app, "ACCESSED_BY", user, src)
        return dec

    def trace_summary(self, ticket_id: str) -> list[str]:
        rows = self.db.execute("SELECT src, rel, dst FROM edges WHERE source=?", (f"ticket:{ticket_id}",)).fetchall()
        return [f"{s} -[{r}]-> {d}" for s, r, d in rows]
