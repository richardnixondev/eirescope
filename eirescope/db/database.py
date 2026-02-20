"""SQLite database for persisting EireScope investigations."""
import os
import json
import sqlite3
import logging
from typing import List, Optional, Dict
from datetime import datetime
from eirescope.core.entity import Entity, EntityType, EntityRelationship, Investigation

logger = logging.getLogger("eirescope.db")

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    initial_query TEXT NOT NULL,
    initial_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    notes TEXT DEFAULT '',
    modules_run TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_module TEXT DEFAULT '',
    confidence REAL DEFAULT 1.0,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    confidence REAL DEFAULT 1.0,
    evidence TEXT DEFAULT '{}',
    FOREIGN KEY (investigation_id) REFERENCES investigations(id),
    FOREIGN KEY (source_entity_id) REFERENCES entities(id),
    FOREIGN KEY (target_entity_id) REFERENCES entities(id)
);

CREATE INDEX IF NOT EXISTS idx_entities_investigation ON entities(investigation_id);
CREATE INDEX IF NOT EXISTS idx_relationships_investigation ON relationships(investigation_id);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
"""


class Database:
    """SQLite database manager for EireScope investigations."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(CREATE_TABLES_SQL)
            conn.commit()
        logger.info(f"Database initialized at {self.db_path}")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save_investigation(self, inv: Investigation):
        """Save or update an investigation and all its entities/relationships."""
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO investigations
                   (id, initial_query, initial_type, status, notes, modules_run, created_at, completed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (inv.id, inv.initial_query, inv.initial_type.value, inv.status,
                 inv.notes, json.dumps(inv.modules_run), inv.created_at, inv.completed_at),
            )
            for entity in inv.entities:
                conn.execute(
                    """INSERT OR REPLACE INTO entities
                       (id, investigation_id, entity_type, value, source_module, confidence, metadata, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (entity.id, inv.id, entity.entity_type.value, entity.value,
                     entity.source_module, entity.confidence,
                     json.dumps(entity.metadata), entity.created_at),
                )
            for rel in inv.relationships:
                conn.execute(
                    """INSERT OR REPLACE INTO relationships
                       (id, investigation_id, source_entity_id, target_entity_id,
                        relationship_type, confidence, evidence)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (rel.id, inv.id, rel.source_entity_id, rel.target_entity_id,
                     rel.relationship_type, rel.confidence, json.dumps(rel.evidence)),
                )
            conn.commit()

    def load_investigation(self, inv_id: str) -> Optional[Investigation]:
        """Load a full investigation by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM investigations WHERE id = ?", (inv_id,)
            ).fetchone()
            if not row:
                return None

            inv = Investigation(
                id=row["id"],
                initial_query=row["initial_query"],
                initial_type=EntityType(row["initial_type"]),
                status=row["status"],
                notes=row["notes"] or "",
                modules_run=json.loads(row["modules_run"]),
                created_at=row["created_at"],
                completed_at=row["completed_at"],
            )

            for erow in conn.execute(
                "SELECT * FROM entities WHERE investigation_id = ?", (inv_id,)
            ):
                inv.entities.append(Entity(
                    id=erow["id"],
                    entity_type=EntityType(erow["entity_type"]),
                    value=erow["value"],
                    source_module=erow["source_module"],
                    confidence=erow["confidence"],
                    metadata=json.loads(erow["metadata"]),
                    created_at=erow["created_at"],
                ))

            for rrow in conn.execute(
                "SELECT * FROM relationships WHERE investigation_id = ?", (inv_id,)
            ):
                inv.relationships.append(EntityRelationship(
                    id=rrow["id"],
                    source_entity_id=rrow["source_entity_id"],
                    target_entity_id=rrow["target_entity_id"],
                    relationship_type=rrow["relationship_type"],
                    confidence=rrow["confidence"],
                    evidence=json.loads(rrow["evidence"]),
                ))

            return inv

    def list_investigations(self, limit: int = 50) -> List[Dict]:
        """List recent investigations (summary only)."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT i.*, COUNT(e.id) as entity_count
                   FROM investigations i
                   LEFT JOIN entities e ON e.investigation_id = i.id
                   GROUP BY i.id
                   ORDER BY i.created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [
                {
                    "id": r["id"],
                    "initial_query": r["initial_query"],
                    "initial_type": r["initial_type"],
                    "status": r["status"],
                    "entity_count": r["entity_count"],
                    "created_at": r["created_at"],
                    "completed_at": r["completed_at"],
                }
                for r in rows
            ]

    def delete_investigation(self, inv_id: str):
        """Delete an investigation and all associated data."""
        with self._conn() as conn:
            conn.execute("DELETE FROM relationships WHERE investigation_id = ?", (inv_id,))
            conn.execute("DELETE FROM entities WHERE investigation_id = ?", (inv_id,))
            conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
            conn.commit()
