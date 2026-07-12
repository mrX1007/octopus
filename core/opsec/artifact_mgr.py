
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Optional


class ArtifactManager:
    """Tracks operational artifacts for precise cleanup and forensic minimization."""

    def __init__(self, db_path: Optional[str] = None, target_ip: str = "local"):
        self.target_ip = target_ip

        if db_path is None:
            base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(base, "data", "c2.db")

        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    path TEXT,
                    description TEXT,
                    user TEXT,
                    marker TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_artifacts_target
                ON artifacts(target_ip, status)
            """)
            conn.commit()

    def record_file(self, file_path: str, description: str = ""):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO artifacts (target_ip, artifact_type, path, description, timestamp)
                VALUES (?, 'file', ?, ?, ?)
            """, (self.target_ip, file_path, description, datetime.now().isoformat()))
            conn.commit()

    def record_ssh_key(self, user: str, key_comment: str):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO artifacts (target_ip, artifact_type, user, marker, timestamp)
                VALUES (?, 'ssh_key', ?, ?, ?)
            """, (self.target_ip, user, key_comment, datetime.now().isoformat()))
            conn.commit()

    def record_cron(self, user: str, marker: str):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO artifacts (target_ip, artifact_type, user, marker, timestamp)
                VALUES (?, 'cron', ?, ?, ?)
            """, (self.target_ip, user, marker, datetime.now().isoformat()))
            conn.commit()

    def record_process(self, pid: int, description: str = ""):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO artifacts (target_ip, artifact_type, marker, description, timestamp)
                VALUES (?, 'process', ?, ?, ?)
            """, (self.target_ip, str(pid), description, datetime.now().isoformat()))
            conn.commit()

    def get_pending_cleanups(self) -> list[dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE target_ip = ? AND status = 'active'",
                (self.target_ip,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_artifacts(self, target_ip: Optional[str] = None) -> list[dict[str, Any]]:
        """Get all artifacts, optionally filtered by target."""
        with self._get_conn() as conn:
            if target_ip:
                rows = conn.execute(
                    "SELECT * FROM artifacts WHERE target_ip = ? ORDER BY timestamp DESC",
                    (target_ip,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM artifacts ORDER BY timestamp DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def mark_cleaned(self, identifier: str):
        """Mark artifact as cleaned by path, marker, or comment."""
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE artifacts SET status = 'cleaned'
                WHERE target_ip = ? AND status = 'active'
                  AND (path = ? OR marker = ?)
            """, (self.target_ip, identifier, identifier))
            conn.commit()

    def mark_all_cleaned(self):
        """Mark all active artifacts for this target as cleaned."""
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE artifacts SET status = 'cleaned' WHERE target_ip = ? AND status = 'active'",
                (self.target_ip,)
            )
            conn.commit()
