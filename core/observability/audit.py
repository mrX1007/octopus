#!/usr/bin/env python3

import json
import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, field
from typing import Any, Optional

from core.secrets import get_redactor


@dataclass
class AuditEntry:
    timestamp: float
    actor: str          # operator name or "system"
    action: str         # "tool.execute", "credential.found", etc.
    target: str         # IP, hostname, or resource
    result: str         # "success", "failed", "timeout"
    details: dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0


class AuditLog:
    """
    SQLite-backed audit log for all framework actions.

    Usage:
        audit = AuditLog()
        audit.log_action("operator1", "scan.start", "10.0.0.1", "success")
        audit.log_tool_execution("nmap", "10.0.0.1", 12.5, 0)
        entries = audit.query(actor="operator1", limit=50)
    """

    def __init__(self, db_path: Optional[str] = None):
        self.redactor = get_redactor()
        if not db_path:
            base = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
            self.db_path = os.path.join(base, "data", "audit.db")
        else:
            self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    result TEXT NOT NULL DEFAULT '',
                    details TEXT NOT NULL DEFAULT '{}',
                    duration REAL NOT NULL DEFAULT 0.0
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)')
            for row in conn.execute(
                "SELECT id, actor, action, target, result, details FROM audit_log"
            ).fetchall():
                details = self.redactor.redact_data(json.loads(row[5] or "{}"))
                safe = (
                    self.redactor.redact_text(row[1], kind="audit_actor"),
                    self.redactor.redact_text(row[2], kind="audit_action"),
                    self.redactor.redact_text(row[3], kind="audit_target"),
                    self.redactor.redact_text(row[4], kind="audit_result"),
                    json.dumps(details, sort_keys=True),
                    row[0],
                )
                conn.execute(
                    "UPDATE audit_log SET actor = ?, action = ?, target = ?, result = ?, details = ? WHERE id = ?",
                    safe,
                )
            conn.commit()

    def log_action(self, actor: str, action: str, target: str = "",
                   result: str = "success", details: Optional[dict] = None,
                   duration: float = 0.0):
        """Log a generic action."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute('''
                INSERT INTO audit_log (timestamp, actor, action, target, result, details, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                self.redactor.redact_text(actor, kind="audit_actor"),
                self.redactor.redact_text(action, kind="audit_action"),
                self.redactor.redact_text(target, kind="audit_target"),
                self.redactor.redact_text(result, kind="audit_result"),
                json.dumps(self.redactor.redact_data(details or {}), sort_keys=True),
                duration,
            ))
            conn.commit()

    def log_tool_execution(self, tool: str, target: str,
                           duration: float, exit_code: int,
                           actor: str = "system"):
        """Log a tool execution."""
        result = "success" if exit_code == 0 else "failed"
        self.log_action(actor, f"tool.{tool}", target, result,
                        {"exit_code": exit_code}, duration)

    def query(self, actor: Optional[str] = None, action: Optional[str] = None,
              target: Optional[str] = None, since: float = 0,
              limit: int = 100) -> list[AuditEntry]:
        """Query audit log with filters."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            sql = "SELECT * FROM audit_log WHERE 1=1"
            params = []
            if actor:
                sql += " AND actor = ?"
                params.append(actor)
            if action:
                sql += " AND action LIKE ?"
                params.append(f"%{action}%")
            if target:
                sql += " AND target = ?"
                params.append(target)
            if since > 0:
                sql += " AND timestamp >= ?"
                params.append(since)
            sql += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(sql, params).fetchall()
        return [AuditEntry(
            timestamp=r["timestamp"], actor=r["actor"],
            action=r["action"], target=r["target"],
            result=r["result"],
            details=self.redactor.redact_data(json.loads(r["details"])),
            duration=r["duration"],
        ) for r in rows]
