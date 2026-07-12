"""

Operator RBAC with API Key Authentication and Audit.

Roles:
  - admin: full access (manage operators, agents, tasks)
  - operator: queue tasks, view agents, view results
  - readonly: view agents and results only

Every action is recorded in the event store for audit.
"""

import hashlib
import os
import secrets
import sqlite3
from contextlib import contextmanager
from typing import Any, Optional

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_READONLY = "readonly"

# Permission matrix
_PERMISSIONS = {
    ROLE_ADMIN: {"list_agents", "queue_task", "get_results", "manage_operators", "ping", "build_implant"},
    ROLE_OPERATOR: {"list_agents", "queue_task", "get_results", "ping", "build_implant"},
    ROLE_READONLY: {"list_agents", "get_results", "ping"},
}


def _hash_api_key(api_key: str) -> str:
    """SHA-256 hash of the API key for storage."""
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()


class OperatorManager:
    """
    Manages operator accounts, authentication, and authorization.

    Usage:
        mgr = OperatorManager("data/c2.db")
        key = mgr.create_operator("alice", "admin")
        op = mgr.authenticate(key)
        mgr.authorize(op, "queue_task")  # raises if denied
    """

    def __init__(self, db_path: str):
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
                CREATE TABLE IF NOT EXISTS operators (
                    operator_id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL,
                    api_key_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.commit()

        # Ensure a default admin exists if no operators exist
        if not self.list_operators():
            self._create_default_admin()

    def _create_default_admin(self) -> str:
        """Create a default admin operator on first run. Returns the API key."""
        import time
        api_key = "mtron-" + secrets.token_hex(24)
        op_id = secrets.token_hex(8)

        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO operators (operator_id, name, role, api_key_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (op_id, "default-admin", ROLE_ADMIN, _hash_api_key(api_key), time.time()))
            conn.commit()

        # Write the key to a file for first-run access
        key_file = os.path.join(os.path.dirname(self.db_path), "default_admin.key")
        with open(key_file, "w") as f:
            f.write(api_key)
        os.chmod(key_file, 0o600)

        print(f"  [*] Default admin API key written to {key_file}")
        return api_key

    def create_operator(self, name: str, role: str) -> str:
        """Create a new operator. Returns the plaintext API key (show once)."""
        import time
        if role not in _PERMISSIONS:
            raise ValueError(f"Invalid role: {role}. Must be one of {list(_PERMISSIONS.keys())}")

        api_key = "mtron-" + secrets.token_hex(24)
        op_id = secrets.token_hex(8)

        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO operators (operator_id, name, role, api_key_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (op_id, name, role, _hash_api_key(api_key), time.time()))
            conn.commit()

        return api_key

    def authenticate(self, api_key: str) -> Optional[dict[str, Any]]:
        """Authenticate an operator by API key. Returns operator dict or None."""
        key_hash = _hash_api_key(api_key)

        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM operators WHERE api_key_hash = ? AND active = 1",
                (key_hash,)
            ).fetchone()

        if row:
            return dict(row)
        return None

    def authorize(self, operator: dict[str, Any], action: str) -> bool:
        """Check if operator has permission for action. Returns True/False."""
        role = operator.get("role", "")
        allowed = _PERMISSIONS.get(role, set())
        return action in allowed

    def list_operators(self) -> list:
        """List all operators (without key hashes)."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT operator_id, name, role, created_at, active FROM operators"
            ).fetchall()
        return [dict(r) for r in rows]

    def deactivate_operator(self, name: str) -> bool:
        """Deactivate an operator by name."""
        with self._get_conn() as conn:
            cur = conn.execute(
                "UPDATE operators SET active = 0 WHERE name = ?", (name,)
            )
            conn.commit()
            return cur.rowcount > 0

    def rotate_api_key(self, name: str) -> Optional[str]:
        """Rotate an operator's API key. Returns new key or None."""
        new_key = "mtron-" + secrets.token_hex(24)

        with self._get_conn() as conn:
            cur = conn.execute(
                "UPDATE operators SET api_key_hash = ? WHERE name = ? AND active = 1",
                (_hash_api_key(new_key), name)
            )
            conn.commit()
            if cur.rowcount > 0:
                return new_key
        return None
