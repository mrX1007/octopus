"""Persistent operator identities and API-key verification.

Operator records do not grant access on their own. A control principal is
created only after :mod:`core.c2.control_auth` also verifies an explicit peer
binding and an explicit mission grant.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from core.actions.zeroizable_buffers import ZeroizableDestinationBufferV2
from core.secrets import OpaqueSecretValueV2, SecretValue

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_READONLY = "readonly"
OPERATOR_ROLES = frozenset({ROLE_ADMIN, ROLE_OPERATOR, ROLE_READONLY})

# Compatibility for the legacy daemon. The canonical control path applies its
# closed RBAC matrix after constructing a fully authenticated principal.
_PERMISSIONS = {
    ROLE_ADMIN: {
        "list_agents",
        "queue_task",
        "get_results",
        "manage_operators",
        "ping",
        "build_implant",
    },
    ROLE_OPERATOR: {
        "list_agents",
        "queue_task",
        "get_results",
        "ping",
        "build_implant",
    },
    ROLE_READONLY: {"list_agents", "get_results", "ping"},
}


def _hash_api_key(api_key: str | SecretValue) -> str:
    """Return the storage digest for one high-entropy API key."""

    if type(api_key) is str:
        if not api_key:
            raise ValueError("API key must not be empty")
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    if type(api_key) is not OpaqueSecretValueV2:
        raise TypeError("API key must be a string or the canonical opaque secret")

    destination = ZeroizableDestinationBufferV2.allocate(api_key.byte_length)
    with api_key.acquire_single_use(consumer_id="c2-operator-auth") as lease, destination:
        copied = lease.read_into(destination)
        with destination.borrow_writable_view() as writable:
            bounded = writable[:copied]
            try:
                return hashlib.sha256(bounded).hexdigest()
            finally:
                bounded.release()


def initialize_operator_schema(connection: sqlite3.Connection) -> None:
    """Create or monotonically migrate the operator schema."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS operators (
            operator_id TEXT PRIMARY KEY,
            subject_id TEXT UNIQUE,
            name TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            api_key_hash TEXT NOT NULL UNIQUE,
            created_at REAL NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            authorization_revision INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(operators)").fetchall()}
    if "subject_id" not in columns:
        connection.execute("ALTER TABLE operators ADD COLUMN subject_id TEXT")
    if "authorization_revision" not in columns:
        connection.execute("ALTER TABLE operators ADD COLUMN authorization_revision INTEGER NOT NULL DEFAULT 1")
    connection.execute(
        "UPDATE operators SET subject_id = 'legacy:' || operator_id WHERE subject_id IS NULL OR subject_id = ''"
    )
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_subject_id ON operators(subject_id)")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_api_key_hash ON operators(api_key_hash)")


def insert_operator_record(
    connection: sqlite3.Connection,
    *,
    operator_id: str,
    subject_id: str,
    name: str,
    role: str,
    api_key: str,
    created_at: float | None = None,
) -> None:
    """Insert an operator into an existing transaction."""

    if role not in OPERATOR_ROLES:
        raise ValueError(f"invalid operator role: {role}")
    if not all(isinstance(value, str) and value for value in (operator_id, subject_id, name)):
        raise ValueError("operator_id, subject_id and name must not be empty")
    if not api_key:
        raise ValueError("API key must not be empty")
    connection.execute(
        """
        INSERT INTO operators (
            operator_id, subject_id, name, role, api_key_hash,
            created_at, active, authorization_revision
        ) VALUES (?, ?, ?, ?, ?, ?, 1, 1)
        """,
        (
            operator_id,
            subject_id,
            name,
            role,
            _hash_api_key(api_key),
            time.time() if created_at is None else float(created_at),
        ),
    )


class OperatorManager:
    """Manage persistent operator records without implicit bootstrap.

    Construction only initializes the schema. In particular, it never creates
    an administrator, writes a key file, or prints secret material.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _get_conn(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _init_schema(self) -> None:
        with self._get_conn() as connection:
            initialize_operator_schema(connection)

    def create_operator(
        self,
        name: str,
        role: str,
        *,
        subject_id: str | None = None,
    ) -> str:
        """Create one explicit operator and return its one-time API key."""

        if role not in OPERATOR_ROLES:
            raise ValueError(f"Invalid role: {role}. Must be one of {sorted(OPERATOR_ROLES)}")
        operator_id = secrets.token_hex(16)
        stable_subject_id = subject_id or f"operator:{secrets.token_hex(16)}"
        api_key = f"octopus-c2-{secrets.token_urlsafe(32)}"
        with self._get_conn() as connection:
            insert_operator_record(
                connection,
                operator_id=operator_id,
                subject_id=stable_subject_id,
                name=name,
                role=role,
                api_key=api_key,
            )
        return api_key

    def authenticate(self, api_key: str | SecretValue) -> dict[str, Any] | None:
        """Verify an API key and return authoritative stored identity data."""

        try:
            key_digest = _hash_api_key(api_key)
        except (TypeError, ValueError, RuntimeError):
            return None
        with self._get_conn() as connection:
            row = connection.execute(
                """
                SELECT operator_id, subject_id, name, role, created_at, active,
                       authorization_revision
                FROM operators
                WHERE api_key_hash = ? AND active = 1
                """,
                (key_digest,),
            ).fetchone()
        return dict(row) if row is not None else None

    def get_operator(self, operator_id: str, *, active_only: bool = False) -> dict[str, Any] | None:
        query = (
            "SELECT operator_id, subject_id, name, role, created_at, active, "
            "authorization_revision FROM operators WHERE operator_id = ?"
        )
        parameters: tuple[object, ...] = (operator_id,)
        if active_only:
            query += " AND active = 1"
        with self._get_conn() as connection:
            row = connection.execute(query, parameters).fetchone()
        return dict(row) if row is not None else None

    def list_operators(self) -> list[dict[str, Any]]:
        """List identities without API-key digests."""

        with self._get_conn() as connection:
            rows = connection.execute(
                """
                SELECT operator_id, subject_id, name, role, created_at, active,
                       authorization_revision
                FROM operators ORDER BY created_at, operator_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def authorize(self, operator: dict[str, Any], action: str) -> bool:
        """Legacy coarse check fenced by the current stored revision."""

        operator_id = operator.get("operator_id")
        if not isinstance(operator_id, str):
            return False
        current = self.get_operator(operator_id, active_only=True)
        if current is None:
            return False
        if operator.get("authorization_revision") != current["authorization_revision"]:
            return False
        return action in _PERMISSIONS.get(str(current["role"]), frozenset())

    def deactivate_operator(self, name: str) -> bool:
        with self._get_conn() as connection:
            cursor = connection.execute(
                """
                UPDATE operators
                SET active = 0, authorization_revision = authorization_revision + 1
                WHERE name = ? AND active = 1
                """,
                (name,),
            )
            return cursor.rowcount == 1

    def rotate_api_key(self, name: str) -> str | None:
        new_key = f"octopus-c2-{secrets.token_urlsafe(32)}"
        with self._get_conn() as connection:
            cursor = connection.execute(
                """
                UPDATE operators
                SET api_key_hash = ?, authorization_revision = authorization_revision + 1
                WHERE name = ? AND active = 1
                """,
                (_hash_api_key(new_key), name),
            )
            if cursor.rowcount != 1:
                return None
        return new_key


__all__ = [
    "OPERATOR_ROLES",
    "ROLE_ADMIN",
    "ROLE_OPERATOR",
    "ROLE_READONLY",
    "OperatorManager",
    "_hash_api_key",
    "initialize_operator_schema",
    "insert_operator_record",
]
