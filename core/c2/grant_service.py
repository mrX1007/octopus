"""Revisioned operator peer bindings and mission grants."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from core.c2.operators import initialize_operator_schema

if TYPE_CHECKING:
    from core.c2.control_auth import AuthenticatedControlPrincipal

SYSTEM_CONTROL_MISSION_ID = "system://c2-control"


class GrantConflictError(RuntimeError):
    """The expected grant revision did not match persistent state."""


@dataclass(frozen=True, order=True)
class PeerBinding:
    uid: int
    gid: int

    def __post_init__(self) -> None:
        if self.uid < 0 or self.gid < 0:
            raise ValueError("peer UID/GID must be non-negative")


@dataclass(frozen=True)
class PeerBindingSnapshot:
    operator_id: str
    binding: PeerBinding
    revision: int


@dataclass(frozen=True)
class MissionGrantSnapshot:
    operator_id: str
    subject_id: str
    mission_id: str
    revision: int


def initialize_grant_schema(connection: sqlite3.Connection) -> None:
    initialize_operator_schema(connection)
    statements = (
        """CREATE TABLE IF NOT EXISTS control_missions (
            mission_id TEXT PRIMARY KEY,
            mission_kind TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS operator_peer_binding_revisions (
            operator_id TEXT PRIMARY KEY REFERENCES operators(operator_id),
            revision INTEGER NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS operator_peer_bindings (
            operator_id TEXT NOT NULL REFERENCES operators(operator_id),
            peer_uid INTEGER NOT NULL,
            peer_gid INTEGER NOT NULL,
            active INTEGER NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (operator_id, peer_uid, peer_gid)
        )""",
        """CREATE TABLE IF NOT EXISTS operator_mission_grant_revisions (
            operator_id TEXT PRIMARY KEY REFERENCES operators(operator_id),
            revision INTEGER NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS operator_mission_grants (
            operator_id TEXT NOT NULL REFERENCES operators(operator_id),
            subject_id TEXT NOT NULL,
            mission_id TEXT NOT NULL REFERENCES control_missions(mission_id),
            active INTEGER NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (operator_id, mission_id)
        )""",
    )
    for statement in statements:
        connection.execute(statement)


def ensure_system_control_mission(
    connection: sqlite3.Connection,
    *,
    now: float | None = None,
) -> None:
    timestamp = time.time() if now is None else float(now)
    connection.execute(
        """
        INSERT INTO control_missions (mission_id, mission_kind, active, created_at)
        VALUES (?, 'system-control', 1, ?)
        ON CONFLICT(mission_id) DO NOTHING
        """,
        (SYSTEM_CONTROL_MISSION_ID, timestamp),
    )
    row = connection.execute(
        "SELECT mission_kind, active FROM control_missions WHERE mission_id = ?",
        (SYSTEM_CONTROL_MISSION_ID,),
    ).fetchone()
    if row is None or str(row[0]) != "system-control" or int(row[1]) != 1:
        raise RuntimeError("canonical system control mission is invalid")


def insert_initial_bootstrap_grants(
    connection: sqlite3.Connection,
    *,
    operator_id: str,
    subject_id: str,
    peer_uid: int,
    peer_gid: int,
    now: float | None = None,
) -> None:
    """Insert exactly one peer binding and the system-control grant."""

    binding = PeerBinding(uid=peer_uid, gid=peer_gid)
    timestamp = time.time() if now is None else float(now)
    initialize_grant_schema(connection)
    ensure_system_control_mission(connection, now=timestamp)
    connection.execute(
        "INSERT INTO operator_peer_binding_revisions (operator_id, revision) VALUES (?, 1)",
        (operator_id,),
    )
    connection.execute(
        """
        INSERT INTO operator_peer_bindings
            (operator_id, peer_uid, peer_gid, active, updated_at)
        VALUES (?, ?, ?, 1, ?)
        """,
        (operator_id, binding.uid, binding.gid, timestamp),
    )
    connection.execute(
        "INSERT INTO operator_mission_grant_revisions (operator_id, revision) VALUES (?, 1)",
        (operator_id,),
    )
    connection.execute(
        """
        INSERT INTO operator_mission_grants
            (operator_id, subject_id, mission_id, active, updated_at)
        VALUES (?, ?, ?, 1, ?)
        """,
        (operator_id, subject_id, SYSTEM_CONTROL_MISSION_ID, timestamp),
    )


PrincipalValidator = Callable[["AuthenticatedControlPrincipal"], bool]


class GrantService:
    """Persist and resolve explicit grants with compare-and-swap revisions."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._principal_validator: PrincipalValidator | None = None
        with self._connection() as connection:
            initialize_grant_schema(connection)
            ensure_system_control_mission(connection)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA foreign_keys=ON")
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

    def bind_principal_validator(self, validator: PrincipalValidator) -> None:
        if self._principal_validator is not None and self._principal_validator != validator:
            raise RuntimeError("principal validator is already bound")
        self._principal_validator = validator

    def _require_current_admin(self, actor: AuthenticatedControlPrincipal) -> None:
        if self._principal_validator is None or not self._principal_validator(actor):
            raise PermissionError("a current authenticated principal is required")
        role = getattr(actor.role, "value", actor.role)
        if role != "admin":
            raise PermissionError("administrator role is required")

    @staticmethod
    def _fence_admin_in_transaction(
        connection: sqlite3.Connection,
        actor: AuthenticatedControlPrincipal,
    ) -> None:
        """Revalidate every persisted actor revision under the write lock."""

        role = getattr(actor.role, "value", actor.role)
        if role != "admin" or time.time() >= actor.expires_at:
            raise PermissionError("current administrator principal is required")
        operator = connection.execute(
            """
            SELECT subject_id, role, authorization_revision
            FROM operators
            WHERE operator_id = ? AND active = 1
            """,
            (actor.operator_id,),
        ).fetchone()
        if (
            operator is None
            or str(operator["subject_id"]) != actor.subject_id
            or str(operator["role"]) != "admin"
            or int(operator["authorization_revision"]) != actor.operator_revision
        ):
            raise PermissionError("administrator operator revision is stale")
        peer = connection.execute(
            """
            SELECT r.revision
            FROM operator_peer_bindings AS b
            JOIN operator_peer_binding_revisions AS r USING (operator_id)
            WHERE b.operator_id = ? AND b.peer_uid = ? AND b.peer_gid = ?
              AND b.active = 1
            """,
            (actor.operator_id, actor.peer.uid, actor.peer.gid),
        ).fetchone()
        if peer is None or int(peer["revision"]) != actor.peer_binding_revision:
            raise PermissionError("administrator peer binding revision is stale")
        mission = connection.execute(
            """
            SELECT r.revision
            FROM operator_mission_grants AS g
            JOIN operator_mission_grant_revisions AS r USING (operator_id)
            JOIN control_missions AS m USING (mission_id)
            WHERE g.operator_id = ? AND g.subject_id = ? AND g.mission_id = ?
              AND g.active = 1 AND m.active = 1
            """,
            (actor.operator_id, actor.subject_id, actor.mission_id),
        ).fetchone()
        if mission is None or int(mission["revision"]) != actor.mission_grant_revision:
            raise PermissionError("administrator mission grant revision is stale")

    @staticmethod
    def _revision(
        connection: sqlite3.Connection,
        table: str,
        operator_id: str,
    ) -> int:
        if table not in {
            "operator_peer_binding_revisions",
            "operator_mission_grant_revisions",
        }:
            raise ValueError("invalid revision table")
        row = connection.execute(
            f"SELECT revision FROM {table} WHERE operator_id = ?",
            (operator_id,),
        ).fetchone()
        return 0 if row is None else int(row[0])

    @staticmethod
    def _require_expected(current: int, expected: int) -> None:
        if expected < 0 or current != expected:
            raise GrantConflictError(f"grant revision conflict: expected {expected}, current {current}")

    @staticmethod
    def _require_active_operator(
        connection: sqlite3.Connection,
        operator_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT operator_id, subject_id, authorization_revision
            FROM operators WHERE operator_id = ? AND active = 1
            """,
            (operator_id,),
        ).fetchone()
        if row is None:
            raise LookupError("active operator not found")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _advance_authorization_revision(
        connection: sqlite3.Connection,
        operator_id: str,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE operators
            SET authorization_revision = authorization_revision + 1
            WHERE operator_id = ? AND active = 1
            """,
            (operator_id,),
        )
        if cursor.rowcount != 1:
            raise LookupError("active operator not found")

    def resolve_peer_binding(
        self,
        operator_id: str,
        *,
        uid: int,
        gid: int,
    ) -> PeerBindingSnapshot | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT b.peer_uid, b.peer_gid, r.revision
                FROM operator_peer_bindings AS b
                JOIN operator_peer_binding_revisions AS r USING (operator_id)
                WHERE b.operator_id = ? AND b.peer_uid = ? AND b.peer_gid = ?
                  AND b.active = 1
                """,
                (operator_id, uid, gid),
            ).fetchone()
        if row is None:
            return None
        return PeerBindingSnapshot(
            operator_id=operator_id,
            binding=PeerBinding(uid=int(row[0]), gid=int(row[1])),
            revision=int(row[2]),
        )

    def allowed_peers(self, operator_id: str) -> tuple[PeerBinding, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT peer_uid, peer_gid FROM operator_peer_bindings
                WHERE operator_id = ? AND active = 1
                ORDER BY peer_uid, peer_gid
                """,
                (operator_id,),
            ).fetchall()
        return tuple(PeerBinding(uid=int(row[0]), gid=int(row[1])) for row in rows)

    def resolve_mission_grant(
        self,
        operator_id: str,
        *,
        subject_id: str,
        mission_id: str,
    ) -> MissionGrantSnapshot | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT g.subject_id, g.mission_id, r.revision
                FROM operator_mission_grants AS g
                JOIN operator_mission_grant_revisions AS r USING (operator_id)
                JOIN control_missions AS m USING (mission_id)
                WHERE g.operator_id = ? AND g.subject_id = ? AND g.mission_id = ?
                  AND g.active = 1 AND m.active = 1
                """,
                (operator_id, subject_id, mission_id),
            ).fetchone()
        if row is None:
            return None
        return MissionGrantSnapshot(
            operator_id=operator_id,
            subject_id=str(row[0]),
            mission_id=str(row[1]),
            revision=int(row[2]),
        )

    def active_mission_ids(self, operator_id: str) -> tuple[str, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT g.mission_id
                FROM operator_mission_grants AS g
                JOIN control_missions AS m USING (mission_id)
                WHERE g.operator_id = ? AND g.active = 1 AND m.active = 1
                ORDER BY g.mission_id
                """,
                (operator_id,),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def sync_operator_peer_bindings(
        self,
        actor: AuthenticatedControlPrincipal,
        *,
        operator_id: str,
        bindings: Iterable[PeerBinding],
        expected_revision: int,
    ) -> int:
        self._require_current_admin(actor)
        desired = tuple(sorted(set(bindings)))
        timestamp = time.time()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._fence_admin_in_transaction(connection, actor)
            self._require_active_operator(connection, operator_id)
            current_revision = self._revision(connection, "operator_peer_binding_revisions", operator_id)
            self._require_expected(current_revision, expected_revision)
            current = {
                PeerBinding(uid=int(row[0]), gid=int(row[1]))
                for row in connection.execute(
                    """
                    SELECT peer_uid, peer_gid FROM operator_peer_bindings
                    WHERE operator_id = ? AND active = 1
                    """,
                    (operator_id,),
                ).fetchall()
            }
            if current == set(desired):
                return current_revision
            new_revision = current_revision + 1
            connection.execute(
                "UPDATE operator_peer_bindings SET active = 0, updated_at = ? WHERE operator_id = ?",
                (timestamp, operator_id),
            )
            for binding in desired:
                connection.execute(
                    """
                    INSERT INTO operator_peer_bindings
                        (operator_id, peer_uid, peer_gid, active, updated_at)
                    VALUES (?, ?, ?, 1, ?)
                    ON CONFLICT(operator_id, peer_uid, peer_gid) DO UPDATE SET
                        active = 1, updated_at = excluded.updated_at
                    """,
                    (operator_id, binding.uid, binding.gid, timestamp),
                )
            connection.execute(
                """
                INSERT INTO operator_peer_binding_revisions (operator_id, revision)
                VALUES (?, ?)
                ON CONFLICT(operator_id) DO UPDATE SET revision = excluded.revision
                """,
                (operator_id, new_revision),
            )
            self._advance_authorization_revision(connection, operator_id)
            return new_revision

    def revoke_operator_peer_binding(
        self,
        actor: AuthenticatedControlPrincipal,
        *,
        operator_id: str,
        binding: PeerBinding,
        expected_revision: int,
    ) -> int:
        self._require_current_admin(actor)
        timestamp = time.time()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._fence_admin_in_transaction(connection, actor)
            self._require_active_operator(connection, operator_id)
            current_revision = self._revision(connection, "operator_peer_binding_revisions", operator_id)
            self._require_expected(current_revision, expected_revision)
            cursor = connection.execute(
                """
                UPDATE operator_peer_bindings SET active = 0, updated_at = ?
                WHERE operator_id = ? AND peer_uid = ? AND peer_gid = ? AND active = 1
                """,
                (timestamp, operator_id, binding.uid, binding.gid),
            )
            if cursor.rowcount == 0:
                return current_revision
            new_revision = current_revision + 1
            connection.execute(
                "UPDATE operator_peer_binding_revisions SET revision = ? WHERE operator_id = ?",
                (new_revision, operator_id),
            )
            self._advance_authorization_revision(connection, operator_id)
            return new_revision

    def sync_operator_mission_grants(
        self,
        actor: AuthenticatedControlPrincipal,
        *,
        operator_id: str,
        mission_ids: Iterable[str],
        expected_revision: int,
    ) -> int:
        self._require_current_admin(actor)
        desired = tuple(sorted(set(mission_ids)))
        if any(not isinstance(mission_id, str) or not mission_id for mission_id in desired):
            raise ValueError("mission IDs must not be empty")
        timestamp = time.time()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._fence_admin_in_transaction(connection, actor)
            operator = self._require_active_operator(connection, operator_id)
            current_revision = self._revision(connection, "operator_mission_grant_revisions", operator_id)
            self._require_expected(current_revision, expected_revision)
            known = {
                str(row[0])
                for row in connection.execute(
                    "SELECT mission_id FROM control_missions WHERE mission_id IN ({}) AND active = 1".format(
                        ",".join("?" for _ in desired) or "NULL"
                    ),
                    desired,
                ).fetchall()
            }
            if known != set(desired):
                raise LookupError("all missions must exist and be active")
            current = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT mission_id FROM operator_mission_grants
                    WHERE operator_id = ? AND active = 1
                    """,
                    (operator_id,),
                ).fetchall()
            }
            if current == set(desired):
                return current_revision
            new_revision = current_revision + 1
            connection.execute(
                "UPDATE operator_mission_grants SET active = 0, updated_at = ? WHERE operator_id = ?",
                (timestamp, operator_id),
            )
            subject_id = str(operator["subject_id"])
            for mission_id in desired:
                connection.execute(
                    """
                    INSERT INTO operator_mission_grants
                        (operator_id, subject_id, mission_id, active, updated_at)
                    VALUES (?, ?, ?, 1, ?)
                    ON CONFLICT(operator_id, mission_id) DO UPDATE SET
                        subject_id = excluded.subject_id,
                        active = 1,
                        updated_at = excluded.updated_at
                    """,
                    (operator_id, subject_id, mission_id, timestamp),
                )
            connection.execute(
                """
                INSERT INTO operator_mission_grant_revisions (operator_id, revision)
                VALUES (?, ?)
                ON CONFLICT(operator_id) DO UPDATE SET revision = excluded.revision
                """,
                (operator_id, new_revision),
            )
            self._advance_authorization_revision(connection, operator_id)
            return new_revision

    def revoke_operator_mission_grant(
        self,
        actor: AuthenticatedControlPrincipal,
        *,
        operator_id: str,
        mission_id: str,
        expected_revision: int,
    ) -> int:
        self._require_current_admin(actor)
        timestamp = time.time()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._fence_admin_in_transaction(connection, actor)
            self._require_active_operator(connection, operator_id)
            current_revision = self._revision(connection, "operator_mission_grant_revisions", operator_id)
            self._require_expected(current_revision, expected_revision)
            cursor = connection.execute(
                """
                UPDATE operator_mission_grants SET active = 0, updated_at = ?
                WHERE operator_id = ? AND mission_id = ? AND active = 1
                """,
                (timestamp, operator_id, mission_id),
            )
            if cursor.rowcount == 0:
                return current_revision
            new_revision = current_revision + 1
            connection.execute(
                "UPDATE operator_mission_grant_revisions SET revision = ? WHERE operator_id = ?",
                (new_revision, operator_id),
            )
            self._advance_authorization_revision(connection, operator_id)
            return new_revision

    def set_peer_binding(
        self,
        operator_id: str,
        *,
        uid: int,
        gid: int,
        active: bool = True,
    ) -> None:
        """Convenience method to set or update a peer binding directly."""
        timestamp = time.time()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO operator_peer_bindings (operator_id, peer_uid, peer_gid, active, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(operator_id, peer_uid, peer_gid) DO UPDATE SET
                    active = excluded.active, updated_at = excluded.updated_at
                """,
                (operator_id, uid, gid, 1 if active else 0, timestamp),
            )
            connection.execute(
                """
                INSERT INTO operator_peer_binding_revisions (operator_id, revision)
                VALUES (?, 1)
                ON CONFLICT(operator_id) DO UPDATE SET revision = revision + 1
                """,
                (operator_id,),
            )

    def set_mission_grant(
        self,
        operator_id: str,
        *,
        subject_id: str,
        mission_id: str,
        active: bool = True,
    ) -> None:
        """Convenience method to set or update a mission grant directly."""
        timestamp = time.time()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO control_missions (mission_id, mission_kind, active, created_at)
                VALUES (?, 'operation', 1, ?)
                ON CONFLICT(mission_id) DO NOTHING
                """,
                (mission_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO operator_mission_grants (operator_id, subject_id, mission_id, active, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(operator_id, mission_id) DO UPDATE SET
                    active = excluded.active, updated_at = excluded.updated_at, subject_id = excluded.subject_id
                """,
                (operator_id, subject_id, mission_id, 1 if active else 0, timestamp),
            )
            connection.execute(
                """
                INSERT INTO operator_mission_grant_revisions (operator_id, revision)
                VALUES (?, 1)
                ON CONFLICT(operator_id) DO UPDATE SET revision = revision + 1
                """,
                (operator_id,),
            )


__all__ = [
    "SYSTEM_CONTROL_MISSION_ID",
    "GrantConflictError",
    "GrantService",
    "MissionGrantSnapshot",
    "PeerBinding",
    "PeerBindingSnapshot",
    "ensure_system_control_mission",
    "initialize_grant_schema",
    "insert_initial_bootstrap_grants",
]
