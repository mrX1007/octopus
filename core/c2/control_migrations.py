"""Versioned database migrations for C2 Control Plane state storage."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import time
from collections.abc import Callable
from typing import NamedTuple


class MigrationStep(NamedTuple):
    version: int
    name: str
    up: Callable[[sqlite3.Connection], None]


def _migration_v1_base_schema(conn: sqlite3.Connection) -> None:
    """Migration 1: Base operators, missions, and grants tables."""
    conn.execute(
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
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_subject_id ON operators(subject_id)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_api_key_hash ON operators(api_key_hash)")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS control_missions (
            mission_id TEXT PRIMARY KEY,
            mission_kind TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS operator_peer_binding_revisions (
            operator_id TEXT PRIMARY KEY REFERENCES operators(operator_id),
            revision INTEGER NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS operator_peer_bindings (
            operator_id TEXT NOT NULL REFERENCES operators(operator_id),
            peer_uid INTEGER NOT NULL,
            peer_gid INTEGER NOT NULL,
            active INTEGER NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (operator_id, peer_uid, peer_gid)
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS operator_mission_grant_revisions (
            operator_id TEXT PRIMARY KEY REFERENCES operators(operator_id),
            revision INTEGER NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS operator_mission_grants (
            operator_id TEXT NOT NULL REFERENCES operators(operator_id),
            subject_id TEXT NOT NULL,
            mission_id TEXT NOT NULL REFERENCES control_missions(mission_id),
            active INTEGER NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (operator_id, mission_id)
        )
        """
    )


def _migration_v2_operator_control_keys(conn: sqlite3.Connection) -> None:
    """Migration 2: Asymmetric operator control verification keys."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS operator_control_signing_keys (
            key_id TEXT PRIMARY KEY,
            operator_id TEXT NOT NULL REFERENCES operators(operator_id),
            public_key_bytes BLOB NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'ed25519',
            key_revision INTEGER NOT NULL DEFAULT 1,
            valid_from_ms INTEGER NOT NULL DEFAULT 0,
            valid_until_ms INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_op_control_keys_operator ON operator_control_signing_keys(operator_id)"
    )


def _migration_v3_replay_store(conn: sqlite3.Connection) -> None:
    """Migration 3: Replay nonce store with indexed expiration."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS control_replay_nonces (
            key_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            mission_id TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (key_id, nonce)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_expires ON control_replay_nonces (expires_at_ms)")


def _migration_v4_2pc_state_machine(conn: sqlite3.Connection) -> None:
    """Migration 4: Expanded 2PC state machine with intent tracking."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS control_resource_revisions (
            resource_ref TEXT PRIMARY KEY,
            revision INTEGER NOT NULL
        )
        """
    )

    table_info = conn.execute("PRAGMA table_info(control_2pc_transactions)").fetchall()
    if not table_info:
        conn.execute(
            """
            CREATE TABLE control_2pc_transactions (
                participant_id TEXT NOT NULL,
                transaction_id TEXT NOT NULL,
                operator_id TEXT NOT NULL DEFAULT '',
                key_id TEXT NOT NULL DEFAULT '',
                key_revision INTEGER NOT NULL DEFAULT 1,
                subject_id TEXT NOT NULL DEFAULT '',
                mission_id TEXT NOT NULL DEFAULT '',
                operation_kind TEXT NOT NULL DEFAULT '',
                transaction_intent_digest TEXT NOT NULL DEFAULT '',
                resource_ref TEXT NOT NULL,
                resource_revision INTEGER NOT NULL,
                phase TEXT NOT NULL,
                action TEXT NOT NULL,
                payload_schema_id TEXT,
                payload_digest TEXT,
                payload_ref TEXT,
                canonical_payload_b64u TEXT,
                prepared_request_digest TEXT,
                prepared_base_revision INTEGER DEFAULT 0,
                prepare_receipt_ref TEXT,
                prepare_receipt_digest TEXT,
                commit_request_digest TEXT,
                commit_receipt_ref TEXT,
                commit_receipt_digest TEXT,
                finalize_request_digest TEXT,
                finalize_receipt_ref TEXT,
                finalize_receipt_digest TEXT,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (participant_id, transaction_id)
            )
            """
        )
    else:
        existing_cols = {str(row[1]) for row in table_info}
        required_cols = {
            "operator_id": "TEXT NOT NULL DEFAULT ''",
            "key_id": "TEXT NOT NULL DEFAULT ''",
            "key_revision": "INTEGER NOT NULL DEFAULT 1",
            "subject_id": "TEXT NOT NULL DEFAULT ''",
            "mission_id": "TEXT NOT NULL DEFAULT ''",
            "operation_kind": "TEXT NOT NULL DEFAULT ''",
            "transaction_intent_digest": "TEXT NOT NULL DEFAULT ''",
            "payload_ref": "TEXT",
            "prepared_request_digest": "TEXT",
            "prepared_base_revision": "INTEGER DEFAULT 0",
            "commit_request_digest": "TEXT",
            "finalize_request_digest": "TEXT",
            "finalize_receipt_ref": "TEXT",
            "finalize_receipt_digest": "TEXT",
        }
        for col_name, col_def in required_cols.items():
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE control_2pc_transactions ADD COLUMN {col_name} {col_def}")


MIGRATIONS: tuple[MigrationStep, ...] = (
    MigrationStep(1, "base_schema", _migration_v1_base_schema),
    MigrationStep(2, "operator_control_keys", _migration_v2_operator_control_keys),
    MigrationStep(3, "replay_store", _migration_v3_replay_store),
    MigrationStep(4, "2pc_state_machine", _migration_v4_2pc_state_machine),
)

LATEST_SCHEMA_VERSION = 4


def _compute_step_checksum(step: MigrationStep) -> str:
    content = f"v{step.version}:{step.name}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def create_preflight_backup(db_path: str) -> str | None:
    """Create a backup of a file-backed SQLite database before migration."""
    if db_path == ":memory:" or db_path.startswith("file:"):
        return None
    if not os.path.exists(db_path):
        return None
    backup_path = f"{db_path}.bak.{int(time.time() * 1000)}"
    shutil.copy2(db_path, backup_path)
    return backup_path


def apply_control_migrations(conn: sqlite3.Connection) -> int:
    """Apply all pending versioned migrations in a transactional manner."""
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at_ms INTEGER NOT NULL,
            checksum TEXT NOT NULL
        )
        """
    )

    applied_rows = conn.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC").fetchall()
    applied_map = {int(row[0]): (str(row[1]), str(row[2])) for row in applied_rows}

    # Verify existing applied migrations
    for version, (name, checksum) in applied_map.items():
        if version > LATEST_SCHEMA_VERSION:
            raise RuntimeError(
                f"Database has future schema version {version} (latest supported is {LATEST_SCHEMA_VERSION})"
            )
        step = next((s for s in MIGRATIONS if s.version == version), None)
        if step is None:
            raise RuntimeError(f"Unknown migration version {version} found in database")
        expected_checksum = _compute_step_checksum(step)
        if checksum != expected_checksum:
            raise RuntimeError(
                f"Migration checksum mismatch for version {version} ({name}): stored {checksum} != expected {expected_checksum}"
            )

    # Apply pending migrations
    now_ms = int(time.time() * 1000)
    for step in MIGRATIONS:
        if step.version not in applied_map:
            step.up(conn)
            checksum = _compute_step_checksum(step)
            conn.execute(
                """
                INSERT INTO schema_migrations (version, name, applied_at_ms, checksum)
                VALUES (?, ?, ?, ?)
                """,
                (step.version, step.name, now_ms, checksum),
            )

    return LATEST_SCHEMA_VERSION


def verify_schema_ready(conn: sqlite3.Connection) -> bool:
    """Verify that the database schema is at the latest migration version."""
    try:
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return row is not None and row[0] == LATEST_SCHEMA_VERSION
    except Exception:
        return False


__all__ = [
    "LATEST_SCHEMA_VERSION",
    "MIGRATIONS",
    "MigrationStep",
    "apply_control_migrations",
    "create_preflight_backup",
    "verify_schema_ready",
]
