"""Tests for C2 database migrations (§14.1)."""

from __future__ import annotations

import sqlite3

import pytest

from core.c2.control_migrations import (
    LATEST_SCHEMA_VERSION,
    apply_control_migrations,
    create_preflight_backup,
    verify_schema_ready,
)

pytestmark = pytest.mark.unit


def test_migrations_fresh_database(tmp_path):
    db_file = str(tmp_path / "migration_test.db")
    with sqlite3.connect(db_file) as conn:
        assert not verify_schema_ready(conn)
        ver = apply_control_migrations(conn)
        assert ver == LATEST_SCHEMA_VERSION
        assert verify_schema_ready(conn)

        # Check tables created
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "operators" in tables
        assert "operator_control_signing_keys" in tables
        assert "control_replay_nonces" in tables
        assert "control_2pc_transactions" in tables
        assert "control_resource_revisions" in tables
        assert "schema_migrations" in tables


def test_migrations_idempotency(tmp_path):
    db_file = str(tmp_path / "idempotent.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        # Apply again
        ver = apply_control_migrations(conn)
        assert ver == LATEST_SCHEMA_VERSION
        assert verify_schema_ready(conn)


def test_migrations_preflight_backup(tmp_path):
    db_file = str(tmp_path / "backup_test.db")
    with sqlite3.connect(db_file) as conn:
        conn.execute("CREATE TABLE dummy (id INTEGER)")
        conn.execute("INSERT INTO dummy VALUES (1)")
        conn.commit()

    backup = create_preflight_backup(db_file)
    assert backup is not None
    assert "bak" in backup

    with sqlite3.connect(backup) as bconn:
        row = bconn.execute("SELECT id FROM dummy").fetchone()
        assert row[0] == 1


def test_migrations_rejects_corrupted_checksum(tmp_path):
    db_file = str(tmp_path / "corrupt.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        # Corrupt checksum in schema_migrations
        conn.execute("UPDATE schema_migrations SET checksum = 'bad_checksum' WHERE version = 1")
        conn.commit()

    with sqlite3.connect(db_file) as conn, pytest.raises(RuntimeError, match="Migration checksum mismatch"):
        apply_control_migrations(conn)
