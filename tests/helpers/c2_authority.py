"""Test authority provisioning helpers for C2 test suites."""

from __future__ import annotations

import os
import sqlite3
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_migrations import apply_control_migrations


def _get_connection(conn_or_path: sqlite3.Connection | str) -> tuple[sqlite3.Connection, bool]:
    if isinstance(conn_or_path, str):
        conn = sqlite3.connect(conn_or_path)
        apply_control_migrations(conn)
        return conn, True
    apply_control_migrations(conn_or_path)
    return conn_or_path, False


def create_test_operator(
    conn_or_path: sqlite3.Connection | str,
    operator_id: str = "op_test_admin",
    subject_id: str = "s_test",
    name: str = "Test Admin",
    role: str = "admin",
    api_key: str | None = None,
    authorization_revision: int = 1,
    active: bool = True,
) -> dict[str, Any]:
    conn, should_close = _get_connection(conn_or_path)
    try:
        from core.c2.operators import insert_operator_record

        key_val = api_key or f"api_key_{operator_id}"
        cur = conn.execute("SELECT operator_id FROM operators WHERE operator_id = ?", (operator_id,))
        if cur.fetchone() is None:
            insert_operator_record(
                conn,
                operator_id=operator_id,
                subject_id=subject_id,
                name=f"Operator {operator_id}" if name == "Test Admin" else name,
                role=role,
                api_key=key_val,
            )
        conn.execute(
            """
            UPDATE operators
            SET active = ?, authorization_revision = ?, subject_id = ?, role = ?
            WHERE operator_id = ?
            """,
            (1 if active else 0, authorization_revision, subject_id, role, operator_id),
        )
        conn.commit()
        cur = conn.execute(
            "SELECT operator_id, subject_id, name, role, active, authorization_revision FROM operators WHERE operator_id = ?",
            (operator_id,),
        )
        row = cur.fetchone()
        return {
            "operator_id": row[0],
            "subject_id": row[1],
            "name": row[2],
            "role": row[3],
            "active": bool(row[4]),
            "authorization_revision": row[5],
        }
    finally:
        if should_close:
            conn.close()


def create_test_control_key(
    conn_or_path: sqlite3.Connection | str,
    key_id: str = "k_test_1",
    operator_id: str = "op_test_admin",
    public_key: bytes | None = None,
    algorithm: str = "ed25519",
    key_revision: int = 1,
    valid_from_ms: int = 0,
    valid_until_ms: int = 253402300799000,
    active: bool = True,
) -> bytes:
    if public_key is None:
        priv = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    elif len(public_key) == 32:
        pub_bytes = public_key
    else:
        raise ValueError(f"public_key must be exactly 32 bytes, got {len(public_key)}")

    conn, should_close = _get_connection(conn_or_path)
    try:
        conn.execute(
            """
            INSERT INTO operator_control_signing_keys (
                key_id, operator_id, public_key_bytes, algorithm,
                key_revision, valid_from_ms, valid_until_ms, active, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(key_id) DO UPDATE SET
                operator_id = excluded.operator_id,
                public_key_bytes = excluded.public_key_bytes,
                algorithm = excluded.algorithm,
                key_revision = excluded.key_revision,
                valid_from_ms = excluded.valid_from_ms,
                valid_until_ms = excluded.valid_until_ms,
                active = excluded.active
            """,
            (
                key_id,
                operator_id,
                pub_bytes,
                algorithm,
                key_revision,
                valid_from_ms,
                valid_until_ms,
                1 if active else 0,
                time.time(),
            ),
        )
        conn.commit()
        return pub_bytes
    finally:
        if should_close:
            conn.close()


def create_test_peer_binding(
    conn_or_path: sqlite3.Connection | str,
    operator_id: str = "op_test_admin",
    peer_uid: int | None = None,
    peer_gid: int | None = None,
    revision: int = 1,
    active: bool = True,
) -> tuple[int, int]:
    uid = os.getuid() if peer_uid is None else peer_uid
    gid = os.getgid() if peer_gid is None else peer_gid
    conn, should_close = _get_connection(conn_or_path)
    try:
        conn.execute(
            """
            INSERT INTO operator_peer_bindings (
                operator_id, peer_uid, peer_gid, active, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(operator_id, peer_uid, peer_gid) DO UPDATE SET
                active = excluded.active,
                updated_at = excluded.updated_at
            """,
            (operator_id, uid, gid, 1 if active else 0, time.time()),
        )
        conn.execute(
            """
            INSERT INTO operator_peer_binding_revisions (
                operator_id, revision
            ) VALUES (?, ?)
            ON CONFLICT(operator_id) DO UPDATE SET
                revision = excluded.revision
            """,
            (operator_id, revision),
        )
        conn.commit()
        return uid, gid
    finally:
        if should_close:
            conn.close()


def create_test_mission(
    conn_or_path: sqlite3.Connection | str,
    mission_id: str = "m_test",
    mission_kind: str = "test",
    active: bool = True,
) -> str:
    conn, should_close = _get_connection(conn_or_path)
    try:
        conn.execute(
            """
            INSERT INTO control_missions (
                mission_id, mission_kind, active, created_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(mission_id) DO UPDATE SET
                mission_kind = excluded.mission_kind,
                active = excluded.active
            """,
            (mission_id, mission_kind, 1 if active else 0, time.time()),
        )
        conn.commit()
        return mission_id
    finally:
        if should_close:
            conn.close()


def create_test_mission_grant(
    conn_or_path: sqlite3.Connection | str,
    operator_id: str = "op_test_admin",
    subject_id: str = "s_test",
    mission_id: str = "m_test",
    revision: int = 1,
    active: bool = True,
) -> tuple[str, str, str]:
    conn, should_close = _get_connection(conn_or_path)
    try:
        create_test_mission(conn, mission_id=mission_id)
        conn.execute(
            """
            INSERT INTO operator_mission_grants (
                operator_id, subject_id, mission_id, active, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(operator_id, mission_id) DO UPDATE SET
                subject_id = excluded.subject_id,
                active = excluded.active,
                updated_at = excluded.updated_at
            """,
            (operator_id, subject_id, mission_id, 1 if active else 0, time.time()),
        )
        conn.execute(
            """
            INSERT INTO operator_mission_grant_revisions (
                operator_id, revision
            ) VALUES (?, ?)
            ON CONFLICT(operator_id) DO UPDATE SET
                revision = excluded.revision
            """,
            (operator_id, revision),
        )
        conn.commit()
        return operator_id, subject_id, mission_id
    finally:
        if should_close:
            conn.close()


def provision_test_authority(
    conn_or_path: sqlite3.Connection | str,
    operator_id: str = "op_test_admin",
    subject_id: str = "s_test",
    key_id: str = "k_test_1",
    public_key: bytes | None = None,
    private_seed: bytes | None = None,
    mission_id: str = "m_test",
    peer_uid: int | None = None,
    peer_gid: int | None = None,
    role: str = "admin",
) -> tuple[str, str, str, bytes, bytes]:
    """Fully provision operator, signing key, peer binding, and mission grant."""
    if private_seed is not None:
        if len(private_seed) != 32:
            raise ValueError(f"private_seed must be 32 bytes, got {len(private_seed)}")
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_seed)
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        priv_seed = private_seed
    elif public_key is not None:
        if len(public_key) != 32:
            raise ValueError(f"public_key must be 32 bytes, got {len(public_key)}")
        pub_bytes = public_key
        priv_seed = b""
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_seed = priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    conn, should_close = _get_connection(conn_or_path)
    try:
        create_test_operator(
            conn,
            operator_id=operator_id,
            subject_id=subject_id,
            name=f"Operator {operator_id}",
            role=role,
        )
        create_test_control_key(
            conn,
            key_id=key_id,
            operator_id=operator_id,
            public_key=pub_bytes,
        )
        create_test_peer_binding(
            conn,
            operator_id=operator_id,
            peer_uid=peer_uid,
            peer_gid=peer_gid,
        )
        create_test_mission_grant(
            conn,
            operator_id=operator_id,
            subject_id=subject_id,
            mission_id=mission_id,
        )
        return operator_id, subject_id, key_id, pub_bytes, priv_seed
    finally:
        if should_close:
            conn.close()
