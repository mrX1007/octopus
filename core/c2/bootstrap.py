"""Root-only, offline, crash-recoverable first-admin bootstrap."""

from __future__ import annotations

import fcntl
import hashlib
import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from core.c2.grant_service import (
    SYSTEM_CONTROL_MISSION_ID,
    initialize_grant_schema,
    insert_initial_bootstrap_grants,
)
from core.c2.operators import ROLE_ADMIN, insert_operator_record

DEFAULT_BOOTSTRAP_KEY_PATH = Path("/root/.config/octopus/c2-bootstrap-admin.key")


class BootstrapState(str, Enum):
    PENDING = "PENDING"
    COMMITTED = "COMMITTED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class BootstrapError(RuntimeError):
    """Bootstrap cannot safely create or recover the first administrator."""


class BootstrapRecoveryRequired(BootstrapError):
    """The database committed but matching key material no longer exists."""


@dataclass(frozen=True)
class C2BootstrapConfig:
    """Non-secret outcome of first-admin bootstrap."""

    admin_id: str
    subject_id: str
    mission_id: str
    peer_uid: int
    peer_gid: int
    key_path: str
    state: BootstrapState


BootstrapAdminRecord = C2BootstrapConfig


def _initialize_journal_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS bootstrap_admin_transactions (
            transaction_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            operator_id TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            peer_uid INTEGER NOT NULL,
            peer_gid INTEGER NOT NULL,
            key_digest TEXT NOT NULL,
            temp_name TEXT NOT NULL,
            final_path TEXT NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )


@contextmanager
def _exclusive_bootstrap_connection(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = db_path.with_name(f"{db_path.name}.bootstrap.lock")
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        lock_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    connection: sqlite3.Connection | None = None
    try:
        os.fchmod(lock_fd, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BootstrapError("exclusive bootstrap lock is unavailable") from exc
        connection = sqlite3.connect(str(db_path), timeout=0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=0")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA locking_mode=EXCLUSIVE")
        try:
            connection.execute("BEGIN EXCLUSIVE")
        except sqlite3.OperationalError as exc:
            raise BootstrapError("exclusive database lock is unavailable") from exc
        initialize_grant_schema(connection)
        _initialize_journal_schema(connection)
        yield connection
    except Exception:
        if connection is not None:
            connection.rollback()
        raise
    finally:
        if connection is not None:
            connection.close()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _ensure_root_key_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BootstrapError("bootstrap key directory must be a real directory")
    os.chmod(directory, 0o700)
    os.chown(directory, 0, 0)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("short write while publishing bootstrap key")
        offset += written


def _create_temp_key(key_path: Path, key_material: bytes) -> Path:
    suffix = secrets.token_hex(12)
    temp_path = key_path.with_name(f".{key_path.name}.{suffix}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temp_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        _write_all(descriptor, key_material)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        with suppress(FileNotFoundError):
            temp_path.unlink()
        raise
    else:
        os.close(descriptor)
    return temp_path


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _file_digest(path: Path) -> str:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BootstrapRecoveryRequired("bootstrap key material is not a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise BootstrapRecoveryRequired("bootstrap key material is not mode 0600")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(4096)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _mark_recovery_required(
    connection: sqlite3.Connection,
    transaction_id: str,
) -> None:
    connection.execute(
        """
        UPDATE bootstrap_admin_transactions
        SET state = ?, updated_at = ? WHERE transaction_id = ?
        """,
        (BootstrapState.RECOVERY_REQUIRED.value, time.time(), transaction_id),
    )
    connection.commit()


def _result_from_row(row: sqlite3.Row, state: BootstrapState) -> C2BootstrapConfig:
    return C2BootstrapConfig(
        admin_id=str(row["operator_id"]),
        subject_id=str(row["subject_id"]),
        mission_id=SYSTEM_CONTROL_MISSION_ID,
        peer_uid=int(row["peer_uid"]),
        peer_gid=int(row["peer_gid"]),
        key_path=str(row["final_path"]),
        state=state,
    )


def _recover_pending(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    requested_key_path: Path,
) -> C2BootstrapConfig:
    transaction_id = str(row["transaction_id"])
    final_path = Path(str(row["final_path"]))
    temp_name = str(row["temp_name"])
    if final_path != requested_key_path or Path(temp_name).name != temp_name:
        _mark_recovery_required(connection, transaction_id)
        raise BootstrapRecoveryRequired("bootstrap journal path binding is invalid")
    temp_path = final_path.parent / temp_name
    expected_digest = str(row["key_digest"])
    final_present = os.path.lexists(final_path)
    temp_present = os.path.lexists(temp_path)
    try:
        final_matches = final_present and _file_digest(final_path) == expected_digest
        temp_matches = temp_present and _file_digest(temp_path) == expected_digest
    except BootstrapRecoveryRequired:
        _mark_recovery_required(connection, transaction_id)
        raise
    if not final_matches and not temp_matches:
        _mark_recovery_required(connection, transaction_id)
        raise BootstrapRecoveryRequired("committed bootstrap key material is missing")
    if not final_matches:
        if final_present:
            _mark_recovery_required(connection, transaction_id)
            raise BootstrapRecoveryRequired("published bootstrap key digest mismatch")
        os.replace(temp_path, final_path)
        _fsync_directory(final_path.parent)
    elif temp_present:
        temp_path.unlink()
        _fsync_directory(final_path.parent)
    connection.execute(
        """
        UPDATE bootstrap_admin_transactions
        SET state = ?, updated_at = ? WHERE transaction_id = ? AND state = ?
        """,
        (
            BootstrapState.COMMITTED.value,
            time.time(),
            transaction_id,
            BootstrapState.PENDING.value,
        ),
    )
    connection.commit()
    return _result_from_row(row, BootstrapState.COMMITTED)


def bootstrap_admin_operator(
    *,
    db_path: str | Path,
    client_uid: int,
    client_gid: int,
    name: str = "bootstrap-admin",
    key_path: str | Path = DEFAULT_BOOTSTRAP_KEY_PATH,
) -> C2BootstrapConfig:
    """Create or recover the sole first administrator without exposing its key."""

    if os.geteuid() != 0:
        raise PermissionError("first-admin bootstrap requires effective UID 0")
    if isinstance(client_uid, bool) or not isinstance(client_uid, int) or client_uid < 0:
        raise ValueError("client UID must be a non-negative integer")
    if isinstance(client_gid, bool) or not isinstance(client_gid, int) or client_gid < 0:
        raise ValueError("client GID must be a non-negative integer")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("administrator name must not be empty")
    database_path = Path(db_path).expanduser().resolve()
    final_path = Path(key_path).expanduser().resolve()
    _ensure_root_key_directory(final_path.parent)

    with _exclusive_bootstrap_connection(database_path) as connection:
        journals = connection.execute(
            "SELECT * FROM bootstrap_admin_transactions ORDER BY created_at"
        ).fetchall()
        if len(journals) > 1:
            raise BootstrapRecoveryRequired("multiple bootstrap journals exist")
        if journals:
            journal = journals[0]
            state = BootstrapState(str(journal["state"]))
            if state is BootstrapState.PENDING:
                return _recover_pending(connection, journal, final_path)
            if state is BootstrapState.RECOVERY_REQUIRED:
                raise BootstrapRecoveryRequired("offline key recovery is required")
            raise BootstrapError("the first administrator is already bootstrapped")

        existing_admin = connection.execute(
            "SELECT operator_id FROM operators WHERE role = ? LIMIT 1",
            (ROLE_ADMIN,),
        ).fetchone()
        if existing_admin is not None:
            raise BootstrapError("an administrator already exists")
        if final_path.exists() or final_path.is_symlink():
            raise BootstrapError("bootstrap key path already exists")

        operator_id = f"admin:{secrets.token_hex(16)}"
        subject_id = f"subject:{secrets.token_hex(16)}"
        api_key = f"octopus-c2-{secrets.token_urlsafe(32)}"
        key_material = api_key.encode("utf-8")
        key_digest = hashlib.sha256(key_material).hexdigest()
        temp_path = _create_temp_key(final_path, key_material)
        transaction_id = f"bootstrap:{secrets.token_hex(16)}"
        timestamp = time.time()
        database_committed = False
        try:
            insert_operator_record(
                connection,
                operator_id=operator_id,
                subject_id=subject_id,
                name=name.strip(),
                role=ROLE_ADMIN,
                api_key=api_key,
                created_at=timestamp,
            )
            insert_initial_bootstrap_grants(
                connection,
                operator_id=operator_id,
                subject_id=subject_id,
                peer_uid=client_uid,
                peer_gid=client_gid,
                now=timestamp,
            )
            connection.execute(
                """
                INSERT INTO bootstrap_admin_transactions (
                    transaction_id, state, operator_id, subject_id,
                    peer_uid, peer_gid, key_digest, temp_name, final_path,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id,
                    BootstrapState.PENDING.value,
                    operator_id,
                    subject_id,
                    client_uid,
                    client_gid,
                    key_digest,
                    temp_path.name,
                    str(final_path),
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
            database_committed = True
        except Exception:
            if not database_committed:
                try:
                    temp_path.unlink()
                    _fsync_directory(temp_path.parent)
                except FileNotFoundError:
                    pass
            raise
        finally:
            del api_key
            del key_material

        # Once the database commit exists, failures deliberately leave the
        # PENDING journal and temp file for idempotent recovery.
        os.replace(temp_path, final_path)
        _fsync_directory(final_path.parent)
        connection.execute("BEGIN EXCLUSIVE")
        cursor = connection.execute(
            """
            UPDATE bootstrap_admin_transactions
            SET state = ?, updated_at = ?
            WHERE transaction_id = ? AND state = ?
            """,
            (
                BootstrapState.COMMITTED.value,
                time.time(),
                transaction_id,
                BootstrapState.PENDING.value,
            ),
        )
        if cursor.rowcount != 1:
            raise BootstrapRecoveryRequired("bootstrap journal commit transition failed")
        connection.commit()
        return C2BootstrapConfig(
            admin_id=operator_id,
            subject_id=subject_id,
            mission_id=SYSTEM_CONTROL_MISSION_ID,
            peer_uid=client_uid,
            peer_gid=client_gid,
            key_path=str(final_path),
            state=BootstrapState.COMMITTED,
        )


class C2AdminBootstrapper:
    """Small offline-command facade; it never holds or returns key plaintext."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        key_path: str | Path = DEFAULT_BOOTSTRAP_KEY_PATH,
    ) -> None:
        self._db_path = db_path
        self._key_path = key_path

    def bootstrap_admin(
        self,
        *,
        client_uid: int,
        client_gid: int,
        name: str = "bootstrap-admin",
    ) -> C2BootstrapConfig:
        return bootstrap_admin_operator(
            db_path=self._db_path,
            client_uid=client_uid,
            client_gid=client_gid,
            name=name,
            key_path=self._key_path,
        )


__all__ = [
    "DEFAULT_BOOTSTRAP_KEY_PATH",
    "BootstrapAdminRecord",
    "BootstrapError",
    "BootstrapRecoveryRequired",
    "BootstrapState",
    "C2AdminBootstrapper",
    "C2BootstrapConfig",
    "bootstrap_admin_operator",
]
