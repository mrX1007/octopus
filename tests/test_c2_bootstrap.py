"""Crash-safety and idempotence tests for offline admin bootstrap."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

import core.c2.bootstrap as bootstrap_module
from core.c2.bootstrap import (
    BootstrapError,
    BootstrapRecoveryRequired,
    BootstrapState,
    bootstrap_admin_operator,
)

pytestmark = pytest.mark.unit


def _simulate_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bootstrap_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(bootstrap_module.os, "chown", lambda *_args: None)
    monkeypatch.setattr(bootstrap_module.os, "fchown", lambda *_args: None)


def _bootstrap(tmp_path: Path):
    return bootstrap_admin_operator(
        db_path=tmp_path / "c2.db",
        client_uid=1000,
        client_gid=1001,
        key_path=tmp_path / "keys" / "admin.key",
    )


def test_bootstrap_key_publication_fsyncs_file_and_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_root(monkeypatch)
    actual_fsync = os.fsync
    fsynced_kinds: list[str] = []

    def observe_fsync(descriptor: int) -> None:
        mode = os.fstat(descriptor).st_mode
        fsynced_kinds.append("directory" if stat.S_ISDIR(mode) else "file")
        actual_fsync(descriptor)

    monkeypatch.setattr(bootstrap_module.os, "fsync", observe_fsync)
    _bootstrap(tmp_path)
    assert "file" in fsynced_kinds
    assert "directory" in fsynced_kinds
    assert fsynced_kinds.index("file") < fsynced_kinds.index("directory")


def test_bootstrap_crash_after_db_commit_finishes_pending_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_root(monkeypatch)
    actual_replace = os.replace
    calls = 0

    def crash_once(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated crash after DB commit")
        actual_replace(source, destination)

    monkeypatch.setattr(bootstrap_module.os, "replace", crash_once)
    with pytest.raises(OSError, match="simulated crash"):
        _bootstrap(tmp_path)
    with sqlite3.connect(tmp_path / "c2.db") as connection:
        assert connection.execute("SELECT state FROM bootstrap_admin_transactions").fetchone()[0] == "PENDING"
        assert connection.execute("SELECT count(*) FROM operators").fetchone()[0] == 1

    recovered = _bootstrap(tmp_path)
    assert recovered.state is BootstrapState.COMMITTED
    assert (tmp_path / "keys" / "admin.key").is_file()
    with sqlite3.connect(tmp_path / "c2.db") as connection:
        assert connection.execute("SELECT count(*) FROM operators").fetchone()[0] == 1
        assert connection.execute("SELECT state FROM bootstrap_admin_transactions").fetchone()[0] == "COMMITTED"


def test_bootstrap_pending_recovery_never_creates_second_admin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_root(monkeypatch)
    monkeypatch.setattr(
        bootstrap_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("crash")),
    )
    with pytest.raises(OSError):
        _bootstrap(tmp_path)
    with pytest.raises(OSError):
        _bootstrap(tmp_path)
    with sqlite3.connect(tmp_path / "c2.db") as connection:
        assert connection.execute("SELECT count(*) FROM operators").fetchone()[0] == 1


def test_bootstrap_missing_key_material_enters_recovery_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_root(monkeypatch)
    actual_replace = os.replace
    monkeypatch.setattr(
        bootstrap_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("crash")),
    )
    with pytest.raises(OSError):
        _bootstrap(tmp_path)
    with sqlite3.connect(tmp_path / "c2.db") as connection:
        temp_name = connection.execute("SELECT temp_name FROM bootstrap_admin_transactions").fetchone()[0]
    (tmp_path / "keys" / temp_name).unlink()
    monkeypatch.setattr(bootstrap_module.os, "replace", actual_replace)
    with pytest.raises(BootstrapRecoveryRequired):
        _bootstrap(tmp_path)
    with sqlite3.connect(tmp_path / "c2.db") as connection:
        assert connection.execute("SELECT state FROM bootstrap_admin_transactions").fetchone()[0] == "RECOVERY_REQUIRED"
        assert connection.execute("SELECT count(*) FROM operators").fetchone()[0] == 1


def test_second_bootstrap_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_root(monkeypatch)
    first = _bootstrap(tmp_path)
    with pytest.raises(BootstrapError, match="already bootstrapped"):
        _bootstrap(tmp_path)
    with sqlite3.connect(tmp_path / "c2.db") as connection:
        assert connection.execute("SELECT count(*) FROM operators").fetchone()[0] == 1
        assert connection.execute("SELECT operator_id FROM operators").fetchone()[0] == first.admin_id


def test_bootstrap_not_exposed_over_control_socket() -> None:
    from core.c2.control_commands import C2ControlActionV1

    assert all("bootstrap" not in action.value for action in C2ControlActionV1)
