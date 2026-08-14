"""First-admin bootstrap contract tests."""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest

import core.c2.bootstrap as bootstrap_module
from core.c2.bootstrap import BootstrapState, bootstrap_admin_operator
from core.c2.grant_service import SYSTEM_CONTROL_MISSION_ID, GrantService
from core.c2.operators import ROLE_ADMIN, OperatorManager

pytestmark = pytest.mark.unit


def _simulate_root(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int]]:
    ownership_calls: list[tuple[int, int]] = []
    monkeypatch.setattr(bootstrap_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(bootstrap_module.os, "chown", lambda _path, uid, gid: ownership_calls.append((uid, gid)))
    monkeypatch.setattr(bootstrap_module.os, "fchown", lambda _fd, uid, gid: ownership_calls.append((uid, gid)))
    return ownership_calls


def test_root_bootstrap_requires_uid_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bootstrap_module.os, "geteuid", lambda: 501)
    with pytest.raises(PermissionError, match="UID 0"):
        bootstrap_admin_operator(
            db_path=tmp_path / "c2.db",
            client_uid=1000,
            client_gid=1001,
            key_path=tmp_path / "admin.key",
        )
    assert not (tmp_path / "c2.db").exists()


def test_root_bootstrap_creates_first_admin_peer_and_system_control_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ownership_calls = _simulate_root(monkeypatch)
    db_path = tmp_path / "c2.db"
    key_path = tmp_path / "keys" / "admin.key"
    outcome = bootstrap_admin_operator(
        db_path=db_path,
        client_uid=1000,
        client_gid=1001,
        key_path=key_path,
    )
    assert outcome.state is BootstrapState.COMMITTED
    assert outcome.mission_id == SYSTEM_CONTROL_MISSION_ID
    assert not hasattr(outcome, "secret_key")
    assert ownership_calls and all(pair == (0, 0) for pair in ownership_calls)

    manager = OperatorManager(str(db_path))
    operators = manager.list_operators()
    assert len(operators) == 1
    assert operators[0]["operator_id"] == outcome.admin_id
    assert operators[0]["role"] == ROLE_ADMIN
    grants = GrantService(str(db_path))
    assert grants.resolve_peer_binding(outcome.admin_id, uid=1000, gid=1001) is not None
    assert (
        grants.resolve_mission_grant(
            outcome.admin_id,
            subject_id=outcome.subject_id,
            mission_id=SYSTEM_CONTROL_MISSION_ID,
        )
        is not None
    )


def test_root_bootstrap_does_not_grant_operational_missions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_root(monkeypatch)
    outcome = bootstrap_admin_operator(
        db_path=tmp_path / "c2.db",
        client_uid=1,
        client_gid=2,
        key_path=tmp_path / "admin.key",
    )
    grants = GrantService(str(tmp_path / "c2.db"))
    assert grants.active_mission_ids(outcome.admin_id) == (SYSTEM_CONTROL_MISSION_ID,)


def test_root_bootstrap_key_file_is_root_owned_0600(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ownership_calls = _simulate_root(monkeypatch)
    key_path = tmp_path / "private" / "admin.key"
    bootstrap_admin_operator(
        db_path=tmp_path / "c2.db",
        client_uid=1,
        client_gid=2,
        key_path=key_path,
    )
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert (0, 0) in ownership_calls
    assert key_path.read_text(encoding="utf-8").startswith("octopus-c2-")
    with sqlite3.connect(tmp_path / "c2.db") as connection:
        digest = connection.execute("SELECT api_key_hash FROM operators").fetchone()[0]
    assert digest not in key_path.read_text(encoding="utf-8")
