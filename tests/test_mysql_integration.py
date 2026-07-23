"""Provisioned MySQL persistence smoke contract."""

from __future__ import annotations

import importlib
import os

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.mysql]


def test_mysql_schema_and_session_round_trip(monkeypatch) -> None:
    if os.environ.get("OCTOPUS_TEST_MYSQL") != "1":
        pytest.skip("provisioned MySQL service is not enabled")

    monkeypatch.setenv("OCTOPUS_DB_HOST", os.environ.get("OCTOPUS_DB_HOST", "127.0.0.1"))
    monkeypatch.setenv("OCTOPUS_DB_USER", os.environ.get("OCTOPUS_DB_USER", "root"))
    monkeypatch.setenv("OCTOPUS_DB_PASS", os.environ["OCTOPUS_DB_PASS"])
    monkeypatch.setenv("OCTOPUS_DB_NAME", os.environ.get("OCTOPUS_DB_NAME", "octopus_test"))

    import config
    import db

    importlib.reload(config)
    importlib.reload(db)
    db.init_db()
    session_id = db.create_session("mysql-integration.invalid")
    try:
        report = db.get_session(session_id)
        assert report["history"] is not None
        assert report["history"][1] == "mysql-integration.invalid"
    finally:
        db.delete_full_session(session_id)
