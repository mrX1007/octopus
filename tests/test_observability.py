"""Hermetic contracts for audit persistence and in-process metrics."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.observability.audit as audit_module
import core.observability.metrics as metrics_module
from core.observability import AuditLog, Metrics
from core.observability.audit import AuditEntry
from core.observability.metrics import MetricEntry
from core.secrets import Redactor, SecretStore, is_secret_ref

pytestmark = pytest.mark.unit


@pytest.fixture
def audit_redactor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Use a real redactor without touching the process-wide secret store."""
    store = SecretStore(str(tmp_path / "secrets" / "secrets.db"), key=b"a" * 32)
    redactor = Redactor(store)
    monkeypatch.setattr(audit_module, "get_redactor", lambda: redactor)
    yield redactor
    store.close()


def test_audit_log_redacts_persists_and_filters_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_redactor: Redactor,
) -> None:
    timestamps = iter((100.0, 110.0, 120.0, 130.0))
    monkeypatch.setattr(
        audit_module,
        "time",
        SimpleNamespace(time=lambda: next(timestamps)),
    )
    db_path = tmp_path / "audit" / "events.db"
    audit = AuditLog(str(db_path))

    audit.log_action(
        "alice",
        "scan.start",
        "host.invalid",
        details={"password": "hunter2", "nested": ["token=abcdef"]},
        duration=1.25,
    )
    audit.log_action("alice", "scan.note", "host.invalid", details=None)
    audit.log_tool_execution("nmap", "host.invalid", 2.5, 0, actor="alice")
    audit.log_tool_execution("curl", "other.invalid", 3.0, 7)

    all_entries = audit.query()
    assert [entry.action for entry in all_entries] == [
        "tool.curl",
        "tool.nmap",
        "scan.note",
        "scan.start",
    ]
    assert all(isinstance(entry, AuditEntry) for entry in all_entries)
    assert all_entries[0].result == "failed"
    assert all_entries[1].result == "success"
    assert all_entries[1].details == {"exit_code": 0}
    assert all_entries[2].details == {}

    protected = all_entries[3].details
    assert is_secret_ref(protected["password"])
    assert "abcdef" not in protected["nested"][0]
    assert "secret://" in protected["nested"][0]

    filtered = audit.query(
        actor="alice",
        action="tool.",
        target="host.invalid",
        since=115.0,
        limit=1,
    )
    assert [(entry.action, entry.duration) for entry in filtered] == [("tool.nmap", 2.5)]
    assert audit.query(actor="nobody") == []

    raw_database = db_path.read_bytes()
    assert b"hunter2" not in raw_database
    assert b"abcdef" not in raw_database


def test_audit_log_default_path_migrates_existing_plaintext(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_redactor: Redactor,
) -> None:
    fake_module = tmp_path / "project" / "core" / "observability" / "audit.py"
    monkeypatch.setattr(audit_module, "__file__", str(fake_module))
    expected_path = tmp_path / "project" / "data" / "audit.db"

    initial = AuditLog()
    assert Path(initial.db_path) == expected_path

    with sqlite3.connect(expected_path) as conn:
        conn.executemany(
            """
            INSERT INTO audit_log
                (timestamp, actor, action, target, result, details, duration)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    1.0,
                    "password=actor-secret",
                    "token=action-secret",
                    "https://user:target-secret@example.invalid",
                    "password=result-secret",
                    json.dumps({"api_key": "detail-secret"}),
                    0.1,
                ),
                (2.0, "system", "legacy.empty", "", "success", "", 0.0),
            ),
        )
        conn.commit()

    migrated = AuditLog()
    rows = migrated.query(limit=10)
    assert rows[0].action == "legacy.empty"
    assert rows[0].details == {}

    protected = rows[1]
    rendered = json.dumps(protected.__dict__, sort_keys=True)
    for plaintext in (
        "actor-secret",
        "action-secret",
        "target-secret",
        "result-secret",
        "detail-secret",
    ):
        assert plaintext not in rendered
    assert "secret://" in rendered


def test_metrics_collect_timers_report_and_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [10.0]
    monkeypatch.setattr(metrics_module, "time", SimpleNamespace(time=lambda: now[0]))
    metrics = Metrics()

    now[0] = 11.0
    metrics.counter("requests")
    now[0] = 12.0
    metrics.counter("requests", 2)
    now[0] = 13.0
    metrics.gauge("queue.depth", 1.23456)
    now[0] = 14.0
    metrics.gauge("queue.depth", 2.34567)

    now[0] = 20.0
    metrics.record_timer("database", 0.25)
    now[0] = 21.0
    metrics.record_timer("database", 0.75)

    now[0] = 22.0
    with metrics.timer("operation"):
        now[0] = 22.4

    now[0] = 23.0
    with pytest.raises(RuntimeError, match="operation failed"), metrics.timer("operation"):
        now[0] = 23.6
        raise RuntimeError("operation failed")

    metrics._metrics["empty.timer"] = MetricEntry(
        name="empty.timer",
        metric_type="timer",
    )
    metrics._metrics["ignored"] = MetricEntry(name="ignored", metric_type="histogram")

    assert metrics.get("requests") == 3
    assert metrics.get("missing") is None

    now[0] = 30.0
    report = metrics.report()
    assert report["uptime_seconds"] == 20.0
    assert report["counters"] == {"requests": 3}
    assert report["gauges"] == {"queue.depth": 2.346}
    assert report["timers"]["database"] == {
        "count": 2,
        "total": 1.0,
        "avg": 0.5,
        "min": 0.25,
        "max": 0.75,
    }
    assert report["timers"]["operation"] == {
        "count": 2,
        "total": 1.0,
        "avg": 0.5,
        "min": 0.4,
        "max": 0.6,
    }
    assert report["timers"]["empty.timer"] == {
        "count": 0,
        "total": 0.0,
        "avg": 0,
        "min": 0,
        "max": 0.0,
    }
    assert "ignored" not in json.dumps(report, sort_keys=True)

    now[0] = 40.0
    metrics.reset()
    assert metrics.get("requests") is None
    now[0] = 41.0
    assert metrics.report() == {
        "uptime_seconds": 1.0,
        "counters": {},
        "gauges": {},
        "timers": {},
    }


def test_get_metrics_returns_one_process_global_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metrics_module, "_global_metrics", None)

    first = metrics_module.get_metrics()
    second = metrics_module.get_metrics()

    assert isinstance(first, Metrics)
    assert second is first
